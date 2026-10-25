//! UI state: process and file-activity table rows, and the recent-events log.

use std::collections::{HashMap, HashSet, VecDeque};
use std::io;
use std::time::{Instant, SystemTime};

use super::notify::Notifier;
use crate::core::detection::Detector;
use crate::core::event::{Event, EventKind, FileOp};
use crate::core::features::chains::{ProcessTreeExtractor, ProcessTreeFeatures};
use crate::core::features::{FileCountExtractor, FileCounts};
use crate::core::framework::Processor;

const LOG_MAX: usize = 1000;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum View {
    Processes,
    Files,
}

pub struct Row {
    pub pid: u32,
    pub name: String,
    pub counts: FileCounts,
    /// File events since the previous tick.
    pub rate: u64,
}

#[derive(Clone)]
pub enum LogKind {
    Start,
    Exec,
    Exit,
    Alert,
    File(FileOp),
}

#[derive(Clone)]
pub struct LogLine {
    pub time: SystemTime,
    pub pid: u32,
    pub name: String,
    pub kind: LogKind,
    pub detail: String,
}

pub struct App {
    extractor: FileCountExtractor,
    tree: ProcessTreeExtractor,
    prev_totals: HashMap<u32, u64>,
    names: HashMap<u32, String>,
    pub rows: Vec<Row>,
    /// Running processes: flagged first, then newest first.
    pub procs: Vec<ProcessTreeFeatures>,
    pub view: View,
    pub log: VecDeque<LogLine>,
    /// Alert lines, kept after the event log has scrolled past them.
    pub alerts: VecDeque<LogLine>,
    pub show_idle: bool,
    pub events_total: u64,
    pub started: Instant,
    /// Where events come from (live, recording, replay), shown in the header.
    pub source: String,
    /// LEDA model, if one was loaded.
    detector: Option<Detector>,
    /// Running processes the model flagged malicious.
    detected: HashSet<u32>,
    /// Desktop notifications for detections; only set for live runs.
    notifier: Option<Notifier>,
}

pub fn total(c: &FileCounts) -> u64 {
    c.file_create_count
        + c.file_open_count
        + c.file_read_count
        + c.file_write_count
        + c.file_rename_count
        + c.file_delete_count
}

impl App {
    pub fn new(source: String, detector: Option<Detector>) -> Self {
        Self {
            extractor: FileCountExtractor::new(),
            tree: ProcessTreeExtractor::new(),
            prev_totals: HashMap::new(),
            names: HashMap::new(),
            rows: Vec::new(),
            procs: Vec::new(),
            view: View::Processes,
            log: VecDeque::new(),
            alerts: VecDeque::new(),
            show_idle: false,
            events_total: 0,
            started: Instant::now(),
            source,
            detector,
            detected: HashSet::new(),
            notifier: None,
        }
    }

    /// Notify the desktop of every detection (not for replays: they are history).
    pub fn with_notifications(mut self) -> Self {
        self.notifier = Some(Notifier::default());
        self
    }

    /// Rebuild the tables from the events received so far.
    pub fn refresh(&mut self) {
        let snapshot = self.extractor.snapshot();
        let mut totals = HashMap::with_capacity(snapshot.len());
        self.rows = snapshot
            .into_iter()
            .map(|p| {
                let t = total(&p.counts);
                totals.insert(p.pid, t);
                let rate = t - self.prev_totals.get(&p.pid).copied().unwrap_or(0).min(t);
                Row { pid: p.pid, name: p.name, counts: p.counts, rate }
            })
            .collect();
        self.prev_totals = totals;
        self.names.retain(|pid, _| self.prev_totals.contains_key(pid));
        // Busiest first; stable order (pid) among equals.
        self.rows
            .sort_by(|a, b| b.rate.cmp(&a.rate).then(total(&b.counts).cmp(&total(&a.counts))).then(a.pid.cmp(&b.pid)));

        self.procs = self.tree.snapshot();
        for p in self.procs.iter_mut().filter(|p| self.detected.contains(&p.pid)) {
            p.alerts.insert(0, "LEDA".into());
        }
        self.procs.sort_by(|a, b| {
            a.alerts.is_empty().cmp(&b.alerts.is_empty()).then(b.start_ticks.cmp(&a.start_ticks)).then(b.pid.cmp(&a.pid))
        });
    }

    /// File rows to display under the current filter.
    pub fn visible(&self) -> impl Iterator<Item = &Row> {
        self.rows.iter().filter(|r| self.show_idle || total(&r.counts) > 0)
    }

    fn push_log(&mut self, ev: &Event, kind: LogKind, detail: String) {
        let name = self.names.get(&ev.pid).cloned().unwrap_or_else(|| "?".into());
        if self.log.len() == LOG_MAX {
            self.log.pop_front();
        }
        self.log.push_back(LogLine { time: ev.timestamp, pid: ev.pid, name, kind, detail });
    }

    /// Log line that also stays in the alerts panel.
    fn push_alert(&mut self, ev: &Event, detail: String) {
        self.push_log(ev, LogKind::Alert, detail);
        if self.alerts.len() == LOG_MAX {
            self.alerts.pop_front();
        }
        self.alerts.extend(self.log.back().cloned());
    }

    fn log_event(&mut self, ev: &Event) {
        // The command line says more than the path; a process that is already gone has neither.
        let program = |cmdline: &String, exe: &Option<std::path::PathBuf>| match exe {
            _ if !cmdline.is_empty() => cmdline.clone(),
            Some(p) => p.display().to_string(),
            None => String::new(),
        };
        let (kind, detail) = match &ev.kind {
            EventKind::ProcessStart { name, exe, cmdline, .. } => {
                self.names.insert(ev.pid, name.clone());
                (LogKind::Start, program(cmdline, exe))
            }
            EventKind::ProcessExec { name, exe, cmdline } => {
                self.names.insert(ev.pid, name.clone());
                (LogKind::Exec, program(cmdline, exe))
            }
            EventKind::ProcessExit => (LogKind::Exit, String::new()),
            EventKind::File { op, path } => (
                LogKind::File(*op),
                path.as_ref().map_or("?".into(), |p| p.display().to_string()),
            ),
        };
        self.push_log(ev, kind, detail);
        if matches!(ev.kind, EventKind::ProcessExit) {
            self.names.remove(&ev.pid);
        }
    }
}

impl Processor for App {
    fn on_event(&mut self, ev: &Event, out: &mut Vec<Event>) -> io::Result<()> {
        self.extractor.on_event(ev, out)?;
        // A start is a new process (possibly a reused pid): all its alerts are new.
        let known_alerts = match ev.kind {
            EventKind::ProcessStart { .. } => 0,
            _ => self.tree.get(ev.pid).map_or(0, |f| f.alerts.len()),
        };
        self.tree.on_event(ev, out)?;
        self.events_total += 1;
        self.log_event(ev);
        if let Some(f) = self.tree.get(ev.pid)
            && f.alerts.len() > known_alerts
        {
            let detail = format!(
                "{} · depth {} · H {:.2} · lnC {:.1} · {}",
                f.alerts[known_alerts..].join(", "),
                f.depth,
                f.cmdline_entropy,
                f.cmdline_complexity,
                f.cmdline
            );
            self.push_alert(ev, detail);
        }
        // A start is a new process (possibly a reused pid), an exit ends it: either way no longer flagged.
        if matches!(ev.kind, EventKind::ProcessStart { .. } | EventKind::ProcessExit) {
            self.detected.remove(&ev.pid);
        }
        let found = match self.detector.as_mut() {
            Some(d) => {
                d.on_event(ev, out)?;
                d.take_detections()
            }
            None => Vec::new(),
        };
        for d in found {
            self.detected.insert(d.pid);
            let detail =
                format!("LEDA malicious {:.2} · {} · {} · {}", d.score, d.trigger, d.chain.join(" > "), d.cmdline);
            self.push_alert(ev, detail);
            if let Some(n) = self.notifier.as_mut() {
                n.notify(&d);
            }
        }
        Ok(())
    }
}
