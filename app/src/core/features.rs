//! Feature extraction: turns the event stream into per-process features.

pub mod chains;

use std::collections::HashMap;
use std::io;

use super::event::{Event, EventKind, FileOp};
use super::framework::Processor;

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct FileCounts {
    pub file_create_count: u64,
    pub file_open_count: u64,
    pub file_read_count: u64,
    pub file_write_count: u64,
    pub file_rename_count: u64,
    pub file_delete_count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessFileCounts {
    pub pid: u32,
    pub name: String,
    /// Cumulative since the process was first seen.
    pub counts: FileCounts,
}

struct Entry {
    name: String,
    start_ticks: Option<u64>,
    counts: FileCounts,
}

/// Counts file events per running process.
#[derive(Default)]
pub struct FileCountExtractor {
    procs: HashMap<u32, Entry>,
}

impl FileCountExtractor {
    pub fn new() -> Self {
        Self::default()
    }

    /// Every known running process, sorted by pid.
    pub fn snapshot(&self) -> Vec<ProcessFileCounts> {
        let mut v: Vec<_> = self
            .procs
            .iter()
            .map(|(&pid, e)| ProcessFileCounts { pid, name: e.name.clone(), counts: e.counts })
            .collect();
        v.sort_unstable_by_key(|p| p.pid);
        v
    }
}

impl Processor for FileCountExtractor {
    fn on_event(&mut self, ev: &Event, _out: &mut Vec<Event>) -> io::Result<()> {
        match &ev.kind {
            EventKind::ProcessStart { name, start_ticks, .. } => {
                let e = self.procs.entry(ev.pid).or_insert_with(|| Entry {
                    name: String::new(),
                    start_ticks: None,
                    counts: FileCounts::default(),
                });
                // A different start time means the pid was reused: start over.
                if e.start_ticks.is_some_and(|t| t != *start_ticks) {
                    e.counts = FileCounts::default();
                }
                e.name.clone_from(name);
                e.start_ticks = Some(*start_ticks);
            }
            EventKind::ProcessExec { name, .. } => {
                if let Some(e) = self.procs.get_mut(&ev.pid) {
                    e.name.clone_from(name);
                }
            }
            EventKind::ProcessExit => {
                self.procs.remove(&ev.pid);
            }
            EventKind::File { op, .. } => {
                // File events can arrive before the process is first scanned.
                let e = self.procs.entry(ev.pid).or_insert_with(|| Entry {
                    name: "?".into(),
                    start_ticks: None,
                    counts: FileCounts::default(),
                });
                let c = &mut e.counts;
                match op {
                    FileOp::Create => c.file_create_count += 1,
                    FileOp::Open => c.file_open_count += 1,
                    FileOp::Read => c.file_read_count += 1,
                    FileOp::Write => c.file_write_count += 1,
                    FileOp::Rename => c.file_rename_count += 1,
                    FileOp::Delete => c.file_delete_count += 1,
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::SystemTime;

    fn ev(pid: u32, kind: EventKind) -> Event {
        Event { timestamp: SystemTime::now(), pid, kind }
    }
    fn start(pid: u32, ticks: u64) -> Event {
        ev(pid, EventKind::ProcessStart { name: "p".into(), exe: None, start_ticks: ticks, ppid: 0, parent_exe: None, cmdline: String::new() })
    }
    fn file(pid: u32, op: FileOp) -> Event {
        ev(pid, EventKind::File { op, path: None })
    }

    #[test]
    fn counts_each_op_and_adopts_early_events() {
        let mut x = FileCountExtractor::new();
        x.on_event(&file(1, FileOp::Open), &mut Vec::new()).unwrap(); // before the process was scanned
        x.on_event(&start(1, 100), &mut Vec::new()).unwrap();
        for op in [FileOp::Create, FileOp::Read, FileOp::Write, FileOp::Rename, FileOp::Delete] {
            x.on_event(&file(1, op), &mut Vec::new()).unwrap();
        }
        let s = x.snapshot();
        assert_eq!(s.len(), 1);
        assert_eq!(s[0].name, "p");
        assert_eq!(
            s[0].counts,
            FileCounts {
                file_create_count: 1,
                file_open_count: 1,
                file_read_count: 1,
                file_write_count: 1,
                file_rename_count: 1,
                file_delete_count: 1,
            }
        );
    }

    #[test]
    fn exit_removes_and_pid_reuse_resets() {
        let mut x = FileCountExtractor::new();
        x.on_event(&start(1, 100), &mut Vec::new()).unwrap();
        x.on_event(&file(1, FileOp::Write), &mut Vec::new()).unwrap();
        x.on_event(&start(1, 200), &mut Vec::new()).unwrap(); // same pid, new start time
        assert_eq!(x.snapshot()[0].counts, FileCounts::default());
        x.on_event(&ev(1, EventKind::ProcessExit), &mut Vec::new()).unwrap();
        assert!(x.snapshot().is_empty());
    }
}
