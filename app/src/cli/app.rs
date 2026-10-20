//! UI state: process table rows and the recent-events log.

use std::collections::{HashMap, VecDeque};
use std::time::{Instant, SystemTime};

use crate::core::event::{Event, EventKind, FileOp};
use crate::core::features::{FileCountExtractor, FileCounts};

const LOG_MAX: usize = 1000;

pub struct Row {
    pub pid: u32,
    pub name: String,
    pub counts: FileCounts,
    /// File events since the previous tick.
    pub rate: u64,
}

pub enum LogKind {
    Start,
    Exit,
    File(FileOp),
}

pub struct LogLine {
    pub time: SystemTime,
    pub pid: u32,
    pub name: String,
    pub kind: LogKind,
    pub detail: String,
}

pub struct App {
    extractor: FileCountExtractor,
    prev_totals: HashMap<u32, u64>,
    names: HashMap<u32, String>,
    pub rows: Vec<Row>,
    pub log: VecDeque<LogLine>,
    pub show_idle: bool,
    pub events_total: u64,
    pub started: Instant,
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
    pub fn new() -> Self {
        Self {
            extractor: FileCountExtractor::new(),
            prev_totals: HashMap::new(),
            names: HashMap::new(),
            rows: Vec::new(),
            log: VecDeque::new(),
            show_idle: false,
            events_total: 0,
            started: Instant::now(),
        }
    }

    /// Feed one batch of sensor events and rebuild the table.
    pub fn tick(&mut self, events: Vec<Event>) {
        for ev in &events {
            self.extractor.process(ev);
            self.events_total += 1;
            self.push_log(ev);
        }

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
    }

    /// Rows to display under the current filter.
    pub fn visible(&self) -> impl Iterator<Item = &Row> {
        self.rows.iter().filter(|r| self.show_idle || total(&r.counts) > 0)
    }

    fn push_log(&mut self, ev: &Event) {
        let (kind, detail) = match &ev.kind {
            EventKind::ProcessStart { name, exe, .. } => {
                self.names.insert(ev.pid, name.clone());
                let exe = exe.as_ref().map(|p| p.display().to_string());
                (LogKind::Start, exe.unwrap_or_default())
            }
            EventKind::ProcessExit => (LogKind::Exit, String::new()),
            EventKind::File { op, path } => (
                LogKind::File(*op),
                path.as_ref().map_or("?".into(), |p| p.display().to_string()),
            ),
        };
        let name = self.names.get(&ev.pid).cloned().unwrap_or_else(|| "?".into());
        if self.log.len() == LOG_MAX {
            self.log.pop_front();
        }
        self.log.push_back(LogLine { time: ev.timestamp, pid: ev.pid, name, kind, detail });
        if matches!(ev.kind, EventKind::ProcessExit) {
            self.names.remove(&ev.pid);
        }
    }
}
