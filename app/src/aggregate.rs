//! Fixed non-overlapping half-open windows `[start, end)` aligned to the Unix epoch,
//! grouped by (process_instance_id, window_start, window_end).
//!
//! Late policy: watermark = max observed ts; windows with `end <= watermark - grace`
//! are finalized. An event for an already-finalized window (or exited instance) is
//! dropped and counted in `late_dropped`.
//! Lifecycle: an instance is alive from its ProcStart signal (or first event) to
//! ProcExit (or collector stop = watermark). One row per alive window, including
//! zero-op windows. Gap markers make any window containing them `partial`.

use crate::event::*;
use crate::identity::ProcessRegistry;
use crate::pathutil::{normalize_path, parent_dir};
use crate::quality::QualityCounters;
use std::collections::{BTreeMap, HashSet};

#[derive(Debug, Clone)]
pub struct WindowSummary {
    pub instance_id: String,
    pub pid: u32,
    pub proc_name: Option<String>,
    pub proc_path: Option<String>,
    pub start_us: i64,
    pub end_us: i64,
    pub duration_us: i64,
    pub complete: bool,
    pub quality: EventQualityStatus,
    /// read, write, create, rename, delete
    pub counts: [u64; 5],
    pub unique_files: u64,
    pub unique_modified: u64,
    pub unique_dirs: u64,
    /// None when any write in the window lacked a measured byte count.
    pub bytes_written: Option<u64>,
}

#[derive(Default)]
struct Acc {
    counts: [u64; 5],
    files: HashSet<String>,
    modified: HashSet<String>,
    dirs: HashSet<String>,
    bytes: u64,
    bytes_missing: bool,
    quality: EventQualityStatus,
}

struct Inst {
    pid: u32,
    name: Option<String>,
    path: Option<String>,
    alive_start: i64,
    next_emit: i64,
    wins: BTreeMap<i64, Acc>,
}

pub struct Aggregator {
    w: i64,
    grace: i64,
    registry: ProcessRegistry,
    inst: BTreeMap<String, Inst>,
    closed: HashSet<String>,
    wm: Option<i64>,
    last_b: i64,
    gaps: Vec<i64>,
    pub q: QualityCounters,
    out: Vec<WindowSummary>,
    emit_idle: bool,
}

impl Aggregator {
    pub fn new(window_us: i64) -> Self {
        assert!(window_us > 0);
        Self {
            w: window_us, grace: window_us, registry: ProcessRegistry::default(), inst: BTreeMap::new(),
            closed: HashSet::new(), wm: None, last_b: i64::MIN, gaps: Vec::new(), q: QualityCounters::default(), out: Vec::new(),
            emit_idle: true,
        }
    }

    pub fn take_output(&mut self) -> Vec<WindowSummary> { std::mem::take(&mut self.out) }

    pub fn set_emit_idle(&mut self, v: bool) { self.emit_idle = v; }

    pub fn signal(&mut self, s: SourceSignal) {
        match s {
            SourceSignal::File(e) => self.event(e),
            SourceSignal::ProcStart { pid, proc_start_utc, name, path, ts } => {
                let t = ts.timestamp_micros();
                self.bump_wm(t);
                let (id, amb) = self.registry.resolve(pid, proc_start_utc);
                if !self.closed.contains(&id) {
                    let w = self.w;
                    let i = self.inst.entry(id).or_insert_with(|| new_inst(pid, t, w));
                    i.name = name.or(i.name.take());
                    i.path = path.or(i.path.take());
                }
                let _ = amb;
                self.finalize();
            }
            SourceSignal::ProcExit { pid, proc_start_utc, ts } => {
                let t = ts.timestamp_micros();
                self.bump_wm(t);
                let (id, _) = self.registry.resolve(pid, proc_start_utc);
                if let Some(mut i) = self.inst.remove(&id) {
                    emit_range(&id, &mut i, t, Some(t), self.w, &self.gaps, self.emit_idle, &mut self.out, &mut self.q);
                }
                self.closed.insert(id);
                self.finalize();
            }
            SourceSignal::Gap { ts } => {
                self.bump_wm(ts.timestamp_micros());
                self.gaps.push(ts.timestamp_micros());
                self.q.collector_gaps += 1;
            }
            SourceSignal::Tick { ts } => {
                self.bump_wm(ts.timestamp_micros());
                self.q.ticks += 1;
                self.finalize();
            }
        }
    }

    fn bump_wm(&mut self, t: i64) {
        self.wm = Some(self.wm.map_or(t, |w| w.max(t)));
    }

    fn event(&mut self, e: RawEvent) {
        self.q.events_received += 1;
        if e.attribution == AttributionStatus::Unattributed {
            self.q.unattributed += 1;
            return;
        }
        let t = e.ts_utc.timestamp_micros();
        self.bump_wm(t);
        let (id, amb) = self.registry.resolve(e.pid, e.proc_start_utc);
        if amb {
            self.q.ambiguous += 1;
        }
        if self.closed.contains(&id) {
            self.q.late_dropped += 1;
            return;
        }
        let w = self.w;
        let i = self.inst.entry(id).or_insert_with(|| new_inst(e.pid, t, w));
        if i.name.is_none() { i.name = e.proc_name.clone(); }
        if i.path.is_none() { i.path = e.proc_path.clone(); }
        let ws = t.div_euclid(w) * w;
        if ws < i.next_emit {
            self.q.late_dropped += 1;
            return;
        }
        let a = i.wins.entry(ws).or_default();
        a.quality = a.quality.max(e.quality);
        let idx = match e.op {
            Operation::Read => 0,
            Operation::Write => 1,
            Operation::Create => 2,
            Operation::Rename => 3,
            Operation::Delete => 4,
            Operation::Other | Operation::Unknown => {
                self.finalize();
                return;
            }
        };
        a.counts[idx] += e.multiplicity;
        if idx == 1 {
            match e.bytes_written {
                Some(b) => a.bytes += b,
                None => a.bytes_missing = true,
            }
        }
        let norm = e.file_path.as_deref().map(normalize_path);
        let key = match (&e.file_identity, &norm) {
            (Some(id), _) => Some(format!("id:{id}")),
            (None, Some(p)) => Some(format!("p:{p}")),
            _ => None,
        };
        match key {
            Some(k) => {
                if idx >= 1 { a.modified.insert(k.clone()); }
                a.files.insert(k);
            }
            None => {
                self.q.missing_file_identity += 1;
                a.quality = a.quality.max(EventQualityStatus::Incomplete);
            }
        }
        if let Some(p) = &norm {
            a.dirs.insert(parent_dir(p).to_string());
        }
        self.finalize();
    }

    fn finalize(&mut self) {
        let Some(wm) = self.wm else { return };
        let b = (wm - self.grace).div_euclid(self.w) * self.w;
        if b <= self.last_b { return; }
        self.last_b = b;
        for (id, i) in self.inst.iter_mut() {
            emit_range(id, i, b, None, self.w, &self.gaps, self.emit_idle, &mut self.out, &mut self.q);
        }
    }

    /// Source end / collector stop: alive_end = watermark for all remaining instances.
    pub fn finish(&mut self) {
        let Some(wm) = self.wm else { return };
        for (id, i) in std::mem::take(&mut self.inst) {
            let mut i = i;
            emit_range(&id, &mut i, wm, Some(wm), self.w, &self.gaps, self.emit_idle, &mut self.out, &mut self.q);
        }
    }
}

fn new_inst(pid: u32, t: i64, w: i64) -> Inst {
    Inst { pid, name: None, path: None, alive_start: t, next_emit: t.div_euclid(w) * w, wins: BTreeMap::new() }
}

/// Emit rows for every window with `start < upto`, advancing `next_emit`.
#[allow(clippy::too_many_arguments)]
fn emit_range(
    id: &str, inst: &mut Inst, upto: i64, alive_end: Option<i64>, w: i64, gaps: &[i64], emit_idle: bool,
    out: &mut Vec<WindowSummary>, q: &mut QualityCounters,
) {
    while inst.next_emit < upto {
        let start = inst.next_emit;
        inst.next_emit += w;
        let end = start + w;
        let dur = end.min(alive_end.unwrap_or(i64::MAX)) - start.max(inst.alive_start);
        let acc = inst.wins.remove(&start).unwrap_or_default();
        if dur <= 0 {
            q.invalid_duration_skipped += 1;
            continue;
        }
        if !emit_idle && acc.counts == [0; 5] && acc.files.is_empty() {
            continue;
        }
        let complete = dur == w && !gaps.iter().any(|g| *g >= start && *g < end);
        let bytes_ok = !acc.bytes_missing;
        if complete { q.windows_complete += 1 } else { q.windows_partial += 1 }
        if !bytes_ok { q.bytes_unavailable_windows += 1 }
        out.push(WindowSummary {
            instance_id: id.to_string(), pid: inst.pid, proc_name: inst.name.clone(), proc_path: inst.path.clone(),
            start_us: start, end_us: end, duration_us: dur, complete, quality: acc.quality, counts: acc.counts,
            unique_files: acc.files.len() as u64, unique_modified: acc.modified.len() as u64,
            unique_dirs: acc.dirs.len() as u64, bytes_written: bytes_ok.then_some(acc.bytes),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{DateTime, TimeZone, Utc};

    fn at(ms: i64) -> DateTime<Utc> { Utc.timestamp_millis_opt(1_000_000_000_000 + ms).unwrap() }
    fn start() -> Option<DateTime<Utc>> { Some(at(-5000)) }

    fn file(ms: i64, op: Operation, path: &str) -> SourceSignal {
        SourceSignal::File(RawEvent {
            event_id: String::new(), ts_utc: at(ms), pid: 9, proc_start_utc: start(), proc_name: Some("p".into()),
            proc_path: None, op, file_path: Some(path.into()), file_identity: None, bytes_written: Some(10),
            source_event_id: None, source_type: "t".into(), attribution: AttributionStatus::Attributed,
            quality: EventQualityStatus::Valid,
            multiplicity: 1,
        })
    }
    fn pstart(ms: i64) -> SourceSignal {
        SourceSignal::ProcStart { pid: 9, proc_start_utc: start(), name: None, path: None, ts: at(ms) }
    }
    fn pexit(ms: i64) -> SourceSignal { SourceSignal::ProcExit { pid: 9, proc_start_utc: start(), ts: at(ms) } }

    // 1_000_000_000_000 ms is a multiple of 2000 ms, so at(0) is window-aligned.
    #[test]
    fn partial_window_for_short_lived_process() {
        let mut a = Aggregator::new(2_000_000);
        a.signal(pstart(0));
        a.signal(file(100, Operation::Write, "c:\\a\\x"));
        a.signal(file(200, Operation::Write, "c:\\a\\y"));
        a.signal(pexit(1300));
        let rows = a.take_output();
        assert_eq!(rows.len(), 1);
        assert!(!rows[0].complete);
        assert_eq!(rows[0].duration_us, 1_300_000);
        assert_eq!(rows[0].unique_modified, 2);
        assert_eq!(rows[0].unique_modified as f64 / (rows[0].duration_us as f64 / 1e6), 2.0 / 1.3);
    }

    #[test]
    fn zero_op_window_inside_alive_span_is_emitted() {
        let mut a = Aggregator::new(2_000_000);
        a.signal(pstart(0));
        a.signal(file(100, Operation::Read, "c:\\a"));
        a.signal(file(4100, Operation::Read, "c:\\a"));
        a.signal(pexit(6000));
        let rows = a.take_output();
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[1].counts, [0; 5]);
        assert!(rows.iter().all(|r| r.complete));
    }

    #[test]
    fn half_open_boundary_and_late_drop() {
        let mut a = Aggregator::new(2_000_000);
        a.signal(pstart(0));
        a.signal(file(2000, Operation::Read, "c:\\a")); // exactly at end -> next window
        a.signal(file(9000, Operation::Read, "c:\\b")); // finalizes windows 0..
        a.signal(file(500, Operation::Read, "c:\\c")); // late
        assert_eq!(a.q.late_dropped, 1);
        let rows = a.take_output();
        assert_eq!(rows[0].counts[0], 0);
        assert_eq!(rows[1].counts[0], 1);
    }

    #[test]
    fn missing_bytes_marks_unavailable() {
        let mut a = Aggregator::new(2_000_000);
        a.signal(pstart(0));
        if let SourceSignal::File(mut e) = file(10, Operation::Write, "c:\\a") {
            e.bytes_written = None;
            a.signal(SourceSignal::File(e));
        }
        a.signal(pexit(2000));
        let rows = a.take_output();
        assert_eq!(rows[0].bytes_written, None);
        assert_eq!(a.q.bytes_unavailable_windows, 1);
    }

    #[test]
    fn multiplicity_counts_ops_and_zero_still_registers_file() {
        let mut a = Aggregator::new(2_000_000);
        a.signal(pstart(0));
        if let SourceSignal::File(mut e) = file(10, Operation::Write, "") {
            e.multiplicity = 50;
            e.bytes_written = Some(4096);
            e.file_path = None;
            a.signal(SourceSignal::File(e));
        }
        if let SourceSignal::File(mut e) = file(20, Operation::Read, "c:\\a\\b") {
            e.multiplicity = 0;
            a.signal(SourceSignal::File(e));
        }
        a.signal(pexit(1000));
        let rows = a.take_output();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].counts[1], 50);
        assert_eq!(rows[0].bytes_written, Some(4096));
        assert_eq!(rows[0].counts[0], 0);
        assert_eq!(rows[0].unique_files, 1);
    }

    #[test]
    fn ticks_flush_windows_without_events() {
        let mut a = Aggregator::new(2_000_000);
        a.signal(pstart(0));
        a.signal(file(100, Operation::Read, "c:\\a"));
        for t in [2000, 4000, 6000] {
            a.signal(SourceSignal::Tick { ts: at(t) });
        }
        let rows = a.take_output();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[1].counts, [0; 5]);
        assert_eq!(a.q.ticks, 3);
    }
}
