//! Live Linux source: samples `/proc/<pid>/{stat,io,fd}` once per interval.
//!
//! Per-process syscall deltas (`syscr`/`syscw`) and `write_bytes` become multiplicity-carrying
//! events; open regular files in `/proc/<pid>/fd` populate the distinct file/dir sets.
//! Cannot observe create/rename/delete or per-file modification (see `capabilities`).

use super::EventSource;
use crate::event::*;
use anyhow::{Context, Result};
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

/// Verified `getconf CLK_TCK` = 100 here. A different kernel value shifts `proc_start_utc`
/// only, which affects identity keys, not features.
const USER_HZ: i64 = 100;
const SKIP_PREFIXES: [&str; 4] = ["/dev/", "/proc/", "/sys/", "/run/"];

pub struct ProcfsSource {
    pub interval: Duration,
    pub duration: Option<Duration>,
    pub stop: Arc<AtomicBool>,
    pub pids: Vec<u32>,
    unreadable: u64,
}

impl ProcfsSource {
    pub fn new(interval: Duration, duration: Option<Duration>, stop: Arc<AtomicBool>, pids: Vec<u32>) -> Self {
        Self { interval, duration, stop, pids, unreadable: 0 }
    }
}

struct Snap {
    start_ticks: u64,
    proc_start: DateTime<Utc>,
    syscr: u64,
    syscw: u64,
    write_bytes: u64,
    started: bool,
}

fn start_ticks(pid: u32) -> Option<u64> {
    let s = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // comm may contain spaces and parens: fields restart after the LAST ')'.
    let rest = &s[s.rfind(')')? + 1..];
    rest.split_whitespace().nth(19)?.parse().ok()
}

enum Io {
    Ok { syscr: u64, syscw: u64, write_bytes: u64 },
    Denied,
    Gone,
}

fn read_io(pid: u32) -> Io {
    let s = match fs::read_to_string(format!("/proc/{pid}/io")) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => return Io::Denied,
        Err(_) => return Io::Gone,
    };
    let (mut r, mut w, mut b) = (None, None, None);
    for l in s.lines() {
        let Some((k, v)) = l.split_once(':') else { continue };
        let v = v.trim().parse::<u64>().ok();
        match k {
            "syscr" => r = v,
            "syscw" => w = v,
            "write_bytes" => b = v,
            _ => {}
        }
    }
    match (r, w, b) {
        (Some(syscr), Some(syscw), Some(write_bytes)) => Io::Ok { syscr, syscw, write_bytes },
        _ => Io::Gone,
    }
}

fn open_files(pid: u32) -> Vec<String> {
    let Ok(rd) = fs::read_dir(format!("/proc/{pid}/fd")) else { return Vec::new() };
    let mut set = HashSet::new();
    for e in rd.flatten() {
        let Ok(t) = fs::read_link(e.path()) else { continue };
        let t = t.display().to_string();
        if t.starts_with('/') && !SKIP_PREFIXES.iter().any(|p| t.starts_with(p)) && !t.ends_with(" (deleted)") {
            set.insert(t);
        }
    }
    set.into_iter().collect()
}

impl EventSource for ProcfsSource {
    fn source_type(&self) -> &'static str { "procfs-linux" }

    fn source_counters(&self) -> (u64, u64) { (0, self.unreadable) }

    fn capabilities(&self) -> serde_json::Value {
        serde_json::json!({
            "file_read_count": "read syscall count (delta /proc/<pid>/io syscr); not per-file",
            "file_write_count": "write syscall count (delta syscw); not per-file",
            "file_create_count": "unavailable from /proc sampling; always 0",
            "file_rename_count": "unavailable from /proc sampling; always 0",
            "file_delete_count": "unavailable from /proc sampling; always 0",
            "unique_files_accessed": "distinct regular files open in /proc/<pid>/fd during the window",
            "unique_files_modified": "unavailable from /proc sampling; always 0",
            "unique_directories_accessed": "parent directories of files open in /proc/<pid>/fd",
            "bytes_written_total": "delta /proc/<pid>/io write_bytes (block layer; excludes cancelled writes)",
            "modified_files_per_second": "always 0 because unique_files_modified is unavailable",
            "write_read_ratio": "ratio of write to read syscall counts",
            "rename_write_ratio": "always 0",
            "delete_write_ratio": "always 0"
        })
    }

    fn run(&mut self, sink: &mut dyn FnMut(SourceSignal)) -> Result<()> {
        let btime: i64 = fs::read_to_string("/proc/stat")
            .ok()
            .and_then(|s| s.lines().find_map(|l| l.strip_prefix("btime ")?.trim().parse().ok()))
            .ok_or_else(|| anyhow::anyhow!("/proc/stat has no btime line"))?;
        let boot = DateTime::from_timestamp(btime, 0).context("btime out of range")?;
        let self_pid = std::process::id();
        let mut snaps: HashMap<u32, Snap> = HashMap::new();
        let mut unreadable_seen: HashSet<u32> = HashSet::new();
        let run_start = Instant::now();
        let mut n: u32 = 0;

        loop {
            let ts = Utc::now();
            let mut seen: HashSet<u32> = HashSet::new();
            for ent in fs::read_dir("/proc")?.flatten() {
                let Some(pid) = ent.file_name().to_str().and_then(|s| s.parse::<u32>().ok()) else { continue };
                if pid == self_pid || (!self.pids.is_empty() && !self.pids.contains(&pid)) {
                    continue;
                }
                let Some(st) = start_ticks(pid) else { continue };
                let (syscr, syscw, write_bytes) = match read_io(pid) {
                    Io::Ok { syscr, syscw, write_bytes } => (syscr, syscw, write_bytes),
                    Io::Denied => {
                        if unreadable_seen.insert(pid) {
                            self.unreadable += 1;
                        }
                        continue;
                    }
                    Io::Gone => continue,
                };
                seen.insert(pid);
                let proc_start = boot + ChronoDuration::microseconds((st as i64) * 1_000_000 / USER_HZ);
                let new = Snap { start_ticks: st, proc_start, syscr, syscw, write_bytes, started: false };
                let Some(old) = snaps.get_mut(&pid) else {
                    snaps.insert(pid, new);
                    continue;
                };
                if old.start_ticks != st {
                    // pid reuse: old instance is gone; the new one has no baseline yet.
                    if old.started {
                        sink(SourceSignal::ProcExit { pid, proc_start_utc: Some(old.proc_start), ts });
                    }
                    *old = new;
                    continue;
                }
                let dr = syscr.saturating_sub(old.syscr);
                let dw = syscw.saturating_sub(old.syscw);
                let db = write_bytes.saturating_sub(old.write_bytes);
                old.syscr = syscr;
                old.syscw = syscw;
                old.write_bytes = write_bytes;
                if dr + dw == 0 {
                    continue;
                }
                let ps = Some(old.proc_start);
                if !old.started {
                    old.started = true;
                    sink(SourceSignal::ProcStart {
                        pid,
                        proc_start_utc: ps,
                        name: fs::read_to_string(format!("/proc/{pid}/comm")).ok().map(|s| s.trim().to_string()),
                        path: fs::read_link(format!("/proc/{pid}/exe")).ok().map(|p| p.display().to_string()),
                        ts,
                    });
                }
                let mk = |op, multiplicity, file_path, bytes_written| {
                    SourceSignal::File(RawEvent {
                        event_id: uuid::Uuid::new_v4().to_string(),
                        ts_utc: ts,
                        pid,
                        proc_start_utc: ps,
                        proc_name: None,
                        proc_path: None,
                        op,
                        file_path,
                        file_identity: None,
                        bytes_written,
                        source_event_id: None,
                        source_type: "procfs-linux".into(),
                        attribution: AttributionStatus::Attributed,
                        quality: EventQualityStatus::Valid,
                        multiplicity,
                    })
                };
                if dr > 0 {
                    sink(mk(Operation::Read, dr, None, None));
                }
                if dw > 0 {
                    sink(mk(Operation::Write, dw, None, Some(db)));
                }
                for f in open_files(pid) {
                    sink(mk(Operation::Read, 0, Some(f), None));
                }
            }
            // Processes no longer visible: close started instances, drop all stale snapshots.
            snaps.retain(|pid, s| {
                if seen.contains(pid) {
                    return true;
                }
                if s.started {
                    sink(SourceSignal::ProcExit { pid: *pid, proc_start_utc: Some(s.proc_start), ts });
                }
                false
            });
            sink(SourceSignal::Tick { ts });

            n += 1;
            let deadline = run_start + self.interval * n;
            loop {
                if self.stop.load(Ordering::Relaxed) {
                    return Ok(());
                }
                let now = Instant::now();
                if self.duration.is_some_and(|d| now.duration_since(run_start) >= d) {
                    return Ok(());
                }
                if now >= deadline {
                    break;
                }
                thread::sleep(deadline.saturating_duration_since(now).min(Duration::from_millis(100)));
            }
        }
    }
}
