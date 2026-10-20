//! Process start/exit events from /proc (no privileges needed).

use std::collections::{HashMap, HashSet};
use std::io;
use std::time::SystemTime;

use crate::core::sensors::Sensor;
use crate::core::event::{Event, EventKind};

/// Detects processes by scanning /proc on every poll.
// ponytail: processes that start and exit between two polls are never seen.
// Use the netlink proc connector (root) or eBPF for exact lifecycle events.
#[derive(Default)]
pub struct ProcessSensor {
    /// pid -> start_ticks of every process already reported.
    known: HashMap<u32, u64>,
}

impl ProcessSensor {
    pub fn new() -> Self {
        Self::default()
    }
}

struct Stat {
    name: String,
    ppid: u32,
    start_ticks: u64,
}

/// Parse `/proc/<pid>/stat`. The name is parenthesised and may itself contain
/// spaces or parentheses, so split on the last ')'.
fn parse_stat(text: &str) -> Option<Stat> {
    let open = text.find('(')?;
    let close = text.rfind(')')?;
    let rest: Vec<&str> = text.get(close + 1..)?.split_whitespace().collect();
    // rest[0] is field 3 (state); field n is rest[n - 3].
    Some(Stat {
        name: text.get(open + 1..close)?.to_string(),
        ppid: rest.get(1)?.parse().ok()?,
        start_ticks: rest.get(19)?.parse().ok()?,
    })
}

impl Sensor for ProcessSensor {
    fn poll(&mut self) -> io::Result<Vec<Event>> {
        let now = SystemTime::now();
        let mut events = Vec::new();
        let mut seen = HashSet::new();

        for entry in std::fs::read_dir("/proc")? {
            let Some(pid) = entry?.file_name().to_str().and_then(|s| s.parse::<u32>().ok()) else {
                continue;
            };
            // Gone already, or unreadable: treat as not running.
            let Ok(text) = std::fs::read_to_string(format!("/proc/{pid}/stat")) else {
                continue;
            };
            let Some(stat) = parse_stat(&text) else { continue };
            // Kernel threads (children of kthreadd) have no user-space behavior.
            if pid == 2 || stat.ppid == 2 {
                continue;
            }
            seen.insert(pid);
            match self.known.insert(pid, stat.start_ticks) {
                Some(old) if old == stat.start_ticks => continue,
                Some(_) => events.push(Event { timestamp: now, pid, kind: EventKind::ProcessExit }),
                None => {}
            }
            events.push(Event {
                timestamp: now,
                pid,
                kind: EventKind::ProcessStart {
                    name: stat.name,
                    exe: std::fs::read_link(format!("/proc/{pid}/exe")).ok(),
                    start_ticks: stat.start_ticks,
                },
            });
        }

        self.known.retain(|pid, _| {
            let alive = seen.contains(pid);
            if !alive {
                events.push(Event { timestamp: now, pid: *pid, kind: EventKind::ProcessExit });
            }
            alive
        });
        Ok(events)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_stat_with_awkward_name() {
        let text = "123 (my (weird) name) S 2 123 123 0 -1 4194560 0 0 0 0 0 0 0 0 20 0 1 0 98765 0 0";
        let s = parse_stat(text).unwrap();
        assert_eq!((s.name.as_str(), s.ppid, s.start_ticks), ("my (weird) name", 2, 98765));
    }

    #[test]
    fn reports_start_once_then_exit() {
        let mut sensor = ProcessSensor::new();
        let me = std::process::id();
        let first = sensor.poll().unwrap();
        assert!(first.iter().any(|e| e.pid == me && matches!(e.kind, EventKind::ProcessStart { .. })));
        // Nothing new for a process that is still running.
        assert!(!sensor.poll().unwrap().iter().any(|e| e.pid == me));

        let mut child = std::process::Command::new("sleep").arg("5").spawn().unwrap();
        let cpid = child.id();
        let started = sensor.poll().unwrap();
        let start = started.iter().find(|e| e.pid == cpid).expect("child start");
        let EventKind::ProcessStart { name, exe, .. } = &start.kind else { panic!() };
        assert_eq!(name, "sleep");
        assert!(exe.as_ref().unwrap().ends_with("sleep"));

        child.kill().unwrap();
        child.wait().unwrap();
        let ended = sensor.poll().unwrap();
        assert!(ended.iter().any(|e| e.pid == cpid && e.kind == EventKind::ProcessExit));
    }
}
