//! Plays back a trace saved by `Recorder`, paced in real time (no privileges needed).

use std::collections::VecDeque;
use std::io;
use std::path::Path;
use std::time::{Duration, Instant, SystemTime};

use super::Sensor;
use crate::core::event::Event;

pub struct ReplaySensor {
    events: VecDeque<Event>,
    /// Timestamp of the first recorded event; None for an empty trace.
    first: Option<SystemTime>,
    started: Instant,
}

impl ReplaySensor {
    pub fn open(path: &Path) -> io::Result<Self> {
        let text = std::fs::read_to_string(path)?;
        let mut events = VecDeque::new();
        for (i, line) in text.lines().enumerate() {
            if line.trim().is_empty() {
                continue;
            }
            let ev: Event = serde_json::from_str(line).map_err(|e| {
                io::Error::new(io::ErrorKind::InvalidData, format!("{}:{}: {e}", path.display(), i + 1))
            })?;
            events.push_back(ev);
        }
        let first = events.front().map(|e| e.timestamp);
        Ok(Self { events, first, started: Instant::now() })
    }
}

impl Sensor for ReplaySensor {
    /// Every event whose offset from the first one has elapsed since `open`.
    fn poll(&mut self) -> io::Result<Vec<Event>> {
        let Some(first) = self.first else { return Ok(Vec::new()) };
        let now = self.started.elapsed();
        let due = self
            .events
            .iter()
            .take_while(|e| e.timestamp.duration_since(first).unwrap_or(Duration::ZERO) <= now)
            .count();
        Ok(self.events.drain(..due).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::event::EventKind;

    fn write_trace(name: &str, content: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!("replay-test-{name}-{}.jsonl", std::process::id()));
        std::fs::write(&path, content).unwrap();
        path
    }

    #[test]
    fn paces_events_in_real_time() {
        let t = SystemTime::now();
        let ev = |timestamp| Event { timestamp, pid: 1, kind: EventKind::ProcessExit };
        let lines: Vec<_> =
            [ev(t), ev(t + Duration::from_secs(3600))].iter().map(|e| serde_json::to_string(e).unwrap()).collect();
        let path = write_trace("pacing", &lines.join("\n"));
        let mut s = ReplaySensor::open(&path).unwrap();
        std::fs::remove_file(&path).unwrap();
        assert_eq!(s.poll().unwrap(), [ev(t)]);
    }

    #[test]
    fn reports_malformed_line_number() {
        let good = r#"{"timestamp":{"secs_since_epoch":1,"nanos_since_epoch":0},"pid":1,"kind":{"type":"ProcessExit"}}"#;
        let path = write_trace("malformed", &format!("{good}\nnot json\n"));
        let err = ReplaySensor::open(&path).err().unwrap();
        std::fs::remove_file(&path).unwrap();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains(":2:"), "{err}");
    }
}
