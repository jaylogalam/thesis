//! Saves the event stream to a JSON Lines trace (one event per line, dispatch order).

use std::fs::{File, OpenOptions};
use std::io::{self, BufWriter, Write};
use std::path::Path;

use crate::core::event::Event;
use super::Processor;

pub struct Recorder {
    out: BufWriter<File>,
}

impl Recorder {
    /// Fails if `path` exists, so an earlier trace is never overwritten.
    pub fn create(path: &Path) -> io::Result<Self> {
        let file = OpenOptions::new().write(true).create_new(true).open(path)?;
        Ok(Self { out: BufWriter::new(file) })
    }

    pub fn flush(&mut self) -> io::Result<()> {
        self.out.flush()
    }
}

impl Processor for Recorder {
    fn on_event(&mut self, ev: &Event, _out: &mut Vec<Event>) -> io::Result<()> {
        serde_json::to_writer(&mut self.out, ev).map_err(io::Error::other)?;
        self.out.write_all(b"\n")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::event::{EventKind, FileOp};
    use crate::core::framework::dispatch;
    use crate::core::sensors::{Sensor, replay::ReplaySensor};
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;
    use std::path::PathBuf;
    use std::time::SystemTime;

    #[test]
    fn round_trips_through_replay() {
        let path = std::env::temp_dir().join(format!("recorder-test-{}.jsonl", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let t = SystemTime::now();
        let ev = |kind| Event { timestamp: t, pid: 7, kind };
        let file = |op, p: &OsStr| ev(EventKind::File { op, path: Some(PathBuf::from(p)) });
        let events = vec![
            ev(EventKind::ProcessStart { name: "p".into(), exe: None, start_ticks: 5 }),
            file(FileOp::Write, OsStr::new("/tmp/x")),
            file(FileOp::Delete, OsStr::from_bytes(b"/tmp/\xff")),
            ev(EventKind::ProcessExit),
        ];

        let mut rec = Recorder::create(&path).unwrap();
        dispatch(events.clone(), &mut [&mut rec]).unwrap();
        rec.flush().unwrap();
        drop(rec);
        let err = Recorder::create(&path).err().unwrap();
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);

        let got = ReplaySensor::open(&path).unwrap().poll().unwrap();
        std::fs::remove_file(&path).unwrap();
        let mut want = events;
        want[2] = file(FileOp::Delete, OsStr::new("/tmp/\u{FFFD}"));
        assert_eq!(got, want);
    }
}
