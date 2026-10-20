//! Layer 0 events: raw, per-action records produced by sensors.

use std::path::PathBuf;
use std::time::SystemTime;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileOp {
    Create,
    Open,
    Read,
    Write,
    Rename,
    Delete,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EventKind {
    /// A process was first seen (`e0` of its event stream).
    ProcessStart {
        name: String,
        exe: Option<PathBuf>,
        /// Process start time in clock ticks since boot; distinguishes a reused pid.
        start_ticks: u64,
    },
    ProcessExit,
    /// `path` is None when the kernel could not resolve it (e.g. already deleted).
    /// For renames it is the old location.
    File { op: FileOp, path: Option<PathBuf> },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event {
    /// When the sensor observed the event (the kernel does not timestamp them).
    pub timestamp: SystemTime,
    pub pid: u32,
    pub kind: EventKind,
}
