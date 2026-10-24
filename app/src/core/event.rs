//! Layer 0 events: raw, per-action records produced by sensors.

use std::path::PathBuf;
use std::time::SystemTime;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FileOp {
    Create,
    Open,
    Read,
    Write,
    Rename,
    Delete,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum EventKind {
    /// A process was first seen (`e0` of its event stream): forked, or
    /// already running when monitoring started.
    ProcessStart {
        name: String,
        #[serde(serialize_with = "lossy")]
        exe: Option<PathBuf>,
        /// Process start time in clock ticks since boot; distinguishes a reused pid.
        start_ticks: u64,
        /// The process that created it (0 if unknown).
        ppid: u32,
        /// Arguments joined by spaces; empty if unreadable.
        cmdline: String,
    },
    /// The process replaced its program image (execve).
    ProcessExec {
        name: String,
        #[serde(serialize_with = "lossy")]
        exe: Option<PathBuf>,
        cmdline: String,
    },
    ProcessExit,
    /// `path` is None when the kernel could not resolve it (e.g. already deleted).
    /// For renames it is the old location.
    File {
        op: FileOp,
        #[serde(serialize_with = "lossy")]
        path: Option<PathBuf>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Event {
    /// When the sensor observed the event (the kernel does not timestamp them).
    pub timestamp: SystemTime,
    pub pid: u32,
    pub kind: EventKind,
}

/// Linux paths may be non-UTF-8, which JSON cannot hold: replace invalid bytes with U+FFFD.
fn lossy<S: serde::Serializer>(p: &Option<PathBuf>, s: S) -> Result<S::Ok, S::Error> {
    p.as_ref().map(|p| p.to_string_lossy()).serialize(s)
}
