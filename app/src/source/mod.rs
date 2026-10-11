use crate::event::SourceSignal;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[cfg(target_os = "linux")]
pub mod procfs;
pub mod replay;
pub mod synth;
#[cfg(windows)]
pub mod etw;

pub trait EventSource {
    /// Yields signals in arrival order. Live sources block; file sources end.
    fn run(&mut self, sink: &mut dyn FnMut(SourceSignal)) -> anyhow::Result<()>;
    fn source_type(&self) -> &'static str;
    /// Per-feature notes on what this source can and cannot observe (goes to manifest.json).
    fn capabilities(&self) -> serde_json::Value { serde_json::json!({}) }
    /// (queue_overflow_dropped, procfs_unreadable_processes); merged after `run` returns.
    fn source_counters(&self) -> (u64, u64) { (0, 0) }
}

/// Vendor-neutral JSONL wire record shared by replay and synth.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SourceRecord {
    File {
        ts: DateTime<Utc>,
        pid: u32,
        proc_start: Option<DateTime<Utc>>,
        name: Option<String>,
        path: Option<String>,
        file_id: Option<String>,
        op: String,
        bytes: Option<u64>,
        src_id: Option<String>,
    },
    ProcStart {
        ts: DateTime<Utc>,
        pid: u32,
        proc_start: Option<DateTime<Utc>>,
        name: Option<String>,
        path: Option<String>,
    },
    ProcExit {
        ts: DateTime<Utc>,
        pid: u32,
        proc_start: Option<DateTime<Utc>>,
    },
    Gap {
        ts: DateTime<Utc>,
    },
    Tick {
        ts: DateTime<Utc>,
    },
}

impl SourceRecord {
    pub fn ts(&self) -> DateTime<Utc> {
        match self {
            Self::File { ts, .. } | Self::ProcStart { ts, .. } | Self::ProcExit { ts, .. } | Self::Gap { ts } | Self::Tick { ts } => *ts,
        }
    }
}
