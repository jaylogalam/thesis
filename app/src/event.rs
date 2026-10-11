use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Operation { Read, Write, Create, Rename, Delete, Other, Unknown }

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AttributionStatus { Attributed, Unattributed, Ambiguous }

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EventQualityStatus { #[default] Valid, Incomplete, Duplicated, Ambiguous, Flagged }

impl EventQualityStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Valid => "valid",
            Self::Incomplete => "incomplete",
            Self::Duplicated => "duplicated",
            Self::Ambiguous => "ambiguous",
            Self::Flagged => "flagged",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawEvent {
    pub event_id: String,
    pub ts_utc: DateTime<Utc>,
    pub pid: u32,
    pub proc_start_utc: Option<DateTime<Utc>>,
    pub proc_name: Option<String>,
    pub proc_path: Option<String>,
    pub op: Operation,
    /// Raw path: debug/identity only, never a feature.
    pub file_path: Option<String>,
    pub file_identity: Option<String>,
    pub bytes_written: Option<u64>,
    pub source_event_id: Option<String>,
    pub source_type: String,
    pub attribution: AttributionStatus,
    pub quality: EventQualityStatus,
    /// Number of logical operations this record represents. 1 for event-per-op sources;
    /// a sampled delta for /proc; 0 means "file observed, no operation counted".
    #[serde(default = "one")]
    pub multiplicity: u64,
}

fn one() -> u64 { 1 }

#[derive(Debug, Clone)]
pub enum SourceSignal {
    File(RawEvent),
    ProcStart { pid: u32, proc_start_utc: Option<DateTime<Utc>>, name: Option<String>, path: Option<String>, ts: DateTime<Utc> },
    ProcExit { pid: u32, proc_start_utc: Option<DateTime<Utc>>, ts: DateTime<Utc> },
    /// Collector restart / telemetry gap at `ts`.
    Gap { ts: DateTime<Utc> },
    /// Wall-clock heartbeat: advances the watermark so windows flush without events.
    Tick { ts: DateTime<Utc> },
}
