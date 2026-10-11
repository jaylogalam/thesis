use serde::Serialize;

#[derive(Debug, Default, Clone, Serialize)]
pub struct QualityCounters {
    pub events_received: u64,
    pub late_dropped: u64,
    pub queue_overflow_dropped: u64,
    pub unattributed: u64,
    pub ambiguous: u64,
    pub windows_complete: u64,
    pub windows_partial: u64,
    pub collector_gaps: u64,
    pub bytes_unavailable_windows: u64,
    pub missing_file_identity: u64,
    pub invalid_duration_skipped: u64,
    pub ticks: u64,
    pub procfs_unreadable_processes: u64,
}
