use crate::aggregate::WindowSummary;

/// Numeric model-input columns, in CSV order. No pid/paths/ids/labels.
pub const FEATURE_COLUMNS: &[&str] = &[
    "file_read_count", "file_write_count", "file_create_count", "file_rename_count", "file_delete_count",
    "unique_files_accessed", "unique_files_modified", "unique_directories_accessed", "bytes_written_total",
    "modified_files_per_second", "write_read_ratio", "rename_write_ratio", "delete_write_ratio",
];

#[derive(Debug, Clone, PartialEq)]
pub struct FeatureRow {
    pub file_read_count: u64,
    pub file_write_count: u64,
    pub file_create_count: u64,
    pub file_rename_count: u64,
    pub file_delete_count: u64,
    pub unique_files_accessed: u64,
    pub unique_files_modified: u64,
    pub unique_directories_accessed: u64,
    /// None = unavailable (left empty in CSV, never zero-filled).
    pub bytes_written_total: Option<u64>,
    pub modified_files_per_second: f64,
    pub write_read_ratio: f64,
    pub rename_write_ratio: f64,
    pub delete_write_ratio: f64,
}

fn ratio(n: u64, d: u64) -> f64 {
    if d == 0 { 0.0 } else { n as f64 / d as f64 }
}

impl FeatureRow {
    /// Caller guarantees `w.duration_us > 0` (aggregator skips otherwise).
    pub fn from_window(w: &WindowSummary) -> Self {
        let [r, wr, c, rn, d] = w.counts;
        let secs = w.duration_us as f64 / 1e6;
        let row = Self {
            file_read_count: r, file_write_count: wr, file_create_count: c, file_rename_count: rn, file_delete_count: d,
            unique_files_accessed: w.unique_files, unique_files_modified: w.unique_modified,
            unique_directories_accessed: w.unique_dirs, bytes_written_total: w.bytes_written,
            modified_files_per_second: w.unique_modified as f64 / secs,
            write_read_ratio: ratio(wr, r), rename_write_ratio: ratio(rn, wr), delete_write_ratio: ratio(d, wr),
        };
        assert!(row.modified_files_per_second.is_finite() && row.write_read_ratio.is_finite()
            && row.rename_write_ratio.is_finite() && row.delete_write_ratio.is_finite());
        row
    }

    pub fn csv_values(&self) -> Vec<String> {
        vec![
            self.file_read_count.to_string(), self.file_write_count.to_string(), self.file_create_count.to_string(),
            self.file_rename_count.to_string(), self.file_delete_count.to_string(),
            self.unique_files_accessed.to_string(), self.unique_files_modified.to_string(),
            self.unique_directories_accessed.to_string(),
            self.bytes_written_total.map_or(String::new(), |b| b.to_string()),
            self.modified_files_per_second.to_string(), self.write_read_ratio.to_string(),
            self.rename_write_ratio.to_string(), self.delete_write_ratio.to_string(),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::EventQualityStatus;

    #[test]
    fn zero_denominators_give_zero_not_nan() {
        let w = WindowSummary {
            instance_id: "p".into(), pid: 1, proc_name: None, proc_path: None, start_us: 0, end_us: 2_000_000,
            duration_us: 2_000_000, complete: true, quality: EventQualityStatus::Valid, counts: [0, 0, 0, 5, 5],
            unique_files: 0, unique_modified: 0, unique_dirs: 0, bytes_written: Some(0),
        };
        let f = FeatureRow::from_window(&w);
        assert_eq!((f.write_read_ratio, f.rename_write_ratio, f.delete_write_ratio), (0.0, 0.0, 0.0));
        assert_eq!(FEATURE_COLUMNS.len(), f.csv_values().len());
    }
}
