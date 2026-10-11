use crate::event::RawEvent;
use crate::features::FEATURE_COLUMNS;
use crate::label::{FEATURE_SCHEMA_VERSION, METADATA_COLUMNS};
use crate::quality::QualityCounters;
use anyhow::Result;
use std::{fs::{self, File}, io::{BufWriter, Write}, path::PathBuf};

pub struct DatasetWriter {
    dir: PathBuf,
    csv: csv::Writer<File>,
    raw: Option<BufWriter<File>>,
}

impl DatasetWriter {
    /// Creates `<out>/<execution_id>/dataset.csv` (+ `raw.jsonl` with debug_raw).
    pub fn create(out: &std::path::Path, execution_id: &str, debug_raw: bool) -> Result<Self> {
        let dir = out.join(execution_id);
        fs::create_dir_all(&dir)?;
        let mut csv = csv::Writer::from_path(dir.join("dataset.csv"))?;
        csv.write_record(METADATA_COLUMNS.iter().chain(FEATURE_COLUMNS))?;
        let raw = if debug_raw { Some(BufWriter::new(File::create(dir.join("raw.jsonl"))?)) } else { None };
        Ok(Self { dir, csv, raw })
    }

    pub fn row(&mut self, meta: Vec<String>, feats: Vec<String>) -> Result<()> {
        self.csv.write_record(meta.iter().chain(feats.iter()))?;
        Ok(())
    }

    pub fn flush(&mut self) -> Result<()> {
        self.csv.flush()?;
        if let Some(w) = &mut self.raw { w.flush()?; }
        Ok(())
    }

    pub fn raw(&mut self, e: &RawEvent) -> Result<()> {
        if let Some(w) = &mut self.raw {
            serde_json::to_writer(&mut *w, e)?;
            w.write_all(b"\n")?;
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn finish(
        mut self, q: &QualityCounters, window_secs: f64, allow_paths: bool, grace_secs: f64, source_type: &str,
        sampling_interval_secs: Option<f64>, emit_idle_windows: bool, capabilities: serde_json::Value,
    ) -> Result<()> {
        self.csv.flush()?;
        if let Some(w) = &mut self.raw { w.flush()?; }
        let m = serde_json::json!({
            "collector_version": env!("CARGO_PKG_VERSION"),
            "feature_schema_version": FEATURE_SCHEMA_VERSION,
            "window": { "seconds": window_secs, "overlap": false, "interval": "[start,end)", "late_grace_seconds": grace_secs },
            "metadata_columns": METADATA_COLUMNS,
            "feature_columns": FEATURE_COLUMNS,
            "process_path_included": allow_paths,
            "source_type": source_type,
            "sampling_interval_seconds": sampling_interval_secs,
            "emit_idle_windows": emit_idle_windows,
            "source_capabilities": capabilities,
            "quality": q,
            "notes": [
                "bytes_written_total is empty when any write in the window lacked a measured byte count",
                "raw file paths are never written to dataset.csv",
                "ground_truth_label is empty for unlabeled executions; splits are done downstream grouped by sample",
            ],
        });
        fs::write(self.dir.join("manifest.json"), serde_json::to_vec_pretty(&m)?)?;
        Ok(())
    }
}
