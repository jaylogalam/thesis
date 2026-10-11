use crate::aggregate::WindowSummary;
use chrono::{DateTime, SecondsFormat};
use clap::ValueEnum;

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum Label { Benign, Ransomware, Unlabeled }

#[derive(Debug, Clone)]
pub struct ExperimentConfig {
    pub experiment_id: String,
    pub execution_id: String,
    pub label: Label,
    pub label_source: String,
    pub scenario_type: String,
}

pub const METADATA_COLUMNS: &[&str] = &[
    "sample_id", "experiment_id", "execution_id", "process_instance_id", "process_id", "process_name", "process_path",
    "window_start_utc", "window_end_utc", "window_duration_seconds", "window_completeness", "telemetry_quality_status",
    "ground_truth_label", "label_source", "scenario_type", "collector_version", "feature_schema_version",
];

pub const FEATURE_SCHEMA_VERSION: &str = "1.0";

fn ts(us: i64) -> String {
    DateTime::from_timestamp_micros(us).unwrap().to_rfc3339_opts(SecondsFormat::Micros, true)
}

impl ExperimentConfig {
    /// Labels come only from the operator; never inferred from features.
    pub fn metadata(&self, sample: u64, w: &WindowSummary, allow_paths: bool) -> Vec<String> {
        let label = match self.label {
            Label::Benign => "benign",
            Label::Ransomware => "ransomware",
            Label::Unlabeled => "",
        };
        vec![
            format!("sample-{sample:06}"), self.experiment_id.clone(), self.execution_id.clone(), w.instance_id.clone(),
            w.pid.to_string(), w.proc_name.clone().unwrap_or_default(),
            if allow_paths { w.proc_path.clone().unwrap_or_default() } else { String::new() },
            ts(w.start_us), ts(w.end_us), (w.duration_us as f64 / 1e6).to_string(),
            if w.complete { "complete" } else { "partial" }.into(), w.quality.as_str().into(),
            label.into(), self.label_source.clone(), self.scenario_type.clone(),
            env!("CARGO_PKG_VERSION").into(), FEATURE_SCHEMA_VERSION.into(),
        ]
    }
}
