use crate::label::{ExperimentConfig, Label};
use crate::pipeline::RunConfig;
use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "runtime-monitor", version, about = "Per-process file-behavior collector and feature extractor")]
pub struct Cli {
    #[command(subcommand)]
    pub cmd: Option<Cmd>,
}

#[derive(Subcommand)]
pub enum Cmd {
    /// Write deterministic synthetic JSONL records for a scenario.
    Synth {
        #[arg(long)]
        scenario: String,
        #[arg(long)]
        out: PathBuf,
    },
    /// Replay a JSONL record file into a dataset.
    Replay {
        #[arg(long = "in")]
        input: PathBuf,
        #[arg(long, default_value_t = 2.0)]
        window_secs: f64,
        #[command(flatten)]
        run: RunArgs,
    },
    /// Live capture of per-process file behavior (default command).
    Live {
        #[arg(long, default_value_t = 1.0)]
        interval_secs: f64,
        #[arg(long, default_value_t = 1.0)]
        window_secs: f64,
        /// Stop after N seconds; omit to run until Ctrl-C.
        #[arg(long)]
        duration_secs: Option<u64>,
        /// Restrict monitoring to these pids (repeatable); default: every readable process.
        #[arg(long = "pid")]
        pids: Vec<u32>,
        /// Also write a row for windows in which a process did nothing.
        #[arg(long)]
        emit_idle_windows: bool,
        #[command(flatten)]
        run: RunArgs,
    },
}

#[derive(Args)]
pub struct RunArgs {
    #[arg(long, default_value = "out")]
    pub out: PathBuf,
    #[arg(long, default_value = "live")]
    pub experiment_id: String,
    #[arg(long)]
    pub execution_id: Option<String>,
    #[arg(long, value_enum, default_value = "unlabeled")]
    pub label: Label,
    #[arg(long, default_value = "none")]
    pub label_source: String,
    #[arg(long, default_value = "live")]
    pub scenario_type: String,
    /// Include process_path in dataset.csv (never file paths).
    #[arg(long)]
    pub allow_paths: bool,
    /// Also write raw.jsonl with normalized events (contains file paths).
    #[arg(long)]
    pub debug_raw: bool,
}

impl RunArgs {
    pub fn into_config(self, window_secs: f64, live: bool, interval: Option<f64>, emit_idle: bool) -> RunConfig {
        let execution_id = self.execution_id
            .unwrap_or_else(|| format!("live-{}", chrono::Utc::now().format("%Y%m%d-%H%M%S")));
        RunConfig {
            exp: ExperimentConfig {
                experiment_id: self.experiment_id, execution_id, label: self.label,
                label_source: self.label_source, scenario_type: self.scenario_type,
            },
            out_dir: self.out, window_secs, allow_paths: self.allow_paths, debug_raw: self.debug_raw,
            emit_idle_windows: emit_idle, live_print: live, sampling_interval_secs: interval,
        }
    }
}
