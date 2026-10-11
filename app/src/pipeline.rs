use crate::aggregate::Aggregator;
use crate::event::SourceSignal;
use crate::export::DatasetWriter;
use crate::features::FeatureRow;
use crate::label::ExperimentConfig;
use crate::quality::QualityCounters;
use crate::source::EventSource;
use anyhow::Result;
use std::path::PathBuf;

pub struct RunConfig {
    pub exp: ExperimentConfig,
    pub out_dir: PathBuf,
    pub window_secs: f64,
    pub allow_paths: bool,
    pub debug_raw: bool,
    pub emit_idle_windows: bool,
    pub live_print: bool,
    pub sampling_interval_secs: Option<f64>,
}

/// source -> aggregate (identity inside) -> features -> label metadata -> export.
pub fn run_pipeline(source: &mut dyn EventSource, cfg: &RunConfig) -> Result<QualityCounters> {
    anyhow::ensure!(cfg.window_secs.is_finite() && cfg.window_secs > 0.0, "--window-secs must be > 0");
    let w_us = (cfg.window_secs * 1e6).round() as i64;
    anyhow::ensure!(w_us > 0, "--window-secs too small");
    let mut agg = Aggregator::new(w_us);
    agg.set_emit_idle(cfg.emit_idle_windows);
    let mut out = DatasetWriter::create(&cfg.out_dir, &cfg.exp.execution_id, cfg.debug_raw)?;
    let mut sample = 0u64;
    let mut err: Option<anyhow::Error> = None;

    let mut drain = |agg: &mut Aggregator, out: &mut DatasetWriter, err: &mut Option<anyhow::Error>| {
        for w in agg.take_output() {
            sample += 1;
            let f = FeatureRow::from_window(&w);
            if cfg.live_print {
                let t = chrono::DateTime::from_timestamp_micros(w.end_us).unwrap_or_default();
                println!(
                    "{} pid={} {} r={} w={} bytes={} files={} dirs={} dur={:.1}s {}",
                    t.format("%H:%M:%S"), w.pid, w.proc_name.as_deref().unwrap_or("?"), w.counts[0], w.counts[1],
                    w.bytes_written.map_or("-".to_string(), |b| b.to_string()), w.unique_files, w.unique_dirs,
                    w.duration_us as f64 / 1e6, if w.complete { "complete" } else { "partial" },
                );
            }
            if let Err(e) = out.row(cfg.exp.metadata(sample, &w, cfg.allow_paths), f.csv_values()) {
                err.get_or_insert(e);
            }
        }
        if let Err(e) = out.flush() {
            err.get_or_insert(e);
        }
    };
    source.run(&mut |s: SourceSignal| {
        if err.is_some() { return; }
        if let SourceSignal::File(e) = &s {
            if let Err(e2) = out.raw(e) { err = Some(e2); return; }
        }
        agg.signal(s);
        drain(&mut agg, &mut out, &mut err);
    })?;
    if let Some(e) = err { return Err(e); }
    agg.finish();
    drain(&mut agg, &mut out, &mut err);
    if let Some(e) = err { return Err(e); }
    let (overflow, unreadable) = source.source_counters();
    agg.q.queue_overflow_dropped += overflow;
    agg.q.procfs_unreadable_processes += unreadable;
    out.finish(
        &agg.q, cfg.window_secs, cfg.allow_paths, cfg.window_secs, source.source_type(),
        cfg.sampling_interval_secs, cfg.emit_idle_windows, source.capabilities(),
    )?;
    Ok(agg.q)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{normalize, source::synth};

    #[test]
    fn section8_example() {
        let mut a = Aggregator::new(2_000_000);
        for r in synth::scenario("section8-example").unwrap() {
            a.signal(normalize::from_record(r, "synth"));
        }
        a.finish();
        let rows = a.take_output();
        assert_eq!(rows.len(), 1);
        let w = &rows[0];
        let f = FeatureRow::from_window(w);
        assert_eq!(w.duration_us, 2_000_000);
        assert!(w.complete);
        assert_eq!((f.file_read_count, f.file_write_count, f.file_create_count, f.file_rename_count, f.file_delete_count), (90, 60, 0, 45, 10));
        assert_eq!((f.unique_files_accessed, f.unique_files_modified, f.unique_directories_accessed), (100, 60, 8));
        assert_eq!(f.bytes_written_total, Some(1_048_576));
        assert_eq!(f.modified_files_per_second, 30.0);
        assert!((f.write_read_ratio - 0.666667).abs() < 1e-6);
        assert_eq!(f.rename_write_ratio, 0.75);
        assert!((f.delete_write_ratio - 0.166667).abs() < 1e-6);
    }
}
