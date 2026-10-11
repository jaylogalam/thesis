mod aggregate;
mod cli;
mod event;
mod export;
mod features;
mod identity;
mod label;
mod normalize;
mod pathutil;
mod pipeline;
mod quality;
mod source;

use clap::Parser;
use cli::{Cli, Cmd};
use source::{EventSource, replay::ReplaySource};
use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
use std::time::Duration;

fn main() -> anyhow::Result<()> {
    let cmd = match Cli::parse().cmd {
        Some(c) => c,
        // Bare invocation = `live` with clap's own defaults (single source of truth).
        None => {
            let prog = std::env::args().next().unwrap_or_default();
            Cli::parse_from([prog, "live".into()]).cmd.expect("live subcommand")
        }
    };
    match cmd {
        Cmd::Synth { scenario, out } => {
            let mut s = String::new();
            for r in source::synth::scenario(&scenario)? {
                s.push_str(&serde_json::to_string(&r)?);
                s.push('\n');
            }
            std::fs::write(&out, s)?;
        }
        Cmd::Replay { input, window_secs, run } => {
            let q = pipeline::run_pipeline(&mut ReplaySource { path: input }, &run.into_config(window_secs, false, None, true))?;
            eprintln!("{q:#?}");
        }
        Cmd::Live { interval_secs, window_secs, duration_secs, pids, emit_idle_windows, run } => {
            anyhow::ensure!(interval_secs.is_finite() && interval_secs > 0.0, "--interval-secs must be > 0");
            let stop = Arc::new(AtomicBool::new(false));
            ctrlc::set_handler({
                let s = stop.clone();
                move || s.store(true, Ordering::Relaxed)
            })?;
            let duration = duration_secs.map(Duration::from_secs);
            let mut src = make_source(Duration::from_secs_f64(interval_secs), duration, stop, pids)?;
            let cfg = run.into_config(window_secs, true, Some(interval_secs), emit_idle_windows);
            eprintln!(
                "live capture: source={} window={}s interval={}s out={} (Ctrl-C to stop)",
                src.source_type(), window_secs, interval_secs, cfg.out_dir.join(&cfg.exp.execution_id).display()
            );
            #[cfg(target_os = "linux")]
            if !is_root() {
                eprintln!("note: only processes owned by the current user expose /proc/<pid>/io; run with sudo to monitor all processes");
            }
            let q = pipeline::run_pipeline(src.as_mut(), &cfg)?;
            eprintln!("{q:#?}");
            eprintln!("dataset: {}", cfg.out_dir.join(&cfg.exp.execution_id).display());
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn is_root() -> bool {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| s.lines().find_map(|l| l.strip_prefix("Uid:")?.split_whitespace().next().map(|u| u == "0")))
        .unwrap_or(false)
}

#[cfg(target_os = "linux")]
fn make_source(interval: Duration, duration: Option<Duration>, stop: Arc<AtomicBool>, pids: Vec<u32>) -> anyhow::Result<Box<dyn EventSource>> {
    Ok(Box::new(source::procfs::ProcfsSource::new(interval, duration, stop, pids)))
}

#[cfg(windows)]
fn make_source(_interval: Duration, duration: Option<Duration>, stop: Arc<AtomicBool>, _pids: Vec<u32>) -> anyhow::Result<Box<dyn EventSource>> {
    Ok(Box::new(source::etw::EtwSource::new(duration, stop)))
}

#[cfg(not(any(target_os = "linux", windows)))]
fn make_source(_: Duration, _: Option<Duration>, _: Arc<AtomicBool>, _: Vec<u32>) -> anyhow::Result<Box<dyn EventSource>> {
    anyhow::bail!("live capture is supported on Linux (/proc) and Windows (ETW) only")
}
