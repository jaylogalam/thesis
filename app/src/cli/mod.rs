//! Terminal UI for the app.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::core::sensors::file::{FileSensor, ProcessFileCounts};

const NAME: &str = env!("CARGO_PKG_NAME");
const VERSION: &str = env!("CARGO_PKG_VERSION");

fn banner() {
    println!("{NAME} v{VERSION}");
}

fn usage() {
    println!("Usage: {NAME} [OPTIONS]");
    println!();
    println!("Logs file activity of every process, once per second. Needs root.");
    println!("Every running process is listed each second; counts are cumulative.");
    println!();
    println!("Options:");
    println!("  -h, --help     Show this help");
    println!("  -V, --version  Show version");
}

/// One log line per process, timestamped in UTC.
fn log_line(p: &ProcessFileCounts) {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
        % 86_400;
    let c = &p.counts;
    println!(
        "[{:02}:{:02}:{:02}] pid={} name={} file_create_count={} file_open_count={} \
         file_read_count={} file_write_count={} file_rename_count={} file_delete_count={}",
        secs / 3600,
        secs / 60 % 60,
        secs % 60,
        p.pid,
        p.name,
        c.file_create_count,
        c.file_open_count,
        c.file_read_count,
        c.file_write_count,
        c.file_rename_count,
        c.file_delete_count,
    );
}

/// Entry point for the CLI. Returns the process exit code.
pub fn run(args: impl Iterator<Item = String>) -> i32 {
    for arg in args {
        match arg.as_str() {
            "-h" | "--help" => {
                banner();
                println!();
                usage();
                return 0;
            }
            "-V" | "--version" => {
                banner();
                return 0;
            }
            other => {
                eprintln!("error: unknown argument '{other}'\n");
                usage();
                return 2;
            }
        }
    }

    let mut sensor = match FileSensor::new() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: {e}");
            return 1;
        }
    };
    banner();
    println!("logging all processes (Ctrl-C to quit)");
    loop {
        match sensor.poll() {
            Ok(procs) => procs.iter().for_each(log_line),
            Err(e) => {
                eprintln!("error: {e}");
                return 1;
            }
        }
        std::thread::sleep(Duration::from_secs(1));
    }
}
