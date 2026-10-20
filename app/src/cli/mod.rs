//! Terminal UI for the app.

use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use ratatui::crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use ratatui::widgets::TableState;

use crate::core::framework::dispatch;
use crate::core::framework::recorder::Recorder;
use crate::core::sensors::{FileSensor, ProcessSensor, Sensor, replay::ReplaySensor};
use app::App;

mod app;
mod ui;

const NAME: &str = env!("CARGO_PKG_NAME");
const VERSION: &str = env!("CARGO_PKG_VERSION");
const TRACE_DIR: &str = "traces";
const TICK: Duration = Duration::from_secs(1);

fn usage() {
    println!("{NAME} v{VERSION}");
    println!();
    println!("Usage: {NAME} [OPTIONS]");
    println!();
    println!("Live view of file activity per process (create, open, read, write,");
    println!("rename, delete). Needs root (Linux) or Administrator (Windows), except with --replay.");
    println!();
    println!("Keys:");
    println!("  q, Ctrl-C  Quit");
    println!("  Up/Down    Select a process row");
    println!("  a          Show/hide processes without file activity");
    println!();
    println!("Options:");
    println!("  --record FILE  Save every event to FILE (JSON Lines; must not exist)");
    println!("                 Default for live runs: {TRACE_DIR}/<local date-time>.jsonl");
    println!("  --no-record    Do not save a trace of a live run");
    println!("  --replay FILE  Play back a recorded FILE instead of live sensors (no root/admin)");
    println!("  -h, --help     Show this help");
    println!("  -V, --version  Show version");
}

/// `traces/YYYY-MM-DD_HH-MM-SS.jsonl` in local time.
fn default_trace_path() -> PathBuf {
    let stamp = chrono::Local::now().format("%Y-%m-%d_%H-%M-%S");
    PathBuf::from(TRACE_DIR).join(format!("{stamp}.jsonl"))
}

/// Entry point for the CLI. Returns the process exit code.
pub fn run(args: impl Iterator<Item = String>) -> i32 {
    let mut args = args;
    let mut record = None;
    let mut replay = None;
    let mut no_record = false;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-h" | "--help" => {
                usage();
                return 0;
            }
            "-V" | "--version" => {
                println!("{NAME} v{VERSION}");
                return 0;
            }
            "--no-record" => no_record = true,
            "--record" | "--replay" => {
                let Some(file) = args.next() else {
                    eprintln!("error: {arg} needs a FILE argument\n");
                    usage();
                    return 2;
                };
                let slot = if arg == "--record" { &mut record } else { &mut replay };
                *slot = Some(PathBuf::from(file));
            }
            other => {
                eprintln!("error: unknown argument '{other}'\n");
                usage();
                return 2;
            }
        }
    }
    if (record.is_some() && replay.is_some()) || (record.is_some() && no_record) {
        let msg = if replay.is_some() { "--record and --replay" } else { "--record and --no-record" };
        eprintln!("error: {msg} cannot be combined\n");
        usage();
        return 2;
    }
    if replay.is_none() && record.is_none() && !no_record {
        record = Some(default_trace_path());
    }

    // Fail before taking over the terminal, so the error stays readable.
    let setup = || -> io::Result<(Vec<Box<dyn Sensor>>, Option<Recorder>)> {
        let sensors: Vec<Box<dyn Sensor>> = match &replay {
            Some(file) => vec![Box::new(ReplaySensor::open(file)?)],
            // Process sensor first so a process is known before its file events.
            None => vec![Box::new(ProcessSensor::new()), Box::new(FileSensor::new()?)],
        };
        if let Some(dir) = record.as_deref().and_then(Path::parent).filter(|d| !d.as_os_str().is_empty()) {
            std::fs::create_dir_all(dir)?;
        }
        let recorder = record.as_deref().map(Recorder::create).transpose()?;
        Ok((sensors, recorder))
    };
    let (mut sensors, mut recorder) = match setup() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: {e}");
            return 1;
        }
    };
    let source = match (&replay, &record) {
        (Some(file), _) => format!("replay {}", file.display()),
        (None, Some(file)) => format!("live · recording to {}", file.display()),
        (None, None) => "live".into(),
    };

    let mut terminal = ratatui::init();
    let result = event_loop(&mut terminal, &mut sensors, recorder.as_mut(), source);
    ratatui::restore();
    match result {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("error: {e}");
            1
        }
    }
}

fn event_loop(
    terminal: &mut ratatui::DefaultTerminal,
    sensors: &mut [Box<dyn Sensor>],
    mut recorder: Option<&mut Recorder>,
    source: String,
) -> io::Result<()> {
    let mut app = App::new(source);
    let mut table = TableState::default();
    let mut next_tick = Instant::now();
    loop {
        if Instant::now() >= next_tick {
            let mut events = Vec::new();
            for s in sensors.iter_mut() {
                events.extend(s.poll()?);
            }
            // Recorder first, so an event is saved even if a later processor fails.
            match recorder.as_deref_mut() {
                Some(r) => {
                    dispatch(events, &mut [r, &mut app])?;
                    r.flush()?;
                }
                None => dispatch(events, &mut [&mut app])?,
            }
            app.refresh();
            next_tick = Instant::now() + TICK;
        }
        terminal.draw(|f| ui::draw(f, &app, &mut table))?;

        if !event::poll(next_tick.saturating_duration_since(Instant::now()))? {
            continue;
        }
        if let Event::Key(key) = event::read()? {
            if key.kind != KeyEventKind::Press {
                continue;
            }
            match key.code {
                KeyCode::Char('q') => break,
                KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => break,
                KeyCode::Char('a') => app.show_idle = !app.show_idle,
                KeyCode::Down => table.select_next(),
                KeyCode::Up => table.select_previous(),
                _ => {}
            }
        }
    }
    if let Some(r) = recorder {
        r.flush()?;
    }
    Ok(())
}
