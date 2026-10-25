//! Terminal UI for the app.

use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use ratatui::crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use ratatui::widgets::TableState;

use crate::core::detection::{Detector, Model};
use crate::core::framework::dispatch;
use crate::core::framework::recorder::Recorder;
use crate::core::sensors::{FileSensor, ProcessSensor, Sensor, replay::ReplaySensor};
use app::{App, View};

mod app;
mod notify;
mod ui;

const NAME: &str = env!("CARGO_PKG_NAME");
const VERSION: &str = env!("CARGO_PKG_VERSION");
const TRACE_DIR: &str = "traces";
const TICK: Duration = Duration::from_secs(1);
/// The app is run from `app/` (see run.sh); `python -m lotl.export` writes here.
const DEFAULT_MODEL: &str = "../ai/models/leda_model.json";

fn usage() {
    println!("{NAME} v{VERSION}");
    println!();
    println!("Usage: {NAME} [OPTIONS]");
    println!();
    println!("Live view of process creation chains: parent and child image, tree depth,");
    println!("command-line entropy, and alerts for suspicious parent-child pairs and");
    println!("command lines. With --files, also file activity per process.");
    println!("Needs Linux >= 6.6 (or root); --files needs root (Linux) or Administrator (Windows).");
    println!();
    println!("Keys:");
    println!("  q, Ctrl-C  Quit");
    println!("  Up/Down    Select a row");
    println!("  Tab        Switch between the process and file views");
    println!("  a          Show/hide processes without file activity (file view)");
    println!();
    println!("Options:");
    println!("  --files        Also watch file activity (fanotify on Linux, ETW on Windows)");
    println!("  --record FILE  Save every event to FILE (JSON Lines; must not exist)");
    println!("                 Default for live runs: {TRACE_DIR}/<local date-time>.jsonl");
    println!("  --no-record    Do not save a trace of a live run");
    println!("  --replay FILE  Play back a recorded FILE instead of live sensors (no root/admin)");
    println!("  --model FILE   LEDA model signature file (default: {DEFAULT_MODEL};");
    println!("                 detection is off if the default file is missing)");
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
    let mut model = None;
    let mut no_record = false;
    let mut files = false;
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
            "--files" => files = true,
            "--record" | "--replay" | "--model" => {
                let Some(file) = args.next() else {
                    eprintln!("error: {arg} needs a FILE argument\n");
                    usage();
                    return 2;
                };
                let slot = match arg.as_str() {
                    "--record" => &mut record,
                    "--replay" => &mut replay,
                    _ => &mut model,
                };
                *slot = Some(PathBuf::from(file));
            }
            other => {
                eprintln!("error: unknown argument '{other}'\n");
                usage();
                return 2;
            }
        }
    }
    let conflict = if record.is_some() && replay.is_some() {
        Some("--record and --replay")
    } else if record.is_some() && no_record {
        Some("--record and --no-record")
    } else if files && replay.is_some() {
        Some("--files and --replay")
    } else {
        None
    };
    if let Some(msg) = conflict {
        eprintln!("error: {msg} cannot be combined\n");
        usage();
        return 2;
    }
    if replay.is_none() && record.is_none() && !no_record {
        record = Some(default_trace_path());
    }

    // Fail before taking over the terminal, so the error stays readable; the model
    // first, so a bad one leaves no empty trace behind. An explicit --model must
    // load; the default one is optional.
    let model = match &model {
        Some(file) => Some(Model::load(file)),
        None => Some(Path::new(DEFAULT_MODEL)).filter(|p| p.exists()).map(Model::load),
    };
    let detector = match model.transpose() {
        Ok(m) => m.map(Detector::new),
        Err(e) => {
            eprintln!("error: {e}");
            return 1;
        }
    };
    let setup = || -> io::Result<(Vec<Box<dyn Sensor>>, Option<Recorder>)> {
        let mut sensors: Vec<Box<dyn Sensor>> = match &replay {
            Some(file) => vec![Box::new(ReplaySensor::open(file)?)],
            None => vec![Box::new(ProcessSensor::new()?)],
        };
        // After the process sensor, so a process is known before its file events.
        if files {
            sensors.push(Box::new(FileSensor::new()?));
        }
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
    let watched = if files { "processes + files" } else { "processes" };
    let source = match (&replay, &record) {
        (Some(file), _) => format!("replay {}", file.display()),
        (None, Some(file)) => format!("live {watched} · recording to {}", file.display()),
        (None, None) => format!("live {watched}"),
    };
    let source = match &detector {
        Some(d) => format!("{source} · LEDA {} trees, triggers {}", d.tree_count(), d.triggers().join(",")),
        None => format!("{source} · LEDA off"),
    };

    let mut terminal = ratatui::init();
    let result = event_loop(&mut terminal, &mut sensors, recorder.as_mut(), source, detector, replay.is_none());
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
    detector: Option<Detector>,
    notify: bool,
) -> io::Result<()> {
    let mut app = App::new(source, detector);
    if notify {
        app = app.with_notifications();
    }
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
                KeyCode::Tab => {
                    app.view = if app.view == View::Processes { View::Files } else { View::Processes };
                    table.select(None);
                }
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
