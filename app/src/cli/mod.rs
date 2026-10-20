//! Terminal UI for the app.

use std::io;
use std::time::{Duration, Instant};

use ratatui::crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use ratatui::widgets::TableState;

use crate::core::sensors::{Sensor, file::FileSensor, process::ProcessSensor};
use app::App;

const NAME: &str = env!("CARGO_PKG_NAME");
const VERSION: &str = env!("CARGO_PKG_VERSION");
const TICK: Duration = Duration::from_secs(1);

fn usage() {
    println!("{NAME} v{VERSION}");
    println!();
    println!("Usage: {NAME} [OPTIONS]");
    println!();
    println!("Live view of file activity per process (create, open, read, write,");
    println!("rename, delete). Needs root.");
    println!();
    println!("Keys:");
    println!("  q, Ctrl-C  Quit");
    println!("  Up/Down    Select a process row");
    println!("  a          Show/hide processes without file activity");
    println!();
    println!("Options:");
    println!("  -h, --help     Show this help");
    println!("  -V, --version  Show version");
}

/// Entry point for the CLI. Returns the process exit code.
pub fn run(args: impl Iterator<Item = String>) -> i32 {
    for arg in args {
        match arg.as_str() {
            "-h" | "--help" => {
                usage();
                return 0;
            }
            "-V" | "--version" => {
                println!("{NAME} v{VERSION}");
                return 0;
            }
            other => {
                eprintln!("error: unknown argument '{other}'\n");
                usage();
                return 2;
            }
        }
    }

    // Fail before taking over the terminal, so the error stays readable.
    let mut file_sensor = match FileSensor::new() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: {e}");
            return 1;
        }
    };
    let mut process_sensor = ProcessSensor::new();

    let mut terminal = ratatui::init();
    let result = event_loop(&mut terminal, &mut process_sensor, &mut file_sensor);
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
    process_sensor: &mut ProcessSensor,
    file_sensor: &mut FileSensor,
) -> io::Result<()> {
    let mut app = App::new();
    let mut table = TableState::default();
    let mut next_tick = Instant::now();
    loop {
        if Instant::now() >= next_tick {
            // Process events first so a process is known before its file events.
            let mut events = process_sensor.poll()?;
            events.extend(file_sensor.poll()?);
            app.tick(events);
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
                KeyCode::Char('q') => return Ok(()),
                KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    return Ok(());
                }
                KeyCode::Char('a') => app.show_idle = !app.show_idle,
                KeyCode::Down => table.select_next(),
                KeyCode::Up => table.select_previous(),
                _ => {}
            }
        }
    }
}
