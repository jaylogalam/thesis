//! Rendering. Top: per-process counters. Bottom: live event log.

use std::time::SystemTime;

use ratatui::layout::{Constraint, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Cell, Paragraph, Row, Table, TableState};
use ratatui::Frame;

use super::app::{App, LogKind, LogLine};
use crate::core::event::FileOp;

/// HH:MM:SS in local time.
fn hms(t: SystemTime) -> String {
    let secs = t
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs()) as libc::time_t;
    // SAFETY: localtime_r only writes into `tm`; result checked.
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    if unsafe { libc::localtime_r(&secs, &mut tm) }.is_null() {
        return "--:--:--".into();
    }
    format!("{:02}:{:02}:{:02}", tm.tm_hour, tm.tm_min, tm.tm_sec)
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
        LogKind::Exit => ("EXIT", Color::DarkGray),
        LogKind::File(op) => op_style(op),
    };
    let dim = Style::new().fg(Color::DarkGray);
    Line::from(vec![
        Span::styled(hms(l.time), dim),
        Span::raw(format!(" {:>7} {:<16.16} ", l.pid, l.name)),
        Span::styled(format!("{label:<7}"), Style::new().fg(color)),
        Span::raw(l.detail.clone()),
    ])
}

pub fn draw(f: &mut Frame, app: &App, table: &mut TableState) {
    let [head, procs, log, keys] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Percentage(55),
        Constraint::Fill(1),
        Constraint::Length(1),
    ])
    .areas(f.area());

    let bold = Style::new().add_modifier(Modifier::BOLD);
    f.render_widget(
        Line::from(vec![
            Span::styled(format!("{} v{}", super::NAME, super::VERSION), bold),
            Span::raw(format!(
                "   processes: {}   events: {}   up: {}s",
                app.rows.len(),
                app.events_total,
                app.started.elapsed().as_secs()
            )),
        ]),
        head,
    );

    let header = Row::new(
        ["PID", "NAME", "EV/s", "CREATE", "OPEN", "READ", "WRITE", "RENAME", "DELETE"].map(Cell::from),
    )
    .style(bold.fg(Color::Cyan));
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
        format!(" processes: all ({shown}) · counts are cumulative ")
    } else {
        format!(" processes: with file activity ({shown}) · counts are cumulative ")
    };
    f.render_stateful_widget(
        Table::new(rows, widths)
            .header(header)
            .block(Block::bordered().title(title))
            .row_highlight_style(Style::new().add_modifier(Modifier::REVERSED)),
        procs,
        table,
    );

    let visible = log.height.saturating_sub(2) as usize;
    let lines: Vec<Line> = app
        .log
        .iter()
        .skip(app.log.len().saturating_sub(visible))
        .map(log_line)
        .collect();
    f.render_widget(
        Paragraph::new(lines).block(Block::bordered().title(" events ")),
        log,
    );

    f.render_widget(
        Span::styled(
            " q quit · ↑/↓ select · a show idle processes",
            Style::new().fg(Color::DarkGray),
        ),
        keys,
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::app::total;
    use crate::core::event::{Event, EventKind};
    use ratatui::{backend::TestBackend, Terminal};
    use std::path::PathBuf;

    fn ev(pid: u32, kind: EventKind) -> Event {
        Event { timestamp: SystemTime::now(), pid, kind }
    }

    #[test]
    fn renders_table_and_event_log() {
        let mut app = App::new();
        app.tick(vec![
            ev(10, EventKind::ProcessStart { name: "editor".into(), exe: None, start_ticks: 1 }),
            ev(11, EventKind::ProcessStart { name: "idle-proc".into(), exe: None, start_ticks: 2 }),
            ev(10, EventKind::File { op: FileOp::Write, path: Some(PathBuf::from("/home/u/notes.txt")) }),
            ev(10, EventKind::File { op: FileOp::Delete, path: None }),
        ]);
        let mut term = Terminal::new(TestBackend::new(100, 24)).unwrap();
        term.draw(|f| draw(f, &app, &mut TableState::default())).unwrap();
        let out = term.backend().to_string();
        assert!(out.contains("editor"), "{out}");
        assert!(out.contains("with file activity (1)"), "idle hidden by default:\n{out}");
        assert!(out.contains("WRITE") && out.contains("/home/u/notes.txt"), "{out}");
        assert_eq!(total(&app.rows[0].counts), 2);
        assert_eq!(app.rows[0].rate, 2);
        println!("{out}");
    }
}
