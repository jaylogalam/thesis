//! Synchronous event delivery: every processor sees every event, and events a
//! processor derives from one are delivered right after it.

use std::collections::VecDeque;
use std::io;

use super::event::Event;

pub trait Processor {
    /// Handle one event. Push derived (higher-layer) events to `out`;
    /// they are dispatched to all processors right after this event.
    fn on_event(&mut self, ev: &Event, out: &mut Vec<Event>) -> io::Result<()>;
}

pub mod recorder;

const MAX_DEPTH: u8 = 8;

/// Deliver `events` to `processors` in slice order, depth-first: derived events
/// are dispatched immediately after their cause, keeping the stream in cause order.
pub fn dispatch(events: Vec<Event>, processors: &mut [&mut dyn Processor]) -> io::Result<()> {
    let mut queue: VecDeque<(Event, u8)> = events.into_iter().map(|e| (e, 0)).collect();
    let mut out = Vec::new();
    while let Some((ev, depth)) = queue.pop_front() {
        for p in processors.iter_mut() {
            p.on_event(&ev, &mut out)?;
        }
        if out.is_empty() {
            continue;
        }
        if depth >= MAX_DEPTH {
            return Err(io::Error::other("event processors re-emitted events more than 8 levels deep"));
        }
        for d in out.drain(..).rev() {
            queue.push_front((d, depth + 1));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::event::{EventKind, FileOp};
    use std::time::SystemTime;

    fn ev(pid: u32, kind: EventKind) -> Event {
        Event { timestamp: SystemTime::now(), pid, kind }
    }

    struct ExitOnFile;
    impl Processor for ExitOnFile {
        fn on_event(&mut self, ev: &Event, out: &mut Vec<Event>) -> io::Result<()> {
            if matches!(ev.kind, EventKind::File { .. }) {
                out.push(self::ev(99, EventKind::ProcessExit));
            }
            Ok(())
        }
    }

    #[derive(Default)]
    struct Pids(Vec<u32>);
    impl Processor for Pids {
        fn on_event(&mut self, ev: &Event, _: &mut Vec<Event>) -> io::Result<()> {
            self.0.push(ev.pid);
            Ok(())
        }
    }

    #[test]
    fn derived_events_follow_their_cause() {
        let file = |pid| ev(pid, EventKind::File { op: FileOp::Write, path: None });
        let mut pids = Pids::default();
        dispatch(vec![file(1), file(2)], &mut [&mut ExitOnFile, &mut pids]).unwrap();
        assert_eq!(pids.0, [1, 99, 2, 99]);
    }

    struct Echo;
    impl Processor for Echo {
        fn on_event(&mut self, ev: &Event, out: &mut Vec<Event>) -> io::Result<()> {
            out.push(ev.clone());
            Ok(())
        }
    }

    #[test]
    fn runaway_processor_errors() {
        assert!(dispatch(vec![ev(1, EventKind::ProcessExit)], &mut [&mut Echo]).is_err());
    }
}
