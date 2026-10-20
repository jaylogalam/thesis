use std::io;

use super::event::Event;

pub mod file;
pub mod process;
pub mod replay;

/// An OS-specific source of raw events.
pub trait Sensor {
    /// Return events observed since the last call, oldest first. Never blocks.
    fn poll(&mut self) -> io::Result<Vec<Event>>;
}
