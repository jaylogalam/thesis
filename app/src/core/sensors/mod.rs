use std::io;

use super::event::Event;

#[cfg(target_os = "linux")]
mod linux;
// Also built for tests on any OS: the event translation in there is plain Rust.
#[cfg(any(windows, test))]
mod windows;
pub mod replay;

#[cfg(target_os = "linux")]
pub use linux::{file::FileSensor, process::ProcessSensor};
#[cfg(windows)]
pub use windows::{file::FileSensor, process::ProcessSensor};

#[cfg(not(any(target_os = "linux", windows)))]
compile_error!("only Linux and Windows have sensors");

/// An OS-specific source of raw events.
pub trait Sensor {
    /// Return events observed since the last call, oldest first. Never blocks.
    fn poll(&mut self) -> io::Result<Vec<Event>>;
}
