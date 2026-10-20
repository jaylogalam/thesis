//! Windows sensors: ETW for file activity, Toolhelp snapshots for processes.
//! Both need Administrator rights for the full picture.

pub mod file;
#[cfg(windows)]
pub mod process;
