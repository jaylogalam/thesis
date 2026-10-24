//! Windows sensors: ETW for file activity, the Sysmon event log for processes.
//! Both need Administrator rights for the full picture.

pub mod file;
pub mod process;
