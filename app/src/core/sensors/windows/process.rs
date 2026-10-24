//! Process start/exit events from Toolhelp snapshots (no privileges needed;
//! protected processes still show up, just without exe path and start time).

use std::collections::{HashMap, HashSet};
use std::ffi::OsString;
use std::io;
use std::os::windows::ffi::OsStringExt;
use std::path::PathBuf;
use std::time::SystemTime;

use windows_sys::Win32::Foundation::{CloseHandle, FILETIME, INVALID_HANDLE_VALUE};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::System::Threading::{
    GetProcessTimes, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW,
};

use crate::core::event::{Event, EventKind};
use crate::core::sensors::Sensor;

/// Detects processes by taking a snapshot on every poll.
// ponytail: processes that start and exit between two polls are never seen.
// Use the Microsoft-Windows-Kernel-Process ETW provider for exact lifecycle events.
#[derive(Default)]
pub struct ProcessSensor {
    /// pid -> start_ticks of every process already reported.
    known: HashMap<u32, u64>,
}

impl ProcessSensor {
    pub fn new() -> io::Result<Self> {
        Ok(Self::default())
    }
}

/// pid 0 is the idle pseudo-process and pid 4 the kernel ("System"): no user-space behavior.
fn is_kernel(pid: u32) -> bool {
    pid == 0 || pid == 4
}

/// Creation time (100 ns ticks since 1601) and exe path of a process; None if it cannot be opened.
// ponytail: protected processes cannot be opened, so they get start_ticks 0 and
// a reused pid goes unnoticed for them.
fn details(pid: u32) -> Option<(u64, Option<PathBuf>)> {
    // SAFETY: plain calls; the handle is closed before returning and buffers outlive the calls.
    unsafe {
        let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if h.is_null() {
            return None;
        }
        let zero = FILETIME { dwLowDateTime: 0, dwHighDateTime: 0 };
        let (mut created, mut a, mut b, mut c) = (zero, zero, zero, zero);
        let ticks = (GetProcessTimes(h, &mut created, &mut a, &mut b, &mut c) != 0)
            .then(|| (u64::from(created.dwHighDateTime) << 32) | u64::from(created.dwLowDateTime));

        let mut buf = [0u16; 1024];
        let mut len = buf.len() as u32;
        let exe = (QueryFullProcessImageNameW(h, 0, buf.as_mut_ptr(), &mut len) != 0)
            .then(|| PathBuf::from(OsString::from_wide(&buf[..len as usize])));
        CloseHandle(h);
        ticks.map(|t| (t, exe))
    }
}

/// `(pid, ppid, name)` of every running process.
fn snapshot() -> io::Result<Vec<(u32, u32, String)>> {
    // SAFETY: the snapshot handle is closed on every path; `entry` is initialised with its size.
    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snap == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        let mut entry: PROCESSENTRY32W = std::mem::zeroed();
        entry.dwSize = size_of::<PROCESSENTRY32W>() as u32;
        let mut procs = Vec::new();
        let mut ok = Process32FirstW(snap, &mut entry) != 0;
        while ok {
            let len = entry.szExeFile.iter().position(|&c| c == 0).unwrap_or(entry.szExeFile.len());
            let name = OsString::from_wide(&entry.szExeFile[..len]).to_string_lossy().into_owned();
            procs.push((entry.th32ProcessID, entry.th32ParentProcessID, name));
            ok = Process32NextW(snap, &mut entry) != 0;
        }
        CloseHandle(snap);
        Ok(procs)
    }
}

impl Sensor for ProcessSensor {
    fn poll(&mut self) -> io::Result<Vec<Event>> {
        let now = SystemTime::now();
        let mut events = Vec::new();
        let mut seen = HashSet::new();

        for (pid, ppid, name) in snapshot()? {
            if is_kernel(pid) {
                continue;
            }
            seen.insert(pid);
            // Unreadable (protected, or gone already): still running, start time unknown.
            let (start_ticks, exe) = details(pid).unwrap_or((0, None));
            match self.known.insert(pid, start_ticks) {
                Some(old) if old == start_ticks => continue,
                Some(_) => events.push(Event { timestamp: now, pid, kind: EventKind::ProcessExit }),
                None => {}
            }
            // ponytail: no command line; reading it takes NtQueryInformationProcess
            // (ProcessCommandLineInformation), so the command-line features stay empty on Windows.
            let kind = EventKind::ProcessStart { name, exe, start_ticks, ppid, cmdline: String::new() };
            events.push(Event { timestamp: now, pid, kind });
        }

        self.known.retain(|pid, _| {
            let alive = seen.contains(pid);
            if !alive {
                events.push(Event { timestamp: now, pid: *pid, kind: EventKind::ProcessExit });
            }
            alive
        });
        Ok(events)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reports_start_once_then_exit() {
        let mut sensor = ProcessSensor::new().unwrap();
        let me = std::process::id();
        let first = sensor.poll().unwrap();
        assert!(first.iter().any(|e| e.pid == me && matches!(e.kind, EventKind::ProcessStart { .. })));
        // Nothing new for a process that is still running.
        assert!(!sensor.poll().unwrap().iter().any(|e| e.pid == me));

        let mut child = std::process::Command::new("cmd").args(["/C", "ping -n 6 127.0.0.1 >nul"]).spawn().unwrap();
        let cpid = child.id();
        let started = sensor.poll().unwrap();
        let start = started.iter().find(|e| e.pid == cpid).expect("child start");
        let EventKind::ProcessStart { name, exe, .. } = &start.kind else { panic!() };
        assert!(name.eq_ignore_ascii_case("cmd.exe"), "{name}");
        assert!(exe.as_ref().unwrap().ends_with("cmd.exe"));

        child.kill().unwrap();
        child.wait().unwrap();
        let ended = sensor.poll().unwrap();
        assert!(ended.iter().any(|e| e.pid == cpid && e.kind == EventKind::ProcessExit));
    }
}
