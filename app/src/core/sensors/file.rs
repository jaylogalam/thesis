//! Per-process file activity counters for Linux, backed by fanotify.
//!
//! One filesystem-wide mark is placed on every real mounted filesystem, so
//! events from all processes are seen. Requires CAP_SYS_ADMIN (run as root).
//! Directory events are not counted.

use std::collections::HashMap;
use std::ffi::CString;
use std::fs::File;
use std::io::{self, Read};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

/// Filesystems worth watching. Pseudo filesystems (proc, sysfs, cgroup...) are skipped.
const FS_TYPES: &[&str] = &[
    "ext4", "btrfs", "xfs", "f2fs", "vfat", "exfat", "ntfs3", "tmpfs", "overlay",
];

const MASK: u64 = libc::FAN_CREATE
    | libc::FAN_OPEN
    | libc::FAN_ACCESS
    | libc::FAN_MODIFY
    | libc::FAN_RENAME
    | libc::FAN_DELETE;

const META_LEN: usize = 24; // sizeof(struct fanotify_event_metadata)
const META_VERSION: u8 = 3;

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct FileCounts {
    pub file_create_count: u64,
    pub file_open_count: u64,
    pub file_read_count: u64,
    pub file_write_count: u64,
    pub file_rename_count: u64,
    pub file_delete_count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessFileCounts {
    pub pid: u32,
    pub name: String,
    /// Cumulative since the sensor started.
    pub counts: FileCounts,
}

pub struct FileSensor {
    fan: File,
    /// Counts by pid. Pruned to running processes on every poll.
    counts: HashMap<u32, FileCounts>,
}

impl FileSensor {
    pub fn new() -> io::Result<Self> {
        let flags = libc::FAN_CLASS_NOTIF
            | libc::FAN_CLOEXEC
            | libc::FAN_NONBLOCK
            | libc::FAN_REPORT_DFID_NAME;
        // SAFETY: plain syscall, result checked.
        let fd = unsafe { libc::fanotify_init(flags, libc::O_RDONLY as u32) };
        if fd < 0 {
            let e = io::Error::last_os_error();
            return Err(needs_root(e));
        }
        // SAFETY: fd is a fresh, valid descriptor we own.
        let fan = File::from(unsafe { OwnedFd::from_raw_fd(fd) });

        // Individual mounts may legitimately fail (e.g. no fsid); only fail if all do.
        let mut marked = 0;
        let mut last_err = io::Error::other("no watchable filesystem found");
        for mount in watchable_mounts()? {
            match mark_filesystem(fan.as_raw_fd(), &mount) {
                Ok(()) => marked += 1,
                Err(e) => last_err = e,
            }
        }
        if marked == 0 {
            return Err(needs_root(last_err));
        }
        Ok(Self { fan, counts: HashMap::new() })
    }

    /// Drain pending events, then return every running process (sorted by pid)
    /// with cumulative counts, zeros for idle ones. Never blocks.
    pub fn poll(&mut self) -> io::Result<Vec<ProcessFileCounts>> {
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            let n = match self.fan.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            };
            for ev in parse_events(&buf[..n]) {
                if ev.fd >= 0 {
                    // SAFETY: the kernel handed us this descriptor; close it.
                    drop(unsafe { OwnedFd::from_raw_fd(ev.fd) });
                }
                // Overflow events carry pid 0 / no process.
                if ev.pid <= 0 {
                    continue;
                }
                add(self.counts.entry(ev.pid as u32).or_default(), ev.mask);
            }
        }
        // ponytail: counts follow the pid, so a reused pid inherits the old counts.
        let mut pids = running_pids()?;
        pids.sort_unstable();
        self.counts.retain(|pid, _| pids.binary_search(pid).is_ok());
        Ok(pids
            .into_iter()
            .map(|pid| ProcessFileCounts {
                pid,
                name: process_name(pid),
                counts: self.counts.get(&pid).copied().unwrap_or_default(),
            })
            .collect())
    }
}

#[derive(Debug, PartialEq, Eq)]
struct Event {
    mask: u64,
    fd: RawFd,
    pid: i32,
}

/// Decode `struct fanotify_event_metadata` records; trailing info records are skipped.
fn parse_events(mut buf: &[u8]) -> Vec<Event> {
    let mut out = Vec::new();
    while buf.len() >= META_LEN {
        let len = u32::from_ne_bytes(buf[0..4].try_into().unwrap()) as usize;
        if buf[4] != META_VERSION || len < META_LEN || len > buf.len() {
            break;
        }
        out.push(Event {
            mask: u64::from_ne_bytes(buf[8..16].try_into().unwrap()),
            fd: i32::from_ne_bytes(buf[16..20].try_into().unwrap()),
            pid: i32::from_ne_bytes(buf[20..24].try_into().unwrap()),
        });
        buf = &buf[len..];
    }
    out
}

fn add(c: &mut FileCounts, mask: u64) {
    let bump = |flag: u64, n: &mut u64| {
        if mask & flag != 0 {
            *n += 1;
        }
    };
    bump(libc::FAN_CREATE, &mut c.file_create_count);
    bump(libc::FAN_OPEN, &mut c.file_open_count);
    bump(libc::FAN_ACCESS, &mut c.file_read_count);
    bump(libc::FAN_MODIFY, &mut c.file_write_count);
    bump(libc::FAN_RENAME, &mut c.file_rename_count);
    bump(libc::FAN_DELETE, &mut c.file_delete_count);
}

fn needs_root(e: io::Error) -> io::Error {
    if e.kind() == io::ErrorKind::PermissionDenied {
        io::Error::new(e.kind(), "fanotify needs root (CAP_SYS_ADMIN); run with sudo")
    } else {
        e
    }
}

fn running_pids() -> io::Result<Vec<u32>> {
    Ok(std::fs::read_dir("/proc")?
        .filter_map(|e| e.ok()?.file_name().to_str()?.parse().ok())
        .collect())
}

fn process_name(pid: u32) -> String {
    std::fs::read_to_string(format!("/proc/{pid}/comm"))
        .map(|s| s.trim_end().to_string())
        .unwrap_or_else(|_| "?".into()) // already exited
}

fn mark_filesystem(fan: RawFd, path: &str) -> io::Result<()> {
    let path = CString::new(path).map_err(io::Error::other)?;
    // SAFETY: `path` is a valid NUL-terminated string for the call's duration.
    let r = unsafe {
        libc::fanotify_mark(
            fan,
            libc::FAN_MARK_ADD | libc::FAN_MARK_FILESYSTEM,
            MASK,
            libc::AT_FDCWD,
            path.as_ptr(),
        )
    };
    if r < 0 { Err(io::Error::last_os_error()) } else { Ok(()) }
}

fn watchable_mounts() -> io::Result<Vec<String>> {
    Ok(parse_mountinfo(&std::fs::read_to_string("/proc/self/mountinfo")?))
}

/// Mount points of watchable filesystems from `/proc/self/mountinfo` text.
fn parse_mountinfo(text: &str) -> Vec<String> {
    text.lines()
        .filter_map(|line| {
            let (pre, post) = line.split_once(" - ")?;
            let mountpoint = pre.split(' ').nth(4)?;
            let fstype = post.split(' ').next()?;
            FS_TYPES
                .contains(&fstype)
                .then(|| mountpoint.replace("\\040", " "))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(mask: u64, fd: i32, pid: i32, extra: usize) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend(((META_LEN + extra) as u32).to_ne_bytes());
        v.push(META_VERSION);
        v.push(0);
        v.extend((META_LEN as u16).to_ne_bytes());
        v.extend(mask.to_ne_bytes());
        v.extend(fd.to_ne_bytes());
        v.extend(pid.to_ne_bytes());
        v.extend(std::iter::repeat(0u8).take(extra)); // info record
        v
    }

    #[test]
    fn parses_records_and_skips_info_payload() {
        let mut buf = record(libc::FAN_CREATE, -1, 42, 32);
        buf.extend(record(libc::FAN_OPEN | libc::FAN_ACCESS, -1, 7, 0));
        assert_eq!(
            parse_events(&buf),
            vec![
                Event { mask: libc::FAN_CREATE, fd: -1, pid: 42 },
                Event { mask: libc::FAN_OPEN | libc::FAN_ACCESS, fd: -1, pid: 7 },
            ]
        );
        // Truncated record is dropped rather than misread.
        assert!(parse_events(&buf[..buf.len() - 1]).len() == 1);
    }

    #[test]
    fn maps_mask_bits_to_counters() {
        let mut c = FileCounts::default();
        add(&mut c, libc::FAN_OPEN | libc::FAN_ACCESS);
        add(&mut c, libc::FAN_MODIFY);
        add(&mut c, libc::FAN_RENAME);
        add(&mut c, libc::FAN_DELETE | libc::FAN_CREATE);
        assert_eq!(
            c,
            FileCounts {
                file_create_count: 1,
                file_open_count: 1,
                file_read_count: 1,
                file_write_count: 1,
                file_rename_count: 1,
                file_delete_count: 1,
            }
        );
    }

    #[test]
    fn lists_running_pids_with_names() {
        let me = std::process::id();
        assert!(running_pids().unwrap().contains(&me));
        assert_ne!(process_name(me), "?");
    }

    #[test]
    fn keeps_only_real_filesystems() {
        let text = "\
22 1 0:21 / /proc rw - proc proc rw
30 1 259:2 / / rw - btrfs /dev/nvme0n1p2 rw
31 30 0:30 / /tmp/my\\040dir rw - tmpfs tmpfs rw
32 30 0:31 / /sys rw shared:2 - sysfs sysfs rw";
        assert_eq!(parse_mountinfo(text), vec!["/", "/tmp/my dir"]);
    }
}
