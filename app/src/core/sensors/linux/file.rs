//! File activity events for Linux, backed by fanotify.
//!
//! One filesystem-wide mark is placed on every real mounted filesystem, so
//! events from all processes are seen. Requires CAP_SYS_ADMIN (run as root).
//! Directory events are not reported. Paths are resolved from the file handle
//! the kernel reports (open_by_handle_at).

use std::collections::HashMap;
use std::ffi::{CString, OsStr};
use std::fs::File;
use std::io::{self, Read};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;
use std::time::SystemTime;

use crate::core::sensors::Sensor;
use crate::core::event::{Event, EventKind, FileOp};

/// Filesystems worth watching. Pseudo filesystems (proc, sysfs, cgroup...) are skipped.
const FS_TYPES: &[&str] = &[
    "ext4", "btrfs", "xfs", "f2fs", "vfat", "exfat", "ntfs3", "tmpfs", "overlay",
];

const OPS: [(u64, FileOp); 6] = [
    (libc::FAN_CREATE, FileOp::Create),
    (libc::FAN_OPEN, FileOp::Open),
    (libc::FAN_ACCESS, FileOp::Read),
    (libc::FAN_MODIFY, FileOp::Write),
    (libc::FAN_RENAME, FileOp::Rename),
    (libc::FAN_DELETE, FileOp::Delete),
];

const MASK: u64 = libc::FAN_CREATE
    | libc::FAN_OPEN
    | libc::FAN_ACCESS
    | libc::FAN_MODIFY
    | libc::FAN_RENAME
    | libc::FAN_DELETE;

const META_VERSION: u8 = 3;
// fanotify_event_info_type values (not exported by the libc crate).
const INFO_DFID_NAME: u8 = 2;
const INFO_OLD_DFID_NAME: u8 = 10;
const INFO_NEW_DFID_NAME: u8 = 12;
/// Directory handles cached before the cache is dropped.
const DIR_CACHE_MAX: usize = 4096;

type Fsid = [i32; 2];

pub struct FileSensor {
    fan: File,
    /// A descriptor on every marked filesystem, as required by open_by_handle_at.
    mounts: Vec<(Fsid, OwnedFd)>,
    // ponytail: a renamed directory keeps its old cached path until the cache is dropped.
    dirs: HashMap<(Fsid, Vec<u8>), PathBuf>,
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
            return Err(needs_root(io::Error::last_os_error()));
        }
        // SAFETY: fd is a fresh, valid descriptor we own.
        let fan = File::from(unsafe { OwnedFd::from_raw_fd(fd) });

        // Individual mounts may legitimately fail (e.g. no fsid); only fail if all do.
        let mut mounts = Vec::new();
        let mut last_err = io::Error::other("no watchable filesystem found");
        for mount in watchable_mounts()? {
            match mark_filesystem(fan.as_raw_fd(), &mount) {
                Ok(()) => {
                    if let Ok(m) = mount_handle(&mount) {
                        mounts.push(m);
                    }
                }
                Err(e) => last_err = e,
            }
        }
        if mounts.is_empty() {
            return Err(needs_root(last_err));
        }
        Ok(Self { fan, mounts, dirs: HashMap::new() })
    }

    fn resolve(&mut self, fid: &Fid) -> Option<PathBuf> {
        let key = (fid.fsid, fid.handle.clone());
        let dir = match self.dirs.get(&key) {
            Some(p) => p.clone(),
            None => {
                let p = self.open_dir(fid)?;
                if self.dirs.len() >= DIR_CACHE_MAX {
                    self.dirs.clear();
                }
                self.dirs.insert(key, p.clone());
                p
            }
        };
        Some(match &fid.name {
            Some(n) if n != b"." => dir.join(OsStr::from_bytes(n)),
            _ => dir,
        })
    }

    /// Path of the directory a handle refers to, or None if it no longer exists.
    fn open_dir(&self, fid: &Fid) -> Option<PathBuf> {
        // struct file_handle needs 4-byte alignment; a Vec<u8> does not promise it.
        let mut words = vec![0u32; fid.handle.len().div_ceil(4)];
        // SAFETY: `words` has at least handle.len() bytes of capacity.
        unsafe {
            std::ptr::copy_nonoverlapping(
                fid.handle.as_ptr(),
                words.as_mut_ptr().cast::<u8>(),
                fid.handle.len(),
            );
        }
        // Try the matching filesystem first. Some filesystems (btrfs subvolumes)
        // report a different fsid than statfs on their mount, so fall back to all.
        let order = self
            .mounts
            .iter()
            .filter(|(id, _)| *id == fid.fsid)
            .chain(self.mounts.iter().filter(|(id, _)| *id != fid.fsid));
        for (_, mount) in order {
            // SAFETY: `words` holds a valid file_handle; result checked.
            let fd = unsafe {
                libc::syscall(
                    libc::SYS_open_by_handle_at,
                    mount.as_raw_fd(),
                    words.as_ptr(),
                    libc::O_PATH | libc::O_CLOEXEC,
                )
            };
            if fd >= 0 {
                // SAFETY: fd is a fresh descriptor we own; closed on drop.
                let fd = unsafe { OwnedFd::from_raw_fd(fd as RawFd) };
                return std::fs::read_link(format!("/proc/self/fd/{}", fd.as_raw_fd())).ok();
            }
        }
        None
    }
}

impl Sensor for FileSensor {
    fn poll(&mut self) -> io::Result<Vec<Event>> {
        let mut buf = vec![0u8; 64 * 1024];
        let mut events = Vec::new();
        loop {
            let n = match self.fan.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            };
            let now = SystemTime::now();
            for raw in parse_events(&buf[..n]) {
                if raw.fd >= 0 {
                    // SAFETY: the kernel handed us this descriptor; close it.
                    drop(unsafe { OwnedFd::from_raw_fd(raw.fd) });
                }
                // Overflow events carry pid 0 and no operation.
                let ops: Vec<FileOp> =
                    OPS.iter().filter(|(bit, _)| raw.mask & bit != 0).map(|(_, op)| *op).collect();
                if raw.pid <= 0 || ops.is_empty() {
                    continue;
                }
                let path = raw.fid.as_ref().and_then(|f| self.resolve(f));
                for op in ops {
                    events.push(Event {
                        timestamp: now,
                        pid: raw.pid as u32,
                        kind: EventKind::File { op, path: path.clone() },
                    });
                }
            }
        }
        Ok(events)
    }
}

#[derive(Debug, PartialEq, Eq)]
struct Fid {
    fsid: Fsid,
    /// Raw `struct file_handle`: handle_bytes, handle_type, f_handle[].
    handle: Vec<u8>,
    /// Name of the object inside the directory the handle refers to.
    name: Option<Vec<u8>>,
}

#[derive(Debug, PartialEq, Eq)]
struct RawEvent {
    mask: u64,
    fd: RawFd,
    pid: i32,
    fid: Option<Fid>,
}

fn u16_at(b: &[u8], i: usize) -> usize {
    u16::from_ne_bytes([b[i], b[i + 1]]) as usize
}
fn u32_at(b: &[u8], i: usize) -> u32 {
    u32::from_ne_bytes(b[i..i + 4].try_into().unwrap())
}

/// Decode `struct fanotify_event_metadata` records and their trailing info records.
fn parse_events(mut buf: &[u8]) -> Vec<RawEvent> {
    let mut out = Vec::new();
    while buf.len() >= 24 {
        let len = u32_at(buf, 0) as usize;
        let meta_len = u16_at(buf, 6);
        if buf[4] != META_VERSION || meta_len < 24 || len < meta_len || len > buf.len() {
            break;
        }
        let mut fid = None;
        let mut info = &buf[meta_len..len];
        while info.len() >= 4 {
            let rec_len = u16_at(info, 2);
            if rec_len < 4 || rec_len > info.len() {
                break;
            }
            let ty = info[0];
            if fid.is_none() && matches!(ty, INFO_DFID_NAME | INFO_OLD_DFID_NAME | INFO_NEW_DFID_NAME) {
                fid = parse_fid(&info[..rec_len]);
            }
            info = &info[rec_len..];
        }
        out.push(RawEvent {
            mask: u64::from_ne_bytes(buf[8..16].try_into().unwrap()),
            fd: u32_at(buf, 16) as i32,
            pid: u32_at(buf, 20) as i32,
            fid,
        });
        buf = &buf[len..];
    }
    out
}

/// Decode `struct fanotify_event_info_fid` followed by a NUL-terminated name.
fn parse_fid(rec: &[u8]) -> Option<Fid> {
    // header(4) fsid(8) | file_handle: handle_bytes(4) handle_type(4) f_handle[...]
    if rec.len() < 20 {
        return None;
    }
    let end = 20 + u32_at(rec, 12) as usize;
    let handle = rec.get(12..end)?.to_vec();
    let name = rec[end..].split(|&b| b == 0).next().filter(|n| !n.is_empty());
    Some(Fid {
        fsid: [u32_at(rec, 4) as i32, u32_at(rec, 8) as i32],
        handle,
        name: name.map(<[u8]>::to_vec),
    })
}

fn needs_root(e: io::Error) -> io::Error {
    if e.kind() == io::ErrorKind::PermissionDenied {
        io::Error::new(e.kind(), "fanotify needs root (CAP_SYS_ADMIN); run with sudo")
    } else {
        e
    }
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

/// The filesystem id of a mount point and a descriptor on it.
fn mount_handle(path: &str) -> io::Result<(Fsid, OwnedFd)> {
    let dir = File::open(path)?;
    // SAFETY: statfs writes into `st`; result checked.
    let mut st: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatfs(dir.as_raw_fd(), &mut st) } < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fsid_t is two C ints.
    let fsid = unsafe { std::mem::transmute::<libc::fsid_t, Fsid>(st.f_fsid) };
    Ok((fsid, dir.into()))
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

    fn info_record(handle: &[u8], name: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend(7i32.to_ne_bytes()); // fsid
        body.extend(9i32.to_ne_bytes());
        body.extend((handle.len() as u32 - 8).to_ne_bytes()); // handle_bytes
        body.extend(&handle[4..]); // handle_type + f_handle
        body.extend(name);
        body.push(0);
        let mut v = vec![INFO_DFID_NAME, 0];
        v.extend(((4 + body.len()) as u16).to_ne_bytes());
        v.extend(body);
        v
    }

    fn record(mask: u64, fd: i32, pid: i32, info: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend(((24 + info.len()) as u32).to_ne_bytes());
        v.push(META_VERSION);
        v.push(0);
        v.extend(24u16.to_ne_bytes());
        v.extend(mask.to_ne_bytes());
        v.extend(fd.to_ne_bytes());
        v.extend(pid.to_ne_bytes());
        v.extend(info);
        v
    }

    #[test]
    fn parses_records_with_fid_and_name() {
        // file_handle as the kernel lays it out: handle_bytes(4) handle_type(4) f_handle(4)
        let mut handle = Vec::new();
        handle.extend(4u32.to_ne_bytes());
        handle.extend(1i32.to_ne_bytes());
        handle.extend([0xAA, 0xBB, 0xCC, 0xDD]);

        let mut buf = record(libc::FAN_CREATE, -1, 42, &info_record(&handle, b"a.txt"));
        buf.extend(record(libc::FAN_OPEN | libc::FAN_ACCESS, -1, 7, &[]));

        let evs = parse_events(&buf);
        assert_eq!(evs.len(), 2);
        assert_eq!((evs[0].mask, evs[0].pid), (libc::FAN_CREATE, 42));
        let fid = evs[0].fid.as_ref().unwrap();
        assert_eq!(fid.fsid, [7, 9]);
        assert_eq!(fid.handle, handle);
        assert_eq!(fid.name.as_deref(), Some(&b"a.txt"[..]));
        assert_eq!((evs[1].pid, evs[1].fid.is_none()), (7, true));
        // Truncated record is dropped rather than misread.
        assert_eq!(parse_events(&buf[..buf.len() - 1]).len(), 1);
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
