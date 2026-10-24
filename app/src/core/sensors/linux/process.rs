//! Process fork/exec/exit events from the kernel process connector (netlink).
//!
//! Needs no privileges on Linux >= 6.6 (root before that). A background thread
//! reads the connector and looks each process up in /proc right away, so most
//! short-lived processes are still seen with their parent and command line.

use std::collections::HashSet;
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{FromRawFd, OwnedFd};
use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver, Sender, TryRecvError};
use std::time::SystemTime;

use crate::core::sensors::Sensor;
use crate::core::event::{Event, EventKind};

// linux/connector.h and linux/cn_proc.h (not exported by the libc crate).
const CN_IDX_PROC: u32 = 1;
const CN_VAL_PROC: u32 = 1;
const PROC_CN_MCAST_LISTEN: u32 = 1;
const PROC_EVENT_NONE: u32 = 0; // reply to the subscription
const PROC_EVENT_FORK: u32 = 1;
const PROC_EVENT_EXEC: u32 = 2;
const PROC_EVENT_EXIT: u32 = 0x8000_0000;
/// nlmsghdr (16 bytes) + cn_msg (20 bytes): where `struct proc_event` starts.
const EVENT_AT: usize = 36;
/// `proc_event.event_data`, after what, cpu and timestamp_ns.
const DATA_AT: usize = EVENT_AT + 16;
const KTHREADD: u32 = 2;

pub struct ProcessSensor {
    rx: Receiver<io::Result<Event>>,
}

impl ProcessSensor {
    /// Subscribes before returning, so a missing permission is reported here.
    pub fn new() -> io::Result<Self> {
        let sock = subscribe()?;
        let (tx, rx) = mpsc::channel();
        std::thread::Builder::new().name("process-sensor".into()).spawn(move || run(sock, &tx))?;
        Ok(Self { rx })
    }
}

impl Sensor for ProcessSensor {
    fn poll(&mut self) -> io::Result<Vec<Event>> {
        let mut events = Vec::new();
        loop {
            match self.rx.try_recv() {
                Ok(ev) => events.push(ev?),
                Err(TryRecvError::Empty) => return Ok(events),
                Err(TryRecvError::Disconnected) => return Err(io::Error::other("process sensor stopped")),
            }
        }
    }
}

/// Reports running processes, then follows the connector until the receiver is dropped.
fn run(mut sock: File, tx: &Sender<io::Result<Event>>) {
    let send = |pid, kind| tx.send(Ok(Event { timestamp: SystemTime::now(), pid, kind })).is_ok();
    let mut known = HashSet::new();
    // Subscribed before this scan, so a process started meanwhile is not missed.
    let running = match scan() {
        Ok(r) => r,
        Err(e) => return drop(tx.send(Err(e))),
    };
    for (pid, stat) in running {
        known.insert(pid);
        if !send(pid, start_kind(pid, stat)) {
            return;
        }
    }

    let mut buf = [0u8; 4096];
    loop {
        let n = match sock.read(&mut buf) {
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            // ponytail: the socket buffer overflowed and events were lost (fork storm
            // outrunning the /proc lookups). eBPF would capture argv in the kernel instead.
            Err(e) if e.raw_os_error() == Some(libc::ENOBUFS) => continue,
            Err(e) => return drop(tx.send(Err(e))),
        };
        let (pid, kind) = match parse(&buf[..n]) {
            Some(Raw::Ack(0)) | None => continue,
            Some(Raw::Ack(err)) => return drop(tx.send(Err(needs_root(io::Error::from_raw_os_error(err))))),
            // Children of kthreadd are kernel threads, with no user-space behavior.
            Some(Raw::Fork { parent, child }) if parent != KTHREADD && known.insert(child) => {
                // Read now: a short-lived child may be gone a moment later.
                let mut stat = read_stat(child).unwrap_or_default();
                stat.ppid = parent;
                (child, start_kind(child, stat))
            }
            // Its fork was missed (started during the scan, or events were lost).
            Some(Raw::Exec(pid)) if known.insert(pid) => (pid, start_kind(pid, read_stat(pid).unwrap_or_default())),
            Some(Raw::Exec(pid)) => (
                pid,
                EventKind::ProcessExec {
                    name: read_stat(pid).map(|s| s.name).unwrap_or_default(),
                    exe: read_exe(pid),
                    cmdline: read_cmdline(pid),
                },
            ),
            Some(Raw::Exit(pid)) if known.remove(&pid) => (pid, EventKind::ProcessExit),
            Some(_) => continue,
        };
        if !send(pid, kind) {
            return;
        }
    }
}

fn subscribe() -> io::Result<File> {
    // SAFETY: plain syscall, result checked.
    let fd = unsafe {
        libc::socket(libc::AF_NETLINK, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, libc::NETLINK_CONNECTOR)
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fd is a fresh, valid descriptor we own.
    let mut sock = File::from(unsafe { OwnedFd::from_raw_fd(fd) });
    // SAFETY: all-zero is a valid sockaddr_nl.
    let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    addr.nl_family = libc::AF_NETLINK as libc::sa_family_t;
    addr.nl_groups = CN_IDX_PROC;
    // SAFETY: `addr` is a valid sockaddr_nl of the size passed.
    let r = unsafe {
        libc::bind(fd, (&raw const addr).cast(), size_of::<libc::sockaddr_nl>() as libc::socklen_t)
    };
    if r < 0 {
        return Err(needs_root(io::Error::last_os_error()));
    }
    // Unaddressed netlink writes go to the kernel.
    sock.write_all(&listen_msg())?;
    Ok(sock)
}

/// nlmsghdr + cn_msg + PROC_CN_MCAST_LISTEN.
fn listen_msg() -> [u8; 40] {
    let mut m = [0u8; 40];
    m[0..4].copy_from_slice(&40u32.to_ne_bytes()); // nlmsg_len
    m[4..6].copy_from_slice(&(libc::NLMSG_DONE as u16).to_ne_bytes()); // nlmsg_type
    m[16..20].copy_from_slice(&CN_IDX_PROC.to_ne_bytes()); // cn_msg.id.idx
    m[20..24].copy_from_slice(&CN_VAL_PROC.to_ne_bytes()); // cn_msg.id.val
    m[32..34].copy_from_slice(&4u16.to_ne_bytes()); // cn_msg.len
    m[36..40].copy_from_slice(&PROC_CN_MCAST_LISTEN.to_ne_bytes());
    m
}

fn needs_root(e: io::Error) -> io::Error {
    if e.kind() == io::ErrorKind::PermissionDenied {
        io::Error::new(e.kind(), "process events need root on Linux < 6.6; run with sudo")
    } else {
        e
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Raw {
    /// Subscription result: 0 or an errno.
    Ack(i32),
    Fork { parent: u32, child: u32 },
    Exec(u32),
    Exit(u32),
}

/// Decode one connector datagram. Thread events (not a whole process) are dropped.
fn parse(buf: &[u8]) -> Option<Raw> {
    let u32_at = |i: usize| buf.get(i..i + 4).map(|b| u32::from_ne_bytes(b.try_into().unwrap()));
    let data = |n: usize| u32_at(DATA_AT + 4 * n);
    if u32_at(16)? != CN_IDX_PROC {
        return None;
    }
    // Fork: parent_pid, parent_tgid, child_pid, child_tgid. Exec/exit: pid, tgid, ...
    match u32_at(EVENT_AT)? {
        PROC_EVENT_NONE => Some(Raw::Ack(data(0)? as i32)),
        PROC_EVENT_FORK => (data(2)? == data(3)?).then_some(Raw::Fork { parent: data(1)?, child: data(3)? }),
        PROC_EVENT_EXEC => (data(0)? == data(1)?).then_some(Raw::Exec(data(1)?)),
        PROC_EVENT_EXIT => (data(0)? == data(1)?).then_some(Raw::Exit(data(1)?)),
        _ => None,
    }
}

/// Every user-space process running now, parents before children.
fn scan() -> io::Result<Vec<(u32, Stat)>> {
    let mut procs = Vec::new();
    for entry in std::fs::read_dir("/proc")? {
        let Some(pid) = entry?.file_name().to_str().and_then(|s| s.parse::<u32>().ok()) else {
            continue;
        };
        // Gone already, or unreadable: treat as not running.
        let Some(stat) = read_stat(pid) else { continue };
        if pid != KTHREADD && stat.ppid != KTHREADD {
            procs.push((pid, stat));
        }
    }
    procs.sort_unstable_by_key(|(pid, s)| (s.start_ticks, *pid));
    Ok(procs)
}

/// A process that has already exited gets empty fields.
fn start_kind(pid: u32, stat: Stat) -> EventKind {
    EventKind::ProcessStart {
        name: stat.name,
        exe: read_exe(pid),
        start_ticks: stat.start_ticks,
        ppid: stat.ppid,
        cmdline: read_cmdline(pid),
    }
}

/// Needs ptrace access: None for other users' processes unless root.
fn read_exe(pid: u32) -> Option<PathBuf> {
    std::fs::read_link(format!("/proc/{pid}/exe")).ok()
}

fn read_cmdline(pid: u32) -> String {
    let raw = std::fs::read(format!("/proc/{pid}/cmdline")).unwrap_or_default();
    let args: Vec<_> = raw.split(|&b| b == 0).filter(|a| !a.is_empty()).map(String::from_utf8_lossy).collect();
    args.join(" ")
}

#[derive(Default)]
struct Stat {
    name: String,
    ppid: u32,
    start_ticks: u64,
}

fn read_stat(pid: u32) -> Option<Stat> {
    parse_stat(&std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?)
}

/// Parse `/proc/<pid>/stat`. The name is parenthesised and may itself contain
/// spaces or parentheses, so split on the last ')'.
fn parse_stat(text: &str) -> Option<Stat> {
    let open = text.find('(')?;
    let close = text.rfind(')')?;
    let rest: Vec<&str> = text.get(close + 1..)?.split_whitespace().collect();
    // rest[0] is field 3 (state); field n is rest[n - 3].
    Some(Stat {
        name: text.get(open + 1..close)?.to_string(),
        ppid: rest.get(1)?.parse().ok()?,
        start_ticks: rest.get(19)?.parse().ok()?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    #[test]
    fn parses_stat_with_awkward_name() {
        let text = "123 (my (weird) name) S 2 123 123 0 -1 4194560 0 0 0 0 0 0 0 0 20 0 1 0 98765 0 0";
        let s = parse_stat(text).unwrap();
        assert_eq!((s.name.as_str(), s.ppid, s.start_ticks), ("my (weird) name", 2, 98765));
    }

    fn datagram(what: u32, data: [u32; 4]) -> Vec<u8> {
        let mut v = listen_msg()[..EVENT_AT].to_vec();
        v.extend(what.to_ne_bytes());
        v.extend([0u8; 12]); // cpu, timestamp_ns
        data.iter().for_each(|d| v.extend(d.to_ne_bytes()));
        v
    }

    #[test]
    fn parses_process_events_and_drops_thread_events() {
        assert_eq!(parse(&datagram(PROC_EVENT_NONE, [1, 0, 0, 0])), Some(Raw::Ack(1)));
        assert_eq!(parse(&datagram(PROC_EVENT_FORK, [10, 10, 11, 11])), Some(Raw::Fork { parent: 10, child: 11 }));
        assert_eq!(parse(&datagram(PROC_EVENT_FORK, [10, 10, 12, 10])), None); // new thread
        assert_eq!(parse(&datagram(PROC_EVENT_EXEC, [11, 11, 0, 0])), Some(Raw::Exec(11)));
        assert_eq!(parse(&datagram(PROC_EVENT_EXIT, [11, 11, 0, 0])), Some(Raw::Exit(11)));
        assert_eq!(parse(&datagram(PROC_EVENT_EXIT, [12, 10, 0, 0])), None); // thread exit
        assert_eq!(parse(&datagram(PROC_EVENT_EXEC, [11, 11, 0, 0])[..DATA_AT + 4]), None); // truncated
    }

    /// Needs the process connector: Linux >= 6.6, or root.
    #[test]
    fn reports_running_then_fork_exec_exit() {
        let mut sensor = ProcessSensor::new().unwrap();
        let mut events = Vec::new();
        let mut until = |events: &mut Vec<Event>, done: &dyn Fn(&Event) -> bool| {
            let deadline = Instant::now() + Duration::from_secs(5);
            while !events.iter().any(done) {
                assert!(Instant::now() < deadline, "timed out: {events:#?}");
                events.extend(sensor.poll().unwrap());
                std::thread::sleep(Duration::from_millis(10));
            }
        };
        let me = std::process::id();
        let mut child = std::process::Command::new("sleep").arg("5").spawn().unwrap();
        let cpid = child.id();

        until(&mut events, &|e| e.pid == cpid && matches!(&e.kind, EventKind::ProcessExec { name, .. } if name == "sleep"));
        assert!(events.iter().any(|e| e.pid == me && matches!(e.kind, EventKind::ProcessStart { .. })));
        let start = events.iter().find(|e| e.pid == cpid).unwrap();
        assert!(matches!(start.kind, EventKind::ProcessStart { ppid, .. } if ppid == me), "{start:?}");
        let exec = events.iter().rfind(|e| e.pid == cpid).unwrap();
        assert!(matches!(&exec.kind, EventKind::ProcessExec { cmdline, .. } if cmdline == "sleep 5"), "{exec:?}");

        child.kill().unwrap();
        child.wait().unwrap();
        until(&mut events, &|e| e.pid == cpid && e.kind == EventKind::ProcessExit);
    }
}
