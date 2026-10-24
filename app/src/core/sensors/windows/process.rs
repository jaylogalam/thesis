//! Process start/exit events read from the Sysmon event log
//! (`Microsoft-Windows-Sysmon/Operational`: Event ID 1 process create, 5 process terminate).
//! Sysmon must be installed and logging both; the log needs Administrator or
//! Event Log Readers membership. Unlike a snapshot poll, it reports every process
//! with its command line and parent image, including short-lived ones.

use std::path::PathBuf;
use std::time::SystemTime;

use crate::core::event::{Event, EventKind};

/// A Sysmon event reduced to the fields the sensor uses.
#[derive(Debug, PartialEq, Eq)]
#[cfg_attr(not(windows), allow(dead_code))]
pub enum Sysmon {
    Create { pid: u32, ppid: u32, image: String, parent_image: Option<String>, cmdline: String, utc_time: String },
    Terminate { pid: u32 },
}

/// Parse the rendered XML of an Event ID 1 or 5; None for any other event or malformed XML.
#[cfg_attr(not(windows), allow(dead_code))]
pub fn parse(xml: &str) -> Option<Sysmon> {
    let id = {
        let rest = &xml[xml.find("<EventID")?..];
        let rest = &rest[rest.find('>')? + 1..];
        &rest[..rest.find('<')?]
    };
    let fields = data_fields(xml);
    let field = |name: &str| fields.iter().find(|(n, _)| *n == name).map(|(_, v)| unescape(v));
    let number = |name: &str| field(name)?.trim().parse::<u32>().ok();
    match id.trim() {
        "1" => Some(Sysmon::Create {
            pid: number("ProcessId")?,
            ppid: number("ParentProcessId")?,
            image: field("Image")?,
            parent_image: field("ParentImage").filter(|p| !p.is_empty() && p != "-"),
            cmdline: field("CommandLine")?,
            utc_time: field("UtcTime")?,
        }),
        "5" => Some(Sysmon::Terminate { pid: number("ProcessId")? }),
        _ => None,
    }
}

/// `(name, raw value)` of every `<Data Name='X'>value</Data>`; `<Data Name='X' />` is empty.
/// Windows renders attributes with single quotes, but either quote is accepted.
fn data_fields(xml: &str) -> Vec<(&str, &str)> {
    const OPEN: &str = "<Data Name=";
    let mut out = Vec::new();
    let mut rest = xml;
    while let Some(i) = rest.find(OPEN) {
        rest = &rest[i + OPEN.len()..];
        let Some(q) = rest.chars().next().filter(|c| matches!(c, '\'' | '"')) else { continue };
        let Some(end) = rest[1..].find(q) else { break };
        let name = &rest[1..1 + end];
        rest = &rest[end + 2..];
        let Some(gt) = rest.find('>') else { break };
        if rest[..gt].ends_with('/') {
            out.push((name, ""));
            rest = &rest[gt + 1..];
        } else {
            let body = &rest[gt + 1..];
            let Some(close) = body.find("</Data>") else { break };
            out.push((name, &body[..close]));
            rest = &body[close..];
        }
    }
    out
}

/// `&amp;` last, so `&amp;lt;` becomes the text `&lt;`.
fn unescape(s: &str) -> String {
    s.replace("&lt;", "<").replace("&gt;", ">").replace("&quot;", "\"").replace("&apos;", "'").replace("&amp;", "&")
}

/// Seconds between 1601-01-01 (FILETIME epoch) and 1970-01-01, in microseconds.
const FILETIME_UNIX_EPOCH_MICROS: u64 = 11_644_473_600_000_000;

/// FILETIME ticks (100 ns since 1601) of a Sysmon `UtcTime`; 0 if unparsable.
fn filetime_ticks(utc_time: &str) -> u64 {
    chrono::NaiveDateTime::parse_from_str(utc_time, "%Y-%m-%d %H:%M:%S%.f")
        .ok()
        .and_then(|t| u64::try_from(t.and_utc().timestamp_micros()).ok())
        .map_or(0, |micros| (micros + FILETIME_UNIX_EPOCH_MICROS) * 10)
}

/// `now` is when the sensor observed the event, as in every other sensor.
#[cfg_attr(not(windows), allow(dead_code))]
pub fn to_events(s: Sysmon, now: SystemTime) -> Event {
    match s {
        Sysmon::Create { pid, ppid, image, parent_image, cmdline, utc_time } => {
            let name = image.rsplit(['\\', '/']).next().unwrap_or(&image).to_string();
            let kind = EventKind::ProcessStart {
                name,
                start_ticks: filetime_ticks(&utc_time),
                ppid,
                parent_exe: parent_image.map(PathBuf::from),
                exe: Some(PathBuf::from(image)),
                cmdline,
            };
            Event { timestamp: now, pid, kind }
        }
        Sysmon::Terminate { pid } => Event { timestamp: now, pid, kind: EventKind::ProcessExit },
    }
}

#[cfg(windows)]
pub use sensor::ProcessSensor;

#[cfg(windows)]
mod sensor {
    use std::ffi::c_void;
    use std::io;
    use std::ptr::null_mut;
    use std::sync::mpsc::{self, Receiver, Sender};
    use std::time::SystemTime;

    use windows_sys::Win32::System::EventLog::{
        EVT_HANDLE, EvtClose, EvtRender, EvtRenderEventXml, EvtSubscribe, EvtSubscribeActionDeliver,
        EvtSubscribeToFutureEvents,
    };

    use super::{parse, to_events};
    use crate::core::event::Event;
    use crate::core::sensors::Sensor;

    const CHANNEL: &str = "Microsoft-Windows-Sysmon/Operational";
    const QUERY: &str = "*[System[(EventID=1 or EventID=5)]]";
    const ERROR_ACCESS_DENIED: i32 = 5;
    const ERROR_EVT_CHANNEL_NOT_FOUND: i32 = 15007;

    type Item = io::Result<Event>;

    /// Subscribes to future Sysmon events; processes already running at start are not reported.
    pub struct ProcessSensor {
        sub: EVT_HANDLE,
        /// Leaked `Sender` owned by the callback; freed in `Drop` after the subscription is closed.
        ctx: *mut Sender<Item>,
        rx: Receiver<Item>,
    }

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(Some(0)).collect()
    }

    impl ProcessSensor {
        pub fn new() -> io::Result<Self> {
            let (tx, rx) = mpsc::channel();
            let ctx = Box::into_raw(Box::new(tx));
            let (channel, query) = (wide(CHANNEL), wide(QUERY));
            // SAFETY: both strings are NUL-terminated and outlive the call; `ctx` stays
            // valid until `Drop` has closed the subscription.
            let sub = unsafe {
                EvtSubscribe(
                    0,
                    null_mut(),
                    channel.as_ptr(),
                    query.as_ptr(),
                    0,
                    ctx as *const c_void,
                    Some(callback),
                    EvtSubscribeToFutureEvents,
                )
            };
            if sub == 0 {
                let err = io::Error::last_os_error();
                // SAFETY: no subscription exists, so nothing else holds `ctx`.
                drop(unsafe { Box::from_raw(ctx) });
                return Err(subscribe_error(err));
            }
            Ok(Self { sub, ctx, rx })
        }
    }

    fn subscribe_error(err: io::Error) -> io::Error {
        match err.raw_os_error() {
            Some(ERROR_EVT_CHANNEL_NOT_FOUND) => io::Error::new(
                io::ErrorKind::NotFound,
                "Sysmon is not installed (log 'Microsoft-Windows-Sysmon/Operational' not found); \
                 install it with: Sysmon64.exe -accepteula -i <config>",
            ),
            Some(ERROR_ACCESS_DENIED) => io::Error::new(
                io::ErrorKind::PermissionDenied,
                "reading the Sysmon log needs Administrator or Event Log Readers membership; \
                 run from an elevated terminal",
            ),
            _ => err,
        }
    }

    /// Runs on a thread of the Windows thread pool.
    unsafe extern "system" fn callback(action: i32, ctx: *const c_void, event: EVT_HANDLE) -> u32 {
        // SAFETY: `ctx` is the `Sender` leaked in `new`, alive until `EvtClose` in `Drop` returns.
        let tx = unsafe { &*(ctx as *const Sender<Item>) };
        let item = if action == EvtSubscribeActionDeliver {
            // SAFETY: `event` is valid for the duration of the callback.
            unsafe { render(event) }.and_then(|xml| parse(&xml)).map(|s| Ok(to_events(s, SystemTime::now())))
        } else {
            // Not a delivery: `event` carries the Win32 error code.
            Some(Err(io::Error::from_raw_os_error(event as i32)))
        };
        if let Some(item) = item {
            // The receiver is gone only while the app shuts down.
            let _ = tx.send(item);
        }
        0
    }

    /// The event as XML text.
    unsafe fn render(event: EVT_HANDLE) -> Option<String> {
        let (mut used, mut props) = (0u32, 0u32);
        // SAFETY: a zero-size buffer only asks for the required size.
        unsafe { EvtRender(0, event, EvtRenderEventXml, 0, null_mut(), &mut used, &mut props) };
        if used == 0 {
            return None;
        }
        let mut buf = vec![0u16; (used as usize).div_ceil(2)];
        // SAFETY: `buf` holds `buf.len() * 2` bytes.
        let ok = unsafe {
            EvtRender(0, event, EvtRenderEventXml, (buf.len() * 2) as u32, buf.as_mut_ptr().cast(), &mut used, &mut props)
        };
        if ok == 0 {
            return None;
        }
        let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
        Some(String::from_utf16_lossy(&buf[..end]))
    }

    impl Sensor for ProcessSensor {
        fn poll(&mut self) -> io::Result<Vec<Event>> {
            self.rx.try_iter().collect()
        }
    }

    impl Drop for ProcessSensor {
        fn drop(&mut self) {
            // SAFETY: closing waits for in-flight callbacks, after which `ctx` is unused.
            unsafe {
                EvtClose(self.sub);
                drop(Box::from_raw(self.ctx));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_xml(utc: &str, parent: &str) -> String {
        format!(
            "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>\
             <EventID>1</EventID><Channel>Microsoft-Windows-Sysmon/Operational</Channel></System>\
             <EventData>\
             <Data Name='RuleName'>-</Data>\
             <Data Name='UtcTime'>{utc}</Data>\
             <Data Name='ProcessId'>4242</Data>\
             <Data Name='Image'>C:\\Windows\\System32\\cmd.exe</Data>\
             <Data Name='CommandLine'>cmd.exe /c echo &quot;a&quot; &amp;&amp; dir</Data>\
             <Data Name='CurrentDirectory' />\
             <Data Name='ParentProcessId'>1000</Data>\
             <Data Name='ParentImage'>{parent}</Data>\
             </EventData></Event>"
        )
    }

    const WORD: &str = "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE";

    #[test]
    fn parses_process_create_and_maps_it_to_an_event() {
        let Some(Sysmon::Create { pid, ppid, image, parent_image, cmdline, utc_time }) =
            parse(&create_xml("2026-10-24 08:12:33.123", WORD))
        else {
            panic!("not a create")
        };
        assert_eq!((pid, ppid), (4242, 1000));
        assert_eq!(image, "C:\\Windows\\System32\\cmd.exe");
        assert_eq!(parent_image.as_deref(), Some(WORD));
        assert_eq!(cmdline, "cmd.exe /c echo \"a\" && dir");
        assert_eq!(utc_time, "2026-10-24 08:12:33.123");

        let now = SystemTime::now();
        let ev = to_events(parse(&create_xml("2026-10-24 08:12:33.123", WORD)).unwrap(), now);
        assert_eq!((ev.pid, ev.timestamp), (4242, now));
        let EventKind::ProcessStart { name, exe, start_ticks, ppid, parent_exe, cmdline } = ev.kind else { panic!() };
        assert_eq!((name.as_str(), ppid), ("cmd.exe", 1000));
        assert_eq!(exe, Some(PathBuf::from("C:\\Windows\\System32\\cmd.exe")));
        assert_eq!(parent_exe, Some(PathBuf::from(WORD)));
        assert_eq!(cmdline, "cmd.exe /c echo \"a\" && dir");

        let later = to_events(parse(&create_xml("2026-10-24 08:12:33.124", WORD)).unwrap(), now);
        let EventKind::ProcessStart { start_ticks: later_ticks, .. } = later.kind else { panic!() };
        assert_eq!(later_ticks - start_ticks, 10_000);
    }

    #[test]
    fn start_ticks_count_from_1601() {
        assert_eq!(filetime_ticks("1970-01-01 00:00:00.000"), 116_444_736_000_000_000);
        assert_eq!(filetime_ticks("not a time"), 0);
    }

    #[test]
    fn dash_parent_is_unknown() {
        let Some(Sysmon::Create { parent_image, .. }) = parse(&create_xml("2026-10-24 08:12:33.123", "-")) else {
            panic!()
        };
        assert_eq!(parent_image, None);
    }

    #[test]
    fn parses_process_terminate() {
        let xml = "<Event><System><EventID>5</EventID></System><EventData>\
                   <Data Name=\"UtcTime\">2026-10-24 08:12:34.000</Data>\
                   <Data Name=\"ProcessId\">4242</Data>\
                   <Data Name=\"Image\">C:\\Windows\\System32\\cmd.exe</Data></EventData></Event>";
        let s = parse(xml).unwrap();
        assert_eq!(s, Sysmon::Terminate { pid: 4242 });
        assert!(matches!(to_events(s, SystemTime::now()).kind, EventKind::ProcessExit));
    }

    #[test]
    fn ignores_other_events_and_garbage() {
        let net = "<Event><System><EventID>3</EventID></System><EventData>\
                   <Data Name='ProcessId'>1</Data></EventData></Event>";
        assert_eq!(parse(net), None);
        assert_eq!(parse("<Event><System><EventID>1</Event"), None);
        assert_eq!(parse(&create_xml("x", WORD)[..200]), None);
        assert_eq!(parse("garbage"), None);
        assert_eq!(parse(""), None);
    }
}
