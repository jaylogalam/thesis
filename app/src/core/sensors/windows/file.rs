//! File activity events for Windows, from the Microsoft-Windows-Kernel-File
//! ETW provider. Needs Administrator rights (starting a real-time ETW session).
//!
//! Directory events are not reported. Paths come as NT device paths
//! (`\Device\HarddiskVolume3\x`) and are rewritten to drive letters.

use std::collections::HashMap;
use std::path::PathBuf;

use crate::core::event::FileOp;

// Event ids of Microsoft-Windows-Kernel-File.
/// An open (or create) request; the only event that carries the file name of a file object.
const CREATE: u16 = 12;
const READ: u16 = 15;
const WRITE: u16 = 16;
const DELETE_PATH: u16 = 26;
/// `FilePath` is the file being renamed, i.e. the old location (as on Linux).
const RENAME_PATH: u16 = 27;
/// Emitted in addition to `CREATE` when a file is really created.
const CREATE_NEW_FILE: u16 = 30;

/// Keyword mask enabling only the events above: CREATE | READ | WRITE |
/// DELETE_PATH | RENAME_SETLINK_PATH | CREATE_NEW_FILE.
// Close (id 14) would let us forget file objects, but it needs the FILEIO keyword,
// which turns on every other file event too.
#[cfg_attr(not(windows), allow(dead_code))]
const KEYWORDS: u64 = 0x80 | 0x100 | 0x200 | 0x400 | 0x800 | 0x1000;

/// File objects remembered before the table is dropped.
const NAMES_MAX: usize = 1 << 16;

/// The parts of an ETW record the tracker needs.
pub struct Record {
    pub id: u16,
    pub file_object: usize,
    /// `FileName` (create) or `FilePath` (delete, rename): an NT path.
    pub path: Option<String>,
}

/// Turns Kernel-File records into `(op, path)`. Reads and writes only carry a
/// file object, so names are remembered from the create that opened it.
// ponytail: a file opened before the trace started, or evicted when the table is
// dropped at NAMES_MAX, shows up with no path. Close events would avoid the drop.
pub struct Tracker {
    /// `(drive, NT device)` pairs, e.g. `("C:", "\Device\HarddiskVolume3")`.
    drives: Vec<(String, String)>,
    names: HashMap<usize, PathBuf>,
}

impl Tracker {
    pub fn new(drives: Vec<(String, String)>) -> Self {
        Self { drives, names: HashMap::new() }
    }

    pub fn on_record(&mut self, r: Record) -> Option<(FileOp, Option<PathBuf>)> {
        let path = r.path.as_deref().map(|p| to_dos(p, &self.drives));
        match r.id {
            CREATE | CREATE_NEW_FILE => {
                if let Some(p) = &path {
                    if self.names.len() >= NAMES_MAX {
                        self.names.clear();
                    }
                    self.names.insert(r.file_object, p.clone());
                }
                Some((if r.id == CREATE { FileOp::Open } else { FileOp::Create }, path))
            }
            READ => Some((FileOp::Read, self.names.get(&r.file_object).cloned())),
            WRITE => Some((FileOp::Write, self.names.get(&r.file_object).cloned())),
            DELETE_PATH => Some((FileOp::Delete, path)),
            RENAME_PATH => Some((FileOp::Rename, path)),
            _ => None,
        }
    }
}

/// Replace a leading NT device (`\Device\HarddiskVolume3`) with its drive letter.
/// Paths on unknown devices are kept as they are.
fn to_dos(nt: &str, drives: &[(String, String)]) -> PathBuf {
    for (letter, device) in drives {
        if let Some(rest) = nt.strip_prefix(device.as_str())
            && (rest.is_empty() || rest.starts_with('\\'))
        {
            return PathBuf::from(format!("{letter}{rest}"));
        }
    }
    PathBuf::from(nt)
}

#[cfg(windows)]
pub use sensor::FileSensor;

#[cfg(windows)]
mod sensor {
    use std::io;
    use std::sync::mpsc::{self, Receiver};
    use std::time::SystemTime;

    use ferrisetw::parser::{Parser, Pointer};
    use ferrisetw::provider::Provider;
    use ferrisetw::trace::{TraceError, UserTrace};
    use ferrisetw::{EventRecord, SchemaLocator};
    use windows_sys::Win32::Storage::FileSystem::QueryDosDeviceW;

    use super::{Record, Tracker, CREATE, CREATE_NEW_FILE, DELETE_PATH, KEYWORDS, READ, RENAME_PATH, WRITE};
    use crate::core::event::{Event, EventKind};
    use crate::core::sensors::Sensor;

    const KERNEL_FILE: &str = "edd08927-9cc4-4e65-b970-c2560fb5c289";
    const SESSION: &str = "app-file-sensor";

    pub struct FileSensor {
        rx: Receiver<Event>,
        /// Dropping the trace stops the ETW session.
        _trace: UserTrace,
    }

    impl FileSensor {
        pub fn new() -> io::Result<Self> {
            let (tx, rx) = mpsc::channel();
            let mut tracker = Tracker::new(dos_drives());
            let provider = Provider::by_guid(KERNEL_FILE)
                .any(KEYWORDS)
                .add_callback(move |record: &EventRecord, locator: &SchemaLocator| {
                    let id = record.event_id();
                    if !matches!(id, CREATE | READ | WRITE | DELETE_PATH | RENAME_PATH | CREATE_NEW_FILE) {
                        return;
                    }
                    let Ok(schema) = locator.event_schema(record) else { return };
                    let parser = Parser::create(record, &schema);
                    let file_object = parser.try_parse::<Pointer>("FileObject").map_or(0, |p| *p);
                    let path = parser
                        .try_parse::<String>("FileName")
                        .or_else(|_| parser.try_parse::<String>("FilePath"))
                        .ok();
                    if let Some((op, path)) = tracker.on_record(Record { id, file_object, path }) {
                        let ev = Event {
                            timestamp: SystemTime::now(),
                            pid: record.process_id(),
                            kind: EventKind::File { op, path },
                        };
                        // The receiver is gone only while the app shuts down.
                        let _ = tx.send(ev);
                    }
                })
                .build();
            let trace = UserTrace::new()
                .named(SESSION.into())
                .enable(provider)
                .start_and_process()
                .map_err(trace_error)?;
            Ok(Self { rx, _trace: trace })
        }
    }

    impl Sensor for FileSensor {
        fn poll(&mut self) -> io::Result<Vec<Event>> {
            Ok(self.rx.try_iter().collect())
        }
    }

    fn trace_error(e: TraceError) -> io::Error {
        use ferrisetw::native::EvntraceNativeError as E;
        match e {
            TraceError::EtwNativeError(E::IoError(e)) if e.kind() == io::ErrorKind::PermissionDenied => {
                io::Error::new(e.kind(), "ETW needs Administrator rights; run from an elevated terminal")
            }
            TraceError::EtwNativeError(E::IoError(e)) => e,
            TraceError::EtwNativeError(E::AlreadyExist) => io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("ETW session '{SESSION}' already exists (another instance, or a crashed one); stop it with: logman stop {SESSION} -ets"),
            ),
            other => io::Error::other(format!("{other:?}")),
        }
    }

    /// `(drive, NT device)` for every drive letter that exists.
    // ponytail: drives mounted after start-up keep their NT path.
    fn dos_drives() -> Vec<(String, String)> {
        (b'A'..=b'Z')
            .filter_map(|c| {
                let drive = format!("{}:", c as char);
                let wide: Vec<u16> = drive.encode_utf16().chain([0]).collect();
                let mut buf = [0u16; 512];
                // SAFETY: `wide` is NUL-terminated and `buf` is valid for `buf.len()` u16s.
                let n = unsafe { QueryDosDeviceW(wide.as_ptr(), buf.as_mut_ptr(), buf.len() as u32) };
                if n == 0 {
                    return None;
                }
                // The result is a list of NUL-separated strings; the first is the device.
                let end = buf.iter().position(|&c| c == 0).unwrap_or(0);
                Some((drive, String::from_utf16_lossy(&buf[..end])))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn drives() -> Vec<(String, String)> {
        vec![("C:".into(), r"\Device\HarddiskVolume3".into()), ("D:".into(), r"\Device\HarddiskVolume30".into())]
    }
    fn rec(id: u16, file_object: usize, path: Option<&str>) -> Record {
        Record { id, file_object, path: path.map(Into::into) }
    }

    #[test]
    fn rewrites_nt_paths_to_drive_letters() {
        let d = drives();
        assert_eq!(to_dos(r"\Device\HarddiskVolume3\Users\a.txt", &d), PathBuf::from(r"C:\Users\a.txt"));
        // Volume30 must not match the Volume3 prefix.
        assert_eq!(to_dos(r"\Device\HarddiskVolume30\x", &d), PathBuf::from(r"D:\x"));
        assert_eq!(to_dos(r"\Device\NamedPipe\p", &d), PathBuf::from(r"\Device\NamedPipe\p"));
    }

    #[test]
    fn reads_and_writes_use_the_name_from_the_create() {
        let mut t = Tracker::new(drives());
        let file = Some(PathBuf::from(r"C:\a"));
        assert_eq!(t.on_record(rec(READ, 7, None)), Some((FileOp::Read, None))); // never opened
        assert_eq!(t.on_record(rec(CREATE, 7, Some(r"\Device\HarddiskVolume3\a"))), Some((FileOp::Open, file.clone())));
        assert_eq!(t.on_record(rec(READ, 7, None)), Some((FileOp::Read, file.clone())));
        assert_eq!(t.on_record(rec(WRITE, 7, None)), Some((FileOp::Write, file.clone())));
        // The file object is reused for another file.
        t.on_record(rec(CREATE_NEW_FILE, 7, Some(r"\Device\HarddiskVolume3\b")));
        assert_eq!(t.on_record(rec(WRITE, 7, None)), Some((FileOp::Write, Some(PathBuf::from(r"C:\b")))));
    }

    #[test]
    fn maps_new_file_delete_and_rename() {
        let mut t = Tracker::new(drives());
        let p = Some(r"\Device\HarddiskVolume3\a");
        let dos = Some(PathBuf::from(r"C:\a"));
        assert_eq!(t.on_record(rec(CREATE_NEW_FILE, 1, p)), Some((FileOp::Create, dos.clone())));
        assert_eq!(t.on_record(rec(DELETE_PATH, 2, p)), Some((FileOp::Delete, dos.clone())));
        assert_eq!(t.on_record(rec(RENAME_PATH, 3, p)), Some((FileOp::Rename, dos)));
        assert_eq!(t.on_record(rec(14, 1, None)), None);
    }
}
