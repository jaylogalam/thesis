//! Live ETW source: Microsoft-Windows-Kernel-File via ferrisetw. Windows only; needs Administrator.
//!
//! UNVERIFIED (written without a Windows toolchain): the ferrisetw API surface, the
//! event-id -> operation table, property names (`FileObject`, `FileName`, `IoSize`) and the
//! timestamp representation must be confirmed against the provider manifest and
//! docs.rs/ferrisetw in the Windows VM. The rest of the pipeline depends only on
//! `op_for_event_id` and the byte-count field.

use super::EventSource;
use crate::event::*;
use crate::normalize::{LowLevel, collapse_logical};
use anyhow::Result;
use chrono::{DateTime, Utc};
use ferrisetw::EventRecord;
use ferrisetw::parser::Parser;
use ferrisetw::provider::Provider;
use ferrisetw::schema_locator::SchemaLocator;
use ferrisetw::trace::{UserTrace, TraceTrait};
use std::collections::HashMap;
use std::sync::mpsc::{TrySendError, sync_channel};
use std::sync::{Arc, Mutex, atomic::{AtomicU64, Ordering}};
use std::time::{Duration, Instant};

const KERNEL_FILE_GUID: &str = "edd08927-9cc4-4e65-b970-c2560fb5c289";
const QUEUE_CAP: usize = 65536;

pub struct EtwSource {
    duration: Option<Duration>,
    stop: Arc<AtomicBool>,
    overflow: Arc<AtomicU64>,
}

impl EtwSource {
    pub fn new(duration: Option<Duration>, stop: Arc<AtomicBool>) -> Self { Self { duration, stop, overflow: Arc::default() } }
}

/// Event id -> (operation, bearsPath). unverified: confirm against the provider manifest.
fn op_for_event_id(id: u16) -> Option<(Operation, bool)> {
    Some(match id {
        12 => (Operation::Other, true),      // Create (open)
        30 => (Operation::Create, true),     // CreateNewFile
        15 => (Operation::Read, false),
        16 => (Operation::Write, false),
        11 | 18 => (Operation::Delete, false), // NameDelete / Delete (no path)
        26 => (Operation::Delete, true),     // DeletePath
        19 => (Operation::Rename, false),    // Rename (no path)
        27 => (Operation::Rename, true),     // RenamePath
        _ => return None,
    })
}

fn filetime_to_utc(ft: i64) -> DateTime<Utc> {
    DateTime::from_timestamp_micros((ft - 116_444_736_000_000_000) / 10).unwrap_or_default()
}

fn proc_start(sys: &mut sysinfo::System, pid: u32) -> Option<DateTime<Utc>> {
    let p = sysinfo::Pid::from_u32(pid);
    sys.refresh_processes(sysinfo::ProcessesToUpdate::Some(&[p]), true);
    let p = sys.process(p)?;
    DateTime::from_timestamp(p.start_time() as i64, 0)
}

impl EventSource for EtwSource {
    fn source_type(&self) -> &'static str { "etw-kernel-file/unverified" }

    fn source_counters(&self) -> (u64, u64) { (self.overflow.load(Ordering::Relaxed), 0) }

    fn capabilities(&self) -> serde_json::Value {
        serde_json::json!({
            "status": "unverified",
            "create_rename_delete": "observed per event; the pre-rename name is unavailable (rename counts once)",
            "bytes_written_total": "sum of IoSize on write events",
        })
    }

    fn run(&mut self, sink: &mut dyn FnMut(SourceSignal)) -> Result<()> {
        let (tx, rx) = sync_channel::<LowLevel>(QUEUE_CAP);
        let ov = self.overflow.clone();
        let names: Arc<Mutex<HashMap<u64, String>>> = Arc::default();
        let nm = names.clone();

        let provider = Provider::by_guid(KERNEL_FILE_GUID)
            .add_callback(move |rec: &EventRecord, loc: &SchemaLocator| {
                let Some((op, has_path)) = op_for_event_id(rec.event_id()) else { return };
                let Ok(schema) = loc.event_schema(rec) else { return };
                let p = Parser::create(rec, &schema);
                let obj: u64 = p.try_parse("FileObject").unwrap_or(0);
                let name: Option<String> = p.try_parse("FileName").ok();
                if let Some(n) = &name {
                    nm.lock().unwrap().insert(obj, n.clone());
                }
                let file_path = name.or_else(|| nm.lock().unwrap().get(&obj).cloned());
                let bytes: Option<u64> = if op == Operation::Write { p.try_parse::<u32>("IoSize").ok().map(u64::from) } else { None };
                let ev = RawEvent {
                    event_id: uuid::Uuid::new_v4().to_string(),
                    ts_utc: filetime_to_utc(rec.timestamp()),
                    pid: rec.process_id(),
                    proc_start_utc: None, // resolved on the consumer side
                    proc_name: None,
                    proc_path: None,
                    op,
                    file_path,
                    file_identity: (obj != 0).then(|| format!("fo:{obj}")),
                    bytes_written: bytes,
                    source_event_id: Some(rec.event_id().to_string()),
                    source_type: "etw-kernel-file/unverified".into(),
                    attribution: AttributionStatus::Attributed,
                    quality: EventQualityStatus::Valid,
                    multiplicity: 1,
                };
                match tx.try_send(LowLevel { key: obj, has_path, event: ev }) {
                    Err(TrySendError::Full(_)) => { ov.fetch_add(1, Ordering::Relaxed); }
                    _ => {}
                }
            })
            .build();

        let trace = UserTrace::new().named("runtime-monitor".into()).enable(provider).start_and_process()
            .map_err(|e| anyhow::anyhow!("failed to start ETW trace (run as Administrator?): {e:?}"))?;

        let mut sys = sysinfo::System::new();
        let mut starts: HashMap<u32, Option<DateTime<Utc>>> = HashMap::new();
        let deadline = self.duration.map(|d| Instant::now() + d);
        while !self.stop.load(Ordering::Relaxed) && deadline.is_none_or(|d| Instant::now() < d) {
            if let Ok(first) = rx.recv_timeout(Duration::from_millis(200)) {
                let mut batch = vec![first];
                while let Ok(l) = rx.try_recv() { batch.push(l); }
                for mut e in collapse_logical(batch) {
                    let st = *starts.entry(e.pid).or_insert_with(|| proc_start(&mut sys, e.pid));
                    e.proc_start_utc = st;
                    if st.is_none() {
                        e.attribution = AttributionStatus::Ambiguous;
                        e.quality = EventQualityStatus::Ambiguous;
                    }
                    if e.pid == 0 { e.attribution = AttributionStatus::Unattributed; }
                    sink(SourceSignal::File(e));
                }
            }
            sink(SourceSignal::Tick { ts: Utc::now() });
        }
        let _ = trace.stop();
        Ok(())
    }
}
