use crate::event::*;
use crate::source::SourceRecord;
use std::collections::HashMap;

/// Explicit op-string table. File *open* is `Other`, never `Read`.
pub fn map_op(s: &str) -> Operation {
    match s.to_ascii_lowercase().as_str() {
        "read" => Operation::Read,
        "write" => Operation::Write,
        "create" => Operation::Create,
        "rename" => Operation::Rename,
        "delete" => Operation::Delete,
        "open" | "other" => Operation::Other,
        _ => Operation::Unknown,
    }
}

pub fn from_record(rec: SourceRecord, source_type: &str) -> SourceSignal {
    match rec {
        SourceRecord::File { ts, pid, proc_start, name, path, file_id, op, bytes, src_id } => {
            let (attribution, quality) = if pid == 0 {
                (AttributionStatus::Unattributed, EventQualityStatus::Incomplete)
            } else if proc_start.is_none() {
                (AttributionStatus::Ambiguous, EventQualityStatus::Ambiguous)
            } else {
                (AttributionStatus::Attributed, EventQualityStatus::Valid)
            };
            SourceSignal::File(RawEvent {
                event_id: uuid::Uuid::new_v4().to_string(),
                ts_utc: ts,
                pid,
                proc_start_utc: proc_start,
                proc_name: name,
                proc_path: None,
                op: map_op(&op),
                file_path: path,
                file_identity: file_id,
                bytes_written: bytes,
                source_event_id: src_id,
                source_type: source_type.to_string(),
                attribution,
                quality,
                multiplicity: 1,
            })
        }
        SourceRecord::ProcStart { ts, pid, proc_start, name, path } => {
            SourceSignal::ProcStart { pid, proc_start_utc: proc_start, name, path, ts }
        }
        SourceRecord::ProcExit { ts, pid, proc_start } => SourceSignal::ProcExit { pid, proc_start_utc: proc_start, ts },
        SourceRecord::Gap { ts } => SourceSignal::Gap { ts },
        SourceRecord::Tick { ts } => SourceSignal::Tick { ts },
    }
}

/// A low-level source event with a correlation key (e.g. ETW file object).
#[cfg_attr(not(windows), allow(dead_code))]
pub struct LowLevel {
    pub key: u64,
    pub has_path: bool,
    pub event: RawEvent,
}

/// Collapse rename/delete events a source reports as several low-level records
/// (ETW Rename+RenamePath, NameDelete+DeletePath) into ONE logical op per
/// (key, op) within the batch, keeping the path-bearing variant.
/// ETW rename carries no old name, so a rename counts once and the old path is unavailable.
#[cfg_attr(not(windows), allow(dead_code))]
pub fn collapse_logical(batch: Vec<LowLevel>) -> Vec<RawEvent> {
    let mut out: Vec<(bool, RawEvent)> = Vec::new();
    let mut idx: HashMap<(u64, Operation), usize> = HashMap::new();
    for l in batch {
        if matches!(l.event.op, Operation::Rename | Operation::Delete) {
            match idx.get(&(l.key, l.event.op)) {
                Some(&i) => {
                    if l.has_path && !out[i].0 {
                        out[i] = (true, l.event);
                    }
                }
                None => {
                    idx.insert((l.key, l.event.op), out.len());
                    out.push((l.has_path, l.event));
                }
            }
        } else {
            out.push((l.has_path, l.event));
        }
    }
    out.into_iter().map(|(_, e)| e).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn ev(op: Operation, path: Option<&str>) -> RawEvent {
        RawEvent {
            event_id: String::new(), ts_utc: Utc::now(), pid: 1, proc_start_utc: None, proc_name: None, proc_path: None,
            op, file_path: path.map(String::from), file_identity: None, bytes_written: None, source_event_id: None,
            source_type: "t".into(), attribution: AttributionStatus::Attributed, quality: EventQualityStatus::Valid,
            multiplicity: 1,
        }
    }

    #[test]
    fn open_is_not_read() {
        assert_eq!(map_op("open"), Operation::Other);
        assert_eq!(map_op("bogus"), Operation::Unknown);
    }

    #[test]
    fn rename_pair_collapses_keeping_path() {
        let b = vec![
            LowLevel { key: 1, has_path: false, event: ev(Operation::Rename, None) },
            LowLevel { key: 1, has_path: true, event: ev(Operation::Rename, Some("a")) },
            LowLevel { key: 2, has_path: true, event: ev(Operation::Rename, Some("b")) },
            LowLevel { key: 1, has_path: true, event: ev(Operation::Write, Some("a")) },
        ];
        let o = collapse_logical(b);
        assert_eq!(o.len(), 3);
        assert_eq!(o[0].file_path.as_deref(), Some("a"));
    }
}
