use super::SourceRecord;
use chrono::{DateTime, Duration, TimeZone, Utc};

pub const SCENARIOS: &[&str] = &["section8-example", "doc-editor", "mass-rewrite"];

fn t0() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 10, 11, 2, 0, 0).unwrap()
}

struct Gen {
    pid: u32,
    name: &'static str,
    start: DateTime<Utc>,
    recs: Vec<SourceRecord>,
    n: u64,
}

impl Gen {
    fn new(pid: u32, name: &'static str, observed_from: DateTime<Utc>) -> Self {
        let start = observed_from - Duration::seconds(60);
        let recs = vec![SourceRecord::ProcStart {
            ts: observed_from,
            pid,
            proc_start: Some(start),
            name: Some(name.into()),
            path: Some(format!("C:\\Program Files\\{name}")),
        }];
        Self { pid, name, start, recs, n: 0 }
    }
    fn file(&mut self, ts: DateTime<Utc>, file: usize, dirs: usize, op: &str, bytes: Option<u64>) {
        self.n += 1;
        self.recs.push(SourceRecord::File {
            ts,
            pid: self.pid,
            proc_start: Some(self.start),
            name: Some(self.name.into()),
            path: Some(format!("C:\\Users\\t\\dir{}\\file{}.docx", file % dirs, file)),
            file_id: None,
            op: op.into(),
            bytes,
            src_id: Some(format!("e{}", self.n)),
        });
    }
    fn exit(&mut self, ts: DateTime<Utc>) {
        self.recs.push(SourceRecord::ProcExit { ts, pid: self.pid, proc_start: Some(self.start) });
    }
}

/// §8 oracle: reads=90 writes=60 create=0 rename=45 delete=10, 100 files, 8 dirs,
/// 60 modified, bytes_written=1048576, in one window [02:00:00, 02:00:02).
fn section8() -> Vec<SourceRecord> {
    let mut g = Gen::new(4120, "example.exe", t0());
    let mut ops: Vec<(usize, &str, Option<u64>)> = Vec::new();
    for f in 60..100 { ops.push((f, "read", None)); }
    for f in 0..50 { ops.push((f, "read", None)); }
    for f in 0..60 { ops.push((f, "write", Some(if f == 59 { 17492 } else { 17476 }))); }
    for f in 0..45 { ops.push((f, "rename", None)); }
    for f in 45..55 { ops.push((f, "delete", None)); }
    for (i, (f, op, b)) in ops.into_iter().enumerate() {
        g.file(t0() + Duration::milliseconds(9 * i as i64), f, 8, op, b);
    }
    g.exit(t0() + Duration::seconds(2));
    g.recs
}

/// Benign: few writes to a handful of files over 2 windows, no renames/deletes.
fn doc_editor() -> Vec<SourceRecord> {
    let mut g = Gen::new(5000, "winword.exe", t0());
    for i in 0..12 { g.file(t0() + Duration::milliseconds(300 * i), (i % 4) as usize, 2, "read", None); }
    for i in 0..3 { g.file(t0() + Duration::milliseconds(2500 + 400 * i), i as usize, 2, "write", Some(4096)); }
    g.exit(t0() + Duration::seconds(4));
    g.recs
}

/// Ransomware-like: 3 windows, each rewriting 40 fresh files (read+write+rename+delete).
fn mass_rewrite() -> Vec<SourceRecord> {
    let mut g = Gen::new(6000, "evil.exe", t0());
    for w in 0..3usize {
        for k in 0..40usize {
            let f = w * 40 + k;
            let base = t0() + Duration::seconds(2 * w as i64) + Duration::milliseconds(45 * k as i64);
            g.file(base, f, 6, "read", None);
            g.file(base + Duration::milliseconds(10), f, 6, "write", Some(65536));
            g.file(base + Duration::milliseconds(20), f, 6, "rename", None);
            g.file(base + Duration::milliseconds(30), f, 6, "delete", None);
        }
    }
    g.exit(t0() + Duration::seconds(6));
    g.recs
}

pub fn scenario(name: &str) -> anyhow::Result<Vec<SourceRecord>> {
    match name {
        "section8-example" => Ok(section8()),
        "doc-editor" => Ok(doc_editor()),
        "mass-rewrite" => Ok(mass_rewrite()),
        _ => anyhow::bail!("unknown scenario '{name}'; available: {}", SCENARIOS.join(", ")),
    }
}
