use super::{EventSource, SourceRecord};
use crate::{event::SourceSignal, normalize};
use anyhow::Context;
use std::{fs::File, io::{BufRead, BufReader}, path::PathBuf};

pub struct ReplaySource {
    pub path: PathBuf,
}

impl EventSource for ReplaySource {
    fn source_type(&self) -> &'static str { "replay-jsonl" }
    fn run(&mut self, sink: &mut dyn FnMut(SourceSignal)) -> anyhow::Result<()> {
        let f = File::open(&self.path).with_context(|| format!("open {}", self.path.display()))?;
        let mut recs = Vec::new();
        for (i, line) in BufReader::new(f).lines().enumerate() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            let r: SourceRecord = serde_json::from_str(&line).with_context(|| format!("line {}", i + 1))?;
            recs.push(r);
        }
        // ponytail: whole-file stable sort, O(n) memory; upgrade to external merge if replay files exceed RAM.
        recs.sort_by_key(|r| r.ts());
        for r in recs {
            sink(normalize::from_record(r, "replay-jsonl"));
        }
        Ok(())
    }
}
