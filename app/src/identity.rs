use chrono::{DateTime, Utc};
use std::collections::HashMap;

/// Maps (pid, process start time) -> stable instance id. PID reuse with a
/// different start time yields a new instance. Missing start time yields a
/// distinct "unknown" instance flagged ambiguous; never merged with attributed ones.
#[derive(Default)]
pub struct ProcessRegistry {
    map: HashMap<(u32, Option<i64>), String>,
    next: u32,
}

impl ProcessRegistry {
    /// Returns (instance id, ambiguous).
    pub fn resolve(&mut self, pid: u32, start: Option<DateTime<Utc>>) -> (String, bool) {
        let key = (pid, start.map(|s| s.timestamp_micros()));
        let id = self.map.entry(key).or_insert_with(|| {
            self.next += 1;
            format!("proc-{:06}", self.next)
        });
        (id.clone(), start.is_none())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    #[test]
    fn pid_reuse_is_distinct() {
        let mut r = ProcessRegistry::default();
        let t1 = Utc.timestamp_opt(100, 0).unwrap();
        let t2 = Utc.timestamp_opt(200, 0).unwrap();
        let (a, _) = r.resolve(7, Some(t1));
        let (b, _) = r.resolve(7, Some(t2));
        let (a2, _) = r.resolve(7, Some(t1));
        let (u, amb) = r.resolve(7, None);
        assert_ne!(a, b);
        assert_eq!(a, a2);
        assert!(amb && u != a && u != b);
    }
}
