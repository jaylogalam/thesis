
use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy)]
enum FileOperation {
    Create,
    Modify,
    Rename,
    Delete,
}

#[derive(Debug)]
struct FileEvent {
    pid: u32,
    process_name: String,
    path: String,
    operation: FileOperation,
    time: Instant,
}

#[derive(Default)]
struct Counts {
    create: usize,
    modify: usize,
    rename: usize,
    delete: usize,
}

impl Counts {
    fn record(&mut self, operation: FileOperation) {
        match operation {
            FileOperation::Create => self.create += 1,
            FileOperation::Modify => self.modify += 1,
            FileOperation::Rename => self.rename += 1,
            FileOperation::Delete => self.delete += 1,
        }
    }

    fn total(&self) -> usize {
        self.create + self.modify + self.rename + self.delete
    }
}

struct ProcessWindow {
    name: String,
    events: VecDeque<(Instant, FileOperation)>,
}

struct Monitor {
    window: Duration,
    threshold: usize,
    processes: HashMap<u32, ProcessWindow>,
}

impl Monitor {
    fn new(window_secs: u64, threshold: usize) -> Self {
        Self {
            window: Duration::from_secs(window_secs),
            threshold,
            processes: HashMap::new(),
        }
    }

    fn ingest(&mut self, event: FileEvent) {
        let now = event.time;
        let window = self.window;

        let process = self.processes
            .entry(event.pid)
            .or_insert_with(|| ProcessWindow {
                name: event.process_name.clone(),
                events: VecDeque::new(),
            });

        process.name.clone_from(&event.process_name);
        process.events.push_back((now, event.operation));

        // Remove events outside the sliding time window.
        while let Some((time, _)) = process.events.front() {
            if now.duration_since(*time) > window {
                process.events.pop_front();
            } else {
                break;
            }
        }

        let mut counts = Counts::default();

        for (_, operation) in &process.events {
            counts.record(*operation);
        }

        let total = counts.total();

        println!(
            "PID={} process={} path={} total={} create={} modify={} rename={} delete={}",
            event.pid,
            process.name,
            event.path,
            total,
            counts.create,
            counts.modify,
            counts.rename,
            counts.delete,
        );

        if total >= self.threshold {
            println!(
                "ALERT: {} (PID {}) performed {} file operations within {:?}",
                process.name, event.pid, total, self.window
            );
        }
    }
}

fn main() {
    let mut monitor = Monitor::new(5, 10);

    // Simulated events for testing. Replace these with real OS events.
    let now = Instant::now();

    for i in 0..12 {
        monitor.ingest(FileEvent {
            pid: 4242,
            process_name: "test-process".into(),
            path: format!("/tmp/test/file-{i}.txt"),
            operation: if i % 3 == 0 {
                FileOperation::Create
            } else {
                FileOperation::Modify
            },
            time: now + Duration::from_millis(i * 100),
        });
    }
}
