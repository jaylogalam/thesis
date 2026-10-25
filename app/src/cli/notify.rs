//! Desktop notification for a LEDA detection: `notify-send` on Linux (the
//! session's notification daemon), a PowerShell toast on Windows. Neither adds
//! a dependency. Delivery is best effort: a missing tool or daemon never
//! affects detection.

use std::time::{Duration, Instant};

use crate::core::detection::Detection;

/// At most one notification per interval; the ones held back are counted in the next.
const MIN_INTERVAL: Duration = Duration::from_secs(5);
/// Command lines are attacker-controlled and unbounded.
const CMDLINE_MAX: usize = 200;

#[derive(Default)]
pub struct Notifier {
    last: Option<Instant>,
    held_back: u32,
}

impl Notifier {
    pub fn notify(&mut self, d: &Detection) {
        if let Some((title, body)) = self.message(d, Instant::now()) {
            // A thread per notification (bounded by the rate limit) reaps the child.
            std::thread::spawn(move || send(&title, &body));
        }
    }

    // ponytail: held-back detections are reported only when a later one passes the limit
    // (they stay in the alerts panel); a timer flush would need a tick hook.
    fn message(&mut self, d: &Detection, now: Instant) -> Option<(String, String)> {
        if self
            .last
            .is_some_and(|t| now.duration_since(t) < MIN_INTERVAL)
        {
            self.held_back += 1;
            return None;
        }
        self.last = Some(now);
        let cmdline: String = d.cmdline.chars().take(CMDLINE_MAX).collect();
        let mut body = format!("{} · {}\n{}", d.chain.join(" > "), d.trigger, cmdline);
        let held_back = std::mem::take(&mut self.held_back);
        if held_back > 0 {
            body.push_str(&format!("\n+{held_back} more since the last notification"));
        }
        Some((format!("Malicious process (score {:.2})", d.score), body))
    }
}

#[cfg(target_os = "linux")]
fn send(title: &str, body: &str) {
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Stdio};

    let mut cmd = Command::new("notify-send");
    cmd.args([
        "-u",
        "critical",
        "-a",
        "LEDA",
        "--",
        title,
        &escape_markup(body),
    ])
    .stdin(Stdio::null())
    .stdout(Stdio::null())
    .stderr(Stdio::null());
    // Live sensors need root, but the notification daemon listens on the invoking
    // user's session bus: run as that user (sudo sets SUDO_UID/SUDO_GID).
    if unsafe { libc::geteuid() } == 0 {
        let id = |k| std::env::var(k).ok().and_then(|v| v.parse::<u32>().ok());
        if let (Some(uid), Some(gid)) = (id("SUDO_UID"), id("SUDO_GID")) {
            cmd.uid(uid).gid(gid).env(
                "DBUS_SESSION_BUS_ADDRESS",
                format!("unix:path=/run/user/{uid}/bus"),
            );
        }
    }
    let _ = cmd.spawn().and_then(|mut child| child.wait());
}

/// Some daemons render the body as markup.
#[cfg(target_os = "linux")]
fn escape_markup(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

#[cfg(windows)]
fn send(title: &str, body: &str) {
    use std::os::windows::process::CommandExt;
    use std::process::{Command, Stdio};

    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    // Text travels in environment variables and is added as DOM text nodes: no quoting or markup injection.
    const SCRIPT: &str = "\
[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType=WindowsRuntime] | Out-Null;\
$x = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent('ToastText02');\
$t = $x.GetElementsByTagName('text');\
$t.Item(0).AppendChild($x.CreateTextNode($env:LEDA_TITLE)) | Out-Null;\
$t.Item(1).AppendChild($x.CreateTextNode($env:LEDA_BODY)) | Out-Null;\
$id = '{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\\WindowsPowerShell\\v1.0\\powershell.exe';\
[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($id).Show([Windows.UI.Notifications.ToastNotification]::new($x))";
    let _ = Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", SCRIPT])
        .env("LEDA_TITLE", title)
        .env("LEDA_BODY", body)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .creation_flags(CREATE_NO_WINDOW)
        .spawn()
        .and_then(|mut child| child.wait());
}

#[cfg(test)]
mod tests {
    use super::*;

    fn det(cmdline: &str) -> Detection {
        Detection {
            pid: 1,
            chain: vec!["nginx".into(), "sh".into()],
            cmdline: cmdline.into(),
            trigger: "exec".into(),
            score: 0.96,
        }
    }

    #[test]
    fn rate_limits_and_counts_held_back() {
        let (mut n, t0) = (Notifier::default(), Instant::now());
        let (title, body) = n.message(&det("id"), t0).unwrap();
        assert_eq!(
            (title.as_str(), body.as_str()),
            ("Malicious process (score 0.96)", "nginx > sh · exec\nid")
        );
        assert!(n.message(&det("a"), t0 + Duration::from_secs(1)).is_none());
        assert!(n.message(&det("b"), t0 + Duration::from_secs(2)).is_none());
        let (_, body) = n.message(&det("c"), t0 + MIN_INTERVAL).unwrap();
        assert!(
            body.ends_with("+2 more since the last notification"),
            "{body}"
        );
        assert!(
            !n.message(&det("d"), t0 + MIN_INTERVAL * 2)
                .unwrap()
                .1
                .contains("more")
        );
    }

    #[test]
    fn truncates_long_cmdline() {
        let (_, body) = Notifier::default()
            .message(&det(&"é".repeat(1000)), Instant::now())
            .unwrap();
        assert_eq!(body.lines().nth(1).unwrap().chars().count(), CMDLINE_MAX);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn escapes_markup() {
        assert_eq!(escape_markup("a<b>&c"), "a&lt;b&gt;&amp;c");
    }
}
