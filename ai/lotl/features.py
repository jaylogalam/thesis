"""Expert-knowledge tags for one process creation chain record.

Follows Boros et al., "Machine Learning and Feature Engineering for Detecting
Living off the Land Attacks" (IoTBDS 2022), §3.2: instead of n-grams (sparse,
over-fits), the command line is labelled with a bounded set of tags for known
binaries, interesting paths, parameters, networking cues and LotL patterns.
Chain tags (parent/ancestor classes) and the numeric features of
`app/src/core/features/chains.rs` (depth, length, entropy, complexity) extend
it from single commands to process creation chains.

`featurize` returns a dict: tags map to 1, numeric features to floats, ready
for `sklearn.feature_extraction.DictVectorizer`.
"""

import ipaddress
import math
import re
import shlex

# Image classes, kept in sync with chains.rs (CONTENT_APPS, INTERPRETERS, TOOLS).
CONTENT_APPS = {
    "firefox", "firefox-esr", "chrome", "chromium", "google-chrome", "brave", "msedge", "opera",
    "vivaldi-bin", "epiphany", "soffice.bin", "libreoffice", "evince", "okular", "zathura",
    "thunderbird", "evolution", "winword", "excel", "powerpnt", "outlook", "msaccess", "onenote",
    "acrord32", "acrobat", "foxitreader", "iexplore",
}
INTERPRETERS = {
    "sh", "bash", "dash", "zsh", "fish", "ksh", "csh", "tcsh", "busybox", "pwsh", "python", "perl",
    "ruby", "php", "node", "lua", "cmd", "powershell", "powershell_ise", "wscript", "cscript", "mshta",
    "rundll32", "regsvr32", "awk", "gawk",
}
TOOLS = {"curl", "wget", "nc", "ncat", "netcat", "socat", "base64", "openssl", "certutil", "bitsadmin", "xxd", "telnet"}
# Network-facing daemons: a shell under one of these is the classic web-shell / RCE chain.
SERVERS = {
    "nginx", "apache2", "httpd", "php-fpm", "lighttpd", "java", "tomcat", "gunicorn", "uwsgi",
    "postgres", "mysqld", "redis-server", "sshd", "vsftpd", "smbd", "w3wp", "sqlservr",
}
# Recon, privilege, persistence and staging binaries common in GTFOBins/LOLBAS chains.
LOTL_BINS = {
    "whoami", "id", "uname", "hostname", "ifconfig", "ip", "netstat", "ss", "ps", "crontab",
    "chmod", "chown", "chattr", "mkfifo", "mknod", "useradd", "usermod", "passwd", "sudo", "su",
    "find", "tar", "zip", "scp", "ssh", "rsync", "dd", "shred", "history", "nohup", "setsid",
    "systemctl", "iptables", "ufw", "setenforce", "auditctl", "journalctl", "insmod", "modprobe",
    "gcc", "cc", "make", "vim", "vi", "less", "more", "env", "xargs", "tee", "cat", "grep", "sed",
    "cut", "getent", "nmap", "docker", "kubectl", "gdb", "strace", "tcpdump", "at", "ldd",
    "schtasks", "wmic", "vssadmin", "bcdedit", "wevtutil", "reg", "net", "netsh", "sc", "msiexec",
}
KNOWN = CONTENT_APPS | INTERPRETERS | TOOLS | SERVERS | LOTL_BINS
CLASSES = (("CONTENT", CONTENT_APPS), ("INTERP", INTERPRETERS), ("TOOL", TOOLS), ("SERVER", SERVERS))

PATHS = {
    "/tmp/": "TMP", "/var/tmp/": "TMP", "/dev/shm/": "SHM", "/dev/tcp/": "DEV_TCP", "/dev/udp/": "DEV_UDP",
    "/dev/null": "DEV_NULL", "/.ssh": "SSH", "authorized_keys": "AUTHORIZED_KEYS", "/etc/passwd": "PASSWD",
    "/etc/shadow": "SHADOW", "/etc/sudoers": "SUDOERS", "/etc/cron": "CRON", "/var/spool/cron": "CRON",
    "/etc/systemd/": "SYSTEMD", "/.config/systemd/": "SYSTEMD", ".bashrc": "RC", ".profile": "RC",
    "/etc/rc.local": "RC", "ld.so.preload": "PRELOAD", "/proc/self/": "PROC_SELF", "/var/log": "VAR_LOG",
    "/var/www": "WEBROOT", "/bin/sh": "BIN_SH", "/bin/bash": "BIN_BASH", "\\appdata\\": "APPDATA",
    "\\temp\\": "TMP", "\\users\\public\\": "PUBLIC",
}
LONG_PARAMS = {
    "--decode", "--output", "--post-file", "--upload-file", "-exec", "-enc", "-encodedcommand",
    "-nop", "-noprofile", "-windowstyle", "-executionpolicy", "--no-check-certificate", "-urlcache",
}

# Rule fragments mirrored from chains.rs CMDLINE_RULES (whole-word matched on the normalized line).
CMDLINE_RULES = (
    ("$(curl", "download_and_run"), ("$(wget", "download_and_run"), ("base64 -d", "base64_decode"),
    ("base64 --decode", "base64_decode"), ("frombase64string", "base64_decode"),
    ("-encodedcommand", "encoded_powershell"), ("-enc ", "encoded_powershell"), ("-w hidden", "hidden_window"),
    ("-windowstyle hidden", "hidden_window"), ("-executionpolicy bypass", "ep_bypass"), ("-ep bypass", "ep_bypass"),
    ("downloadstring(", "ps_download"), ("downloadfile(", "ps_download"), ("invoke-webrequest", "ps_download"),
    ("iex(", "invoke_expression"), ("iex (", "invoke_expression"), ("invoke-expression", "invoke_expression"),
    ("certutil -urlcache", "certutil_abuse"), ("certutil -decode", "certutil_abuse"),
    ("bitsadmin /transfer", "bits_download"), ("vssadmin delete shadows", "delete_shadows"),
    ("wmic shadowcopy delete", "delete_shadows"), ("wevtutil cl", "clear_event_log"),
    ("wevtutil clear-log", "clear_event_log"), ("set-mppreference -disablerealtimemonitoring", "disable_defender"),
    ("netsh advfirewall set allprofiles state off", "disable_firewall"), ("/dev/tcp/", "reverse_shell"),
    ("/dev/udp/", "reverse_shell"), ("nc -e", "reverse_shell"), ("ncat -e", "reverse_shell"),
    ("socat exec:", "reverse_shell"), ("bash -i", "interactive_shell"), ("chmod +x /tmp/", "run_from_temp"),
    ("chmod +x /dev/shm/", "run_from_temp"), ("history -c", "clear_history"), ("unset histfile", "disable_history"),
    ("histfile=/dev/null", "disable_history"), ("rm -rf /var/log", "delete_logs"),
    ("journalctl --vacuum", "delete_logs"), ("setenforce 0", "disable_selinux"), ("auditctl -d", "delete_audit_rules"),
    ("auditctl -e 0", "disable_audit"), ("stop auditd", "stop_audit"), ("iptables -f", "flush_firewall"),
    ("ufw disable", "disable_firewall"), ("ld_preload=", "preload_hijack"), ("ld.so.preload", "preload_hijack"),
)
# Paper §3.2 regexes: interpreter one-liners that open sockets or spawn shells.
PATTERNS = {
    "python_socket": r"python[\d.]*\s.*-c.*socket", "python_pty": r"python[\d.]*\s.*-c.*pty",
    "python_connect": r"python[\d.]*\s.*-c.*\.connect", "python_shell": r"python[\d.]*\s.*-c.*(pty|subprocess|os\.system).*sh",
    "perl_socket": r"perl\s.*-e.*socket", "ruby_socket": r"ruby\s.*-rsocket", "php_socket": r"php\s.*-r.*fsockopen",
    "lua_socket": r"lua\s.*-e.*socket", "awk_inet": r"awk\s.*/inet/tcp", "node_child": r"node\s.*-e.*child_process",
    "mkfifo_pipe": r"mkfifo\s.*(nc|ncat|sh)\b", "dup_fd": r"(0>&1|>&\s*/dev/|<&\d)", "exec_fd": r"exec\s+\d+<>",
    "echo_pipe_decode": r"echo\s+\S{16,}\s*\|\s*(base64|xxd)", "suid_bit": r"chmod\s+([ug]\+s|[2467]\d{3})",
    "curl_to_file_exec": r"(curl|wget)\s.*(-o|-O)\s*\S+.*(&&|;)\s*(chmod|sh|bash|\./)",
    "cron_write": r"(crontab\s+-|>>?\s*/etc/cron|/var/spool/cron)", "ssh_key_write": r">>?\s*\S*authorized_keys",
    "user_add": r"(useradd|adduser|usermod\s+-a?G\s*(sudo|wheel|root))", "sudoers_write": r">>?\s*/etc/sudoers",
    "find_exec_shell": r"find\s.*-exec\s+(/bin/)?(ba)?sh", "tar_checkpoint": r"--checkpoint-action=exec",
    "vi_shell": r"vim?\s.*-c\s*['\"]?:?!", "env_shell": r"env\s+(/bin/)?(ba)?sh\b", "nohup_bg": r"nohup\s.*&\s*$",
    "shell_c_long": r"\b(ba)?sh\s+-c\s+\S.{120,}",
}
_PATTERNS = {k: re.compile(v, re.IGNORECASE) for k, v in PATTERNS.items()}
_IPV4 = re.compile(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?![\d.])")
# Internal ranges only (RFC 1918, link-local, CGNAT): `ip_address.is_private` also covers the
# documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) used in examples.
_INTERNAL = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "100.64.0.0/10")]
_URL = re.compile(r"\b(https?|ftp|tftp|smb|ldap)://", re.IGNORECASE)
_DOMAIN = re.compile(r"\b[a-z0-9-]+(?:\.[a-z0-9-]+)*\.(?:com|net|org|io|ru|cn|xyz|top|sh|me|co|onion|tk)\b", re.IGNORECASE)


def base(img: str) -> str:
    """Known name, also behind a version suffix (python3.12 -> python, php8 -> php, apache2 stays)."""
    if img in KNOWN:
        return img
    return img.rstrip("0123456789.") or img


def image_class(img: str) -> str:
    b = base(img)
    return next((name for name, members in CLASSES if b in members), "OTHER")


def known(img: str) -> str:
    b = base(img)
    return b if b in KNOWN else "OTHER"


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in (s.count(ch) for ch in set(s)))


def log_complexity(s: str) -> float:
    """ln(1 + entropy * e^k), k = character-class changes; same as chains.rs `log_complexity`."""
    def cls(c: str) -> int:
        if "A" <= c <= "Z":
            return 0
        if "a" <= c <= "z":
            return 1
        if "0" <= c <= "9":
            return 2
        return 3 if c.isascii() else 4

    h = shannon_entropy(s)
    if h == 0.0:
        return 0.0
    x = math.log(h) + sum(cls(a) != cls(b) for a, b in zip(s, s[1:]))
    return max(x, 0.0) + math.log1p(math.exp(-abs(x)))


def _contains_word(s: str, pat: str) -> bool:
    """`pat` in `s` not glued to a longer word ("| sh" must not match "| sha256sum")."""
    start = s.find(pat)
    while start != -1:
        before = s[start - 1] if start else ""
        after = s[start + len(pat): start + len(pat) + 1]
        open_ok = not pat[0].isalnum() or not before.isalnum()
        close_ok = not pat[-1].isalnum() or not (after.isalpha() or after == "_")
        if open_ok and close_ok:
            return True
        start = s.find(pat, start + 1)
    return False


def _tokens(cmdline: str) -> list[str]:
    try:
        return shlex.split(cmdline, posix=True)
    except ValueError:  # unbalanced quotes
        return cmdline.split()


def featurize(record: dict) -> dict[str, float]:
    chain = [c.lower() for c in record["chain"]] or [""]
    cmdline = record["cmdline"]
    img, parent = chain[-1], chain[-2] if len(chain) > 1 else ""
    ancestors = chain[:-1]
    f: dict[str, float] = {}

    def tag(t: str) -> None:
        f[t] = 1.0

    # Chain: who spawned whom, by known name and by class.
    ic, pc = image_class(img), image_class(parent) if parent else "NONE"
    tag(f"IMG_{known(img)}")
    tag(f"IMG_CLASS_{ic}")
    tag(f"PARENT_{known(parent) if parent else 'NONE'}")
    tag(f"PARENT_CLASS_{pc}")
    tag(f"PAIR_CLASS_{pc}>{ic}")
    if len(chain) > 2:
        tag(f"GPARENT_CLASS_{image_class(chain[-3])}")
    for a in ancestors:
        if (ac := image_class(a)) in ("CONTENT", "SERVER"):
            tag(f"ANCESTOR_{ac}")
    interp_run = 0
    for c in reversed(chain):
        if image_class(c) != "INTERP":
            break
        interp_run += 1

    # Command line, paper §3.2 tag classes.
    norm = " ".join(cmdline.lower().split()).replace(" |", "|").replace("| ", "|")
    toks = _tokens(cmdline)
    for t in toks:
        name = t.replace("\\", "/").rsplit("/", 1)[-1].lower().removesuffix(".exe")
        if (k := known(name)) != "OTHER":
            tag(f"CMD_{k}")
        tl = t.lower()
        if re.fullmatch(r"-[a-zA-Z]", t) or tl in LONG_PARAMS:
            tag(f"PARAM_{t if len(t) == 2 else tl}")
    for frag, label in PATHS.items():
        if frag in norm:
            tag(f"PATH_{label}")
    for m in _IPV4.findall(cmdline):
        try:
            ip = ipaddress.ip_address(m)
        except ValueError:
            continue
        tag("IP_LOOPBACK" if ip.is_loopback else "IP_PRIVATE" if any(ip in n for n in _INTERNAL) else "IP_PUBLIC")
    for proto in _URL.findall(cmdline):
        tag(f"URL_{proto.upper()}")
    if _DOMAIN.search(cmdline):
        tag("DOMAIN")
    for frag, label in CMDLINE_RULES:
        if _contains_word(norm, frag):
            tag(f"RULE_{label}")
    # `... | sh`, `... | sudo python3`: whatever runs after a pipe is an interpreter.
    for seg in norm.split("|")[1:]:
        words = [w for w in seg.split(" ") if w and w != "sudo"]
        if words and image_class(words[0].rsplit("/", 1)[-1]) == "INTERP":
            tag("RULE_pipe_to_interpreter")
    for name, rx in _PATTERNS.items():
        if rx.search(cmdline):
            tag(f"PAT_{name}")

    n_tags = len(f)
    f.update({
        "num_depth": float(len(ancestors)),
        "num_interp_run": float(interp_run),
        "num_cmdline_len": float(len(cmdline)),
        "num_cmdline_entropy": shannon_entropy(cmdline),
        "num_cmdline_complexity": log_complexity(cmdline),
        "num_image_complexity": log_complexity(img),
        "num_args": float(len(toks)),
        "num_pipes": float(norm.count("|")),
        "num_tags": float(n_tags),
    })
    return f
