"""Model signature file for the runtime detector (LEDA §3, §4.2).

One JSON file carries everything `app/src/core/detection` needs: the forest
(per tree: children, split feature and threshold, leaf P(malicious)), the
DictVectorizer feature names, the feature-extractor tables and the selected
triggers. With `--golden`, the same file plus featurized records and their
`predict_proba`, the parity fixture for the Rust tests.

    cd ai && uv run python -m lotl.export --golden ../app/src/core/detection/parity.json
"""

import argparse
import json
import sys
from pathlib import Path

import joblib

from lotl.chains import MAX_ANCESTORS
from lotl.features import (CMDLINE_RULES, CONTENT_APPS, INTERPRETERS, LONG_PARAMS, LOTL_BINS, PATHS, PATTERNS,
                           SERVERS, TOOLS, featurize)
from lotl.train import DEFAULT_BENIGN, DEFAULT_MALICIOUS, ROOT, load_all


def forest_json(model) -> list[dict]:
    """Trees of the pipeline's forest; a leaf has `left == -1`, `p1` is its P(class 1)."""
    trees = []
    for est in model["rf"].estimators_:
        t = est.tree_
        trees.append({"left": t.children_left.tolist(), "right": t.children_right.tolist(),
                      "feature": t.feature.tolist(), "threshold": t.threshold.tolist(),
                      "p1": (t.value[:, 0, 1] / t.value[:, 0, :].sum(axis=1)).tolist()})
    return trees


def signature(model, triggers: list[str]) -> dict:
    return {
        "version": 1,
        "threshold": 0.5,
        "triggers": triggers,
        "extractor": {
            "max_ancestors": MAX_ANCESTORS,
            "content_apps": sorted(CONTENT_APPS), "interpreters": sorted(INTERPRETERS), "tools": sorted(TOOLS),
            "servers": sorted(SERVERS), "lotl_bins": sorted(LOTL_BINS),
            "paths": [list(p) for p in PATHS.items()], "long_params": sorted(LONG_PARAMS),
            "cmdline_rules": [list(r) for r in CMDLINE_RULES], "patterns": [list(p) for p in PATTERNS.items()],
        },
        "features": list(model["vec"].feature_names_),
        "trees": forest_json(model),
    }


def golden_cases(model, n: int) -> list[dict]:
    """Every malicious record plus a deterministic stride sample of benign ones, about `n` in total."""
    seen: set[tuple] = set()
    labeled: list[tuple[int, dict]] = []
    for y, recs in ((0, load_all(DEFAULT_BENIGN)), (1, load_all(DEFAULT_MALICIOUS))):
        for r in recs:
            key = (tuple(r["chain"]), r["cmdline"])
            if key not in seen:
                seen.add(key)
                labeled.append((y, r))
    malicious = [r for y, r in labeled if y == 1]
    benign = sorted((r for y, r in labeled if y == 0), key=lambda r: (r["chain"], r["cmdline"]))
    stride = max(1, len(benign) // max(1, n - len(malicious)))
    cases = []
    for y, r in [(1, r) for r in malicious] + [(0, r) for r in benign[::stride]]:
        f = featurize(r)
        cases.append({"chain": r["chain"], "cmdline": r["cmdline"], "label": y, "features": f,
                      "p1": float(model.predict_proba([f])[0][1])})
    return cases


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--model", type=Path, default=ROOT / "models/model.joblib")
    ap.add_argument("--selection", type=Path, default=ROOT / "models/trigger_selection.json")
    ap.add_argument("--out", type=Path, default=ROOT / "models/leda_model.json")
    ap.add_argument("--golden", type=Path, help="also write a parity fixture (signature + golden cases)")
    ap.add_argument("--golden-n", type=int, default=400)
    args = ap.parse_args(argv)

    if not args.model.exists():
        sys.exit(f"{args.model} missing: run `python -m lotl.train` first")
    if not args.selection.exists():
        sys.exit(f"{args.selection} missing: run `python -m lotl.prototype` first")
    model = joblib.load(args.model)
    triggers = json.loads(args.selection.read_text())["selected"]
    sig = signature(model, triggers)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(sig))
    print(f"wrote {args.out}: {len(sig['trees'])} trees, {len(sig['features'])} features, triggers {triggers}")
    if args.golden:
        sig["golden"] = golden_cases(model, args.golden_n)
        args.golden.parent.mkdir(parents=True, exist_ok=True)
        args.golden.write_text(json.dumps(sig))
        print(f"wrote {args.golden}: {len(sig['golden'])} golden cases")


if __name__ == "__main__":
    main()
