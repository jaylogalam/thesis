"""Random Forest training pipeline for suspicious process creation chains.

    uv run python -m lotl.train                       # defaults below
    uv run python -m lotl.train --benign ../app/traces/*.jsonl seeds/benign_admin.jsonl \
                                --malicious seeds/malicious_chains.jsonl attack-trace.jsonl

Stages (Boros et al., IoTBDS 2022):
  1. load      runtime-monitor traces or hand-written record files -> one record per executed program
  2. dedup     normalize volatile tokens (numbers, hex, IPs, UUIDs) and drop duplicates; a chain seen
               with both labels is ambiguous and dropped (§3.1)
  3. features  expert tags + numeric chain features (`lotl.features`, §3.2)
  4. split     stratified hold-out test set
  5. validate  stratified k-fold cross-validation on the training split (§4, k=5)
  6. fit       DictVectorizer -> RandomForestClassifier on the training split
  7. test      precision / recall / F1 / false-positive rate on the held-out split
  8. save      model.joblib (whole sklearn Pipeline: takes `featurize` dicts), metrics.json,
               feature_importance.tsv
"""

import argparse
import glob
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction import DictVectorizer
from sklearn.metrics import confusion_matrix, precision_recall_fscore_support
from sklearn.model_selection import StratifiedKFold, cross_validate, train_test_split
from sklearn.pipeline import Pipeline

from lotl.chains import load
from lotl.features import featurize

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_BENIGN = [str(ROOT.parent / "app/traces/*.jsonl"), str(ROOT / "seeds/benign_admin.jsonl")]
DEFAULT_MALICIOUS = [str(ROOT / "seeds/malicious_chains.jsonl")]

# Stringlifier stand-in (§3.1): same command line with different volatile values is one example.
_VOLATILE = [
    (re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I), "<UUID>"),
    (re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b"), "<IP>"),
    (re.compile(r"\b[0-9a-f]{8,}\b", re.I), "<HEX>"),
    (re.compile(r"\d+"), "<N>"),
]


def normalize(cmdline: str) -> str:
    for rx, sub in _VOLATILE:
        cmdline = rx.sub(sub, cmdline)
    return cmdline


def load_all(patterns: list[str]) -> list[dict]:
    records = []
    for pat in patterns:
        paths = sorted(glob.glob(pat)) or [pat]
        for p in paths:
            try:
                got = load(Path(p))
            except ValueError as e:
                print(f"skip: {e}", file=sys.stderr)
                continue
            print(f"  {len(got):6d} records  {p}")
            records += got
    return records


def dedup(benign: list[dict], malicious: list[dict]) -> tuple[list[dict], list[int], int]:
    labels: dict[tuple, set[int]] = defaultdict(set)
    first: dict[tuple, dict] = {}
    for y, recs in ((0, benign), (1, malicious)):
        for r in recs:
            key = (tuple(r["chain"]), normalize(r["cmdline"]))
            labels[key].add(y)
            first.setdefault(key, r)
    keep = [k for k, ys in labels.items() if len(ys) == 1]
    return [first[k] for k in keep], [next(iter(labels[k])) for k in keep], len(labels) - len(keep)


def rates(y_true, y_pred) -> dict:
    p, r, f1, _ = precision_recall_fscore_support(y_true, y_pred, average="binary", zero_division=0)
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    return {"precision": p, "recall": r, "f1": f1, "fpr": fp / max(fp + tn, 1),
            "confusion": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)}}


def main(argv: list[str] | None = None) -> dict:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--benign", nargs="+", default=DEFAULT_BENIGN, help="traces / record files (globs ok)")
    ap.add_argument("--malicious", nargs="+", default=DEFAULT_MALICIOUS, help="traces / record files (globs ok)")
    ap.add_argument("--out", type=Path, default=ROOT / "models")
    ap.add_argument("--trees", type=int, default=50, help="paper: 50 estimators")
    ap.add_argument("--folds", type=int, default=5)
    ap.add_argument("--test-size", type=float, default=0.2)
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args(argv)

    print("[1/8] load benign")
    benign = load_all(args.benign)
    print("[1/8] load malicious")
    malicious = load_all(args.malicious)

    records, y, ambiguous = dedup(benign, malicious)
    y = np.array(y)
    n_mal = int(y.sum())
    print(f"[2/8] dedup: {len(benign) + len(malicious)} -> {len(records)} unique "
          f"({len(records) - n_mal} benign, {n_mal} malicious, {ambiguous} ambiguous dropped)")
    if n_mal < args.folds or len(records) - n_mal < args.folds:
        sys.exit(f"need at least {args.folds} unique examples per class")

    X = [featurize(r) for r in records]
    print(f"[3/8] features: {len({k for x in X for k in x})} distinct")

    idx = np.arange(len(records))
    i_tr, i_te = train_test_split(idx, test_size=args.test_size, stratify=y, random_state=args.seed)
    X_tr, X_te = [X[i] for i in i_tr], [X[i] for i in i_te]
    print(f"[4/8] split: train {len(i_tr)} ({int(y[i_tr].sum())} malicious), test {len(i_te)} ({int(y[i_te].sum())} malicious)")

    def model() -> Pipeline:
        return Pipeline([
            ("vec", DictVectorizer(sparse=True)),
            ("rf", RandomForestClassifier(n_estimators=args.trees, class_weight="balanced_subsample",
                                          n_jobs=-1, random_state=args.seed)),
        ])

    cv = cross_validate(model(), X_tr, y[i_tr], cv=StratifiedKFold(args.folds, shuffle=True, random_state=args.seed),
                        scoring=("precision", "recall", "f1", "average_precision"))
    cv_summary = {m: {"mean": float(cv[f"test_{m}"].mean()), "std": float(cv[f"test_{m}"].std())}
                  for m in ("precision", "recall", "f1", "average_precision")}
    print(f"[5/8] {args.folds}-fold CV: " + "  ".join(f"{m} {s['mean']:.3f}±{s['std']:.3f}" for m, s in cv_summary.items()))

    clf = model().fit(X_tr, y[i_tr])
    print(f"[6/8] fit: {args.trees} trees on {len(i_tr)} examples")

    pred = clf.predict(X_te)
    test = rates(y[i_te], pred)
    print("[7/8] test: " + "  ".join(f"{k} {v:.3f}" for k, v in test.items() if k != "confusion") + f"  {test['confusion']}")
    # §3.2: inspect the tags of failed examples to refine the feature extraction.
    errors = [{"label": int(y[i]), "chain": records[i]["chain"], "cmdline": records[i]["cmdline"],
               "tags": sorted(k for k in X[i] if not k.startswith("num_"))}
              for i, p in zip(i_te, pred) if p != y[i]]
    for e in errors:
        print(f"      {'FN' if e['label'] else 'FP'}  {' > '.join(e['chain'])}: {e['cmdline'][:100]}")

    args.out.mkdir(parents=True, exist_ok=True)
    joblib.dump(clf, args.out / "model.joblib")
    names = clf["vec"].get_feature_names_out()
    ranked = sorted(zip(names, clf["rf"].feature_importances_), key=lambda t: -t[1])
    (args.out / "feature_importance.tsv").write_text("".join(f"{n}\t{v:.5f}\n" for n, v in ranked))
    metrics = {
        "data": {"unique": len(records), "malicious": n_mal, "benign": len(records) - n_mal, "ambiguous_dropped": ambiguous,
                 "benign_sources": args.benign, "malicious_sources": args.malicious},
        "params": {"trees": args.trees, "folds": args.folds, "test_size": args.test_size, "seed": args.seed},
        "cv": cv_summary, "test": test, "test_errors": errors,
        "top_features": [[n, float(v)] for n, v in ranked[:25]],
    }
    (args.out / "metrics.json").write_text(json.dumps(metrics, indent=2, default=float))
    print(f"[8/8] saved model.joblib, metrics.json, feature_importance.tsv -> {args.out}")
    print("      top features: " + ", ".join(n for n, _ in ranked[:10]))
    return metrics


if __name__ == "__main__":
    main()
