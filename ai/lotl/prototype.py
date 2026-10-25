"""LEDA §4.2 prototyping: replay labelled data, score each monitored process at every candidate
trigger point, and pick the smallest set of trigger event types whose OR-combined predictions
reach the target F1.

A sample is one monitored process (a pid of a recorded trace, or the leaf of a synthesized seed).
Its prediction for a trigger is the OR of the model's flags over every snapshot where the trigger
fires; its prediction for a trigger set is the OR over the set. F1 is measured on the training
corpus with the already trained model, so it is optimistic.

    python -m lotl.prototype [--model models/model.joblib] [--threshold 0.9]
"""

import argparse
import csv
import glob
import itertools
import json
import sys
from collections.abc import Callable
from pathlib import Path

import joblib
import numpy as np
from sklearn.metrics import precision_recall_fscore_support

from lotl.chains import iter_snapshots, read_events, read_records, synthesize
from lotl.features import cmdline_rule_hits, featurize, image_class
from lotl.train import DEFAULT_BENIGN, DEFAULT_MALICIOUS, ROOT

Snapshot = dict  # {"pid": int, "chain": list[str], "cmdline": str, "kind": str}

TRIGGERS: list[tuple[str, Callable[[Snapshot], bool]]] = [
    ("start", lambda s: s["kind"] == "ProcessStart"),
    ("exec", lambda s: s["kind"] == "ProcessExec"),
    ("interp_child", lambda s: s["kind"] == "ProcessStart" and len(s["chain"]) >= 2
     and image_class(s["chain"][-2]) == "INTERP"),
    ("rule_hit", lambda s: bool(cmdline_rule_hits(s["cmdline"]))),
]


def snapshots(events: list[dict]) -> list[Snapshot]:
    return [{"pid": p, "chain": c, "cmdline": cm, "kind": k} for p, c, cm, k in iter_snapshots(events)]


def trace_samples(events: list[dict]) -> list[list[Snapshot]]:
    """One sample per pid of a recorded trace."""
    by_pid: dict[int, list[Snapshot]] = {}
    for s in snapshots(events):
        by_pid.setdefault(s["pid"], []).append(s)
    return list(by_pid.values())


def seed_sample(record: dict) -> list[Snapshot]:
    """The leaf process of a synthesized seed; its ancestors are context, not samples."""
    snaps = snapshots(synthesize(record))
    leaf = snaps[-1]["pid"] if snaps else None
    return [s for s in snaps if s["pid"] == leaf] or [
        {"pid": 0, "chain": record["chain"], "cmdline": record["cmdline"], "kind": ""}]


def build_matrix(benign: list[list[Snapshot]], malicious: list[list[Snapshot]], model,
                 triggers=TRIGGERS) -> tuple[np.ndarray, list[dict], list[str]]:
    """`triggerPrediction[N][M]`: per sample, per trigger, OR of model flags where the trigger fires."""
    samples = [(0, s) for s in benign] + [(1, s) for s in malicious]
    flat = [snap for _, snaps in samples for snap in snaps]
    flags = model.predict([featurize(s) for s in flat]) if flat else np.array([])
    matrix = np.zeros((len(samples), len(triggers)), dtype=int)
    meta, i = [], 0
    for row, (label, snaps) in enumerate(samples):
        for snap, flag in zip(snaps, flags[i:i + len(snaps)]):
            if flag:
                for j, (_, fires) in enumerate(triggers):
                    matrix[row, j] |= fires(snap)
        i += len(snaps)
        last = snaps[-1]
        m = {"label": label, "chain": last["chain"], "cmdline": last["cmdline"]}
        if label and not any(fires(s) for s in snaps for _, fires in triggers):
            m["undetectable"] = True
            print(f"warn: malicious sample fires no trigger: {' > '.join(last['chain'])}: {last['cmdline'][:100]}",
                  file=sys.stderr)
        meta.append(m)
    return matrix, meta, [name for name, _ in triggers]


def scores(y_true, y_pred) -> dict:
    p, r, f1, _ = precision_recall_fscore_support(y_true, y_pred, average="binary", zero_division=0)
    return {"precision": float(p), "recall": float(r), "f1": float(f1)}


def select_triggers(matrix: np.ndarray, labels, threshold: float) -> dict:
    """Smallest trigger subset with F1 >= threshold; else the smallest one with the best F1."""
    best = None
    for k in range(1, matrix.shape[1] + 1):
        for subset in itertools.combinations(range(matrix.shape[1]), k):
            s = scores(labels, matrix[:, list(subset)].any(axis=1).astype(int))
            if s["f1"] >= threshold:
                return {"subset": list(subset), **s, "reached_threshold": True}
            if best is None or s["f1"] > best["f1"]:
                best = {"subset": list(subset), **s}
    return {**best, "reached_threshold": False}


def load_benign(patterns: list[str]) -> list[list[Snapshot]]:
    samples = []
    for pat in patterns:
        for p in sorted(glob.glob(pat)) or [pat]:
            with open(p, encoding="utf-8") as f:
                first = next((l for l in f if l.strip() and not l.lstrip().startswith("//")), "{}")
            if "kind" in json.loads(first):
                try:
                    got = trace_samples(read_events(Path(p)))
                except ValueError as e:
                    print(f"skip: {p}: {e}", file=sys.stderr)
                    continue
            else:
                got = [seed_sample(r) for r in read_records(Path(p))]
            print(f"  {len(got):6d} samples  {p}")
            samples += got
    return samples


def load_malicious(patterns: list[str]) -> list[list[Snapshot]]:
    samples = []
    for pat in patterns:
        for p in sorted(glob.glob(pat)) or [pat]:
            got = [seed_sample(r) for r in read_records(Path(p))]
            print(f"  {len(got):6d} samples  {p}")
            samples += got
    return samples


def main(argv: list[str] | None = None) -> dict:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--model", type=Path, default=ROOT / "models/model.joblib")
    ap.add_argument("--benign", nargs="+", default=DEFAULT_BENIGN, help="traces / record files (globs ok)")
    ap.add_argument("--malicious", nargs="+", default=DEFAULT_MALICIOUS, help="record files (globs ok)")
    ap.add_argument("--threshold", type=float, default=0.9)
    ap.add_argument("--out", type=Path, default=ROOT / "models")
    args = ap.parse_args(argv)

    if not args.model.exists():
        sys.exit(f"{args.model} missing: run `python -m lotl.train` first")
    model = joblib.load(args.model)
    print("[1/3] load benign")
    benign = load_benign(args.benign)
    print("[1/3] load malicious")
    malicious = load_malicious(args.malicious)

    matrix, meta, names = build_matrix(benign, malicious, model)
    labels = np.array([m["label"] for m in meta])
    per_trigger = {n: scores(labels, matrix[:, j])["f1"] for j, n in enumerate(names)}
    print(f"[2/3] triggerPrediction {matrix.shape[0]}x{matrix.shape[1]} ({int(labels.sum())} malicious): "
          + "  ".join(f"{n} F1 {f:.3f}" for n, f in per_trigger.items()))

    sel = select_triggers(matrix, labels, args.threshold)
    subset = [names[j] for j in sel["subset"]]
    result = {
        "threshold": args.threshold, "per_trigger_f1": per_trigger, "selected": subset,
        "precision": sel["precision"], "recall": sel["recall"], "f1": sel["f1"],
        "reached_threshold": sel["reached_threshold"], "num_samples": len(meta), "num_malicious": int(labels.sum()),
        "undetectable": [m for m in meta if m.get("undetectable")],
    }
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "trigger_selection.json").write_text(json.dumps(result, indent=2))
    with open(args.out / "trigger_prediction.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["label", "chain", "cmdline", *names])
        for m, row in zip(meta, matrix):
            w.writerow([m["label"], ">".join(m["chain"]), m["cmdline"], *row.tolist()])
    print(f"[3/3] selected {subset}: precision {sel['precision']:.3f} recall {sel['recall']:.3f} F1 {sel['f1']:.3f}"
          + ("" if sel["reached_threshold"] else f"  (threshold {args.threshold} not reached)")
          + f"  -> {args.out}")
    return result


if __name__ == "__main__":
    main()
