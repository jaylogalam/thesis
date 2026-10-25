"""Process creation chains from `runtime-monitor` JSON Lines traces.

Every program a process runs (first sighting or execve) becomes one record:
`{"chain": [root image, ..., parent image, image], "cmdline": str}`. Image
naming mirrors `app/src/core/features/chains.rs` so both sides agree.
"""

import json
from pathlib import Path

MAX_ANCESTORS = 8


def image(name: str, exe: str | None) -> str:
    """Lowercased file name without `.exe`; the process name if the exe is unreadable."""
    lower = (Path(exe.replace("\\", "/")).name if exe else name).lower()
    return lower.removesuffix(".exe")


def _ancestors(procs: dict[int, dict], ppid: int) -> list[str]:
    out, seen = [], set()
    while ppid in procs and ppid not in seen and len(out) < MAX_ANCESTORS:
        seen.add(ppid)
        out.append(procs[ppid]["image"])
        ppid = procs[ppid]["ppid"]
    return out[::-1]


def read_trace(path: Path) -> list[dict]:
    """One record per program executed in the trace, with its ancestry at that moment."""
    procs: dict[int, dict] = {}
    records = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            ev = json.loads(line)
            pid, kind = ev["pid"], ev["kind"]
            match kind["type"]:
                case "ProcessStart":
                    if "ppid" not in kind:
                        raise ValueError(f"{path}: trace predates process chains (no ppid/cmdline)")
                    img = image(kind["name"], kind.get("exe"))
                    parent = procs.get(kind["ppid"])
                    procs[pid] = {"image": img, "ppid": kind["ppid"], "cmdline": kind["cmdline"]}
                    # A fork that has not exec'd yet repeats its parent's program.
                    if parent and parent["image"] == img and parent["cmdline"] == kind["cmdline"]:
                        continue
                    if not parent and kind.get("parent_exe"):
                        anc = [image("", kind["parent_exe"])]
                    else:
                        anc = _ancestors(procs, kind["ppid"])
                case "ProcessExec":
                    p = procs.setdefault(pid, {"ppid": 0})
                    p["image"] = image(kind["name"], kind.get("exe"))
                    p["cmdline"] = kind["cmdline"]
                    anc = _ancestors(procs, p["ppid"])
                case "ProcessExit":
                    procs.pop(pid, None)
                    continue
                case _:
                    continue
            records.append({"chain": anc + [procs[pid]["image"]], "cmdline": procs[pid]["cmdline"]})
    return records


def read_records(path: Path) -> list[dict]:
    """Hand-written records (`{"chain": [...], "cmdline": ...}` per line)."""
    with open(path, encoding="utf-8") as f:
        return [json.loads(l) for l in f if l.strip() and not l.lstrip().startswith("//")]


def load(path: Path) -> list[dict]:
    """Records from a trace (events) or a record file, told apart by the first line."""
    with open(path, encoding="utf-8") as f:
        first = next((l for l in f if l.strip() and not l.lstrip().startswith("//")), "{}")
    return read_trace(path) if "kind" in json.loads(first) else read_records(path)
