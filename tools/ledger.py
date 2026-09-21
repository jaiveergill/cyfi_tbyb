#!/usr/bin/env python3
"""
Experiment ledger. Every result file this project generates opens with the same
block: which artifacts were read, their hashes, which code produced the numbers
and at what revision, what the analysis was allowed to assume, and what the
budget was.

So a number in the write-up can be traced back to the conditions that produced
it without rerunning anything, and a number generated under different conditions
looks different.
"""
from __future__ import annotations

import hashlib
import pathlib
import platform
import subprocess
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]

# Evidence classes. Every claim in the write-up is tagged with one of these.
CLASSES = {
    "static": "static observation - read out of the PE, the metadata or the AOT image",
    "symbolic": "symbolic observation - produced by execution under the models listed",
    "inference": "inference - argued from the two above, not directly observed",
    "fixture": "supplied fixture - a value this analysis provided, not one it recovered",
    "unresolved": "unresolved - the analysis did not recover this value",
}


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def revision():
    try:
        out = subprocess.run(["git", "-C", str(ROOT), "rev-parse", "--short", "HEAD"],
                             capture_output=True, text=True, timeout=10)
        rev = out.stdout.strip() or "unknown"
        dirty = subprocess.run(["git", "-C", str(ROOT), "status", "--porcelain"],
                               capture_output=True, text=True, timeout=20).stdout.strip()
        return rev + ("+dirty" if dirty else "")
    except Exception:
        return "unknown"


def source_digest(paths):
    h = hashlib.sha256()
    for p in sorted(str(x) for x in paths):
        try:
            h.update(pathlib.Path(p).read_bytes())
        except OSError:
            pass
    return h.hexdigest()[:16]


def versions():
    out = {"python": sys.version.split()[0], "platform": platform.platform(),
           "machine": platform.machine()}
    for mod in ("angr", "claripy", "cle", "pyvex", "dnfile"):
        try:
            out[mod] = __import__(mod).__version__
        except Exception:
            out[mod] = "absent"
    try:
        mono = subprocess.run(["mono", "--version"], capture_output=True,
                              text=True, timeout=10).stdout.splitlines()[0]
        out["mono"] = mono.split("version")[-1].strip().split()[0]
    except Exception:
        out["mono"] = "absent"
    return out


def header(title, artifacts=(), sources=(), entry=None, inputs=None,
           models=None, budget=None, technique=None, notes=()):
    """The standard preamble. Returns a string; callers print it."""
    L = []
    w = 74
    L.append("=" * w)
    L.append(title)
    L.append("=" * w)
    L.append(f"  generated   {time.strftime('%Y-%m-%d %H:%M:%S %Z')}")
    L.append(f"  revision    {revision()}")
    if sources:
        L.append(f"  source hash {source_digest(sources)}  "
                 f"({', '.join(sorted(pathlib.Path(s).name for s in sources))})")
    v = versions()
    L.append(f"  environment python {v['python']}, angr {v['angr']}, "
             f"cle {v['cle']}, pyvex {v['pyvex']}, dnfile {v['dnfile']}, "
             f"mono {v['mono']}")
    L.append(f"              {v['platform']}  ({v['machine']})")
    for path in artifacts:
        p = pathlib.Path(path)
        if p.exists():
            L.append(f"  artifact    {p.relative_to(ROOT) if p.is_absolute() and ROOT in p.parents else p}")
            L.append(f"              {p.stat().st_size:,} bytes  sha256 {sha256(p)}")
    if entry:
        L.append(f"  entry point {entry}")
    if inputs:
        L.append(f"  symbolic in {inputs}")
    if technique:
        L.append(f"  technique   {technique}")
    if models:
        L.append("  models installed")
        for m in models:
            L.append(f"                {m}")
    if budget:
        L.append(f"  budget      {budget}")
    for n in notes:
        L.append(f"  note        {n}")
    L.append("")
    return "\n".join(L)


def legend():
    L = ["", "-" * 74, "EVIDENCE CLASSES USED ABOVE", "-" * 74]
    for k, v in CLASSES.items():
        L.append(f"  [{k}]".ljust(16) + v)
    return "\n".join(L)
