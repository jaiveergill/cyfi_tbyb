#!/usr/bin/env python3
"""
Shared setup for the GravityRat experiments.

Everything that decides what the analysis is allowed to assume lives here, so
that the comparison scripts can state plainly that the two arms differ only in
the exploration strategy.
"""
from __future__ import annotations

import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))

import managed_runtime as mr      # noqa: E402

EXE = ROOT / "case1" / "samples" / "extracted" / "Win32.GravityRAT.exe"
SO = pathlib.Path(str(EXE) + ".so")

SOURCES = [ROOT / "tools" / "callsite_map.py",
           ROOT / "tools" / "managed_runtime.py",
           ROOT / "tools" / "managed_call_explorer.py",
           ROOT / "tools" / "aot_bridge.py"]

# Host facts the sample reads off the machine it runs on. There is nothing in
# the binary to recover for these, so each is replaced by a fixture that names
# itself; anything downstream that captures one says where it came from.
FIXTURE_PREFIXES = ("LSASS_Models_Identification_",)


def build(models=None, fixtures=True):
    """A ManagedRuntime with the standard model set installed.

    Returns (runtime, description) where description is the list of models, for
    the ledger header.
    """
    rt = mr.ManagedRuntime(str(EXE), str(SO))
    rt.install(models or {})
    described = [
        "mono AOT linkage table resolved (every plt_FOO -> FOO)",
        f"{len(rt.alloc_types)} allocation sites typed from their `newobj`",
        f"{len(rt.literals)} `ldstr` literals written into their GOT slots",
        "per-object header so unbox/null checks read concrete, selecting no callee",
        "mono throw helpers modelled as not returning",
        "String.Concat modelled at each arity the image uses",
        "uninitialised memory reads as zero (CLR zero-initialises managed memory)",
    ]
    fixed = []
    if fixtures:
        for name, addr in list(rt.syms.items()):
            base = name[4:] if name.startswith("plt_") else name
            if base.startswith(FIXTURE_PREFIXES):
                rt.proj.hook(addr, mr._Fixture(text=f"<{base}>", label=base),
                             replace=True)
                fixed.append(base)
        described.append(f"{len(set(fixed))} host-fact getters replaced by "
                         f"labelled fixtures (LSASS.Models.Identification.*)")
    for name in (models or {}):
        described.append(f"model: {name}")
    rt.fixtures = sorted(set(fixed))
    return rt, described


def walk(simgr, budget, cap=400, collect=None):
    """Step a manager under a fixed budget. Returns (steps, peak active).

    `cap` bounds the frontier so that a run which does explode is stopped rather
    than swapping the host; runs that hit it say so.
    """
    steps = peak = 0
    while simgr.active and steps < budget and len(simgr.active) < cap:
        simgr.step()
        steps += 1
        peak = max(peak, len(simgr.active))
        if collect is not None:
            collect(simgr, steps)
    return steps, peak


def all_states(simgr):
    """Every state the run produced, including the ones angr filed as errors.

    `errored` is not a stash: it holds ErrorRecord objects on the manager
    itself. Skipping it loses exactly the states that matter here, because an
    unresolved indirect call branches to address zero and angr files that as an
    error rather than as a dead end.
    """
    out = []
    for stash in simgr.stashes.values():
        out.extend(stash)
    for rec in getattr(simgr, "errored", []):
        st = getattr(rec, "state", None)
        if st is not None:
            out.append(st)
    return out


def blocks_touched(simgr):
    """Every basic block any state actually executed."""
    out = set()
    for st in all_states(simgr):
        out.update(st.history.bbl_addrs)
    return out
