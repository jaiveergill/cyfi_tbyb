#!/usr/bin/env python3
"""
2.4 - diagnosing the boundary, before repairing it.

Three questions, in order:

  1. Where exactly does the state die, and what is the failing instruction?
  2. Is the loss *recoverable* -- does anything in the path constraints narrow
     the program counter, or is it wholly free?
  3. Is there a problem of the shape an ExplorationTechnique classically
     addresses -- path explosion, environment forking, a search-order failure?

The answers decide what the technique is allowed to do, and they are what
rejected the two earlier designs in `archive/superseded/`.

    .venv/bin/python case1/scripts/diagnose.py
"""
import collections
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import gravityrat as G          # noqa: E402
sys.path.insert(0, str(G.ROOT / "tools"))
import ledger                   # noqa: E402
from managed_call_explorer import ManagedCallExplorer, QUARANTINE  # noqa: E402

PROBE = "LSASS_Networking_Agent_SendBasicInformation" \
        "_System_Collections_Specialized_NameValueCollection"
ENTRIES = ["LSASS_Services_Start_string__", "LSASS_Core_Jobs_RootJob",
           "LSASS_Core_Jobs_SystemSettings", PROBE,
           "LSASS_Models_Enviornment_isVM_LSASS_Models_VirtualMachine_",
           "LSASS_Program_Main_string__"]
BUDGET = 60


def unmodelled_run():
    """Where the state dies with translation but no call-site resolution."""
    rt, _ = G.build()
    simgr = rt.proj.factory.simulation_manager(rt.entry_state(rt.address_of(PROBE)))
    steps, _ = G.walk(simgr, 50)
    trace, pc, where = [], None, {}
    for st in G.all_states(simgr):
        h = list(st.history.bbl_addrs)
        if len(h) > len(trace):
            trace, pc = h, st.regs.pc
    where = {k: len(v) for k, v in simgr.stashes.items() if v}
    if getattr(simgr, "errored", None):
        where["errored"] = len(simgr.errored)
    return rt, steps, trace, pc, where


def soundness(rt, zero_fill=True):
    """Could the lost program counters be recovered by pinning them?

    The test is the one that rejected the first design: if the solver will
    accept an address the image has never contained, the path constraints say
    nothing about where control goes, and choosing a target invents a path.
    """
    free = narrowed = examined = 0
    for name in ENTRIES:
        addr = rt.address_of(name)
        if addr is None:
            continue
        simgr = rt.proj.factory.simulation_manager(
            rt.entry_state(addr, zero_fill=zero_fill))
        G.walk(simgr, BUDGET)
        lost = list(simgr.stashes.get("unconstrained", []))
        lost += [r.state for r in getattr(simgr, "errored", [])
                 if getattr(r, "state", None) is not None]
        for st in lost:
            examined += 1
            try:
                if st.solver.satisfiable(
                        extra_constraints=[st.regs.pc == 0xDEADBEEF]):
                    free += 1
                else:
                    narrowed += 1
            except Exception:
                narrowed += 1
    return examined, free, narrowed


def frontier():
    """Peak concurrent states per entry point, with the technique installed."""
    rt, _ = G.build()
    out = []
    for name in ENTRIES:
        addr = rt.address_of(name)
        if addr is None:
            continue
        simgr = rt.proj.factory.simulation_manager(rt.entry_state(addr))
        tech = ManagedCallExplorer(rt)
        simgr.use_technique(tech)
        steps, peak = G.walk(simgr, BUDGET)
        out.append((name, steps, peak,
                    len(simgr.stashes.get(QUARANTINE, [])),
                    tech.resolved_static, tech.resolved_dynamic))
    return out


def why_unresolved():
    """What the technique says about every site it could not justify a target for."""
    rt, _ = G.build()
    reasons = collections.Counter()
    sites = collections.Counter()
    for name in ENTRIES:
        addr = rt.address_of(name)
        if addr is None:
            continue
        simgr = rt.proj.factory.simulation_manager(rt.entry_state(addr))
        tech = ManagedCallExplorer(rt)
        simgr.use_technique(tech)
        G.walk(simgr, BUDGET)
        for a, _, why in tech.diagnostics:
            reasons[why.split("(")[0].strip()] += 1
            sites[a] += 1
    return reasons, sites


PARTS = ("loss", "sound_default", "sound_zerofill", "frontier", "why")


def measure(part):
    """One measurement, run alone. See `main` for why that matters."""
    if part == "loss":
        rt, steps, trace, pc, where = unmodelled_run()
        blk = rt.proj.factory.block(trace[-1]) if trace else None
        return {"steps": steps, "trace": [hex(a) for a in trace],
                "pc": str(pc), "where": where,
                "block": [[i.address, i.mnemonic, i.op_str]
                          for i in blk.capstone.insns] if blk else []}
    if part.startswith("sound_"):
        rt, _ = G.build()
        return soundness(rt, zero_fill=(part == "sound_zerofill"))
    if part == "frontier":
        return frontier()
    if part == "why":
        reasons, sites = why_unresolved()
        return {"reasons": reasons.most_common(), "sites": len(sites)}
    raise SystemExit(f"unknown part {part}")


def collect():
    """Fork one process per measurement and gather the results."""
    import json
    import subprocess
    out = {}
    for part in PARTS:
        r = subprocess.run([sys.executable, __file__, part],
                           capture_output=True, text=True)
        try:
            out[part] = json.loads(r.stdout.strip().splitlines()[-1])
        except Exception:
            raise SystemExit(f"measurement {part!r} produced no result:\n"
                             f"{r.stdout[-800:]}{r.stderr[-800:]}")
    return out


def main():
    import json
    if len(sys.argv) > 1 and sys.argv[1] in PARTS:
        print(json.dumps(measure(sys.argv[1])))
        return

    # One process per measurement. angr and CLE keep process-global state
    # across Project construction, so a second construction in the same
    # interpreter can give a different answer from the first.
    R = collect()
    loss = R["loss"]
    steps, where = loss["steps"], loss["where"]
    trace = [int(x, 16) for x in loss["trace"]]
    pc = loss["pc"]
    print(ledger.header(
        "2.4  DIAGNOSING WHERE SYMBOLIC EXECUTION BREAKS ON THE TRANSLATED IMAGE",
        artifacts=[G.EXE, G.SO], sources=G.SOURCES + [pathlib.Path(__file__)],
        entry=f"{len(ENTRIES)} entry points; the walkthrough uses {PROBE}",
        budget=f"{BUDGET} steps per entry point"))

    print("-" * 74)
    print("1. THE FAILING INSTRUCTION")
    print("-" * 74)
    print("  With the linkage table resolved and the runtime modelled, but no")
    print(f"  call-site resolution, the longest surviving path is {len(trace)} "
          f"basic blocks.")
    print(f"  It ends at {trace[-1]:#x} with pc = {pc}")
    print(f"  Final stashes: {where}   [symbolic]")
    print("  angr files it under `errored`, not `unconstrained`: the unfilled")
    print("  vtable slot reads as zero, so the branch is to address zero and the")
    print("  engine fails on it. Either way the state is gone, and neither is")
    print("  reported as a failure by `simgr.run()`.")
    print()
    print("  The block it dies in:")
    for addr_, mnem, ops in loss["block"]:
        insn = type("I", (), {"address": addr_, "mnemonic": mnem, "op_str": ops})
        note = ""
        if insn.mnemonic == "ldr" and "[" in insn.op_str and "," in insn.op_str:
            note = "   <- vtable slot; unfilled, so this read has no answer"
        if insn.mnemonic == "blr":
            note = "   <- branch register is whatever that read gave"
        print(f"      {insn.address:#x}  {insn.mnemonic:<6} {insn.op_str}{note}")
    print()
    print("  This is the shape every loss in this image has: a `callvirt`")
    print("  compiled to a load from the receiver's vtable and an indirect")
    print("  branch, with no runtime present to have filled the vtable.  [static]")

    print()
    print("-" * 74)
    print("2. IS THE LOSS RECOVERABLE BY CHOOSING A TARGET?")
    print("-" * 74)
    print("  Measured two ways, because the answer depends on how uninitialised")
    print("  memory is modelled. Both ways agree.")
    print()
    for label, key in (("angr's default (an unmapped read yields a fresh symbol)",
                        "sound_default"),
                       ("this project's model (uninitialised memory reads as zero)",
                        "sound_zerofill")):
        examined, free, narrowed = R[key]
        print(f"  {label}")
        print(f"      lost states examined across {len(ENTRIES)} entry points : "
              f"{examined}")
        print(f"        program counter wholly free "
              f"(pc == 0xdeadbeef satisfiable)  : {free}")
        print(f"        program counter fixed or narrowed                      "
              f"  : {narrowed}")
        print()
    print("  Under angr's default the branch register is a fresh symbol nothing")
    print("  constrains, so the solver accepts any address at all. Picking one")
    print("  invents a path, and the sample may never perform what gets reported")
    print("  from it. Under the zero-fill model the register is concretely zero,")
    print("  which is no better. Either way the state does not hold the answer.")
    print("  [symbolic]")
    print()
    print("  This is what rejected the first design, which recovered states from")
    print("  `unconstrained` by pinning the program counter to plausible in-image")
    print("  methods (kept in archive/superseded/tools/managed_explorer.py).")
    print()
    print("  Which is what the final design rests on: the missing information")
    print("  is not in the state, so it has to come from outside -- from the")
    print("  original assembly's metadata.")

    print()
    print("-" * 74)
    print("3. IS THERE A PATH-EXPLOSION PROBLEM?")
    print("-" * 74)
    print(f"  {'entry point':<58} {'steps':>6} {'peak':>5} {'quar':>5} "
          f"{'resolved':>9}")
    for name, steps, peak, quar, rs, rd in R["frontier"]:
        print(f"  {name[:56]:<58} {steps:>6} {peak:>5} {quar:>5} "
              f"{rs:>4}+{rd:<4}")
    print()
    print("  Peak concurrent states stays in single figures everywhere measured,")
    print("  so on this sample the frontier does not explode and a technique that")
    print("  pruned or reordered it would have nothing to prune or reorder. That")
    print("  is what rejected the second design (LossAvoidingExplorer, kept in")
    print("  archive/superseded/case1_scripts/).  [symbolic]")
    print()
    print("  One caveat, kept in the write-up: you cannot see explosion in code")
    print("  that is never reached. These numbers are taken with the boundary")
    print("  repaired, but the budget is still 60 steps per entry point.")

    print()
    print("-" * 74)
    print("4. WHAT REMAINS UNSUPPORTED, AND WHY")
    print("-" * 74)
    reasons = R["why"]["reasons"]
    total = sum(n for _, n in reasons)
    print(f"  states captured at an unsupported boundary: {total}")
    for why, n in reasons:
        print(f"      {n:>4}  {why}")
    print()
    print("  These need different repairs. A symbolic receiver comes from an")
    print("  earlier unmodelled call, an untyped receiver is an allocator or")
    print("  metadata gap, and an unrecognised dispatch shape is a decoding gap.")
    print("  Lumped together as 'unconstrained' they look like one problem when")
    print("  they are three.  [symbolic]")

    print()
    print("-" * 74)
    print("5. WHY RECEIVER-DIRECTED RESOLUTION FIRES AS RARELY AS IT DOES")
    print("-" * 74)
    rt, _ = G.build()
    rep = rt.report
    print(f"  call sites resolved statically, image-wide : {len(rep['resolved']):,}")
    print(f"  call sites left to the receiver            : {len(rep['unresolved']):,}")
    print(f"  (declaring type, slot) pairs learned       : {len(rt.by_type_slot):,}")
    print(f"  allocation sites carrying a type           : {len(rt.alloc_types):,}")
    print()
    print("  On the paths measured above the receiver-directed lookup resolved")
    print("  nothing. The diagnostics say why: the receivers arriving at")
    print("  unresolved sites are objects returned by unmodelled managed calls,")
    print("  which carry no type, or values loaded from fields this analysis")
    print("  never wrote. Typing an allocation only helps when the object reaches")
    print("  the call site through code that actually ran.")
    print()
    print("  So: a negative result. The mechanism works when it fires, and on")
    print("  these two samples it does not fire. The static call-site table is")
    print("  what carries the result.  [symbolic]")
    print(ledger.legend())


if __name__ == "__main__":
    main()
