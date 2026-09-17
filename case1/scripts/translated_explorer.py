#!/usr/bin/env python3
"""
2.3 - Symbolic execution on the AOT-translated image.

Two runs against the same entry point, so that translation and runtime
modelling can be told apart:

  A. plain angr on the .so       -- machine code exists, but mono left the
                                    linkage table empty, so calls leaving a
                                    method branch through null
  B. the same, via aot_bridge    -- linkage table resolved, allocator modelled,
                                    unresolved runtime calls hooked
  C. the full runtime model      -- B plus GOT literals, object headers, throw
                                    helpers, typed allocation and String.Concat

Each stage adds one thing, and the step count says what it bought. None of the
three resolves an indirect call site; that is §2.4's subject, and the point of
stage C is to show how far modelling alone gets before the boundary is reached.

Symbolic emulation only; the sample is never executed.

    .venv/bin/python case1/scripts/translated_explorer.py
"""
import logging
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))

import angr           # noqa: E402
import aot_bridge as ab  # noqa: E402

logging.getLogger("angr").setLevel(logging.CRITICAL)
logging.getLogger("cle").setLevel(logging.CRITICAL)

SO = str(ROOT / "case1" / "samples" / "extracted" / "Win32.GravityRAT.exe.so")
ENTRY = ("LSASS_Networking_Agent_SendBasicInformation"
         "_System_Collections_Specialized_NameValueCollection")
STEPS = 50


def rule(title):
    print(f"\n{'=' * 68}\n{title}\n{'=' * 68}")


def explore(proj, label):
    syms = ab.aot_symbols(proj)
    if ENTRY not in syms:
        print(f"  {ENTRY} not in image"); return
    state = proj.factory.call_state(syms[ENTRY])
    simgr = proj.factory.simulation_manager(state)

    steps = 0
    while simgr.active and steps < STEPS:
        simgr.step()
        steps += 1

    print(f"\n[{label}]")
    print(f"  entry     {ENTRY}  {syms[ENTRY]:#x}")
    print(f"  steps run {steps} of {STEPS}")
    print(f"  stashes   {({k: len(v) for k, v in simgr.stashes.items() if v})}")

    # Where did the states end up? The last few blocks say where it broke.
    byaddr = {a: n for n, a in syms.items()}
    for stash in ("unconstrained", "errored", "deadended", "active"):
        for st in simgr.stashes.get(stash, [])[:1]:
            s = st.state if stash == "errored" else st
            trace = list(s.history.bbl_addrs)[-6:]
            print(f"  {stash}: {len(list(s.history.bbl_addrs))} blocks, last few:")
            for a in trace:
                print(f"      {a:#x}  {byaddr.get(a, proj.loader.describe_addr(a))}")
            if stash == "errored":
                print(f"      error: {st.error}")
    return simgr


def main():
    sys.path.insert(0, str(ROOT / "tools"))
    import ledger
    print(ledger.header(
        "2.3  WHAT TRANSLATION BUYS, AND WHERE IT STOPS",
        artifacts=[ROOT / "case1" / "samples" / "extracted" / "Win32.GravityRAT.exe",
                   SO],
        sources=[ROOT / "tools" / "aot_bridge.py",
                 ROOT / "tools" / "managed_runtime.py", __file__],
        entry=ENTRY, budget=f"{STEPS} steps"))

    rule("A. PLAIN angr ON THE TRANSLATED IMAGE")
    proj_a = angr.Project(SO, auto_load_libs=False)
    print(f"  arch {proj_a.arch}   {len(ab.aot_symbols(proj_a)):,} symbols")
    explore(proj_a, "no runtime modelling")

    rule("B. WITH aot_bridge RUNTIME MODELLING")
    proj_b = ab.load(SO)
    unres = ab.unresolved_plt(proj_b)
    allocs = ab.hook_allocators(proj_b)
    ab.hook_pure(proj_b, [n for n in unres if n not in allocs
                          and "plt_" + n not in allocs], retbits=64)
    print(f"  linkage table resolved; {len(unres)} unresolved runtime calls hooked, "
          f"{len(allocs)} allocator entries modelled")
    explore(proj_b, "linkage table resolved + runtime hooked")

    rule("C. WITH THE FULL RUNTIME MODEL (tools/managed_runtime.py)")
    import managed_runtime as mr
    rt = mr.ManagedRuntime(SO[:-3], SO)
    rt.install({})
    print(f"  {len(rt.literals)} string literals written into their GOT slots; "
          f"{len(rt.alloc_types)} allocation sites typed;")
    print("  per-object headers, throw helpers and String.Concat modelled")
    simgr = rt.proj.factory.simulation_manager(
        rt.entry_state(rt.address_of(ENTRY)))
    steps = 0
    while simgr.active and steps < STEPS:
        simgr.step()
        steps += 1
    print("\n[full runtime model, no call-site resolution]")
    print(f"  steps run {steps} of {STEPS}")
    print(f"  stashes   {({k: len(v) for k, v in simgr.stashes.items() if v})}"
          f"   errored {len(getattr(simgr, 'errored', []))}")
    print()
    print("  Modelling alone gets the state into the method and no further: the")
    print("  first `callvirt` is an indirect branch through a vtable that does")
    print("  not exist, and no amount of modelling the *callee* helps, because")
    print("  the problem is not knowing which callee it is.  [symbolic]")


if __name__ == "__main__":
    main()
