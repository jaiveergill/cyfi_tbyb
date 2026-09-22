#!/usr/bin/env python3
"""
2.2 - Default explorer failure on Win32.GravityRAT.

Runs angr's default (BFS) and DFS explorers from the entry point and measures
how far each gets. Symbolic emulation only; the sample is never executed.

    .venv/bin/python case1/scripts/default_explorer.py
"""
import logging
import pathlib

import angr
import dnfile
import pefile

# Resolve the sample against the repository root rather than the working
# directory, so the script runs the same from anywhere.
ROOT = pathlib.Path(__file__).resolve().parents[2]
SAMPLE = str(ROOT / "case1" / "samples" / "extracted" / "Win32.GravityRAT.exe")

logging.getLogger("angr").setLevel(logging.ERROR)
logging.getLogger("cle").setLevel(logging.ERROR)


def rule(title):
    print(f"\n{'=' * 68}\n{title}\n{'=' * 68}")


def explore(proj, technique, label):
    """Run one explorer to completion and report the block trace."""
    simgr = proj.factory.simulation_manager(proj.factory.entry_state())
    if technique:
        simgr.use_technique(technique)
    simgr.run()

    print(f"\n[{label}]")
    print("  stashes:", {k: len(v) for k, v in simgr.stashes.items() if v})
    for stash, states in simgr.stashes.items():
        for st in states:
            blocks = list(st.history.bbl_addrs)
            print(f"  {stash}: {len(blocks)} basic blocks, jumpkind {st.history.jumpkind}")
            for addr in blocks:
                who = f"  hooked by {proj.hooked_by(addr)}" if proj.is_hooked(addr) else ""
                print(f"    {addr:#x}  {proj.loader.describe_addr(addr)}{who}")
    return simgr


def main():
    import sys as _s
    _s.path.insert(0, str(ROOT / "tools"))
    import ledger
    print(ledger.header("2.2  THE DEFAULT EXPLORER ON THE ORIGINAL PE",
                        artifacts=[SAMPLE], sources=[__file__],
                        entry="the PE entry point", budget="50 steps"))
    proj = angr.Project(SAMPLE, auto_load_libs=False)

    rule("TARGET")
    print(f"  {SAMPLE}")
    print(f"  arch {proj.arch}   entry {proj.entry:#x}")
    block = proj.factory.block(proj.entry)
    print(f"\n  entry block is {block.instructions} instruction(s):")
    for insn in block.capstone.insns:
        print(f"    {insn.address:#x}  {insn.mnemonic} {insn.op_str}")

    # Breadth-first against depth-first: search order is the only thing an
    # ExplorationTechnique controls.
    rule("1. DEFAULT (BFS) vs DFS")
    explore(proj, None, "default BFS")
    explore(proj, angr.exploration_techniques.DFS(), "DFS")

    rule("2. CFG COVERAGE")
    cfg = proj.analyses.CFGFast()
    executable = sum(s.memsize for obj in proj.loader.all_objects
                     for s in getattr(obj, "sections", []) if s.is_executable)
    print(f"  functions {len(cfg.kb.functions)}   nodes {cfg.graph.number_of_nodes()}"
          f"   edges {cfg.graph.number_of_edges()}")
    print(f"  executable bytes in the image: {executable:,}")
    for addr, fn in cfg.kb.functions.items():
        print(f"    {addr:#x}  {fn.name}")

    # How much of the file is machine code at all? The entry stub is a single
    # 6-byte jmp; everything else in .text is CIL method bodies.
    rule("3. HOW MUCH OF THIS IS NATIVE CODE?")
    pe = pefile.PE(SAMPLE)
    text = next(s for s in pe.sections if s.Name.startswith(b".text"))
    dn = dnfile.dnPE(SAMPLE)
    bodies = sum(1 for t in dn.net.mdtables.TypeDef.rows
                 for m in t.MethodList if m.row is not None and m.row.Rva)
    native = proj.factory.block(proj.entry).size
    print(f"  .text raw size      {text.SizeOfRawData:,} B")
    print(f"  CIL method bodies   {bodies}")
    print(f"  native code         {native} B  "
          f"({100 * native / text.SizeOfRawData:.6f}% of .text)")
    print(f"  ratio               1 native instruction per "
          f"{text.SizeOfRawData // max(native, 1):,} bytes of .text")


if __name__ == "__main__":
    main()
