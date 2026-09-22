#!/usr/bin/env python3
"""
2.2 - Run angr's default explorers on a .NET sample and record where they stop.

Symbolic emulation only; the sample is never executed natively.

    .venv/bin/python tools/default_explorer_failure.py <sample>
"""
import logging
import sys

import angr
import capstone
import dnfile


class Capture(logging.Handler):
    def __init__(self):
        super().__init__()
        self.records = []

    def emit(self, r):
        self.records.append((r.levelno, f"{r.name}: {r.getMessage()}"))


def rule(t):
    print(f"\n{'=' * 72}\n{t}\n{'=' * 72}")


def run(proj, tech, label):
    st = proj.factory.entry_state()
    simgr = proj.factory.simulation_manager(st)
    if tech:
        simgr.use_technique(tech)
    simgr.run()
    print(f"\n[{label}]")
    print(f"  stashes: {({k: len(v) for k, v in simgr.stashes.items() if v})}")
    for stash, states in simgr.stashes.items():
        for s in states:
            blocks = list(s.history.bbl_addrs)
            print(f"  {stash}: {len(blocks)} basic blocks   jumpkind {s.history.jumpkind}")
            print(f"    trace {[hex(b) for b in blocks]}")
            for a in blocks:
                extra = f"  hooked by {proj.hooked_by(a)}" if proj.is_hooked(a) else ""
                print(f"    {a:#x}  {proj.loader.describe_addr(a)}{extra}")


def main():
    sample = sys.argv[1]
    sys.path.insert(0, __file__.rsplit("/", 1)[0])
    import ledger
    print(ledger.header("2.2  THE DEFAULT EXPLORER ON THE ORIGINAL PE",
                        artifacts=[sample], sources=[__file__],
                        entry="the PE entry point", budget="50 steps"))
    cap = Capture()
    for n in ("cle", "angr"):
        lg = logging.getLogger(n)
        lg.addHandler(cap)
        lg.setLevel(logging.INFO)
    logging.getLogger().setLevel(logging.WARNING)

    rule("TARGET")
    print(f"  {sample}")

    # Some packed .NET samples cannot be loaded at all: CLE's PE relocation
    # handling throws before a Project exists. Recorded, then worked around.
    load_kwargs = {"auto_load_libs": False}
    try:
        proj = angr.Project(sample, **load_kwargs)
        print("  default load: OK")
    except Exception as e:
        print(f"  default load: FAILED -- {type(e).__name__}: {e}")
        print("    angr could not construct a Project at all.")
        load_kwargs["perform_relocations"] = False
        proj = angr.Project(sample, **load_kwargs)
        print("  retry with perform_relocations=False: OK")
    print(f"  arch {proj.arch}  entry {proj.entry:#x}  opts {load_kwargs}")
    blk = proj.factory.block(proj.entry)
    print(f"\n  entry block, {blk.instructions} instruction(s):")
    for i in blk.capstone.insns:
        print(f"    {i.address:#x}  {i.mnemonic} {i.op_str}")

    rule("1. DEFAULT (BFS) AND DFS")
    run(proj, None, "default BFS")
    run(proj, angr.exploration_techniques.DFS(), "DFS")
    print("\n  identical -> not a search-strategy failure")

    rule("2. CFG COVERAGE")
    # The warnings CFGFast raises are reported here rather than left on
    # stderr.
    cap.records.clear()
    cfg = proj.analyses.CFGFast()
    for lvl, r in cap.records:
        if lvl >= logging.WARNING:
            print(f"  {r}")
    ex = sum(s.memsize for o in proj.loader.all_objects
             for s in getattr(o, "sections", []) if s.is_executable)
    print(f"  functions {len(cfg.kb.functions)}  nodes {cfg.graph.number_of_nodes()}"
          f"  edges {cfg.graph.number_of_edges()}  executable bytes {ex:,}")
    for a, f in cfg.kb.functions.items():
        print(f"    {a:#x}  {f.name}")

    rule("3. LOADER OUTPUT, auto_load_libs=True")
    cap.records.clear()
    try:
        angr.Project(sample, auto_load_libs=True,
                     perform_relocations=load_kwargs.get("perform_relocations", True))
    except Exception as e:
        print(f"  <load failed: {type(e).__name__}: {e}>")
    for _, r in cap.records:
        print(f"  {r}")

    rule("4. IS .text ACTUALLY x86?")
    pe = dnfile.dnPE(sample)
    td = pe.net.mdtables.TypeDef
    rva = next((m.row.Rva for t in td.rows for m in t.MethodList
                if m.row is not None and m.row.Rva), 0)
    if rva:
        data = pe.get_data(rva, 32)
        print(f"  bytes at first method body rva {rva:#x}:")
        print("    " + " ".join(f"{b:02x}" for b in data))
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        print("\n  as x86:")
        for i in list(md.disasm(data, pe.OPTIONAL_HEADER.ImageBase + rva))[:8]:
            print(f"    {i.address:#010x}  {i.mnemonic:<7} {i.op_str}")
        # CIL method headers come in two shapes and they are read differently.
        # Tiny (low 2 bits == 2) packs the code size into the top 6 bits of the
        # single header byte; fat (low 2 bits == 3) is a 12-byte structure.
        fmt = data[0] & 3
        if fmt == 2:
            print(f"\n  as a CIL method header: TINY  code size {data[0] >> 2} bytes"
                  f"  (header is 1 byte)")
        elif fmt == 3:
            ms = int.from_bytes(data[2:4], "little")
            cs = int.from_bytes(data[4:8], "little")
            print(f"\n  as a CIL method header: FAT  maxstack {ms}  code size {cs} bytes"
                  f"  (header is 12 bytes)")
        else:
            print(f"\n  as a CIL method header: unrecognised format bits {fmt}")


if __name__ == "__main__":
    main()
