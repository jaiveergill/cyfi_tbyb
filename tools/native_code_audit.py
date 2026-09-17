#!/usr/bin/env python3
"""
2.2 evidence: how much of a .NET PE is actually native code, and what exactly
breaks when angr is pointed at it.

Answers three questions that "angr has no CIL lifter" alone does not:
  1. what fraction of the file is x86 that angr could legitimately execute
  2. whether the PE loads at all, and if not, which relocation kills it
  3. whether the bytes at the entry point are decodable once it does load

    .venv/bin/python tools/native_code_audit.py <sample>
"""
import struct
import sys

import dnfile
import pefile


def rule(t):
    print(f"\n{'=' * 72}\n{t}\n{'=' * 72}")


def audit_native(path):
    pe = pefile.PE(path)
    dn = dnfile.dnPE(path)
    total = len(pe.__data__)

    rule("1. NATIVE CODE INVENTORY")

    # The CLI header tells us where the managed metadata lives.
    d14 = pe.OPTIONAL_HEADER.DATA_DIRECTORY[14]
    print(f"  file size                {total:,} B")
    print(f"  CLI header               rva {d14.VirtualAddress:#x} size {d14.Size}")

    # Every method body belonging to a TypeDef is CIL, not machine code.
    # A body whose header does not parse, or whose declared size exceeds the
    # file, is not readable statically -- on a packed sample the bodies have
    # been relocated into an encrypted section and the header bytes are
    # ciphertext. Those are counted separately rather than summed, because
    # summing ciphertext-derived sizes produces a meaningless total.
    secs = [(sec.VirtualAddress,
             sec.VirtualAddress + max(sec.Misc_VirtualSize, sec.SizeOfRawData),
             sec.Name.rstrip(b"\x00")) for sec in pe.sections]

    def section_of(rva):
        for lo, hi, nm in secs:
            if lo <= rva < hi:
                return nm
        return b"<unmapped>"

    import collections
    per_section = collections.Counter()
    readable = unreadable = 0
    bodies = 0
    for td in dn.net.mdtables.TypeDef.rows:
        for m in td.MethodList:
            row = m.row
            if row is None or not row.Rva:
                continue
            per_section[section_of(row.Rva)] += 1
            try:
                hdr = pe.get_data(row.Rva, 12)
            except Exception:
                unreadable += 1
                continue
            fmt = hdr[0] & 3
            if fmt == 2:
                size = 1 + (hdr[0] >> 2)
            elif fmt == 3:
                size = 12 + struct.unpack("<I", hdr[4:8])[0]
            else:
                unreadable += 1
                continue
            if size > total:
                unreadable += 1
                continue
            readable += 1
            bodies += size

    nmethods = readable + unreadable
    print(f"  method bodies            {nmethods} total")
    for nm, cnt in per_section.most_common():
        print(f"                             {cnt:>4} in section {nm!r}")
    print(f"  readable CIL             {readable} methods, {bodies:,} B")
    if unreadable:
        print(f"  UNREADABLE bodies        {unreadable} methods -- header does not"
              " parse or declares an impossible size")
        print("                           (bodies relocated into an encrypted"
              " section; ciphertext, not CIL)")

    # The only native code in a managed PE is the entry stub.
    ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    print(f"  entry point stub         rva {ep:#x}")
    try:
        import capstone
        mode = capstone.CS_MODE_64 if pe.FILE_HEADER.Machine == 0x8664 else capstone.CS_MODE_32
        md = capstone.Cs(capstone.CS_ARCH_X86, mode)
        stub = pe.get_data(ep, 16)
        insns = list(md.disasm(stub, pe.OPTIONAL_HEADER.ImageBase + ep))
        first = insns[0] if insns else None
        if first:
            print(f"    {first.mnemonic} {first.op_str}   ({first.size} bytes)")
            print(f"  NATIVE CODE TOTAL        {first.size} B "
                  f"= {100.0 * first.size / total:.6f}% of the file")
    except Exception as e:
        print(f"    <capstone: {e}>")

    execbytes = sum(s.SizeOfRawData for s in pe.sections
                    if s.Characteristics & 0x20000000)
    print(f"  bytes in X sections      {execbytes:,}  "
          f"(what CFGFast is asked to analyse)")
    print(f"  ratio                    1 native instruction per "
          f"{execbytes // max(first.size if first else 1, 1):,} executable bytes")


def audit_relocs(path):
    """Reproduce the read cle performs, using cle, not pefile.

    pefile will happily read past a section's mapped end straight out of the
    file buffer, so a pefile-based check reports every relocation as fine even
    when cle cannot service it. The failure only appears through cle's memory.
    """
    rule("2. RELOCATIONS AS CLE SEES THEM")
    import logging
    import angr
    logging.getLogger("angr").setLevel(logging.CRITICAL)
    logging.getLogger("cle").setLevel(logging.CRITICAL)

    pe = pefile.PE(path)
    pe.parse_data_directories()
    try:
        proj = angr.Project(path, auto_load_libs=False, perform_relocations=False)
    except Exception as e:
        print(f"  cannot load even without relocations: {type(e).__name__}: {e}")
        return
    base = proj.loader.main_object.mapped_base

    dirs = getattr(pe, "DIRECTORY_ENTRY_BASERELOC", [])
    if not dirs:
        print("  no relocation directory")
        return
    short = 0
    for block in dirs:
        for r in block.entries:
            if r.type == 0:
                continue
            va = base + r.rva
            got = proj.loader.memory.load(va, 4)
            seg = proj.loader.main_object.find_segment_containing(va)
            end = (seg.vaddr + seg.memsize) if seg else 0
            status = "OK" if len(got) == 4 else f"SHORT ({len(got)}/4)"
            if len(got) != 4:
                short += 1
            print(f"  rva {r.rva:#x} type {r.type}  va {va:#x}  segment ends {end:#x}"
                  f"  read {status}")
    if short:
        print(f"\n  {short} relocation(s) cannot be serviced by cle.")
        print("  cle does struct.unpack('<I', ...) on the result, so a short read")
        print("  raises struct.error inside Loader.__init__ -- angr.Project()")
        print("  never returns and no analysis is possible at all.")


def audit_entry(path):
    rule("3. ENTRY POINT AS ANGR SEES IT")
    import logging
    import angr
    logging.getLogger("angr").setLevel(logging.CRITICAL)
    logging.getLogger("cle").setLevel(logging.CRITICAL)
    kwargs = {"auto_load_libs": False}
    try:
        proj = angr.Project(path, **kwargs)
        print("  loaded with default options")
    except Exception as e:
        print(f"  default load failed: {type(e).__name__}: {e}")
        kwargs["perform_relocations"] = False
        proj = angr.Project(path, **kwargs)
        print("  loaded with perform_relocations=False")

    ep = proj.entry
    print(f"  entry {ep:#x}  {proj.loader.describe_addr(ep)}")
    seg = proj.loader.main_object.find_segment_containing(ep)
    print(f"  segment containing entry: {seg}")
    try:
        raw = proj.loader.memory.load(ep, 8)
        print(f"  bytes at entry via cle: {raw.hex()}")
    except Exception as e:
        print(f"  cle cannot read entry: {type(e).__name__}: {e}")
    blk = proj.factory.block(ep)
    print(f"  angr block: {blk.instructions} instruction(s), size {blk.size}")
    for i in blk.capstone.insns:
        print(f"    {i.address:#x}  {i.mnemonic} {i.op_str}")
    if blk.instructions == 0:
        print("  -> angr decodes nothing here, so the SimulationManager starts"
              "\n     with no steppable state at all.")


def _ledger_header(target):
    """The standard evidence header; see tools/ledger.py."""
    import pathlib as _p
    import sys as _s
    _s.path.insert(0, str(_p.Path(__file__).resolve().parent))
    import ledger as _l
    return _l.header("2.2  NATIVE-CODE INVENTORY", artifacts=[target], sources=[__file__])


def main():
    path = sys.argv[1]
    print(_ledger_header(path))
    print(f"sample: {path}")
    audit_native(path)
    audit_relocs(path)
    audit_entry(path)


if __name__ == "__main__":
    main()
