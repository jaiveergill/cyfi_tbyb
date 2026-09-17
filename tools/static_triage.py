#!/usr/bin/env python3
"""
2.1 - Static triage of a .NET PE. Parse-only; the sample is never executed.

    .venv/bin/python tools/static_triage.py <sample>
"""
import collections
import hashlib
import math
import pathlib
import re
import sys

import dnfile
import pefile


def rule(t):
    print(f"\n{'=' * 72}\n{t}\n{'=' * 72}")


def entropy(b):
    if not b:
        return 0.0
    c = collections.Counter(b)
    n = len(b)
    return -sum((v / n) * math.log2(v / n) for v in c.values())


def _ledger_header(target):
    """The standard evidence header; see tools/ledger.py."""
    import pathlib as _p
    import sys as _s
    _s.path.insert(0, str(_p.Path(__file__).resolve().parent))
    import ledger as _l
    return _l.header("2.1  STATIC TRIAGE", artifacts=[target], sources=[__file__])


def main():
    path = pathlib.Path(sys.argv[1])
    print(_ledger_header(path))
    data = path.read_bytes()

    rule("IDENTITY")
    print(f"  path        {path}")
    print(f"  size        {len(data):,} bytes")
    for algo in ("md5", "sha1", "sha256"):
        print(f"  {algo:<11} {hashlib.new(algo, data).hexdigest()}")

    pe = pefile.PE(data=data)
    mach = {0x14C: "x86 (32-bit)", 0x8664: "x86-64", 0x1C0: "ARM"}.get(
        pe.FILE_HEADER.Machine, hex(pe.FILE_HEADER.Machine))
    d14 = pe.OPTIONAL_HEADER.DATA_DIRECTORY[14]
    print(f"  machine     {mach}")
    print(f"  entry RVA   {pe.OPTIONAL_HEADER.AddressOfEntryPoint:#x}")
    print(f"  image base  {pe.OPTIONAL_HEADER.ImageBase:#x}")
    print(f"  CLI header  rva {d14.VirtualAddress:#x} size {d14.Size}"
          f"   -> {'.NET assembly' if d14.VirtualAddress else 'NATIVE (not .NET)'}")

    rule("SECTIONS")
    for s in pe.sections:
        nm = s.Name.rstrip(b"\x00").decode(errors="replace")
        body = s.get_data()
        print(f"  {nm:<10} vaddr {s.VirtualAddress:#010x}  raw {s.SizeOfRawData:>9,} B"
              f"  entropy {entropy(body):.2f}"
              f"  {'X' if s.Characteristics & 0x20000000 else ' '}")

    rule("NATIVE IMPORTS")
    try:
        pe.parse_data_directories()
        for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
            dll = entry.dll.decode(errors="replace")
            names = [i.name.decode(errors="replace") for i in entry.imports if i.name]
            print(f"  {dll}: {', '.join(names) if names else '(ordinals)'}")
    except Exception as e:
        print(f"  <none / {e}>")

    rule("ENTRY POINT")
    try:
        import capstone
        ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        code = pe.get_data(ep, 16)
        mode = capstone.CS_MODE_64 if pe.FILE_HEADER.Machine == 0x8664 else capstone.CS_MODE_32
        md = capstone.Cs(capstone.CS_ARCH_X86, mode)
        for i in list(md.disasm(code, pe.OPTIONAL_HEADER.ImageBase + ep))[:3]:
            print(f"  {i.address:#x}  {i.mnemonic} {i.op_str}")
    except Exception as e:
        print(f"  <{e}>")

    dn = dnfile.dnPE(str(path))
    md = dn.net.mdtables

    rule("ASSEMBLY REFERENCES (runtime dependencies)")
    for r in getattr(md, "AssemblyRef", None).rows if getattr(md, "AssemblyRef", None) else []:
        v = f"{r.MajorVersion}.{r.MinorVersion}.{r.BuildNumber}.{r.RevisionNumber}"
        print(f"  {str(r.Name):<32} {v}")

    rule("TYPEDEFS (code in this assembly)")
    for td in md.TypeDef.rows:
        full = ".".join(p for p in (str(td.TypeNamespace or ""), str(td.TypeName or "")) if p)
        methods = [str(m.row.Name) for m in td.MethodList if m.row is not None]
        print(f"  {full}")
        if methods:
            print(f"      {len(methods)} method(s): {', '.join(methods[:12])}"
                  f"{' ...' if len(methods) > 12 else ''}")

    rule("TYPEREFS (external API surface)")
    ns = collections.Counter()
    for tr in md.TypeRef.rows:
        ns[str(tr.TypeNamespace or "<none>")] += 1
    for n, c in ns.most_common(24):
        print(f"  {c:>4}  {n}")

    rule("CAPABILITY INDICATORS IN TYPEREFS")
    want = ("Net", "Sockets", "Http", "Cryptography", "IO", "Registry", "Diagnostics",
            "Reflection", "Threading", "Management", "Forms", "InteropServices")
    for w in want:
        hits = sorted({f"{tr.TypeNamespace}.{tr.TypeName}"
                       for tr in md.TypeRef.rows if w in str(tr.TypeNamespace or "")})
        print(f"  {w:<16} {len(hits):>3}" + (f"  e.g. {hits[0]}" if hits else ""))

    rule("MANIFEST RESOURCES / FIELD RVA")
    mr = getattr(md, "ManifestResource", None)
    print(f"  ManifestResource rows: {len(mr.rows) if mr else 0}")
    for r in (mr.rows if mr else []):
        print(f"    {str(r.Name)}")
    fr = getattr(md, "FieldRva", None)
    print(f"  FieldRva rows: {len(fr.rows) if fr else 0}   "
          f"({'embedded byte arrays present' if fr and fr.rows else 'no field-initialised blobs'})")

    rule("STRINGS")
    printable = re.findall(rb"[\x20-\x7e]{8,}", data)
    uniq = {s for s in printable}
    print(f"  ascii runs >=8 chars: {len(printable):,}  unique: {len(uniq):,}")
    us = dn.net.user_strings
    n_us = 0
    if us:
        try:
            i = 1
            while i < us.sizeof():
                s = us.get(i)
                if s is None:
                    break
                n_us += 1
                i += max(1, len(s.raw_data) if hasattr(s, "raw_data") else 2)
        except Exception:
            pass
    print(f"  #US heap size: {us.sizeof() if us else 0:,} bytes")


if __name__ == "__main__":
    main()
