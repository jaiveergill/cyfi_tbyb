#!/usr/bin/env python3
"""
Map each AOT-translated method to the runtime APIs it calls.

mono's AOT output routes every call through a named PLT entry, so a static
sweep of each method body for direct branches into the PLT recovers a call
graph from translated managed code to the base class library. Calls that leave
the assembly appear as unresolved PLT entries and are exactly the behaviours
worth choosing as symbolic execution goals.

    .venv/bin/python tools/aot_behaviour_map.py <image.so> [--category REGEX]
"""
import argparse
import collections
import os
import re
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", "tools"))
sys.path.insert(0, "tools")

import logging
logging.getLogger("angr").setLevel(logging.CRITICAL)
logging.getLogger("cle").setLevel(logging.CRITICAL)

import aot_bridge as ab

CATEGORIES = {
    "anti-analysis": r"EnterDebugMode|NtSetInformationProcess|GetProcessesByName|"
                     r"IsDebuggerPresent|CheckRemoteDebugger|GetCurrentProcess",
    "network":       r"UdpClient|WebClient|WebRequest|Socket|Dns|TcpClient",
    "cryptography":  r"Aes|Rijndael|RNGCrypto|DeriveBytes|CryptoStream|MD5|SHA",
    "process":       r"OpenProcess|ReadProcessMemory|WriteProcessMemory|Process_Start|"
                     r"GetProcesses|ProcessStartInfo",
    "filesystem":    r"System_IO_File|System_IO_Directory|System_IO_Path|CreateFile|WriteFile",
}


def method_calls(proj, lo, hi, plt_names):
    """Names of PLT entries directly branched to from [lo, hi)."""
    out = []
    a = lo
    while a < hi:
        try:
            blk = proj.factory.block(a)
        except Exception:
            break            # synthetic end can run past mapped memory
        if blk.size == 0:
            break
        for insn in blk.capstone.insns:
            if insn.mnemonic == "bl":
                try:
                    tgt = int(insn.op_str.replace("#", ""), 16)
                except ValueError:
                    continue
                nm = plt_names.get(tgt)
                if nm:
                    out.append(nm)
        a += blk.size
    return out


def _ledger_header(target):
    """The standard evidence header; see tools/ledger.py."""
    import pathlib as _p
    import sys as _s
    _s.path.insert(0, str(_p.Path(__file__).resolve().parent))
    import ledger as _l
    return _l.header("2.5  TRANSLATED METHOD -> RUNTIME API MAP", artifacts=[target], sources=[__file__])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("image")
    ap.add_argument("--category", default=None)
    args = ap.parse_args()
    print(_ledger_header(args.image))

    proj = ab.load(args.image)
    syms = ab.aot_symbols(proj)
    unres = ab.unresolved_plt(proj)

    plt_names = {}
    for name, addr in syms.items():
        if name.startswith("plt_"):
            plt_names[addr] = name[4:]

    methods = sorted(
        ((n, a) for n, a in syms.items()
         if not n.startswith("plt_") and "wrapper" not in n and "jit_icall" not in n),
        key=lambda kv: kv[1])

    bounds = []
    for i, (n, a) in enumerate(methods):
        end = methods[i + 1][1] if i + 1 < len(methods) else a + 0x400
        bounds.append((n, a, end))

    print(f"image: {args.image}")
    print(f"  translated methods      {len(methods)}")
    print(f"  unresolved runtime calls {len(unres)}")

    hits = collections.defaultdict(list)
    for name, lo, hi in bounds:
        calls = method_calls(proj, lo, hi, plt_names)
        for cat, pattern in CATEGORIES.items():
            matched = sorted({c for c in calls if re.search(pattern, c)})
            if matched:
                hits[cat].append((name, lo, matched))

    for cat in CATEGORIES:
        entries = hits.get(cat, [])
        print(f"\n{'=' * 72}\n{cat.upper()}  --  {len(entries)} method(s)\n{'=' * 72}")
        if args.category and args.category != cat:
            print("  (suppressed)")
            continue
        for name, addr, calls in entries:
            print(f"  {addr:#x}  {name}")
            for c in calls:
                print(f"             -> {c}")


if __name__ == "__main__":
    main()
