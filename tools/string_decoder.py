#!/usr/bin/env python3
"""
2.3 - recover a .NET assembly's obfuscated string layer.

Samples that keep their strings in the #US heap but store them encoded defeat a
plain `strings` pass: the literals are present and readable as bytes, but carry
no meaning until decoded. This walks the heap, attempts each supported encoding
on every literal, and reports the ones that yield printable text.

Decoding is pure parsing. The sample is never executed.

    .venv/bin/python tools/string_decoder.py <assembly> [--all] [--min N]
"""
import argparse
import base64
import binascii
import re

import dnfile

# Grouped on the same axes as tools/aot_behaviour_map.py so that a decoded
# literal can be lined up against the runtime API that consumes it.
CATEGORIES = [
    ("ANALYSIS TOOLS", re.compile(
        r"ollydbg|x32dbg|x64dbg|dnspy|de4dot|ilspy|dotpeek|megadumper|"
        r"processhacker|procexp|pe-sieve|protection_id|lordpe|cff explorer|"
        r"rdg packer|nofuserex|unconfuserex|universal_fixer|windbg|immunity", re.I)),
    ("NETWORK CAPTURE TOOLS", re.compile(
        r"wireshark|tcpdump|dumpcap|fiddler|networkminer|intercepter|"
        r"httpnetworksniffer|http sniffer|iewatch|firesheep|tcpview|"
        r"networktrafficview|http analyzer", re.I)),
    ("CRYPTOGRAPHIC MATERIAL", re.compile(r"RSAKeyValue|<Modulus>|BEGIN .*KEY|AQAB")),
    ("RANSOM NOTE", re.compile(
        r"your files|Key Identifier|Client IP|Client Unique|Date of encryption|"
        r"Number of files|BTC Wallet|bitcoin|ransom", re.I)),
    ("SHADOW COPY / BACKUP", re.compile(
        r"vssadmin|shadowstorage|delete shadows|wbadmin|bcdedit|fsutil|"
        r"\*\.bak|\*\.vhd|\*\.bkf", re.I)),
    ("SERVICE CONTROL", re.compile(r"^\s*(stop|config) \S|taskkill|/IM |sc\.exe", re.I)),
    ("DEFENCE EVASION", re.compile(
        r"Set-MpPreference|ControlledFolderAccess|Defender|LegalNotice|"
        r"ProcessHide|paexec", re.I)),
    ("NETWORK ENDPOINTS", re.compile(r"https?://|\.onion|icanhazip|\d+\.\d+\.\d+\.\d+")),
]


def try_decode(s):
    """Return (scheme, plaintext) for the first encoding that yields text."""
    if len(s) >= 8 and len(s) % 4 == 0 and re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", s):
        try:
            out = base64.b64decode(s, validate=True).decode("utf-8")
            if out.isprintable() or "\n" in out:
                return "base64", out
        except (binascii.Error, UnicodeDecodeError):
            pass
    if len(s) >= 8 and len(s) % 2 == 0 and re.fullmatch(r"[0-9a-fA-F]+", s):
        try:
            out = bytes.fromhex(s).decode("utf-8")
            if out.isprintable():
                return "hex", out
        except (ValueError, UnicodeDecodeError):
            pass
    return None, None


def user_strings(pe):
    """Every literal in the #US heap, walked by its length prefix."""
    heap = pe.net.user_strings
    data = heap.__data__
    out, off = [], 1
    while off < len(data):
        b0 = data[off]
        if b0 & 0x80 == 0:
            size, hdr = b0, 1
        elif b0 & 0xC0 == 0x80:
            size, hdr = ((b0 & 0x3F) << 8) | data[off + 1], 2
        else:
            size = ((b0 & 0x1F) << 24) | (data[off + 1] << 16) | \
                   (data[off + 2] << 8) | data[off + 3]
            hdr = 4
        off += hdr
        if size == 0 or off + size > len(data):
            off += max(size, 1)
            continue
        try:
            out.append(data[off:off + size - 1].decode("utf-16-le"))
        except UnicodeDecodeError:
            pass
        off += size
    return out


def _ledger_header(target):
    """The standard evidence header; see tools/ledger.py."""
    import pathlib as _p
    import sys as _s
    _s.path.insert(0, str(_p.Path(__file__).resolve().parent))
    import ledger as _l
    return _l.header("2.3  THE #US LITERAL HEAP, DECODED", artifacts=[target], sources=[__file__])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("assembly")
    ap.add_argument("--all", action="store_true",
                    help="also list literals that are already plaintext")
    ap.add_argument("--min", type=int, default=4, metavar="N",
                    help="ignore decoded results shorter than N characters")
    args = ap.parse_args()
    print(_ledger_header(args.assembly))

    pe = dnfile.dnPE(args.assembly)
    lits = sorted(set(user_strings(pe)))

    decoded = []
    for s in lits:
        scheme, out = try_decode(s)
        if out and len(out) >= args.min:
            decoded.append((scheme, s, out))

    print(f"assembly: {args.assembly}")
    print(f"  #US heap literals   {len(lits)}")
    print(f"  decoded             {len(decoded)}")
    by_scheme = {}
    for scheme, _, _ in decoded:
        by_scheme[scheme] = by_scheme.get(scheme, 0) + 1
    for scheme, n in sorted(by_scheme.items()):
        print(f"    {scheme:<8} {n}")

    claimed = set()
    for title, rx in CATEGORIES:
        hits = sorted({out for _, _, out in decoded if rx.search(out)} - claimed)
        if not hits:
            continue
        claimed |= set(hits)
        print(f"\n{'=' * 72}\n{title}  --  {len(hits)}\n{'=' * 72}")
        for h in hits:
            print(f"  {h}")

    rest = sorted({out for _, _, out in decoded} - claimed)
    if rest:
        print(f"\n{'=' * 72}\nUNCATEGORISED  --  {len(rest)}\n{'=' * 72}")
        for h in rest:
            print(f"  {h}")

    if args.all:
        plain = sorted({s for s in lits if not try_decode(s)[1]})
        print(f"\n{'=' * 72}\nPLAINTEXT LITERALS  --  {len(plain)}\n{'=' * 72}")
        for p in plain:
            print(f"  {p}")


if __name__ == "__main__":
    main()
