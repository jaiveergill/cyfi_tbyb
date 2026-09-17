#!/usr/bin/env python3
"""
2.3 - Tools used: CIL disassembler for .NET methods.

angr cannot lift CIL, monodis aborts on this sample's obfuscated metadata, and
de4dot needs a .NET SDK. This reads method bodies straight out of the PE with
dnfile + dncil, so it has no dependency on a CLR being present.

    .venv/bin/python tools/cil_disasm.py <assembly> [--type NAME] [--method NAME]

--type and --method are substring matches; with neither, every method in every
type is listed.
"""
import argparse
import sys

import dnfile
from dncil.cil.body import CilMethodBody
from dncil.cil.body.reader import CilMethodBodyReaderBase
from dncil.cil.error import MethodBodyFormatError
from dncil.clr.token import Token, StringToken


class DnfileMethodBodyReader(CilMethodBodyReaderBase):
    """Feeds raw bytes from the PE at a MethodDef's RVA into dncil."""

    def __init__(self, pe, row):
        self.pe = pe
        self.offset = self.pe.get_offset_from_rva(row.Rva)

    def read(self, n):
        data = self.pe.get_data(self.pe.get_rva_from_offset(self.offset), n)
        self.offset += n
        return data

    def tell(self):
        return self.offset

    def seek(self, offset):
        self.offset = offset
        return self.offset


def build_token_map(pe):
    """token value -> metadata row, for every table row.

    MethodDef rows carry only a method name, which is ambiguous across an
    assembly -- three unrelated types here each declare a `Start`. Each TypeDef
    owns a contiguous run of MethodDef rows, so walking the TypeDef table once
    tags every MethodDef with its declaring type, and a resolved `call` reads
    `LSASS.Jobs.DriveScan::Start` instead of `Start`.
    """
    tokens = {}
    for table in pe.net.mdtables.tables.values():
        if table is None:
            continue
        for rid, row in enumerate(table.rows, 1):
            tokens[(table.number << 24) | rid] = row
    for td in pe.net.mdtables.TypeDef:
        ns = str(td.TypeNamespace or "")
        tn = str(td.TypeName or "")
        owner = ".".join(p for p in (ns, tn) if p)
        for md in td.MethodList:
            if md.row is not None:
                try:
                    md.row._owner = owner
                except Exception:
                    pass
    return tokens


def describe_row(row):
    cls = row.__class__.__name__
    # TypeRef/TypeDef name themselves with TypeNamespace + TypeName, not Name.
    tn = getattr(row, "TypeName", None)
    if tn is not None:
        ns = str(getattr(row, "TypeNamespace", "") or "")
        return ".".join(p for p in (ns, str(tn)) if p)
    name = getattr(row, "Name", None)
    if name is None:
        return cls
    name = str(name)
    own = getattr(row, "_owner", None)
    if own:
        return f"{cls} {own}::{name}"
    # MemberRef / TypeRef carry a parent that gives the call its meaning.
    parent = getattr(row, "Class", None) or getattr(row, "ResolutionScope", None)
    target = getattr(parent, "row", None) if parent is not None else None
    if target is not None:
        ns = str(getattr(target, "TypeNamespace", "") or "")
        tn = str(getattr(target, "TypeName", "") or getattr(target, "Name", "") or "")
        owner = ".".join(p for p in (ns, tn) if p)
        if owner:
            return f"{cls} {owner}::{name}"
    return f"{cls} {name}"


def resolve(tokens, pe, token):
    if isinstance(token, StringToken):
        try:
            return '"%s"' % pe.net.user_strings.get(token.rid).value
        except Exception as e:
            return f"string#{token.rid} <{e.__class__.__name__}>"
    row = tokens.get(token.value)
    if row is None:
        return f"token(0x{token.value:08x})"
    return describe_row(row)


def read_body(pe, row):
    try:
        return CilMethodBody(DnfileMethodBodyReader(pe, row))
    except MethodBodyFormatError as e:
        return e


def format_body(pe, tokens, body):
    lines = []
    for insn in body.instructions:
        operand = insn.operand
        if isinstance(operand, Token):
            text = resolve(tokens, pe, operand)
        elif operand is None:
            text = ""
        else:
            text = str(operand)
        lines.append(
            f"    {insn.offset - body.offset:04X}  {insn.opcode.name:<12} {text}"
        )
    return lines


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("assembly")
    ap.add_argument("--type", dest="typename", help="substring match on TypeDef name")
    ap.add_argument("--method", dest="method", help="substring match on method name")
    args = ap.parse_args()

    pe = dnfile.dnPE(args.assembly)
    tokens = build_token_map(pe)

    for td in pe.net.mdtables.TypeDef:
        full = ".".join(
            p for p in (str(td.TypeNamespace or ""), str(td.TypeName or "")) if p
        )
        if args.typename and args.typename not in full:
            continue
        print(f"\n// ===== type {full} =====")
        for md in td.MethodList:
            row = md.row
            if row is None:
                continue
            name = str(row.Name)
            if args.method and args.method not in name:
                continue
            print(f"\n.method {name}  // rva=0x{row.Rva:x}")
            if not row.Rva:
                print("    <abstract or pinvoke: no body>")
                continue
            body = read_body(pe, row)
            if isinstance(body, MethodBodyFormatError):
                print(f"    <unreadable: {body}>")
                continue
            print(
                f"    // code size {body.code_size} bytes, "
                f"maxstack {body.max_stack}, {len(body.instructions)} instructions"
            )
            for line in format_body(pe, tokens, body):
                print(line)


if __name__ == "__main__":
    sys.exit(main())
