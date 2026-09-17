#!/usr/bin/env python3
"""
2.3 - Call-site resolution: which managed method does each indirect call in the
AOT image actually invoke?

Mono compiles a CIL `callvirt` on a virtual or interface method into an
indirect branch through the receiver's vtable:

    ldr x1, [x1]          ; receiver -> vtable
    ldr x16, [x1, #0x108] ; vtable slot -> callee
    blr x16

With no mono runtime present the vtable pointer is whatever the allocator left
in the object header, so the slot read comes from unmapped memory and the
branch register is symbolic. angr files the state under 'unconstrained' and
drops it. Supplying a *universal* vtable (every slot -> one stub) keeps the
state alive but is wrong: slot +0x108 then means `NameValueCollection.Add` on
every object in the program, whatever its type.

This module recovers the real target of each site from evidence in the two
artifacts that are already on disk:

  * the AOT image gives, for every method body, the ordered sequence of calls
    it makes - direct ones (`bl plt_FOO`, where the symbol names the callee)
    and indirect ones (`blr`, where it does not, but the slot offset is
    visible);
  * the original PE's metadata gives, for the same method, the ordered sequence
    of CIL call/callvirt/newobj instructions with their resolved targets.

Direct calls appear in both and carry a name, so they are *anchors*. Aligning
the two sequences on the anchors leaves the indirect sites confined to gaps
between consecutive anchors; when a gap holds exactly as many indirect sites as
it holds unmatched CIL virtual calls, the pairing inside it is forced and each
site's callee is determined. Gaps where the counts disagree are reported
unresolved rather than guessed.

Two independent checks are run on the result:

  * slot consistency - every site resolved to the same callee must read the
    same vtable slot, across every method in the image. A wrong alignment
    shows up as one callee with several slots.
  * allocation provenance - `newobj` anchors give each allocation site the
    managed type it constructs, so a receiver's type can be checked at run
    time against the type the call site expects.

    .venv/bin/python tools/callsite_map.py <assembly.exe> [--method SUBSTR] [--json OUT]
"""
from __future__ import annotations

import argparse
import collections
import json
import logging
import re
import sys

sys.path.insert(0, __file__.rsplit("/", 1)[0])

logging.getLogger("angr").setLevel(logging.CRITICAL)
logging.getLogger("cle").setLevel(logging.CRITICAL)

# Mono emits these around managed calls; they have no CIL instruction of their
# own, so they must not be treated as anchors.
RUNTIME_PREFIXES = (
    "_jit_icall_", "mono_", "wrapper_alloc_object_", "wrapper_write_barrier",
    "wrapper_castclass", "wrapper_stelemref", "wrapper_unbox",
)
# CIL instructions that are not calls but that mono compiles into an indirect
# call through the receiver's vtable.
INDIRECT_OPS = frozenset(("stelem.ref",))

# CIL instructions other than `ldstr` that mono compiles into a GOT read.
GOT_USERS = frozenset((
    "ldsfld", "ldsflda", "stsfld", "newobj", "newarr", "castclass", "isinst",
    "box", "unbox", "unbox.any", "ldtoken", "ldftn", "ldvirtftn", "initobj",
    "sizeof", "ldelema", "constrained.",
))
GOT_USERS = GOT_USERS - {"newarr"}

# Allocation entries: the CIL instruction they belong to is a `newobj`.
ALLOC_MARKERS = ("ves_icall_object_new", "AllocSmall", "AllocVector",
                 "AllocString", "mono_gc_alloc", "object_new")


def _norm_native(sym: str) -> str:
    """Strip the decorations mono adds so a PLT symbol can be name-matched."""
    s = sym
    if s.startswith("plt_"):
        s = s[4:]
    for pref in ("wrapper_remoting_invoke_with_check_", "wrapper_managed_to_native_",
                 "wrapper_native_to_managed_", "wrapper_delegate_invoke_",
                 "wrapper_runtime_invoke_", "wrapper_synchronized_"):
        if s.startswith(pref):
            s = s[len(pref):]
    return s


def _cil_target(text: str):
    """('Owner', 'Method') from a resolved CIL operand, either part possibly None."""
    body = text.split(" ", 1)[1] if text.startswith(("MemberRefRow ", "MethodDefRow ",
                                                     "MethodSpecRow ", "TypeRefRow ")) else text
    if "::" in body:
        owner, method = body.split("::", 1)
        return owner, method
    return None, body


def _name_matches(native: str, owner, method) -> bool:
    """Does this PLT symbol name the CIL callee?

    Mono spells mscorlib types by their internal names (`string` for
    System.String) and appends the parameter types, so the comparison is on
    `_`-delimited tokens rather than on the whole string.
    """
    if not method:
        return False
    tokens = native.split("_")
    low = [t.lower() for t in tokens]
    m = method.replace(".", "")            # .ctor -> ctor
    if not re.search(r"(?:^|_)" + re.escape(m) + r"(?:_|$)", native):
        return False
    if owner:
        last = owner.rsplit(".", 1)[-1]
        if last.lower() not in low:
            # generic instantiations spell the owner differently; the method
            # name alone is then the only evidence, which is weaker but still
            # an anchor when it is unique in the gap.
            return False
    return True


def native_calls(proj, lo, hi):
    """Ordered events in [lo,hi).

    ('direct', addr, symbol)    a `bl` to a named symbol
    ('indirect', addr, slot)    a `blr`; slot is the byte offset the branch
                                register was loaded from - a positive immediate
                                for a virtual call, a negative register-built
                                offset for an interface call, None if unknown
    ('got', addr, (off, reg))   a load from the AOT global offset table. Mono
                                puts every `ldstr` literal, type handle and
                                method pointer behind one of these, and leaves
                                them all null in the image for the runtime to
                                fill. The slot offset is a stable, image-wide
                                identifier for the constant the load wants.
    """
    names = {s.rebased_addr: s.name for s in proj.loader.main_object.symbols if s.name}
    out, addr = [], lo
    gotbase = {}
    while addr < hi:
        try:
            block = proj.factory.block(addr)
        except Exception:
            break
        if block.size == 0:
            break
        imm, loads = {}, {}
        for insn in block.capstone.insns:
            m, ops = insn.mnemonic, insn.op_str.replace(" ", "")
            if m == "mov" and ops.count(",") == 1 and ops.split(",")[1].startswith("#"):
                try:
                    imm[ops.split(",")[0]] = int(ops.split("#")[1], 0)
                except ValueError:
                    pass
            elif m == "movk" and "lsl" in ops:
                p = ops.split(",")
                try:
                    v, sh = int(p[1].lstrip("#"), 0), int(p[2].split("#")[1], 0)
                    if p[0] in imm:
                        imm[p[0]] = (imm[p[0]] & ~(0xFFFF << sh)) | (v << sh)
                except (ValueError, IndexError):
                    pass
            elif m == "adrp":
                try:
                    gotbase[ops.split(",")[0]] = insn.operands[1].imm
                except Exception:
                    pass
            elif m == "add" and ops.count(",") == 2:
                d, s1, s2 = ops.split(",")
                if s1 in gotbase and s2.startswith("#"):
                    try:
                        gotbase[d] = gotbase[s1] + int(s2[1:], 0)
                    except ValueError:
                        gotbase.pop(d, None)
                else:
                    gotbase.pop(d, None)
            elif m.startswith("ldr") and "[" in ops:
                dst = ops.split(",")[0]
                inner = ops.split("[", 1)[1].rstrip("]").split(",")
                if len(inner) == 2 and inner[1].startswith("#"):
                    try:
                        loads[dst] = int(inner[1].lstrip("#"), 0)
                    except ValueError:
                        loads.pop(dst, None)
                    if inner[0] in gotbase and dst in loads:
                        out.append(("got", insn.address,
                                    (gotbase[inner[0]] + loads[dst], dst)))
                    gotbase.pop(dst, None)
                elif len(inner) == 2 and inner[1] in imm:
                    v = imm[inner[1]] & ((1 << 64) - 1)
                    loads[dst] = v - (1 << 64) if v & (1 << 63) else v
                elif len(inner) == 1:
                    loads[dst] = 0
                    gotbase.pop(dst, None)
                else:
                    loads.pop(dst, None)
                    gotbase.pop(dst, None)
            elif m == "bl":
                try:
                    tgt = int(ops.replace("#", ""), 16)
                except ValueError:
                    continue
                sym = names.get(tgt)
                if sym:
                    out.append(("direct", insn.address, sym))
            elif m == "blr":
                out.append(("indirect", insn.address, loads.get(ops.strip())))
        addr += block.size
    return out


def cil_calls(body, resolve):
    """Ordered (il_offset, opcode, owner, method, token) for each call in a body.

    The token is carried because the operand's *text* collapses overloads --
    `Stream::Write(byte[],int,int)` and `Stream::Write(byte)` print identically
    but are different metadata rows occupying different vtable slots. Keying the
    consistency check on the token instead of the name keeps them apart.
    """
    out = []
    for insn in body.instructions:
        name = insn.opcode.name
        if name in ("call", "callvirt", "newobj", "newarr", "calli"):
            owner, method = _cil_target(resolve(insn.operand))
            tok = getattr(insn.operand, "value", None)
            out.append((insn.offset - body.offset, name, owner, method, tok))
        elif name == "ldstr":
            text = resolve(insn.operand)
            if text.startswith('"') and text.endswith('"'):
                out.append((insn.offset - body.offset, "ldstr", None, text[1:-1], None))
        elif name in INDIRECT_OPS:
            # `stelem.ref` is not a call in CIL, but mono compiles it into one:
            # the array-store write barrier and covariance check are reached
            # through the array's own vtable, exactly like a `callvirt`
            # (`ldr x3,[arr]; ldr x16,[x3,#0x108]; blr x16`). Counting it as a
            # call is what keeps the alignment honest -- without it every array
            # store steals the identity of whatever CIL call came next, which on
            # Thanos mislabelled 210 sites.
            out.append((insn.offset - body.offset, "indirect-op", None, name, None))
        elif name in GOT_USERS:
            # These also read the GOT -- a static field's storage, a type's
            # vtable, a method pointer. They claim no literal, but they occupy a
            # slot load, so counting them is what lets a gap that mixes them
            # with an `ldstr` still add up.
            out.append((insn.offset - body.offset, "gotuser", None, name, None))
    return out


def align(nat, cil, slot_of=None):
    """Anchor-align the two sequences; return per-indirect-site resolutions.

    `slot_of` maps a metadata token to the vtable slot that token was observed
    to use elsewhere in the image. It is empty on the first pass and supplied on
    the second, where it breaks ties in gaps that hold more CIL candidates than
    indirect sites: a candidate whose token is known to sit in a different slot
    -- or to be called directly, and so to have no slot at all -- cannot be the
    one this site invokes.

    Returns (resolved, unresolved, allocs).
    """
    slot_of = slot_of or {}
    gots = [e for e in nat if e[0] == "got"]
    nat = [e for e in nat if e[0] != "got"]
    # `newobj` is both an anchor (it names the allocation) and a GOT reader, so
    # it stays in both streams.
    lits = [c for c in cil if c[1] in ("ldstr", "gotuser", "newobj", "newarr")]
    cil = [c for c in cil if c[1] not in ("ldstr", "gotuser")]
    # 1. anchors: greedy monotonic match of named direct calls onto CIL calls.
    anchors = []        # (native_index, cil_index)
    j = 0
    for i, (kind, addr, info) in enumerate(nat):
        if kind != "direct":
            continue
        sym = _norm_native(info)
        if any(sym.startswith(p) for p in RUNTIME_PREFIXES):
            # allocation helpers anchor onto `newobj`, which is a real CIL
            # instruction; everything else mono-internal is skipped.
            if any(mk in sym for mk in ALLOC_MARKERS):
                # `newarr` allocates too. Looking only for `newobj` sends the
                # cursor past every array store in the method, which is what
                # collapsed Thanos's exfiltration routine into one 9-site gap.
                want = ("newarr",) if "Vector" in sym or "Array" in sym \
                    else ("newobj", "newarr")
                k = next((x for x in range(j, len(cil))
                          if cil[x][1] in want), None)
                if k is not None:
                    anchors.append((i, k))
                    j = k + 1
            continue
        k = next((x for x in range(j, len(cil))
                  if _name_matches(sym, cil[x][2], cil[x][3])), None)
        if k is not None:
            anchors.append((i, k))
            j = k + 1

    matched_cil = {k for _, k in anchors}
    resolved, unresolved = [], []

    # 2. each indirect site lies between two consecutive anchors. The CIL calls
    #    in the same gap that no anchor claimed are its candidates.
    bounds = [(-1, -1)] + anchors + [(len(nat), len(cil))]
    for (ni0, ci0), (ni1, ci1) in zip(bounds, bounds[1:]):
        sites = [(a, s) for kind, a, s in nat[ni0 + 1:ni1] if kind == "indirect"]
        cands = [c for x, c in enumerate(cil[ci0 + 1:ci1], start=ci0 + 1)
                 if x not in matched_cil
                 and c[1] in ("callvirt", "call", "indirect-op")]
        if not sites:
            continue
        how = "gap"
        if len(cands) > len(sites) and slot_of:
            # Narrow on the slot each candidate is known to use image-wide.
            slots = {s for _, s in sites}
            narrowed = [c for c in cands
                        if c[4] in slot_of and slot_of[c[4]] in slots]
            if len(narrowed) == len(sites):
                cands, how = narrowed, "gap+slot"
        if len(sites) == len(cands):
            for (addr, slot), (il, op, owner, method, tok) in zip(sites, cands):
                resolved.append({"addr": addr, "slot": slot, "il": il, "token": tok,
                                 "owner": owner, "method": method, "op": op,
                                 "how": how})
            continue

        # The gap does not close as a whole. A site inside it can still be
        # settled on its own, when exactly one candidate in the gap is known --
        # from everywhere else in the image -- to be dispatched through the slot
        # this site reads. Mono lays a loop body out after the loop header, so
        # address order and IL order disagree inside a `foreach`, which is what
        # breaks the whole-gap pairing; the slot does not care about layout.
        claimed = set()
        for addr, slot in sites:
            if slot is None:
                unresolved.append((addr, slot, "no slot offset recovered"))
                continue
            hits = [c for c in cands if c[4] not in claimed
                    and c[4] in slot_of and slot_of[c[4]] == slot]
            if len({c[4] for c in hits}) == 1:
                il, op, owner, method, tok = hits[0]
                claimed.add(tok)
                resolved.append({"addr": addr, "slot": slot, "il": il,
                                 "token": tok, "owner": owner, "method": method,
                                 "op": op, "how": "slot"})
            else:
                unresolved.append((addr, slot,
                                   f"gap holds {len(sites)} indirect site(s) and "
                                   f"{len(cands)} unmatched CIL call(s); "
                                   f"{len({c[4] for c in hits})} of them are known "
                                   f"to use slot "
                                   f"{slot if slot is None else hex(slot)}"))

    # 2b. string literals. Every `ldstr` compiles to a load from a GOT slot the
    #     runtime would fill with a MonoString*; the image leaves it null. The
    #     slot offset is stable image-wide, so pairing the GOT loads in an
    #     anchor gap with the `ldstr` literals in the same gap recovers what
    #     each slot holds -- and the same slot recurring in other methods with
    #     the same literal is the check that the pairing is right.
    literals = []
    for (ni0, ci0), (ni1, ci1) in zip(bounds, bounds[1:]):
        a0 = nat[ni0][1] if ni0 >= 0 else -1
        a1 = nat[ni1][1] if ni1 < len(nat) else 1 << 62
        g = [e for e in gots if a0 < e[1] < a1]
        i0 = cil[ci0][0] if ci0 >= 0 else -1
        i1 = cil[ci1][0] if ci1 < len(cil) else 1 << 62
        l = [c for c in lits if i0 < c[0] < i1]
        if any(c[1] == "ldstr" for c in l) and len(g) == len(l):
            for (_, addr, (off, reg)), (il, kind, _, text, _) in zip(g, l):
                if kind == "ldstr":
                    literals.append({"got": off, "text": text, "addr": addr,
                                     "reg": reg, "il": il})

    # Out-of-line blocks defeat the address-ordered pairing above: mono lays a
    # branch's cold side away from its IL position, so its `ldstr` lands in a
    # different anchor gap from the literal it belongs to. When a method has
    # exactly one GOT load and exactly one `ldstr` still unclaimed, there is
    # only one pairing available and it is taken.
    claimed_got = {l["addr"] for l in literals}
    claimed_il = {l["il"] for l in literals}
    spare_g = [e for e in gots if e[1] not in claimed_got]
    spare_l = [c for c in lits if c[1] == "ldstr" and c[0] not in claimed_il]
    if len(spare_g) == 1 and len(spare_l) == 1:
        (_, addr, (off, reg)), (il, _, _, text, _) = spare_g[0], spare_l[0]
        literals.append({"got": off, "text": text, "addr": addr,
                         "reg": reg, "il": il})

    # 3. allocation provenance: each allocation anchor names the type it builds.
    allocs = []
    for i, k in anchors:
        sym = _norm_native(nat[i][2])
        if any(mk in sym for mk in ALLOC_MARKERS) and cil[k][1] == "newobj":
            allocs.append({"addr": nat[i][1], "owner": cil[k][2], "il": cil[k][0],
                           "token": cil[k][4]})
    return resolved, unresolved, allocs, literals


def build(exe_path, so_path=None, method_filter=None, passes=2):
    """Resolve every indirect call site in the image. Returns a report dict.

    Two passes. The first aligns on anchors alone and, from the sites it
    resolves unambiguously, learns which vtable slot each callee occupies. The
    second replays the alignment with that table available, which settles gaps
    the first pass had to leave open.
    """
    import angr
    import dnfile
    from dncil.cil.body import CilMethodBody
    sys.path.insert(0, __file__.rsplit("/", 1)[0])
    import cil_disasm as cd

    so_path = so_path or exe_path + ".so"
    proj = angr.Project(so_path, auto_load_libs=False)
    pe = dnfile.dnPE(exe_path)
    tokens = cd.build_token_map(pe)
    resolve = lambda t: cd.resolve(tokens, pe, t)

    # rva -> AOT symbol. Mono's symbol name is the mangled full method name, so
    # the two artifacts are joined on (type name, method name) instead.
    sym_by_name = {}
    for s in proj.loader.main_object.symbols:
        if s.name and not s.name.startswith("plt_") and s.size:
            sym_by_name.setdefault(s.name, s)

    # Pass 0: collect the raw sequences once; the alignment is then cheap to
    # replay with a slot table in hand.
    units = []
    for td in pe.net.mdtables.TypeDef:
        ns = str(td.TypeNamespace or "")
        tn = str(td.TypeName or "")
        full = ".".join(p for p in (ns, tn) if p)
        for md in td.MethodList:
            row = md.row
            if row is None or not row.Rva:
                continue
            mname = str(row.Name)
            if method_filter and method_filter not in mname and method_filter not in full:
                continue
            mangled = re.sub(r"[^A-Za-z0-9]", "_", f"{full}.{mname}")
            cands = [n for n in sym_by_name
                     if n == mangled or n.startswith(mangled + "_")]
            if not cands:
                continue
            sym = sym_by_name[min(cands, key=len)]
            body = cd.read_body(pe, row)
            if not isinstance(body, CilMethodBody):
                continue
            units.append((f"{full}::{mname}", sym,
                          native_calls(proj, sym.rebased_addr,
                                       sym.rebased_addr + sym.size),
                          cil_calls(body, resolve)))

    slot_of = {}
    for p in range(passes):
        report = {"image": so_path, "assembly": exe_path, "methods": [],
                  "resolved": [], "unresolved": [], "allocs": [],
                  "literals": [], "pass": p + 1}
        for name, sym, nat, cil in units:
            res, unres, allocs, lits = align(nat, cil, slot_of)
            n_ind = sum(1 for k, _, _ in nat if k == "indirect")
            if not n_ind and not allocs:
                continue
            report["methods"].append({"name": name, "sym": sym.name,
                                      "addr": sym.rebased_addr, "size": sym.size,
                                      "indirect": n_ind, "resolved": len(res)})
            for r in res:
                r["in"] = name
                report["resolved"].append(r)
            for a, sl, why in unres:
                report["unresolved"].append({"addr": a, "slot": sl, "why": why,
                                             "in": name})
            for a in allocs:
                a["in"] = name
                report["allocs"].append(a)
            for lt in lits:
                lt["in"] = name
                report["literals"].append(lt)
        # Learn the slot table for the next pass: only callees that were
        # unanimous are trusted; a token seen in two slots teaches nothing.
        seen = collections.defaultdict(collections.Counter)
        for r in report["resolved"]:
            if r.get("token") is not None:
                seen[r["token"]][r["slot"]] += 1
        slot_of = {t: next(iter(c)) for t, c in seen.items() if len(c) == 1}
    return report


def literal_map(report):
    """GOT slot -> string literal, keeping only slots with a unanimous pairing."""
    by = collections.defaultdict(collections.Counter)
    for lit in report["literals"]:
        by[lit["got"]][lit["text"]] += 1
    good = {k: next(iter(v)) for k, v in by.items() if len(v) == 1}
    conflicting = {k: v for k, v in by.items() if len(v) > 1}
    corroborated = {k for k, v in by.items() if len(v) == 1 and sum(v.values()) > 1}
    return good, conflicting, corroborated


def validate(report):
    """Slot consistency: one callee must read one slot, image-wide."""
    by_callee = collections.defaultdict(collections.Counter)
    names = {}
    for r in report["resolved"]:
        key = r.get("token") or (f"{r['owner']}::{r['method']}")
        names[key] = f"{r['owner']}::{r['method']}" if r["owner"] else r["method"]
        by_callee[key][r["slot"]] += 1
    by_callee = {names[k]: v if len(v) == 1 else v for k, v in by_callee.items()} \
        if False else {k: v for k, v in by_callee.items()}
    report["_callee_names"] = names
    consistent = {k: v for k, v in by_callee.items() if len(v) == 1}
    conflicting = {k: v for k, v in by_callee.items() if len(v) > 1}
    return consistent, conflicting


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("assembly")
    ap.add_argument("--so")
    ap.add_argument("--method")
    ap.add_argument("--json")
    args = ap.parse_args()

    rep = build(args.assembly, args.so, args.method)
    consistent, conflicting = validate(rep)

    import ledger
    print(ledger.header("2.3  CALL-SITE RESOLUTION BY ANCHORED ALIGNMENT",
                        artifacts=[args.assembly, rep["image"]],
                        sources=[__file__, __file__.replace("callsite_map",
                                                            "cil_disasm")]))
    n_ind = sum(m["indirect"] for m in rep["methods"])
    n_res = len(rep["resolved"])
    print("=" * 72)
    print("2.3  CALL-SITE RESOLUTION BY ANCHORED ALIGNMENT")
    print("=" * 72)
    print(f"  assembly {args.assembly}")
    print(f"  image    {rep['image']}")
    print(f"  methods carrying an indirect call or an allocation : {len(rep['methods']):,}")
    print(f"  indirect call sites                                : {n_ind:,}")
    print(f"    resolved to a named callee                       : {n_res:,}"
          f"  ({100.0 * n_res / n_ind:.1f}%)" if n_ind else "")
    ways = collections.Counter(r.get("how", "gap") for r in rep["resolved"])
    for how, label in (("gap", "the anchor gap closes exactly"),
                       ("gap+slot", "gap closes once slots narrow it"),
                       ("slot", "single site, unique slot in the gap")):
        if ways.get(how):
            print(f"        {ways[how]:>5}  {label}")
    print(f"    left unresolved                                  : {len(rep['unresolved']):,}")
    print(f"  allocation sites typed from a `newobj` anchor      : {len(rep['allocs']):,}")

    print("\n" + "-" * 72)
    print("VALIDATION: does each callee read a single vtable slot?")
    print("-" * 72)
    print(f"  callees resolved              : {len(consistent) + len(conflicting):,}")
    print(f"  one callee -> one slot        : {len(consistent):,}")
    print(f"  one callee -> several slots   : {len(conflicting):,}")
    nm = rep["_callee_names"]
    for k, v in sorted(conflicting.items(), key=lambda kv: -sum(kv[1].values()))[:10]:
        print(f"      {nm.get(k, k)}  " + ", ".join(
            f"{s:#x}x{n}" if s is not None and s >= 0 else f"{s}x{n}"
            for s, n in v.items()))

    good, conflicting_lits, corroborated = literal_map(rep)
    print("\n" + "-" * 72)
    print("STRING LITERALS RECOVERED INTO GOT SLOTS")
    print("-" * 72)
    print(f"  ldstr <-> GOT-load pairings       : {len(rep['literals']):,}")
    print(f"  distinct GOT slots implicated     : {len(good) + len(conflicting_lits):,}")
    print(f"    slot carries one literal        : {len(good):,}  (used)")
    print(f"    slot seen more than once, same  : {len(corroborated):,}  (corroborated)")
    print(f"    slot disagrees with itself      : {len(conflicting_lits):,}  (discarded)")

    top = sorted(consistent.items(), key=lambda kv: -sum(kv[1].values()))[:25]
    print("\n" + "-" * 72)
    print("MOST-CALLED RESOLVED CALLEES")
    print("-" * 72)
    for k, v in top:
        s, n = next(iter(v.items()))[0], sum(v.values())
        print(f"  {n:>4} site(s)  slot {s if s is None else hex(s):>8}   {nm.get(k, k)}")

    if args.method:
        print("\n" + "-" * 72)
        print(f"SITES IN METHODS MATCHING {args.method!r}")
        print("-" * 72)
        for m in rep["methods"]:
            print(f"\n  {m['name']}   {m['addr']:#x}  "
                  f"({m['resolved']}/{m['indirect']} indirect sites resolved)")
            for r in rep["resolved"]:
                if r["in"] == m["name"]:
                    s = r["slot"]
                    print(f"      {r['addr']:#x}  slot {s if s is None else hex(s):>7}"
                          f"  IL {r['il']:04X}  -> {r['owner']}::{r['method']}")
            for u in rep["unresolved"]:
                if u["in"] == m["name"]:
                    print(f"      {u['addr']:#x}  UNRESOLVED  {u['why']}")
            lits = [l for l in rep["literals"] if l["in"] == m["name"]
                    and l["got"] in good]
            for lt in lits:
                print(f"      {lt['addr']:#x}  ldstr  got {lt['got']:#x} -> "
                      f"{lt['reg']:<3} = {lt['text']!r}")

    if args.json:
        with open(args.json, "w") as fh:
            json.dump(rep, fh, indent=1)
        print(f"\n  wrote {args.json}")


if __name__ == "__main__":
    main()
