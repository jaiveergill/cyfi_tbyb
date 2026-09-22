#!/usr/bin/env python3
"""
2.3 - the runtime surface an AOT-translated .NET assembly needs before symbolic
execution of it means anything.

`mono --aot=full` emits native code, but it emits code that expects the mono
runtime underneath it. Four things the runtime would supply are simply absent
from the `.so`:

  the linkage table    every inter-method call goes through a `plt_FOO` entry
                       the runtime patches at load time; unpatched it is a
                       branch to zero.
  the object allocator `newobj` is a call into the GC. Without it `new` returns
                       an unconstrained symbol and the first field access on the
                       result destroys the state.
  the GOT             `ldstr`, static-field addresses and type handles are all
                       loads from a global offset table the runtime fills. Every
                       string literal in the program reads as null.
  virtual dispatch     `callvirt` compiles to a load from the receiver's vtable
                       followed by an indirect branch. No runtime means no
                       vtable, so the branch register is symbolic.

This module supplies the first three. The fourth is call-site resolution and
belongs to `managed_call_explorer`, because deciding it needs the state.

Nothing here runs the sample. The `.so` is a compiler artifact; every hook below
is a Python stand-in that angr executes instead of real runtime code.
"""
from __future__ import annotations

import logging
import sys
import pathlib

import angr
import claripy

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import aot_bridge as ab            # noqa: E402
import callsite_map as csmap       # noqa: E402

logging.getLogger("angr").setLevel(logging.CRITICAL)
logging.getLogger("cle").setLevel(logging.CRITICAL)

# Scratch regions, kept far apart so an address identifies its own kind.
HEAP = 0xE8000000        # objects handed out by the allocator
HEAP_STRIDE = 0x400
HEADERS = 0xF4000000     # per-object type headers (see new_object)
HEADER_STRIDE = 0x200
LITERALS = 0xD8000000    # MonoStrings for recovered `ldstr` constants
SCRATCH = 0xDC000000     # strings built at run time (Concat, sentinels)
SCRATCH_STRIDE = 0x800

# Element types from ECMA-335 II.23.1.16, enough to tell a reference return
# from a scalar one.
ET_VOID, ET_STRING, ET_PTR, ET_BYREF = 0x01, 0x0E, 0x0F, 0x10
ET_VALUETYPE = 0x11
ET_CLASS, ET_VAR, ET_ARRAY, ET_GENERICINST = 0x12, 0x13, 0x14, 0x15
ET_OBJECT, ET_SZARRAY, ET_MVAR = 0x1C, 0x1D, 0x1E
REFERENCE_RETURNS = frozenset((ET_STRING, ET_CLASS, ET_ARRAY, ET_GENERICINST,
                               ET_OBJECT, ET_SZARRAY, ET_VAR, ET_MVAR))


def _uncompress(blob, i):
    """ECMA-335 compressed unsigned integer."""
    b = blob[i]
    if b & 0x80 == 0:
        return b, i + 1
    if b & 0x40 == 0:
        return ((b & 0x3F) << 8) | blob[i + 1], i + 2
    return (((b & 0x1F) << 24) | (blob[i + 1] << 16) |
            (blob[i + 2] << 8) | blob[i + 3]), i + 4


def return_kind(sig: bytes):
    """('kind', type-token) for a MethodDef/MemberRef signature.

    kind is 'void', 'scalar', 'string' or 'ref'.

    Whether a call returns a managed reference or a number decides what a stub
    standing in for it must hand back. A reference stub has to return a pointer
    to a laid-out object, because the caller will dereference it; a scalar stub
    has to return an unconstrained symbol, because the caller will branch on it.
    Getting this backwards is what loses the state either way, so it is read
    from the metadata rather than guessed from the method's name.
    """
    if not sig:
        return "scalar", None
    i = 0
    cc = sig[i]
    i += 1
    if cc & 0x10:                      # GENERIC: a generic-parameter count follows
        _, i = _uncompress(sig, i)
    _, i = _uncompress(sig, i)         # parameter count
    while i < len(sig) and sig[i] in (0x1F, 0x20):   # CMOD_REQD / CMOD_OPT
        i += 1
        _, i = _uncompress(sig, i)
    if i >= len(sig):
        return "scalar", None
    et = sig[i]
    i += 1
    if et == ET_VOID:
        return "void", None
    if et == ET_STRING:
        return "string", None
    if et in (ET_CLASS, ET_VALUETYPE):
        # A TypeDefOrRef coded index follows: rid in the high bits, the table
        # it points into in the low two. Decoding it names the class the call
        # returns, which is what gives the returned object a type.
        try:
            coded, i = _uncompress(sig, i)
        except IndexError:
            return "ref", None
        table = {0: "TypeDef", 1: "TypeRef", 2: "TypeSpec"}.get(coded & 3)
        return ("ref" if et == ET_CLASS else "scalar"), (table, coded >> 2)
    if et in (ET_PTR, ET_BYREF):
        return "ref", None
    return ("ref" if et in REFERENCE_RETURNS else "scalar"), None


# --------------------------------------------------------------------------
# object model
# --------------------------------------------------------------------------

def new_object(state, type_name=None):
    """Allocate a distinct managed object, give it a header, record its type.

    The type comes from the allocation site, which `callsite_map` pairs with the
    `newobj` in the CIL. It is what lets a later virtual call on this object be
    resolved from the receiver rather than from the call site alone.

    Every object gets its own zero-filled header block and points at it. This
    is *not* a vtable: no callee is selected out of it, because call sites are
    resolved by name. It exists because the compiler emits null checks and
    type-flag tests against the header on the way into a virtual call --
    `ldr x1,[x0]; ldrb w2,[x1,#0x2c]` guards the unbox in
    `Settings::get_Identified`. Without a header those read from address 0 and
    fork into mono's throw-corlib-exception helper on a check that has nothing
    to do with the malware's logic; with one they read concrete zero, the
    well-typed answer.
    """
    n = state.globals.get("_n_obj", 0)
    state.globals["_n_obj"] = n + 1
    addr = HEAP + n * HEAP_STRIDE
    hdr = HEADERS + n * HEADER_STRIDE
    end = state.arch.memory_endness
    state.memory.store(addr, claripy.BVV(0, HEAP_STRIDE * 8))
    state.memory.store(hdr, claripy.BVV(0, HEADER_STRIDE * 8))
    state.memory.store(addr, claripy.BVV(hdr, 64), endness=end)
    # The header chain mono's unbox check walks is `obj -> vtable -> klass`,
    # ending in a comparison against a type handle the GOT would supply. Both
    # links are given a mapped, zero-filled block so that the walk reads
    # concrete zero and matches the (also zero) handle, i.e. the check passes.
    # Not a vtable: no callee is selected out of it.
    state.memory.store(hdr, claripy.BVV(hdr + HEADER_STRIDE // 2, 64), endness=end)
    if type_name:
        # globals is copied per state, so the map has to be immutable to stay
        # correct across forks.
        state.globals["_types"] = state.globals.get("_types", ()) + \
            ((addr, type_name),)
    return addr


def object_type(state, addr):
    for a, t in state.globals.get("_types", ()):
        if a == addr:
            return t
    return None


def new_string(state, text):
    """Lay out a MonoString in scratch space and return its address."""
    n = state.globals.get("_n_str", 0)
    state.globals["_n_str"] = n + 1
    addr = SCRATCH + n * SCRATCH_STRIDE
    ab.make_string(state, addr, text[: (SCRATCH_STRIDE - 0x40) // 2])
    return addr


def read_string(state, ptr, limit=512):
    """Read a MonoString back, or None if it is not a readable one."""
    if ptr is None or state.solver.symbolic(ptr):
        return None
    addr = state.solver.eval(ptr)
    if addr == 0:
        return None
    try:
        raw = state.memory.load(addr + ab.MONOSTRING_LEN_OFF, 4,
                                endness=state.arch.memory_endness)
        if state.solver.symbolic(raw):
            return None
        n = state.solver.eval(raw)
        if n == 0:
            return ""
        if n > limit:
            return None
        chars = state.memory.load(addr + ab.MONOSTRING_CHARS_OFF, n * 2)
        if state.solver.symbolic(chars):
            return None
        return state.solver.eval(chars, cast_to=bytes).decode("utf-16-le", "replace")
    except Exception:
        return None


# --------------------------------------------------------------------------
# stand-ins for runtime entry points
# --------------------------------------------------------------------------

class TypedAllocator(angr.SimProcedure):
    """mono's object allocator, with the allocated type recorded.

    The allocation sites are the ones `callsite_map` paired with a `newobj`, so
    the type being constructed is known statically; the return address says
    which site this is.
    """
    IS_FUNCTION = True

    def __init__(self, types=None, **kw):
        super().__init__(**kw)
        self.types = types or {}

    def run(self, *args):  # pylint: disable=arguments-differ
        st = self.state
        try:
            site = st.solver.eval(st.regs.lr) - 4
        except Exception:
            site = None
        return claripy.BVV(new_object(st, self.types.get(site)), st.arch.bits)


class ManagedStub(angr.SimProcedure):
    """Stand-in for a managed method this analysis does not model.

    Returns an object or an unconstrained scalar according to the callee's
    metadata signature, and records that it was called. The declared assumption
    is that the method has no effect the rest of the analysis depends on -- true
    for the logging and formatting helpers that dominate the list, false for
    anything that transforms data the analysis then reads, which is why the
    calls are counted and reported rather than passed over silently.
    """
    IS_FUNCTION = True

    def __init__(self, label="managed", kind="scalar", type_name=None,
                 log=None, **kw):
        super().__init__(**kw)
        self.label = label
        self.kind = kind
        self.type_name = type_name
        self.log = log

    def run(self, *args):  # pylint: disable=arguments-differ
        st = self.state
        if self.log is not None:
            self.log.append(self.label)
        if self.kind == "void":
            return claripy.BVV(0, st.arch.bits)
        if self.kind == "string":
            # A labelled fixture, not a recovered value. It names the method
            # that would have produced it.
            return claripy.BVV(new_string(st, f"<{self.label}>"), st.arch.bits)
        if self.kind == "ref":
            return claripy.BVV(new_object(st, self.type_name), st.arch.bits)
        return claripy.BVS(f"{self.label}_ret", st.arch.bits)


class VectorAllocator(angr.SimProcedure):
    """mono's array allocator: `AllocVector(vtable, element_count)`.

    An array whose length field is left at zero fails every bounds check the
    compiler emits, so the first `stelem` on it throws and the path is lost.
    The count is in x1 at the call, so the length is written from there.
    """
    IS_FUNCTION = True

    def run(self, *args):  # pylint: disable=arguments-differ
        st = self.state
        addr = new_object(st, "System.Array")
        n = st.regs.x1
        st.memory.store(addr + ab.MONOARRAY_LEN_OFF, n,
                        endness=st.arch.memory_endness)
        return claripy.BVV(addr, st.arch.bits)


class StelemRef(angr.SimProcedure):
    """`stelem.ref`: store a reference into a managed array.

    Mono routes this through the array's vtable, so it arrives here as an
    indirect call with (array, index, value) in x0..x2. Modelling it is what
    makes an assembled `string[]` readable afterwards -- on Thanos the whole
    exfiltration report is built as one.
    """
    IS_FUNCTION = True

    def run(self, *args):  # pylint: disable=arguments-differ
        st = self.state
        arr, idx, val = st.regs.x0, st.regs.x1, st.regs.x2
        if not st.solver.symbolic(arr) and not st.solver.symbolic(idx):
            a, i = st.solver.eval(arr), st.solver.eval(idx)
            if a and i < 4096:
                st.memory.store(a + ab.MONOARRAY_DATA_OFF + i * 8, val,
                                endness=st.arch.memory_endness)
        return claripy.BVV(0, st.arch.bits)


def read_ref_array(state, ptr, limit=256):
    """The element pointers of a managed reference array, or None."""
    if ptr is None or state.solver.symbolic(ptr):
        return None
    addr = state.solver.eval(ptr)
    if addr == 0:
        return None
    raw = state.memory.load(addr + ab.MONOARRAY_LEN_OFF, 8,
                            endness=state.arch.memory_endness)
    if state.solver.symbolic(raw):
        return None
    n = state.solver.eval(raw)
    if n > limit:
        return None
    out = []
    for i in range(n):
        out.append(state.memory.load(addr + ab.MONOARRAY_DATA_OFF + i * 8, 8,
                                     endness=state.arch.memory_endness))
    return out


class StringConcatArray(angr.SimProcedure):
    """`System.String::Concat(string[])`."""
    IS_FUNCTION = True

    def run(self, *args):  # pylint: disable=arguments-differ
        st = self.state
        elems = read_ref_array(st, st.regs.x0)
        if elems is None:
            return claripy.BVV(new_string(st, "<unresolved>"), st.arch.bits)
        parts = [read_string(st, e) for e in elems]
        text = "".join(p if p is not None else "<unresolved>" for p in parts)
        return claripy.BVV(new_string(st, text), st.arch.bits)


class Base64Decode(angr.SimProcedure):
    """`System.Convert::FromBase64String` -- returns a real managed byte[]."""
    IS_FUNCTION = True

    def run(self, *args):  # pylint: disable=arguments-differ
        import base64
        st = self.state
        text = read_string(st, st.regs.x0)
        try:
            data = base64.b64decode(text or "", validate=False)
        except Exception:
            data = b""
        addr = new_object(st, "System.Byte[]")
        ab.make_byte_array(st, addr, data or b"\x00")
        st.memory.store(addr + ab.MONOARRAY_LEN_OFF,
                        claripy.BVV(len(data), 64),
                        endness=st.arch.memory_endness)
        return claripy.BVV(addr, st.arch.bits)


class EncodingGetString(angr.SimProcedure):
    """`System.Text.Encoding::GetString(byte[])` -- UTF-8/ASCII, as the sample uses."""
    IS_FUNCTION = True

    def run(self, *args):  # pylint: disable=arguments-differ
        st = self.state
        data = _read_array(st, st.regs.x1)
        if data is None:
            data = _read_array(st, st.regs.x0)
        text = data.decode("utf-8", "replace") if data else "<unresolved>"
        return claripy.BVV(new_string(st, text), st.arch.bits)


class EncodingGetBytes(angr.SimProcedure):
    """`System.Text.Encoding::GetBytes(string)` -- a real managed byte[].

    Needed because the bytes it produces are what the sample then writes to the
    network: without it the request body at `Stream.Write` is a symbol.
    """
    IS_FUNCTION = True

    def run(self, *args):  # pylint: disable=arguments-differ
        st = self.state
        text = read_string(st, st.regs.x1)
        if text is None:
            text = read_string(st, st.regs.x0)
        data = (text or "").encode("utf-8")
        addr = new_object(st, "System.Byte[]")
        ab.make_byte_array(st, addr, data or b"\x00")
        st.memory.store(addr + ab.MONOARRAY_LEN_OFF, claripy.BVV(len(data), 64),
                        endness=st.arch.memory_endness)
        return claripy.BVV(addr, st.arch.bits)


class StaticCallSite(angr.SimProcedure):
    """A call site delivered as an ordinary hook rather than by the technique.

    Used by the D arm of the comparisons, which asks whether the
    ExplorationTechnique produces the result or merely delivers the call-site
    table. For that to mean anything both deliveries need the same semantics,
    and the obvious `proj.hook(site, model, length=4)` does not have them:
    `length` applies to plain-function hooks, so given a SimProcedure angr
    ignores it and `ret()` goes to the link register -- every hooked site
    returned out of the enclosing method. Verified with `lr = 0xdeadbeef`: the
    successor's program counter was 0xdeadbeef, not site+4.

    `IS_FUNCTION = False` suppresses the implicit return; `lr` is set to the
    instruction after the call and control transferred to the model, which then
    returns to it. Same semantics as `ManagedCallExplorer.successors()`, without
    a technique.
    """
    IS_FUNCTION = False

    def __init__(self, target=0, resume=0, **kw):
        super().__init__(**kw)
        self.target = target
        self.resume = resume

    def run(self, *args):  # pylint: disable=arguments-differ
        self.state.regs.lr = claripy.BVV(self.resume, self.state.arch.bits)
        self.jump(self.target)


def hook_sites_statically(rt):
    """Install the whole call-site table as ordinary hooks. Returns the count."""
    n = 0
    for site, rec in rt.sites.items():
        target, _ = rt.stub_for(rec)
        if target is None:
            continue
        rt.proj.hook(site, StaticCallSite(target=target, resume=site + 4),
                     length=4, replace=True)
        n += 1
    return n


class ThrowStub(angr.SimProcedure):
    """mono's throw helpers, which do not return.

    Modelled as returning, they are worse than useless: execution falls out of
    the bottom of the throw into whatever method the linker laid down next. On
    GravityRat that is literally the next method in the image, and the run
    entered a four-block cycle between `Settings::get_Identified`'s null-check
    throw and `Settings::set_Identified` and never left it. Terminating the path
    is both correct and what stops the cycle.
    """
    IS_FUNCTION = True
    NO_RET = True

    def __init__(self, label="throw", log=None, **kw):
        super().__init__(**kw)
        self.label = label
        self.log = log

    def run(self, *args):  # pylint: disable=arguments-differ
        if self.log is not None:
            self.log.append(self.label)
        self.exit(1)


THROW_PATTERNS = ("throw_exception", "throw_corlib_exception", "rethrow",
                  "undeniable_exception", "raise_exception")


class StringConcat(angr.SimProcedure):
    """System.String::Concat over `arity` string arguments.

    Left unmodelled, Concat is the single most damaging stub in either sample:
    it builds the C2 URL, and an unconstrained return makes the URL
    unrecoverable at the transport call downstream. Modelled, the parts that are
    real strings come through; parts that are still symbolic are named in the
    result so the recovered and the unrecovered halves stay distinguishable.
    """
    IS_FUNCTION = True

    def __init__(self, arity=2, **kw):
        super().__init__(**kw)
        self.arity = arity

    def run(self, *args):  # pylint: disable=arguments-differ
        st = self.state
        parts = []
        for i in range(self.arity):
            val = getattr(st.regs, f"x{i}")
            s = read_string(st, val)
            parts.append(s if s is not None else "<unresolved>")
        return claripy.BVV(new_string(st, "".join(parts)), st.arch.bits)


class CollectionCtor(angr.SimProcedure):
    """NameValueCollection/StringCollection .ctor -- start an empty collection."""
    IS_FUNCTION = True

    def run(self, *args):  # pylint: disable=arguments-differ
        st = self.state
        this = st.solver.eval(st.regs.x0) if not st.solver.symbolic(st.regs.x0) else None
        if this is not None:
            st.globals[f"_coll_{this:x}"] = ()
        return claripy.BVV(0, st.arch.bits)


class CollectionAdd(angr.SimProcedure):
    """NameValueCollection::Add(name, value) / StringCollection::Add(value).

    The pair is appended to the receiver's own collection, keyed by the
    receiver's address, so two collections alive at once do not merge -- which
    is exactly what a single shared capture list would do.
    """
    IS_FUNCTION = True

    def __init__(self, pairs=True, log=None, **kw):
        super().__init__(**kw)
        self.pairs = pairs
        self.log = log

    def run(self, *args):  # pylint: disable=arguments-differ
        st = self.state
        if st.solver.symbolic(st.regs.x0):
            return claripy.BVV(0, st.arch.bits)
        this = st.solver.eval(st.regs.x0)
        if self.pairs:
            item = (read_string(st, st.regs.x1), read_string(st, st.regs.x2))
        else:
            item = (None, read_string(st, st.regs.x1))
        key = f"_coll_{this:x}"
        st.globals[key] = st.globals.get(key, ()) + (item,)
        if self.log is not None:
            self.log.append((this, item, st.globals.get("_site", None)))
        return claripy.BVV(0, st.arch.bits)


def collection_of(state, ptr):
    """The (name, value) pairs recorded for the collection at `ptr`."""
    if ptr is None or state.solver.symbolic(ptr):
        return None
    return state.globals.get(f"_coll_{state.solver.eval(ptr):x}")


class CaptureCall(angr.SimProcedure):
    """Record an outbound call's arguments; never perform it.

    Every network model in this project is capture-only: the arguments are read
    out of the state and written to a Python list, and a stub value is returned.
    No socket is opened, no name resolved, no byte sent.
    """
    IS_FUNCTION = True

    def __init__(self, label="call", argspec=(), log=None, kind="scalar", **kw):
        super().__init__(**kw)
        self.label = label
        self.argspec = argspec      # ('str'|'coll'|'int'|'bytes'|'obj', name)
        self.log = log
        self.kind = kind

    def run(self, *args):  # pylint: disable=arguments-differ
        st = self.state
        rec = {"call": self.label, "args": []}
        for i, (kind, name) in enumerate(self.argspec):
            reg = getattr(st.regs, f"x{i}")
            if kind == "str":
                val = read_string(st, reg)
            elif kind == "coll":
                val = collection_of(st, reg)
            elif kind == "bytes":
                val = _read_array(st, reg)
                if val is not None:
                    val = val.decode("utf-8", "replace")
            elif kind == "int":
                val = None if st.solver.symbolic(reg) else st.solver.eval(reg)
            else:
                val = None if st.solver.symbolic(reg) else hex(st.solver.eval(reg))
            rec["args"].append((name, val, "symbolic" if val is None else "concrete"))
        if self.log is not None:
            self.log.append(rec)
        if self.kind == "ref":
            return claripy.BVV(new_object(st, None), st.arch.bits)
        return claripy.BVS(f"{self.label}_ret", st.arch.bits)


def _read_array(state, ptr, limit=4096):
    """Read a MonoArray of bytes back out, if it is concrete."""
    if ptr is None or state.solver.symbolic(ptr):
        return None
    addr = state.solver.eval(ptr)
    if addr == 0:
        return None
    try:
        raw = state.memory.load(addr + ab.MONOARRAY_LEN_OFF, 8,
                                endness=state.arch.memory_endness)
        if state.solver.symbolic(raw):
            return None
        n = state.solver.eval(raw)
        if n == 0 or n > limit:
            return None
        data = state.memory.load(addr + ab.MONOARRAY_DATA_OFF, n)
        if state.solver.symbolic(data):
            return None
        return state.solver.eval(data, cast_to=bytes)
    except Exception:
        return None


# --------------------------------------------------------------------------
# assembling the runtime
# --------------------------------------------------------------------------

class _Fixture(angr.SimProcedure):
    """A method replaced by a labelled constant string."""
    IS_FUNCTION = True

    def __init__(self, text="", label="fixture", log=None, **kw):
        super().__init__(**kw)
        self.text = text
        self.label = label
        self.log = log

    def run(self, *args):  # pylint: disable=arguments-differ
        if self.log is not None:
            self.log.append(self.label)
        return claripy.BVV(new_string(self.state, self.text), self.state.arch.bits)


class _Const(angr.SimProcedure):
    """A method forced to a constant scalar."""
    IS_FUNCTION = True

    def __init__(self, value=0, **kw):
        super().__init__(**kw)
        self.value = value

    def run(self, *args):  # pylint: disable=arguments-differ
        return claripy.BVV(self.value, self.state.arch.bits)


class ManagedRuntime:
    """Everything the AOT image needs that the mono runtime would have supplied."""

    def __init__(self, exe, so=None, report=None):
        self.exe = str(exe)
        self.so = str(so or (str(exe) + ".so"))
        self.report = report if report is not None else csmap.build(self.exe, self.so)
        self.proj = angr.Project(self.so, auto_load_libs=False)
        self.syms = ab.aot_symbols(self.proj)
        self.literals, self.lit_conflicts, self.lit_corroborated = \
            csmap.literal_map(self.report)
        # A callee using more than one vtable slot is a misalignment, and
        # there is no telling which of its sites is wrong. Its sites go to
        # `unresolved` rather than being installed.
        by_token = {}
        for r in self.report["resolved"]:
            if r.get("token") is not None:
                by_token.setdefault(r["token"], set()).add(r["slot"])
        self.conflicting = {t for t, slots in by_token.items() if len(slots) > 1}

        self.sites, self.unresolved = {}, {}
        for r in self.report["resolved"]:
            if r.get("token") in self.conflicting:
                self.unresolved[r["addr"]] = {
                    "addr": r["addr"], "slot": r["slot"], "in": r.get("in"),
                    "why": f"callee {r['owner']}::{r['method']} resolves to more "
                           f"than one vtable slot image-wide; the mapping is "
                           f"not trustworthy at this site"}
            else:
                self.sites[r["addr"]] = r
        self.n_conflict_sites = len(self.report["resolved"]) - len(self.sites)
        for u in self.report["unresolved"]:
            self.unresolved[u["addr"]] = u
        self.alloc_types = {a["addr"]: a["owner"] for a in self.report["allocs"]
                            if a.get("owner")}
        self.signatures = self._signatures()
        # (declaring type, slot) -> callee, learned from the sites that did
        # resolve.
        self.by_type_slot = {}
        for r in self.report["resolved"]:
            if r["owner"] and r["slot"] is not None:
                self.by_type_slot.setdefault((r["owner"], r["slot"]),
                                             f"{r['owner']}::{r['method']}")
        self.stubs = {}          # callee name -> hooked address (explicit models)
        self._typed_stubs = {}   # callee name -> hooked address (from signature)
        self.calls = []          # every ManagedStub invocation, for accounting
        self.captures = []       # every CaptureCall record
        self.adds = []           # every CollectionAdd
        self.models = {}

    # ---------------- metadata ----------------

    def _signatures(self):
        """callee name -> ('ref'|'void'|'scalar'|'string', returned type name)."""
        import dnfile
        pe = dnfile.dnPE(self.exe)

        def type_name(ref):
            if ref is None:
                return None
            table, rid = ref
            rows = getattr(pe.net.mdtables, table, None)
            if rows is None or not 1 <= rid <= len(rows.rows):
                return None
            row = rows.rows[rid - 1]
            ns = str(getattr(row, "TypeNamespace", "") or "")
            tn = str(getattr(row, "TypeName", "") or "")
            return ".".join(p for p in (ns, tn) if p) or None

        out = {}
        for tbl in ("MemberRef", "MethodDef"):
            table = getattr(pe.net.mdtables, tbl, None)
            if table is None:
                continue
            for row in table.rows:
                try:
                    blob = bytes(row.Signature.value)
                except Exception:
                    continue
                kind, ref = return_kind(blob)
                name = str(row.Name)
                owner = ""
                cls = getattr(row, "Class", None)
                tgt = getattr(cls, "row", None) if cls is not None else None
                if tgt is not None:
                    ns = str(getattr(tgt, "TypeNamespace", "") or "")
                    tn = str(getattr(tgt, "TypeName", "") or "")
                    owner = ".".join(p for p in (ns, tn) if p)
                out.setdefault(f"{owner}::{name}" if owner else name,
                               (kind, type_name(ref)))
        return out

    # ---------------- installation ----------------

    def install(self, models=None):
        """Resolve the linkage table, model allocation, hook unresolved calls.

        `models` maps a callee name to a SimProcedure instance. Note what is
        *not* done here: the indirect call sites are left alone. Standing a
        model in for one of those is the intervention `ManagedCallExplorer`
        makes, and keeping it out of the static setup is what lets the two
        arms of the comparison share everything except the technique.
        """
        ab.resolve_plt(self.proj)
        self.models = dict(models or {})

        allocators = ab.hook_allocators(self.proj)
        alloc = TypedAllocator(types=self.alloc_types)
        vector = VectorAllocator()
        for name, addr in allocators.items():
            self.proj.hook(addr, vector if "AllocVector" in name else alloc,
                           replace=True)

        unresolved_plt = ab.unresolved_plt(self.proj)
        self.throws = []
        for name, addr in unresolved_plt.items():
            if addr in allocators.values():
                continue
            if any(t in name for t in THROW_PATTERNS):
                self.proj.hook(addr, ThrowStub(label=name, log=self.throws),
                               replace=True)
                continue
            proc = self._model_for(name)
            if proc is None:
                kind, type_name = self._kind_for(name)
                proc = ManagedStub(label=name, kind=kind, type_name=type_name,
                                   log=self.calls)
            self.proj.hook(addr, proc, replace=True)
        # String.Concat's arity is spelled out in the PLT symbol, and the model
        # needs it to know how many argument registers to read.
        for name, addr in self.syms.items():
            base = name[4:] if name.startswith("plt_") else name
            if base == "string_Concat_string__":
                self.proj.hook(addr, StringConcatArray(), replace=True)
            elif base.startswith("string_Concat_"):
                n = base.count("_string")
                if 1 <= n <= 4:
                    self.proj.hook(addr, StringConcat(arity=n), replace=True)
            elif base == "System_Convert_FromBase64String_string":
                self.proj.hook(addr, Base64Decode(), replace=True)

        # One hooked address per modelled callee; call sites point at these.
        for name, proc in self.models.items():
            addr = self.proj.loader.extern_object.allocate()
            self.proj.hook(addr, proc)
            self.stubs[name] = addr
        # A stub per resolved-but-unmodelled callee, typed from the callee's
        # own metadata signature, so it returns the kind the caller expects.
        self._typed_stubs = {}
        for rec in self.sites.values():
            callee = (f"{rec['owner']}::{rec['method']}" if rec.get("owner")
                      else rec.get("method"))
            if callee in self.stubs or callee in self._typed_stubs:
                continue
            kind, type_name = self.signatures.get(callee, (None, None))
            if kind is None:
                continue                      # no signature: fall back below
            addr = self.proj.loader.extern_object.allocate()
            self.proj.hook(addr, ManagedStub(label=callee, kind=kind,
                                             type_name=type_name,
                                             log=self.calls))
            self._typed_stubs[callee] = addr

        # The last resort, for a callee whose signature could not be read.
        self._generic = self.proj.loader.extern_object.allocate()
        self.proj.hook(self._generic, ManagedStub(label="managed_call",
                                                  kind="ref", log=self.calls))

        return self

    def _model_for(self, plt_name):
        """A model registered under a callee name that this PLT symbol spells."""
        for name, proc in self.models.items():
            short = name.split("::")[-1]
            owner = name.split("::")[0].rsplit(".", 1)[-1] if "::" in name else ""
            n = plt_name
            if short in n and (not owner or owner.lower() in n.lower()):
                return proc
        return None

    def _kind_for(self, plt_name):
        best = None
        for full, (kind, type_name) in self.signatures.items():
            short = full.split("::")[-1]
            if not short:
                continue
            if plt_name.endswith(short) or f"_{short}_" in plt_name:
                owner = full.split("::")[0].rsplit(".", 1)[-1] if "::" in full else ""
                exact = owner and owner.lower() in plt_name.lower()
                if exact:
                    return kind, type_name
                best = best or (kind, type_name)
        if best:
            return best
        if "__ctor" in plt_name or plt_name.endswith("_ctor"):
            return "void", None
        return "scalar", None

    def stub_for(self, rec):
        """The hooked address that should stand in for this call site."""
        if rec is None:
            return None
        callee = (f"{rec['owner']}::{rec['method']}" if rec.get("owner")
                  else rec.get("method"))
        target = self.stubs.get(callee) or self._typed_stubs.get(callee) \
            or self._generic
        return target, callee

    # ---------------- state construction ----------------

    ZERO_FILL = (angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
                 angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS)

    def entry_state(self, addr, zero_fill=True, **kw):
        """A call state with the GOT's string literals laid down in memory.

        Filling the GOT is the step that turns `ldstr` from a null read into a
        real MonoString, which is what makes a captured argument legible rather
        than a symbol.

        `zero_fill` makes uninitialised memory read as zero rather than as a
        fresh symbol. The CLR zero-initialises managed memory and a class's
        statics before its `.cctor` runs, so zero is the correct answer; it also
        stops a null static-field slot becoming a symbolic object, then a
        symbolic vtable pointer, then a symbolic program counter. Measured on
        `Core.Jobs::SystemSettings`: without it both `SettingsBase::Save` sites
        report "receiver symbolic"; with it the singleton is null on first read,
        the property constructs it, and the receiver is typed. Values from
        outside the process are unaffected -- they arrive through stubs that
        return symbols or labelled fixtures on purpose.
        """
        opts = kw.pop("add_options", set())
        if zero_fill:
            opts = set(opts) | set(self.ZERO_FILL)
        state = self.proj.factory.call_state(addr, add_options=opts, **kw)
        end = state.arch.memory_endness
        n = 0
        for slot, text in sorted(self.literals.items()):
            sa = LITERALS + n * SCRATCH_STRIDE
            n += 1
            ab.make_string(state, sa, text[: (SCRATCH_STRIDE - 0x40) // 2])
            state.memory.store(slot, claripy.BVV(sa, 64), endness=end)
        state.globals["_n_str"] = 0
        state.globals["_n_obj"] = 0
        return state

    # ---------------- fixtures ----------------

    def fixture(self, match, text, log=None):
        """Replace a method with a labelled deterministic string.

        For host facts -- a CPU id, a MAC address, a machine name -- there is no
        value to recover: they are properties of the machine the sample would
        run on, not of the sample. A fixture supplies one, and names itself, so
        that anything downstream that captures it says where it came from and
        cannot be read as data recovered from a victim.

        Returns the symbols it replaced, so a run can state exactly which
        methods were stood in for.
        """
        hooked = []
        for name, addr in self.syms.items():
            base = name[4:] if name.startswith("plt_") else name
            if match in base:
                self.proj.hook(addr, _Fixture(text=text, label=base, log=log),
                               replace=True)
                hooked.append(base)
        return sorted(set(hooked))

    def force(self, match, value):
        """Force a method to a constant scalar (an environment gate)."""
        hooked = []
        for name, addr in self.syms.items():
            base = name[4:] if name.startswith("plt_") else name
            if match in base:
                self.proj.hook(addr, _Const(value=value), replace=True)
                hooked.append(base)
        return sorted(set(hooked))

    def address_of(self, name):
        return self.syms.get(name)

    def name_of(self, addr):
        for n, a in self.syms.items():
            if a == addr:
                return n
        return None
