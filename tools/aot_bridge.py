#!/usr/bin/env python3
"""
The .NET -> angr bridge.

mono --aot=full translates an assembly's CIL into a native shared object. angr
can lift that. Two things stand in the way, and this module removes both:

  1. Inter-method calls go through mono's AOT PLT, which the mono runtime fills
     in at load time. With no runtime present every plt_* entry is a null jump,
     so any method that calls another crashes on `No bytes in memory at 0x0`.
     resolve_plt() rewires each plt_FOO to the real FOO body.

  2. Managed arguments are MonoObjects, not raw pointers. make_byte_array()
     lays out a MonoArray by hand so a managed byte[] can be passed in.

Nothing here executes the assembly under a CLR; mono is used only as an
ahead-of-time compiler, and angr does the rest.
"""
from __future__ import annotations

import angr
import claripy

# MonoArray, 64-bit:  +0 vtable  +8 sync  +16 bounds  +24 max_length  +32 data
MONOARRAY_DATA_OFF = 32
MONOARRAY_LEN_OFF = 24


class PltTrampoline(angr.SimProcedure):
    """Stands in for an unresolved mono AOT PLT entry: jump to the real body."""

    NO_RET = False
    IS_FUNCTION = True

    def run(self, target=None, name=None):  # pylint:disable=arguments-differ
        self.jump(target)


def aot_symbols(proj, prefix=""):
    """All AOT method symbols, name -> rebased address."""
    out = {}
    for sym in proj.loader.main_object.symbols:
        if sym.name and sym.name.startswith(prefix):
            out[sym.name] = sym.rebased_addr
    return out


def resolve_plt(proj, verbose=False):
    """Point every plt_FOO at FOO. Returns the mapping that was installed."""
    syms = aot_symbols(proj)
    installed = {}
    for name, addr in syms.items():
        if not name.startswith("plt_"):
            continue
        real = syms.get(name[4:])
        if real is None:
            continue
        proj.hook(addr, PltTrampoline(target=real, name=name), replace=True)
        installed[name] = (addr, real)
        if verbose:
            print(f"  plt {addr:#x} -> {real:#x}  {name[4:]}")
    return installed


def make_byte_array(state, addr, data, vtable=0xC0FFEE00):
    """Lay out a MonoArray of bytes at `addr`. `data` is a BV or bytes."""
    end = state.arch.memory_endness
    if isinstance(data, (bytes, bytearray)):
        data = claripy.BVV(bytes(data))
    length = len(data) // 8
    state.memory.store(addr + 0, claripy.BVV(vtable, 64), endness=end)
    state.memory.store(addr + 8, claripy.BVV(0, 64), endness=end)
    state.memory.store(addr + 16, claripy.BVV(0, 64), endness=end)
    state.memory.store(addr + MONOARRAY_LEN_OFF, claripy.BVV(length, 64), endness=end)
    state.memory.store(addr + MONOARRAY_DATA_OFF, data)
    return addr


def load(so_path, resolve=True, verbose=False):
    proj = angr.Project(so_path, auto_load_libs=False)
    if resolve:
        resolve_plt(proj, verbose=verbose)
    return proj


# MonoString, 64-bit:  +0 vtable  +8 sync  +16 length (int32)  +20 UTF-16 chars
MONOSTRING_LEN_OFF = 16
MONOSTRING_CHARS_OFF = 20


def make_string(state, addr, text, vtable=0xC0FFEE10):
    """Lay out a MonoString at `addr`. `text` is str, bytes (UTF-16LE) or a BV."""
    import claripy as _c
    end = state.arch.memory_endness
    if isinstance(text, str):
        data = _c.BVV(text.encode("utf-16-le"))
        nchars = len(text)
    elif isinstance(text, (bytes, bytearray)):
        data = _c.BVV(bytes(text))
        nchars = len(text) // 2
    else:
        data = text
        nchars = len(text) // 16
    state.memory.store(addr + 0, _c.BVV(vtable, 64), endness=end)
    state.memory.store(addr + 8, _c.BVV(0, 64), endness=end)
    state.memory.store(addr + MONOSTRING_LEN_OFF, _c.BVV(nchars, 32), endness=end)
    state.memory.store(addr + MONOSTRING_CHARS_OFF, data)
    return addr


def unresolved_plt(proj):
    """plt_* entries with no matching AOT body in this image.

    These are the calls that leave the assembly -- mscorlib and the mono
    runtime. They are the 'significant runtime system dependencies' the
    analysis has to model, and each one is a place symbolic execution stops
    unless it is hooked.
    """
    syms = aot_symbols(proj)
    out = {}
    for name, addr in syms.items():
        if name.startswith("plt_") and name[4:] not in syms:
            out[name[4:]] = addr
    return out


class UnconstrainedFunction(angr.SimProcedure):
    """Replace a pure helper with a fresh unconstrained symbolic return.

    This is the crudest of the models in this project and it is kept only for
    the stage-by-stage comparison in `translated_explorer.py`, where the point
    is to show what the *minimum* runtime modelling buys before
    `managed_runtime.py` takes over. The declared assumption is that the callee
    has no effect the rest of the analysis depends on, which is false for
    anything that transforms data the caller then reads. `managed_runtime.py`
    replaces it with a stub that reads the callee's metadata signature and
    returns an object, a labelled string or a scalar accordingly.
    """

    def __init__(self, retbits=32, label="ret", bounded=False, **kwargs):
        super().__init__(**kwargs)
        self.retbits = retbits
        self.label = label
        self.bounded = bounded

    def run(self, *args):  # pylint:disable=arguments-differ
        ret = claripy.BVS(f"{self.label}_unconstrained", self.retbits)
        if self.bounded:
            # A fully symbolic return is wrong for a method whose result is
            # branched on or called through: the value propagates into the
            # program counter and the state goes unconstrained. Bounding it to
            # {0,1} keeps boolean results forking both ways while making
            # pointer-shaped uses resolve to null rather than to an arbitrary
            # address.
            self.state.solver.add(claripy.ULE(ret, 1))
        return ret


def hook_pure(proj, symbols, retbits=32, bounded=False):
    """Hook each named AOT method, and its PLT entry, with an unconstrained return."""
    syms = aot_symbols(proj)
    hooked = {}
    for name in symbols:
        for cand in (name, "plt_" + name):
            addr = syms.get(cand)
            if addr is not None:
                proj.hook(addr, UnconstrainedFunction(retbits=retbits, label=name,
                                                      bounded=bounded),
                          replace=True)
                hooked[cand] = addr
    return hooked


def find_jump_table_targets(proj, lo, hi, skip_handlers=True):
    """Blocks in [lo,hi) with no direct predecessor -- i.e. jump-table arms.

    mono leaves a switch's jump table null in the image, exactly as it leaves
    the PLT null: the runtime fills both at load time. So an AOT'd C# switch
    ends in ``br x0`` through a null pointer and every arm is lost. The arms
    are still in the image, they just have no direct branch into them, which is
    what this recovers.
    """
    starts, targeted = [], set()
    a = lo
    while a < hi:
        blk = proj.factory.block(a)
        if blk.size == 0:
            break
        starts.append(a)
        insns = blk.capstone.insns
        if insns:
            last = insns[-1]
            if last.mnemonic in ("b", "bl") or last.mnemonic.startswith("b."):
                try:
                    targeted.add(int(last.op_str.replace("#", ""), 16))
                except ValueError:
                    pass
            if last.mnemonic.startswith(("cb", "tb")):
                try:
                    targeted.add(int(last.op_str.split("#")[-1], 16))
                except ValueError:
                    pass
            if last.mnemonic not in ("b", "br", "ret"):
                targeted.add(a + blk.size)
        a += blk.size
    orphans = [s for s in starts if s not in targeted and s != lo]
    if not skip_handlers:
        return orphans

    # A try/catch handler also has no direct predecessor, so it looks like a
    # switch arm. Mono's handlers open by asking the runtime for the pending
    # exception; real arms do not. Without this filter the arm list is shifted
    # and the last case falls off the end, which is why the reconstruction is
    # checked against the CIL switch instruction before it is used (see
    # case1/scripts/dispatch_analysis.py).
    names = {v: k for k, v in aot_symbols(proj).items()}
    kept = []
    for addr in orphans:
        a, handler = addr, False
        for _ in range(4):
            blk = proj.factory.block(a)
            if blk.size == 0:
                break
            for insn in blk.capstone.insns:
                if insn.mnemonic == "bl":
                    try:
                        tgt = names.get(int(insn.op_str.replace("#", ""), 16), "")
                    except ValueError:
                        continue
                    if tgt:
                        handler = "undeniable_exception" in tgt
                        break
            else:
                a += blk.size
                continue
            break
        if not handler:
            kept.append(addr)
    return kept


HEAP_BASE = 0xE0000000
HEAP_STRIDE = 0x200


class BumpAllocator(angr.SimProcedure):
    """Model mono's object allocator.

    AOT-translated managed code allocates through runtime icalls such as
    ves_icall_object_new_specific. Replacing those with an unconstrained return
    hands every `new` a symbolic pointer, and the first field access or virtual
    call on the result sends the state unconstrained. Returning successive
    concrete addresses from a scratch region keeps allocated objects addressable
    and distinct.

    `managed_runtime.TypedAllocator` supersedes this: it also records the
    managed type of each allocation and gives each object a header. This one is
    kept for the stage-by-stage comparison in `translated_explorer.py`.
    """

    NO_RET = False
    IS_FUNCTION = True

    def run(self, *args):  # pylint:disable=arguments-differ
        n = self.state.globals.get("_alloc_n", 0)
        self.state.globals["_alloc_n"] = n + 1
        addr = HEAP_BASE + n * HEAP_STRIDE
        # zero a header so vtable/sync slots read as concrete rather than symbolic
        self.state.memory.store(addr, claripy.BVV(0, HEAP_STRIDE * 8))
        return claripy.BVV(addr, self.state.arch.bits)


ALLOCATOR_PATTERNS = (
    "object_new", "ves_icall_object_new", "_jit_icall_mono_object_new",
    "AllocVector", "AllocSmall", "AllocString", "mono_gc_alloc",
)


def hook_allocators(proj, patterns=ALLOCATOR_PATTERNS):
    """Hook every runtime allocation entry with the bump allocator."""
    syms = aot_symbols(proj)
    hooked = {}
    for name, addr in syms.items():
        base = name[4:] if name.startswith("plt_") else name
        if any(p in base for p in patterns):
            proj.hook(addr, BumpAllocator(), replace=True)
            hooked[name] = addr
    return hooked
