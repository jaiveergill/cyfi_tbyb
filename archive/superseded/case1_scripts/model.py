#!/usr/bin/env python3
"""
Runtime model for the AOT-translated GravityRat image.

aot_bridge resolves the linkage table and hooks unresolved runtime calls, but
its allocator zeroes the object header. On this sample that is fatal: Mono
compiles interface calls as a load through the object's vtable, so a zero
header means a read from address (0 + slot), which is unmapped, which yields a
symbolic program counter, which discards the state. See NOTES.md §2.4.

This module supplies the missing piece -- objects whose header points at a
synthetic vtable wide enough to cover every slot offset the image actually
uses -- and is shared by the diagnostic scripts so they all model identically.

Slot bounds are measured, not assumed; slot_offsets() below regenerates them.
"""
import angr
import claripy

VTABLE = 0xF0000000     # synthetic vtable base
SLOT_LO = 0x100         # interface slots sit below it   (measured: -0x98)
SLOT_HI = 0x800         # virtual slots sit above it     (measured: +0x7a0)
OBJECTS = 0xE8000000    # objects handed out by the allocator
STRIDE = 0x400


def _fresh_object(state, index, region=0):
    addr = OBJECTS + region + index * STRIDE
    state.memory.store(addr, claripy.BVV(0, STRIDE * 8))
    state.memory.store(addr, claripy.BVV(VTABLE, 64),
                       endness=state.arch.memory_endness)
    return addr


class VirtualStub(angr.SimProcedure):
    """Stands in for any method reached through a synthetic vtable slot."""

    IS_FUNCTION = True

    def run(self):  # pylint: disable=arguments-differ
        n = self.state.globals.get("_vstub", 0)
        self.state.globals["_vstub"] = n + 1
        return _fresh_object(self.state, n, region=0x1000000)


class HeaderedAllocator(angr.SimProcedure):
    """Like aot_bridge's BumpAllocator, but the header points at a vtable."""

    IS_FUNCTION = True

    def run(self, *args):  # pylint: disable=arguments-differ
        n = self.state.globals.get("_alloc", 0)
        self.state.globals["_alloc"] = n + 1
        return _fresh_object(self.state, n)


def install(proj, ab):
    """Resolve the linkage table, model allocation, hook unresolved calls."""
    handler = proj.loader.extern_object.allocate()
    proj.hook(handler, VirtualStub())

    unresolved = ab.unresolved_plt(proj)
    allocators = ab.hook_allocators(proj)
    for addr in allocators.values():
        proj.hook(addr, HeaderedAllocator(), replace=True)
    ab.hook_pure(proj, [n for n in unresolved
                        if n not in allocators and "plt_" + n not in allocators],
                 retbits=64)
    return handler, unresolved, allocators


def entry_state(proj, addr, handler):
    """A call state with the synthetic vtable laid down in memory."""
    state = proj.factory.call_state(addr)
    for off in range(-SLOT_LO, SLOT_HI, 8):
        state.memory.store(VTABLE + off, claripy.BVV(handler, 64),
                           endness=state.arch.memory_endness)
    return state


def slot_offsets(proj, ab):
    """Measure the vtable slot offsets the image actually uses.

    Only loads that feed an indirect branch count: a vtable slot is by
    definition a value that ends up in `blr`. Counting every `ldr` immediate
    instead inflates the positive set with ordinary field and stack accesses
    and reports a range the dispatch code never uses.

    Virtual dispatch uses an immediate offset; interface dispatch builds a
    negative offset in a register with a mov/movk pair and indexes with it.
    """
    import collections
    positive, negative = collections.Counter(), collections.Counter()
    for sym in proj.loader.main_object.symbols:
        if not sym.name or sym.name.startswith("plt_") or not sym.size:
            continue
        addr, end = sym.rebased_addr, sym.rebased_addr + sym.size
        while addr < end:
            try:
                block = proj.factory.block(addr)
            except Exception:
                break
            if block.size == 0:
                break
            insns = list(block.capstone.insns)
            regs = {}
            for i, insn in enumerate(insns):
                m, ops = insn.mnemonic, insn.op_str.replace(" ", "")
                if m == "mov" and ops.count(",") == 1 and ops.split(",")[1].startswith("#"):
                    try:
                        regs[ops.split(",")[0]] = int(ops.split("#")[1], 0)
                    except ValueError:
                        pass
                elif m == "movk" and "lsl" in ops:
                    parts = ops.split(",")
                    try:
                        imm = int(parts[1].lstrip("#"), 0)
                        sh = int(parts[2].split("#")[1], 0)
                        if parts[0] in regs:
                            regs[parts[0]] = (regs[parts[0]] & ~(0xFFFF << sh)) | (imm << sh)
                    except (ValueError, IndexError):
                        pass
                elif m == "blr":
                    branch_reg = ops.strip()
                    # walk back for the load that filled the branch register
                    for prev in reversed(insns[:i]):
                        if not prev.mnemonic.startswith("ldr"):
                            continue
                        pops = prev.op_str.replace(" ", "")
                        if not pops.startswith(branch_reg + ","):
                            continue
                        if "[" not in pops:
                            break
                        inner = pops.split("[", 1)[1].rstrip("]")
                        parts = inner.split(",")
                        if len(parts) == 2 and parts[1].startswith("#"):
                            try:
                                positive[int(parts[1].lstrip("#"), 0)] += 1
                            except ValueError:
                                pass
                        elif len(parts) == 2 and parts[1] in regs:
                            v = regs[parts[1]] & ((1 << 64) - 1)
                            if v & (1 << 63):
                                v -= 1 << 64
                            negative[v] += 1
                        break
            addr += block.size
    return positive, negative
