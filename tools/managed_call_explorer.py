#!/usr/bin/env python3
"""
2.4 - ManagedCallExplorer: an angr ExplorationTechnique for the boundary that
destroys states on AOT-translated .NET.

The failure. On both samples states are not multiplied, they are destroyed, and
always at one instruction shape. A CIL `callvirt` on a virtual or interface
method compiles to

    ldr  x3, [x3]          ; receiver -> vtable pointer
    ldr  x16, [x3, #0x108] ; vtable slot -> callee address
    blr  x16

With no mono runtime the object header holds no vtable pointer, so the slot read
comes from memory nothing wrote and the branch register has no usable value.
The state is lost, with every constraint the path had accumulated.

The repair. Resolve the call site to the method the *original assembly* says it
invokes. `callsite_map` does that offline by aligning the AOT method's ordered
call sequence against the same method's CIL; this class applies the result to a
running state. Two earlier designs were rejected on measurements - pinning the
program counter to in-image methods (unsound: the counter is wholly free), and
one synthetic vtable shared by every object (wrong: slot +0x108 names three
different methods in this corpus). Both are in archive/superseded/, with the
measurements, and LOGBOOK.md 2.3-2.5 has the detail.

Hooks overridden:

  setup()       create the quarantine stash.
  successors()  the intervention, and the only hook positioned to make it: it
                has to happen between the vtable load and the branch, inside a
                basic block. `filter()` and `step_state()` see the state only
                after the branch has already destroyed the program counter.
                Truncates the block so the state stops on the call, then
                re-enters at the modelled callee with constraints and history
                intact.
  step()        quarantine and accounting, which need the whole frontier and the
                terminal stashes.

`filter()`, `selector()` and `complete()` are deliberately not overridden: there
is no reason to recategorise, skip or halt early here.

What this is measured to be worth, which is less than it looks. Arm D of the
comparisons installs the *same* call-site table as ordinary hooks under the
default manager (`managed_runtime.hook_sites_statically`). It matches this class
on every behavioural measure and covers slightly more blocks - 307 against 291
on GravityRat, 1,026 against 1,009 on Thanos. So the coverage belongs to the
table, which is a static analysis; what this class adds that a hook cannot is
the quarantine: a state reaching a call site no evidence can resolve is filed
with a diagnostic naming why, instead of being lost. The receiver-directed half
(`dynamic=True`) fires zero times on both samples and is kept for the diagnostic
it produces, not for coverage. See LOGBOOK.md 2.10.
"""
from __future__ import annotations

import angr
import claripy
from angr.engines.successors import SimSuccessors

QUARANTINE = "unsupported_runtime"


class ManagedCallExplorer(angr.ExplorationTechnique):
    """Resolves managed indirect calls before they destroy the state."""

    def __init__(self, runtime, dynamic=True, quarantine=True, verbose=False):
        super().__init__()
        self.rt = runtime
        self.dynamic = dynamic          # allow receiver-type resolution
        self.quarantine = quarantine
        self.verbose = verbose

        self.sites = runtime.sites               # addr -> static resolution
        self.unresolved = runtime.unresolved     # addr -> why
        self._stop_at = set(self.sites) | set(self.unresolved)

        self.steps = 0
        self.peak_active = 0
        self.resolved_static = 0
        self.resolved_dynamic = 0
        self.unsupported = 0
        self.diagnostics = []        # (addr, callee-or-None, reason)
        self._pending = []           # states captured at an unsupported boundary
        self.reached = {}            # callee -> first step it was invoked at
        self._block_cache = {}

    # ---------------- hooks ----------------

    def setup(self, simgr):
        for stash in (QUARANTINE,):
            simgr.stashes.setdefault(stash, [])

    def successors(self, simgr, state, **kwargs):
        addr = state.addr

        # (a) standing on a call site: resolve it and enter the model directly.
        if addr in self._stop_at and "num_inst" not in kwargs:
            target, callee, how = self._resolve(state, addr)
            if target is not None:
                nxt = state.copy()
                nxt.regs.lr = claripy.BVV(addr + 4, state.arch.bits)
                nxt.regs.ip = claripy.BVV(target, state.arch.bits)
                nxt.globals["_site"] = addr
                if how == "static":
                    self.resolved_static += 1
                else:
                    self.resolved_dynamic += 1
                self.reached.setdefault(callee, self.steps)
                if self.verbose:
                    print(f"    [{how}] {addr:#x} -> {callee}")
                return simgr.successors(
                    nxt, **{k: v for k, v in kwargs.items() if k != "num_inst"})
            # No target could be justified, so hold the state at the call site
            # with its constraints and history intact, and record why.
            why = self._why(state, addr)
            self.unsupported += 1
            if self.quarantine:
                held = state.copy()
                held.globals["_unsupported"] = (addr, why)
                self._pending.append((held, addr, why))
                return SimSuccessors(addr, state)   # no successors: stop here
            return simgr.successors(state, **kwargs)

        # (b) a call site lies ahead in this block: stop the state on it, so
        #     that (a) gets the chance to act before the branch is taken.
        stop = self._next_site(state, addr)
        if stop is not None and stop > addr:
            kwargs["num_inst"] = (stop - addr) // 4
        return simgr.successors(state, **kwargs)

    def step(self, simgr, stash="active", **kwargs):
        simgr = simgr.step(stash=stash, **kwargs)
        self.steps += 1
        if self._pending:
            for held, addr, why in self._pending:
                self.diagnostics.append((addr, None, why))
                simgr.stashes[QUARANTINE].append(held)
            self._pending = []
        self.peak_active = max(self.peak_active, len(simgr.stashes[stash]))
        return simgr

    # ---------------- resolution ----------------

    def _resolve(self, state, addr):
        """(target address, callee name, how) for the call site at `addr`."""
        rec = self.sites.get(addr)
        if rec is not None:
            target, callee = self.rt.stub_for(rec)
            return target, callee, "static"
        if not self.dynamic:
            return None, None, None
        # Receiver-directed resolution. AArch64 puts `this` in x0 at the call.
        slot = (self.unresolved.get(addr) or {}).get("slot")
        if slot is None:
            return None, None, None
        recv = state.regs.x0
        if state.solver.symbolic(recv):
            return None, None, None
        typ = self.rt.by_type_slot.get((self._type_of(state, recv), slot))
        if typ is None:
            return None, None, None
        return self.rt.stubs.get(typ, self.rt._generic), typ, "dynamic"

    def _type_of(self, state, recv):
        from managed_runtime import object_type
        try:
            return object_type(state, state.solver.eval(recv))
        except Exception:
            return None

    def _why(self, state, addr):
        """Classify why this site could not be resolved -- the diagnostic.

        The point of separating these is that they call for different repairs:
        a missing object header is an allocator problem, a missing target is a
        metadata problem, and a symbolic receiver is a genuine consequence of an
        earlier unmodelled call rather than a defect here.
        """
        rec = self.unresolved.get(addr)
        slot = rec.get("slot") if rec else None
        recv = state.regs.x0
        if state.solver.symbolic(recv):
            return "receiver symbolic (an earlier unmodelled call returned it)"
        if slot is None:
            return "dispatch shape not recognised: no slot offset recovered"
        if state.solver.eval(recv) == 0:
            return ("receiver is null (it came from a field, static or local "
                    "this analysis never wrote)")
        if self._type_of(state, recv) is None:
            return f"receiver {state.solver.eval(recv):#x} has no recorded type " \
                   f"(not produced by a typed allocation site)"
        return (f"receiver type {self._type_of(state, recv)} has no known callee "
                f"at slot {slot:#x}")

    def _next_site(self, state, addr):
        """The first call site strictly inside the block starting at `addr`."""
        if addr in self._block_cache:
            hit = self._block_cache[addr]
        else:
            try:
                block = self.project.factory.block(addr)
                ends = [a for a in block.instruction_addrs if a in self._stop_at]
            except Exception:
                ends = []
            hit = min((a for a in ends if a > addr), default=None)
            self._block_cache[addr] = hit
        return hit

    # ---------------- reporting ----------------

    def summary(self):
        return {
            "steps": self.steps,
            "resolved_static": self.resolved_static,
            "resolved_dynamic": self.resolved_dynamic,
            "unsupported": self.unsupported,
            "peak_active": self.peak_active,
            "callees": dict(self.reached),
        }
