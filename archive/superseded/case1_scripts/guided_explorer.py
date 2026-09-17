#!/usr/bin/env python3
"""
2.4 - LossAvoidingExplorer: an ExplorationTechnique for the failure this
sample actually exhibits.

The brief lists four ways real malware defeats symbolic execution: path
explosion, environment checks that fork irrelevant branches, obfuscated control
flow, and calls to APIs angr does not model. On GravityRat it is the fourth,
and the first is absent -- measured in 2_4_diagnosis.txt, peak concurrent
states is 7 at worst and 1-2 typically.

States here are not multiplied, they are destroyed. An unmodelled call returns
an unconstrained value; that value reaches a branch register; angr files the
state under 'unconstrained' and drops it. 19 of 19 such states were checked and
none has a program counter the path constraints narrow at all, so pinning it to
a target would invent control flow rather than recover it.

What a technique can legitimately do about that is route around it. This one
watches where states die, attributes each death to the block that produced it,
and then steers the frontier away from call sites already known to destroy
states -- spending the remaining budget on paths that stay inside modelled
code.

Hooks overridden:

  setup()      allocate the stashes the policy uses.
  filter()     divert a state that reaches a goal into 'found' so it stops
               consuming budget and the run can terminate.
  step()       the scheduling decision. It needs the whole frontier at once
               (to rank it) and the terminal stashes (to learn from them),
               neither of which filter() can see, since filter() is handed one
               state at a time and no history of what has already died.
  complete()   stop once every goal has been reached.

The assumption it exploits: loss is a property of the *call site*, not of the
path that reached it. A block that destroyed one state will destroy the next,
because the unmodelled call behind it returns an unconstrained value every
time. That makes a death a reusable signal rather than a one-off.
"""
from __future__ import annotations

import angr


class LossAvoidingExplorer(angr.ExplorationTechnique):
    """Steers exploration away from call sites that destroy states."""

    def __init__(self, goals, active_cap=12, deferred_cap=64, verbose=False):
        super().__init__()
        self.goals = dict(goals)
        self.active_cap = active_cap
        self.deferred_cap = deferred_cap
        self.verbose = verbose

        self.found = {}
        self.steps = 0
        self.seen = set()
        self.lossy = {}        # block address -> how many states it destroyed
        self.lost = 0
        self.avoided = 0
        self.peak_active = 0

    # ---------------- hooks ----------------

    def setup(self, simgr):
        for stash in ("deferred", "found"):
            simgr.stashes.setdefault(stash, [])

    def filter(self, simgr, state, **kwargs):
        """Record a goal the first time it is reached, but let the state run on.

        An earlier version stashed goal-reaching states in 'found'. With a goal
        set of any size that silently drains the frontier -- a state that
        touches a runtime API is usually mid-path, not finished, and parking it
        throws away everything downstream of the call. Coverage collapsed to 98
        blocks against the default explorer's 449 for exactly this reason.
        Goals are now waypoints to be noted, not terminal states.
        """
        if state.addr in self.goals and state.addr not in self.found:
            self.found[state.addr] = self.steps
            if self.verbose:
                print(f"    [reached] {self.goals[state.addr]} at step {self.steps}")
        return simgr.filter(state, **kwargs)

    def step(self, simgr, stash="active", **kwargs):
        simgr = simgr.step(stash=stash, **kwargs)
        self.steps += 1
        self._learn(simgr)
        self._rank(simgr, stash)
        self._release(simgr)
        self.peak_active = max(self.peak_active, len(simgr.stashes[stash]))
        return simgr

    def complete(self, simgr):
        # Goals are waypoints, so completion is exhaustion of the frontier,
        # which the simulation manager already decides. Never halt early.
        return False

    # ---------------- policy ----------------

    def _learn(self, simgr):
        """Attribute each destroyed state to the block that produced it."""
        for st in simgr.stashes.get("unconstrained", []):
            history = list(st.history.bbl_addrs)
            if history:
                culprit = history[-1]
                self.lossy[culprit] = self.lossy.get(culprit, 0) + 1
            self.lost += 1

    def _score(self, state):
        """Rank: away from known-lossy blocks, then toward unseen code, then depth.

        The lossy term dominates because a state about to re-enter a block that
        has already destroyed states is the least likely of any to survive the
        next step, whatever else is true of it.
        """
        risky = self.lossy.get(state.addr, 0)
        if risky:
            self.avoided += 1
        novel = 0 if state.addr in self.seen else 1
        return (-risky, novel, len(state.history.bbl_addrs))

    def _rank(self, simgr, stash):
        frontier = sorted(simgr.stashes[stash], key=self._score, reverse=True)
        for st in frontier:
            self.seen.add(st.addr)
        if len(frontier) > self.active_cap:
            simgr.stashes[stash] = frontier[: self.active_cap]
            simgr.stashes["deferred"].extend(frontier[self.active_cap:])
        else:
            simgr.stashes[stash] = frontier
            # top back up from the backlog, best-first
            pool = sorted(simgr.stashes["deferred"], key=self._score, reverse=True)
            take = self.active_cap - len(frontier)
            if take > 0 and pool:
                simgr.stashes[stash].extend(pool[:take])
                simgr.stashes["deferred"] = pool[take:]
        if len(simgr.stashes["deferred"]) > self.deferred_cap:
            ranked = sorted(simgr.stashes["deferred"], key=self._score, reverse=True)
            simgr.stashes["deferred"] = ranked[: self.deferred_cap]

    def _release(self, simgr):
        """Terminal states cannot reach a goal; keep the counts, drop the memory."""
        for terminal in ("deadended", "errored", "unconstrained"):
            simgr.stashes[terminal] = []
