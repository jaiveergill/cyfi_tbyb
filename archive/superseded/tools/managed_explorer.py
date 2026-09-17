#!/usr/bin/env python3
"""
2.4 - Custom ExplorationTechnique for mono-AOT'd managed code.

Designed against a measured failure. On the AOT'd target the default BFS
explorer reaches 0 of 5 command handlers: it fans out inside the byte-mixing
loop that runs before the dispatch switch, hits 257 concurrent states and
1.2 GB of RSS in 39 steps, and never arrives at the switch at all.

Two earlier designs are recorded here because their failures shaped this one:

  v1, prune loop-spinners.  Wrong: the loop sits on the only control-flow path
      to the dispatch switch, so discarding states inside it starves the
      search. Measured 0/5 with the active stash drained to empty in 20 steps.

  v2, merge the frontier by address.  Correct in principle -- the loop's paths
      do reconverge -- but SimState.merge on symbolic memory cost more per step
      than the exploration it saved, and the run blew through a 180 s budget
      without finishing.

The structural fact both versions missed: the analysis does not need every path
through the preprocessing loop, it needs *one*. The loop transforms the buffer;
the switch downstream keys on cmd[0], which the loop never writes. So a single
traversal exposes the whole dispatch table, and the 2**16 alternatives are
redundant work. This version therefore drives toward code it has not seen
yet, holding the frontier small, and keeps that frontier topped up best-first
so that sibling arms of the dispatch switch are not stranded behind whichever
arm the walk entered first.

Hooks overridden, and why:

  setup()      allocate the stashes the policy needs.
  filter()     divert states landing on a goal into 'found', so a reached
               handler stops consuming step budget and the run can terminate.
  step()       the scheduling decision. Ranking can only happen once successors
               exist, so it cannot live in filter(). After each round the
               frontier is scored for novelty, truncated to `active_cap`, and
               the remainder parked in 'deferred' -- parked, never dropped, so
               nothing is lost if the goals turn out to need it.
  complete()   halt as soon as every goal has been reached.
"""
from __future__ import annotations

import angr


class ManagedDispatchExplorer(angr.ExplorationTechnique):
    """Novelty-driven, depth-preferring exploration for AOT-translated CIL."""

    def __init__(
        self,
        goals,
        dispatch_range=None,
        active_cap=8,
        deferred_cap=48,
        resolve_indirect=True,
        max_targets=16,
        deferred_stash="deferred",
        found_stash="found",
        verbose=False,
    ):
        super().__init__()
        self.goals = dict(goals)          # addr -> label
        self.dispatch_range = dispatch_range   # (lo, hi) of the dispatch fn
        self.active_cap = active_cap
        self.deferred_cap = deferred_cap
        self.resolve_indirect = resolve_indirect
        self.max_targets = max_targets
        self.deferred_stash = deferred_stash
        self.found_stash = found_stash
        self.verbose = verbose

        self.seen = set()                 # every address the search has touched
        self.found = {}                   # goal addr -> step index
        self.steps = 0
        self.peak_active = 0
        self.deferred_peak = 0
        self.dropped = 0
        self.retired = {}   # terminal stash -> count released
        self.resolved = 0   # indirect branches enumerated

    # ---------- scoring -------------------------------------------------

    def _score(self, state):
        """Rank a state: unexplored code first, then depth.

        Novelty is what pulls the search *out* of the loop -- a state that has
        just left it is standing somewhere no state has stood before, so it
        outranks the ones still going round. Depth is the tie-break, which is
        what makes the walk depth-first rather than breadth-first.
        """
        novel = 0 if state.addr in self.seen else 1
        # A state still inside the dispatch function can still uncover another
        # switch arm. A state that has descended into a handler body cannot --
        # that handler is already recorded, and its internals are leaf work.
        # Measured: without this the search found two arms and then spent the
        # rest of its budget inside them, ending 2/5.
        in_dispatch = 0
        if self.dispatch_range is not None:
            lo, hi = self.dispatch_range
            in_dispatch = 1 if lo <= state.addr < hi else 0
        return (in_dispatch, novel, len(state.history.bbl_addrs))

    # ---------- hooks ---------------------------------------------------

    def setup(self, simgr):
        for stash in (self.deferred_stash, self.found_stash):
            if stash not in simgr.stashes:
                simgr.stashes[stash] = []

    def filter(self, simgr, state, **kwargs):
        if state.addr in self.goals and state.addr not in self.found:
            self.found[state.addr] = self.steps
            if self.verbose:
                print(f"    [found] {self.goals[state.addr]} at step {self.steps}")
            return self.found_stash
        return simgr.filter(state, **kwargs)

    def step(self, simgr, stash="active", **kwargs):
        simgr = simgr.step(stash=stash, **kwargs)
        self.steps += 1

        # Rank before recording: a state is only "novel" until it is scored.
        frontier = sorted(simgr.stashes[stash], key=self._score, reverse=True)
        for st in frontier:
            self.seen.add(st.addr)

        # Hold the frontier small. The overflow is parked, not discarded.
        if len(frontier) > self.active_cap:
            simgr.stashes[stash] = frontier[: self.active_cap]
            simgr.stashes[self.deferred_stash].extend(frontier[self.active_cap:])
        else:
            simgr.stashes[stash] = frontier

        # Top the frontier back up from 'deferred', best-first.
        #
        # Refilling only when the frontier is completely empty was measured at
        # 2/5: the walk punched through the loop, then dug into whichever switch
        # arm it happened to take and left the sibling arms parked. A dispatch
        # table is exactly the shape where siblings matter, so the frontier is
        # topped up every round and the best-scoring parked state is taken
        # rather than the most recently parked one.
        if len(simgr.stashes[stash]) < self.active_cap and simgr.stashes[self.deferred_stash]:
            pool = sorted(simgr.stashes[self.deferred_stash], key=self._score, reverse=True)
            take = self.active_cap - len(simgr.stashes[stash])
            simgr.stashes[stash].extend(pool[:take])
            simgr.stashes[self.deferred_stash] = pool[take:]

        # Bound the backlog as well as the frontier. A SimState on this target
        # costs roughly 5 MB, so an unbounded 'deferred' stash reproduces
        # exactly the memory failure the technique exists to avoid -- measured:
        # the run was SIGKILLed on a 3.8 GB host. Beyond the cap the
        # lowest-scoring states are released; they are the ones furthest from
        # new code, so they are the least likely to reach an unvisited goal.
        if len(simgr.stashes[self.deferred_stash]) > self.deferred_cap:
            ranked = sorted(simgr.stashes[self.deferred_stash],
                            key=self._score, reverse=True)
            self.dropped += len(ranked) - self.deferred_cap
            simgr.stashes[self.deferred_stash] = ranked[: self.deferred_cap]

        # Resolve indirect branches before anything is retired.
        #
        # A C# switch over a character compiles to a jump table, and the
        # indirect branch that reads it has a symbolic target, so angr files the
        # state under 'unconstrained' and the arm is never explored. Measured on
        # the translated target: the two-character arm ("10", uninstall) was reached and the
        # single-character arms 1..9 were all lost this way. Asking the solver
        # for the feasible targets and forking one state per target recovers
        # them. Capped, because an genuinely unbounded target set would
        # reintroduce the explosion the rest of this class exists to avoid.
        if self.resolve_indirect and simgr.stashes.get("unconstrained"):
            recovered = []
            for st in simgr.stashes["unconstrained"]:
                try:
                    targets = st.solver.eval_upto(st.regs.pc, self.max_targets)
                except Exception:
                    continue
                for t in targets:
                    if not self.project.loader.find_object_containing(t):
                        continue
                    fork = st.copy()
                    fork.add_constraints(fork.regs.pc == t)
                    if not fork.solver.satisfiable():
                        continue
                    fork.regs.pc = t
                    recovered.append(fork)
                    self.resolved += 1
            simgr.stashes["unconstrained"] = []
            simgr.stashes[stash].extend(recovered)

        # Release terminal states. A state that has deadended, errored or gone
        # unconstrained can never reach a goal, but angr keeps it stashed and it
        # still owns its memory plugin and constraint set. Left alone these
        # stashes grow without bound for the whole run -- measured: the process
        # was SIGKILLed even with the frontier and backlog both capped. Only the
        # counts are worth keeping.
        for terminal in ("deadended", "errored", "unconstrained"):
            n = len(simgr.stashes.get(terminal, ()))
            if n:
                self.retired[terminal] = self.retired.get(terminal, 0) + n
                simgr.stashes[terminal] = []

        self.peak_active = max(self.peak_active, len(simgr.stashes[stash]))
        self.deferred_peak = max(self.deferred_peak,
                                 len(simgr.stashes[self.deferred_stash]))
        return simgr

    def complete(self, simgr):
        return len(self.found) >= len(self.goals)
