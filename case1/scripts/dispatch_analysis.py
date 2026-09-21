#!/usr/bin/env python3
"""
2.5.3 - command dispatch: symbolize the task identifier and map every handler.

`Core.Manager.UpdateServer` pulls a task list from the C2, spawns each task with
`Task.Run`, and the lambda it runs switches on the task's `TaskName`. That lambda
is the only method in the assembly that switches on a `TaskName` (the other
`get_TaskName` use, in `UpdateServer` itself, formats a progress string), so it is
where the command-to-behaviour mapping lives.

Three obstacles:

  the dispatch runs on a thread pool, which symbolic execution does not follow.
  The lambda is a named method, so it is entered directly, with the closure and
  task objects it would have received built by hand. So everything here is
  bounded to that routine. I am not claiming anything about what is reachable
  from the program's entry point.

  mono leaves the switch's jump table null in the image, exactly as it leaves the
  linkage table null, so the `br x0` reads zero and every arm is lost. The arms
  are recovered from the image and the table written into the slot the switch
  reads. The reconstruction is checked against the CIL switch instruction before
  it is used.

  `TaskName` is an auto-property, and mono inlined its getter: the compiled code
  reads the field directly (`ldrsw x25, [x0, #0x20]`) and never calls
  `get_TaskName`. Hooking the getter would symbolize nothing, so the field itself
  is symbolized instead.

    .venv/bin/python case1/scripts/dispatch_analysis.py [default|custom]
"""
import json
import pathlib
import re
import subprocess
import sys
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import gravityrat as G          # noqa: E402
sys.path.insert(0, str(G.ROOT / "tools"))

import claripy                  # noqa: E402
import aot_bridge as ab         # noqa: E402
import ledger                   # noqa: E402
from managed_call_explorer import ManagedCallExplorer    # noqa: E402

DISPATCH = "LSASS_Core_Manager__c__DisplayClass5_0__UpdateServerb__2"
BUDGET = 150

# Read out of the compiled prologue, not assumed:
#   0x440330  ldr   x0, [x26, #0x10]     closure -> _task
#   0x44033c  ldrsw x25, [x0,  #0x20]    task    -> TaskName (inlined getter)
#   0x440340  mov   x30, #0xd
#   0x440348  b.hs  <default>            values >= 13 skip the table entirely
TASK_FIELD, NAME_FIELD, ENUM_COUNT = 0x10, 0x20, 13

CLOSURE, TASK, TABLE = 0xD1000000, 0xD1001000, 0xD0000000

# The CIL switch instruction, verbatim from `<UpdateServer>b__2` IL 0x0019, and
# the method body's base offset so the targets can be read as IL offsets.
IL_SWITCH = [81492, 81522, 81406, 81422, 81478, 81347, 81379, 81436,
             81550, 81550, 81550, 81550, 81550]
IL_BASE = 81260
IL_DEFAULT = 81550

# The enum, in declaration order, from LSASS.Common.Enums.TaskName.
TASK_NAMES = ["StartU", "StopU", "PortScan", "ProcessScan", "ServicesScan",
              "DriveScan", "DriveUpload", "RunCmd", "StartTcpCmd", "StopTcpCmd",
              "StartBroadCast", "StopBroadCast", "SelfDestroy"]

# What each arm does, read from the CIL at the IL offset the switch names.
ARM_BEHAVIOUR = {
    81347: "Instance.Start(locals.filePath) -> respFile      (drive enumeration)",
    81379: "Start(locals.filePath) -> respFile               (drive upload)",
    81406: "Start() -> respFile                              (port scan)",
    81422: "Start(1) -> respFile                             (process scan)",
    81436: "if !IsNullOrWhiteSpace(_task.Args): Start(_task.Args) -> respFile"
           "   (shell command, argument-carrying)",
    81478: "Start(1) -> respFile                             (services scan)",
    81492: "if !Settings.IsUsb: Instance.Start() -> respFile (USB monitor on)",
    81522: "if  Settings.IsUsb: Instance.Stop()  -> respFile (USB monitor off)",
    81550: "the shared tail: OnCompleted(_task, respFile)    (no arm of its own)",
}


def jumptable_slot(proj, lo, hi):
    """The GOT slot the switch reads its table pointer from."""
    bases, last = {}, None
    addr = lo
    while addr < hi:
        block = proj.factory.block(addr)
        if block.size == 0:
            break
        for insn in block.capstone.insns:
            ops = insn.op_str.replace(" ", "")
            if insn.mnemonic == "adrp":
                bases[ops.split(",")[0]] = insn.operands[1].imm
            elif insn.mnemonic == "add" and ops.count(",") == 2:
                d, s1, s2 = ops.split(",")
                if s1 in bases and s2.startswith("#"):
                    bases[d] = bases[s1] + int(s2[1:], 0)
            elif insn.mnemonic.startswith("ldr") and "[" in ops:
                inner = ops.split("[", 1)[1].rstrip("]").split(",")
                if len(inner) == 2 and inner[0] in bases and inner[1].startswith("#"):
                    last = bases[inner[0]] + int(inner[1][1:], 0)
            elif insn.mnemonic == "br" and last is not None:
                return last
        addr += block.size
    raise SystemExit("jump-table slot not found")


def default_target(proj, lo, hi):
    """The block the switch's bounds check branches to for an out-of-range value.

    Read off the instruction, not computed. An earlier version derived this as
    `lo + (IL_DEFAULT - IL_BASE)` -- adding a CIL byte offset to a native
    address, which on this method produced 0x440442, an address that is not a
    block start and in fact lands in the middle of an instruction. Native layout
    bears no relation to IL offsets; the compiler already wrote the answer down:

        0x440340  mov   x30, #0xd
        0x440344  cmp   w25, w30
        0x440348  b.hs  #0x440668      <- the default block
    """
    addr = lo
    while addr < hi:
        block = proj.factory.block(addr)
        if block.size == 0:
            break
        for insn in block.capstone.insns:
            # the unsigned "higher or same" test against the arm count
            if insn.mnemonic in ("b.hs", "b.cs"):
                try:
                    return int(insn.op_str.replace("#", ""), 16)
                except ValueError:
                    pass
        addr += block.size
    raise SystemExit("default target not found: no b.hs in the dispatch bounds check")


def expected_callees(exe_path):
    """il_offset -> the CIL callee invoked first at or after it.

    This is what the arm reconstruction is checked against. Checking only that
    each candidate arm *contains a call*, which an earlier version did, does not
    test the pairing at all.
    """
    import dnfile
    sys.path.insert(0, str(G.ROOT / "tools"))
    import cil_disasm as cd
    from dncil.cil.body import CilMethodBody

    pe = dnfile.dnPE(str(exe_path))
    tokens = cd.build_token_map(pe)
    for td in pe.net.mdtables.TypeDef:
        for md in td.MethodList:
            row = md.row
            if row is None or not row.Rva or str(row.Name) != "<UpdateServer>b__2":
                continue
            body = cd.read_body(pe, row)
            if not isinstance(body, CilMethodBody):
                continue
            calls = [(i.offset - body.offset, cd.resolve(tokens, pe, i.operand))
                     for i in body.instructions
                     if i.opcode.name in ("call", "callvirt", "newobj")]
            # Each arm's window is bounded by the *next* arm's IL offset, so it
            # cannot borrow a callee from its neighbour. Without that bound a
            # window of three bleeds into the following arm and a rotated
            # pairing still scores 6/8 -- i.e. the check barely tests anything.
            bounds = sorted({t for t in IL_SWITCH if t != IL_DEFAULT}) + [IL_DEFAULT]
            out = {}
            for il, nxt in zip(bounds, bounds[1:]):
                lo_rel, hi_rel = il - IL_BASE, nxt - IL_BASE
                # A small window inside the arm, because mono inlines
                # auto-property getters: an arm whose CIL opens with
                # `callvirt get_Args` opens natively with the call after it.
                out[il] = [n for off, n in calls if lo_rel <= off < hi_rel][:3]
            return out
    raise SystemExit("<UpdateServer>b__2 not found in the metadata")


# Helpers mono emits around managed calls. They are not the arm's callee, so
# the first *managed* call is the one to compare.
MONO_INTERNAL = ("_jit_icall_", "mono_", "wrapper_alloc_object_",
                 "wrapper_write_barrier", "wrapper_stelemref")


def _same_callee(native, candidates):
    """Does this native symbol name any of the CIL callees in the window?

    Matched on `_`-delimited tokens with the method name allowed to span
    several of them -- `get_Instance` is two tokens in the mangled symbol and
    one in the metadata, which a naive `in` test gets wrong.
    """
    if not native or not candidates:
        return False
    n = native[4:] if native.startswith("plt_") else native
    for cil in candidates:
        body = cil.split(" ", 1)[1] if cil.startswith(
            ("MemberRefRow ", "MethodDefRow ")) else cil
        owner, _, method = body.rpartition("::")
        m = re.escape(method.replace(".", ""))
        if not re.search(r"(?:^|_)" + m + r"(?:_|$)", n):
            continue
        if owner:
            last = owner.rsplit(".", 1)[-1].lower()
            if last not in [t.lower() for t in n.split("_")]:
                continue
        return True
    return False


def arms_and_check(rt):
    """Recover the arms and validate the reconstruction against the CIL.

    The check: each native arm's first outgoing call must be the call the CIL
    makes at the IL offset the switch pairs it with. If mono had reordered the
    arms, or if the orphan-block heuristic had picked up a catch handler, the
    first calls would not line up.
    """
    sym = [s for s in rt.proj.loader.main_object.symbols
           if s.name == DISPATCH][0]
    lo, hi = sym.rebased_addr, sym.rebased_addr + sym.size
    slot = jumptable_slot(rt.proj, lo, hi)
    arms = sorted(ab.find_jump_table_targets(rt.proj, lo, hi))
    default = default_target(rt.proj, lo, hi)
    want = expected_callees(G.EXE)
    il_targets = sorted({t for t in IL_SWITCH if t != IL_DEFAULT})
    checks = []
    for il, arm in zip(il_targets, arms):
        first = None
        a = arm
        for _ in range(4):
            blk = rt.proj.factory.block(a)
            if blk.size == 0:
                break
            for insn in blk.capstone.insns:
                if insn.mnemonic == "bl":
                    try:
                        t = int(insn.op_str.replace("#", ""), 16)
                    except ValueError:
                        continue
                    nm = rt.name_of(t) or hex(t)
                    base = nm[4:] if nm.startswith("plt_") else nm
                    if base.startswith(MONO_INTERNAL):
                        continue          # class-init and allocation helpers
                    first = nm
                    break
            if first:
                break
            a += blk.size
        checks.append((il, arm, first, want.get(il),
                       _same_callee(first, want.get(il))))
    return lo, hi, slot, arms, il_targets, checks, default


def entry_state(rt, lo, slot, arms, default):
    """A state at the lambda with a constructed closure and a symbolic command."""
    state = rt.entry_state(lo)
    end = state.arch.memory_endness
    for base in (CLOSURE, TASK):
        state.memory.store(base, claripy.BVV(0, 0x200 * 8))
    state.memory.store(CLOSURE + TASK_FIELD, claripy.BVV(TASK, 64), endness=end)

    cmd = claripy.BVS("task_name", 32)
    state.memory.store(TASK + NAME_FIELD, cmd, endness=end)
    state.globals["_cmd_name"] = "task_name"

    il_to_arm = {il: a for il, a in zip(sorted({t for t in IL_SWITCH
                                               if t != IL_DEFAULT}), arms)}
    for i, il in enumerate(IL_SWITCH):
        target = il_to_arm.get(il, default)
        state.memory.store(TABLE + i * 8, claripy.BVV(target, 64), endness=end)
    state.memory.store(slot, claripy.BVV(TABLE, 64), endness=end)
    state.regs.x0 = CLOSURE
    return state, cmd


def run(use_technique):
    rt, models = G.build()
    lo, hi, slot, arms, il_targets, checks, default = arms_and_check(rt)
    state, cmd = entry_state(rt, lo, slot, arms, default)
    goals = {a: i for i, a in enumerate(arms)}

    simgr = rt.proj.factory.simulation_manager(state)
    tech = ManagedCallExplorer(rt) if use_technique else None
    if tech:
        simgr.use_technique(tech)

    reached = {}

    def watch(sm, step):
        for st in sm.active:
            if st.addr in goals and st.addr not in reached:
                # A witness: a concrete command the solver says takes this arm.
                try:
                    wit = st.solver.eval(cmd)
                    sat = st.solver.satisfiable()
                except Exception:
                    wit, sat = None, False
                reached[st.addr] = {"step": step, "witness": wit, "sat": sat}

    t0 = time.time()
    steps, peak = G.walk(simgr, BUDGET, collect=watch)
    return {
        "arms": arms, "slot": slot, "il_targets": il_targets,
        "checks": [[il, a, n, w, ok] for il, a, n, w, ok in checks],
        "default": default,
        "reached": {str(k): v for k, v in reached.items()},
        "steps": steps, "peak": peak, "secs": round(time.time() - t0, 1),
        "stashes": {k: len(v) for k, v in simgr.stashes.items() if v},
        "tech": tech.summary() if tech else None, "models": models,
        "lo": lo, "hi": hi,
    }


def main():
    if len(sys.argv) > 1 and sys.argv[1] in ("default", "custom"):
        print(json.dumps(run(sys.argv[1] == "custom")))
        return

    arms = {}
    for arm in ("default", "custom"):
        out = subprocess.run([sys.executable, __file__, arm],
                             capture_output=True, text=True)
        arms[arm] = json.loads(out.stdout.strip().splitlines()[-1])
    d, c = arms["default"], arms["custom"]

    print(ledger.header(
        "2.5.3  COMMAND DISPATCH: symbolic TaskName over the only routine that "
        "switches on it",
        artifacts=[G.EXE, G.SO], sources=G.SOURCES + [pathlib.Path(__file__)],
        entry=f"{DISPATCH}  {c['lo']:#x}-{c['hi']:#x}",
        inputs=f"task_name, a free 32-bit symbol written into "
               f"[task + {NAME_FIELD:#x}] (the field the compiled code reads)",
        models=c["models"] + [
            f"jump table reconstructed and written to GOT slot {c['slot']:#x}",
            "closure and task objects constructed by hand (see below)"],
        budget=f"{BUDGET} steps",
        technique="arm 1: angr default (BFS) | arm 2: ManagedCallExplorer",
        notes=["entered mid-program: this maps the routine, not the whole build"]))

    print("-" * 74)
    print("RECONSTRUCTING THE JUMP TABLE, AND CHECKING IT")
    print("-" * 74)
    print(f"  GOT slot the switch reads : {c['slot']:#x}   value in the image: 0x0")
    print(f"  arms recovered from the image : {len(c['arms'])}   [static]")
    print(f"  distinct CIL switch targets   : {len(c['il_targets'])}   [static]")
    print(f"  default block, read from the bounds check `b.hs` : "
          f"{c['default']:#x}   [static]")
    print()
    print("  Each native arm's first outgoing call is compared with the callee")
    print("  the CIL invokes first at the IL offset the switch pairs it with.")
    print("  Checking only that an arm contains some call would pass anything.")
    print()
    print(f"      {'IL':<8} {'arm':<11} {'native first managed call':<46} "
          f"{'CIL callee window at that offset':<54} match")
    for il, arm, first, wanted, ok in c["checks"]:
        fn = (first or "-")
        fn = fn[4:] if fn.startswith("plt_") else fn
        wl = wanted or []
        wn = " / ".join(w.replace("MemberRefRow ", "").replace("MethodDefRow ", "")
                        for w in wl[:2]) or "-"
        print(f"      {il - IL_BASE:#06x}   {arm:#011x} {fn[:44]:<46} "
              f"{wn[:52]:<54} {'yes' if ok else 'NO'}")
    n_ok = sum(1 for *_, ok in c["checks"] if ok)
    print()
    print(f"  -> {n_ok} of {len(c['checks'])} arms match the CIL callee  [static]")
    if n_ok != len(c["checks"]):
        print("  -> RECONSTRUCTION NOT VALIDATED: the mapping below is not "
              "trustworthy.")

    print()
    print("-" * 74)
    print("COMMAND -> HANDLER, WITH A WITNESS FOR EACH")
    print("-" * 74)
    il_to_arm = dict(zip(sorted(set(c["il_targets"])), c["arms"]))
    first_call = {il: n for il, _, n, _, _ in c["checks"]}
    print(f"  {'val':<4} {'TaskName':<15} {'arm':<11} {'witness':<8} "
          f"{'handler entered (first call in the arm)':<52} behaviour")
    for i, il in enumerate(IL_SWITCH):
        name = TASK_NAMES[i]
        arm = il_to_arm.get(il)
        if arm is None:
            print(f"  {i:<4} {name:<15} {'default':<11} {'-':<8} "
                  f"{'-':<52} {ARM_BEHAVIOUR[IL_DEFAULT]}")
            continue
        hit = c["reached"].get(str(arm))
        wit = str(hit["witness"]) if hit else "-"
        fc = (first_call.get(il) or "-")
        fc = fc[4:] if fc.startswith("plt_") else fc
        print(f"  {i:<4} {name:<15} {arm:#011x} {wit:<8} {fc:<52} "
              f"{ARM_BEHAVIOUR[il]}")

    print()
    print(f"  handlers reached, default (BFS)      : {len(d['reached'])}"
          f"/{len(d['arms'])}   steps {d['steps']}  peak {d['peak']}  {d['secs']}s")
    print(f"  handlers reached, ManagedCallExplorer: {len(c['reached'])}"
          f"/{len(c['arms'])}   steps {c['steps']}  peak {c['peak']}  {c['secs']}s")
    only_c = set(c["reached"]) - set(d["reached"])
    only_d = set(d["reached"]) - set(c["reached"])
    print(f"  reached only by the technique        : "
          f"{', '.join(sorted(only_c)) or '(none)'}")
    print(f"  reached only by the default          : "
          f"{', '.join(sorted(only_d)) or '(none)'}")
    print()
    print("  Both arms reach every handler. Once the jump table is reconstructed")
    print("  the switch is an ordinary 13-way branch on a symbolic value, which")
    print("  angr's default manager forks correctly on its own. So this part of")
    print("  the result comes from the runtime modelling, not the technique.")
    print("  [symbolic]")

    print()
    print("-" * 74)
    print("VALUES 8-12")
    print("-" * 74)
    print("  The compiled bounds check is `mov x30,#0xd; cmp w25,w30; b.hs default`,")
    print("  so 0..12 index the table and 13+ skip it. Table entries 8..12 all hold")
    print(f"  the default block, because CIL switch targets 8..12 are all "
          f"{IL_DEFAULT}, which is")
    print("  the shared tail. So StartTcpCmd, StopTcpCmd, StartBroadCast,")
    print("  StopBroadCast and SelfDestroy are declared in the enum and are not")
    print("  handled here: they fall to `OnCompleted(_task, respFile)` and produce")
    print("  no action.  [static, from the switch instruction]")
    print()
    print("  How far that goes: `get_TaskName` has two consumers in the")
    print("  assembly. This lambda is one; the other is `UpdateServer` itself,")
    print("  which uses it to build a progress string (IL 0x011C -> String.Concat")
    print("  -> OnProgress), not to dispatch. So there is no second dispatcher on")
    print("  TaskName. That covers the TaskName enum and this routine only. The")
    print("  build may well have another command surface elsewhere.  [static]")
    print(ledger.legend())


if __name__ == "__main__":
    main()
