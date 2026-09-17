#!/usr/bin/env python3
"""
2.5.1 (case 2) - Thanos's anti-analysis checks, and what forcing them does.

Thanos carries the usual set: `CheckRemoteDebuggerPresent`, an
`NtSetInformationProcess` call to set `ProcessBreakOnTermination`, and a scan of
running process names against a list of analysis tools. The brief asks for these
to be forced to the "not being analyzed" answer and for a statement of what
becomes reachable.

The answer here has a twist worth the section on its own: in *this build* most of
them never run, because each is gated on a static string field that the class
constructor sets to "NO". Thanos is builder-produced ransomware, and the builder
writes the affiliate's choices into `.cctor` as string constants. So the
configuration is recoverable without running anything, and it says which
features this particular affiliate turned on.

Three parts:

  1. the build's configuration, read out of `.cctor`;
  2. the analysis-tool list, recovered by *executing* `.cctor` -- the names are
     base64 constants decoded at run time, so this is a test of the decoder
     model as much as of the exploration;
  3. forcing the checks that do run, and measuring what that changes.

    .venv/bin/python case2/scripts/anti_analysis.py [natural|clean]
"""
import json
import pathlib
import subprocess
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import thanos as T              # noqa: E402
sys.path.insert(0, str(T.ROOT / "tools"))

import dnfile                   # noqa: E402
import ledger                   # noqa: E402
import managed_runtime as mr    # noqa: E402
import cil_disasm as cd         # noqa: E402
from dncil.cil.body import CilMethodBody   # noqa: E402
from managed_call_explorer import ManagedCallExplorer   # noqa: E402

MAIN_TYPE = "MufMaOSvGyvz.IyUWqQZlcOSTLhq"
CCTOR = "MufMaOSvGyvz_IyUWqQZlcOSTLhq__cctor"
BUDGET = 400

# The checks that are not behind a flag, or whose flag is on in this build.
FORCED = ["MufMaOSvGyvz_ghEykQIAJr_CheckRemoteDebuggerPresent",
          "MufMaOSvGyvz_xxKHdLdCMeOG_NtSetInformationProcess",
          "System_Diagnostics_Process_GetProcessesByName_string",
          "System_Diagnostics_Process_EnterDebugMode"]

ENTRIES = ["MufMaOSvGyvz_ghEykQIAJr_CmOCZJRfKEYgY",
           "MufMaOSvGyvz_xxKHdLdCMeOG_bfVvoFmZrqIvYF",
           "lowFQsJSlrFgr_qMyHPNTWke_CusTKXtiVMDCm_string",
           "MufMaOSvGyvz_hpvgypLXixi__cctor"]


def static_config():
    """`ldstr X; stsfld F` in .cctor, and `ldsfld F; ldstr "YES"` gates in Main."""
    pe = dnfile.dnPE(str(T.EXE))
    tokens = cd.build_token_map(pe)
    flags, gates = {}, []
    for td in pe.net.mdtables.TypeDef:
        full = ".".join(p for p in (str(td.TypeNamespace or ""),
                                    str(td.TypeName or "")) if p)
        if full != MAIN_TYPE:
            continue
        for md in td.MethodList:
            row = md.row
            if row is None or not row.Rva:
                continue
            body = cd.read_body(pe, row)
            if not isinstance(body, CilMethodBody):
                continue
            ins = list(body.instructions)
            for i, x in enumerate(ins):
                if x.opcode.name == "stsfld" and i and \
                        ins[i - 1].opcode.name == "ldstr":
                    name = cd.resolve(tokens, pe, x.operand).split()[-1]
                    val = cd.resolve(tokens, pe, ins[i - 1].operand).strip('"')
                    flags.setdefault(name, val)
                if x.opcode.name == "ldsfld" and i + 2 < len(ins) and \
                        ins[i + 1].opcode.name == "ldstr" and \
                        ins[i + 2].opcode.name == "call":
                    name = cd.resolve(tokens, pe, x.operand).split()[-1]
                    want = cd.resolve(tokens, pe, ins[i + 1].operand).strip('"')
                    if want in ("YES", "NO") and str(row.Name) == "Main":
                        gates.append((x.offset - body.offset, name, want))
    return flags, gates


def run(mode):
    """mode: 'natural' | 'clean' (every check answers 'not being analysed')."""
    rt, models = T.build(T.base_models())
    forced = []
    if mode == "clean":
        for name in FORCED:
            forced += rt.force(name, 0)
        models.append(f"{len(set(forced))} anti-analysis entry points forced to 0")
    blocks, callees = set(), set()
    for name in ENTRIES:
        addr = rt.address_of(name)
        if addr is None:
            continue
        simgr = rt.proj.factory.simulation_manager(rt.entry_state(addr))
        tech = ManagedCallExplorer(rt)
        simgr.use_technique(tech)
        T.walk(simgr, BUDGET)
        blocks |= T.blocks_touched(simgr)
        callees |= set(tech.reached)
    return {"mode": mode, "forced": sorted(set(forced)), "models": models,
            "blocks": len(blocks), "callees": sorted(callees)}


def toollist():
    """Execute .cctor and capture the analysis-tool names it decodes."""
    adds = []
    models = T.base_models()
    models["Add"] = mr.CollectionAdd(pairs=False, log=adds)
    rt, _ = T.build(models)
    simgr = rt.proj.factory.simulation_manager(rt.entry_state(rt.address_of(CCTOR)))
    simgr.use_technique(ManagedCallExplorer(rt))
    T.walk(simgr, 900)
    return [a[1][1] for a in adds if a[1][1]]


def main():
    if len(sys.argv) > 1 and sys.argv[1] in ("natural", "clean"):
        print(json.dumps(run(sys.argv[1])))
        return
    if len(sys.argv) > 1 and sys.argv[1] == "tools":
        print(json.dumps(toollist()))
        return

    res = {}
    for mode in ("natural", "clean"):
        out = subprocess.run([sys.executable, __file__, mode],
                             capture_output=True, text=True)
        res[mode] = json.loads(out.stdout.strip().splitlines()[-1])
    names = json.loads(subprocess.run([sys.executable, __file__, "tools"],
                                      capture_output=True, text=True)
                       .stdout.strip().splitlines()[-1])
    flags, gates = static_config()

    print(ledger.header(
        "2.5.1 (case 2)  ANTI-ANALYSIS IN THANOS: a build whose checks are "
        "mostly switched off",
        artifacts=[T.EXE, T.SO], sources=T.SOURCES + [pathlib.Path(__file__)],
        entry=f"{len(ENTRIES)} methods carrying a check; .cctor for the config",
        models=res["natural"]["models"],
        budget=f"{BUDGET} steps per entry point",
        technique="ManagedCallExplorer in both arms",
        notes=["the two arms differ only in what the checks return"]))

    print("-" * 74)
    print("1. THE BUILD'S CONFIGURATION, FROM .cctor")
    print("-" * 74)
    print("  Thanos is builder-produced: the affiliate's choices are compiled in")
    print("  as `ldstr` constants assigned to static fields by the class")
    print("  constructor, and `Main` gates each feature on `field == \"YES\"`.")
    print()
    onoff = {k: v for k, v in flags.items() if v in ("YES", "NO", "EVET")}
    on = [k for k, v in onoff.items() if v in ("YES", "EVET")]
    off = [k for k, v in onoff.items() if v == "NO"]
    print(f"  boolean-looking flags set in .cctor : {len(onoff)}   [static]")
    print(f"      on  ({len(on)}): " + ", ".join(sorted(on)))
    print(f"      off ({len(off)}): " + ", ".join(sorted(off)))
    print()
    print("  other configuration constants:")
    for k, v in sorted(flags.items()):
        if v not in ("YES", "NO", "EVET"):
            # The ransom note is a 700-character base64 blob; it is printed in
            # full, decoded, in 2_3_decoded_strings.txt, so it is elided here.
            shown = v if len(v) <= 64 else v[:61] + "..."
            print(f"      {k:<22} = {shown!r}"
                  + (f"   ({len(v)} chars, elided)" if len(v) > 64 else ""))
    print()
    print(f"  gates in Main that test one of these: {len(gates)}   [static]")
    for off_, name, want in gates[:20]:
        state = flags.get(name, "?")
        verdict = "OPEN" if state == want else "CLOSED"
        print(f"      IL {off_:#06x}  {name:<22} == {want!r}   "
              f"(.cctor sets {state!r})  -> {verdict}")
    if len(gates) > 20:
        print(f"      ... and {len(gates) - 20} more")
    print()
    print("  So most of this build's optional behaviour -- including part of the")
    print("  anti-analysis -- is switched off before any check runs. That is a")
    print("  property of this build, recovered without executing it, and it is")
    print("  the first thing worth knowing about the sample.  [static]")

    print()
    print("-" * 74)
    print("2. THE LISTS .cctor BUILDS, RECOVERED BY EXECUTING IT")
    print("-" * 74)
    print(f"  strings captured at the collections' Add calls: {len(names)}"
          f"   [symbolic]")
    print("  Each is a base64 `ldstr` constant decoded at run time by an in-image")
    print("  helper; the decoder is modelled by `Convert.FromBase64String`, so")
    print("  these come back as text rather than as symbols.")
    print()
    for i in range(0, len(names), 4):
        print("      " + "  ".join(f"{n:<22}" for n in names[i:i + 4]))
    print()
    print("  `.cctor` fills several collections, and executing it walks all of")
    print("  them in order: first the process names the sample watches for or")
    print("  masquerades as, then the `net stop` service list, then the")
    print("  `vssadmin` shadow-copy commands and the backup-file wildcards.")
    print("  The entries marked <unresolved> are the ones whose GOT literal slot")
    print("  the recovery declined to claim, not ones that decoded to nothing.")
    print()
    print("  This is the ransomware behaviour, connected to an executed path")
    print("  rather than inferred from nearby API names: the strings are read")
    print("  back out of the state at the `Add` call that stores them, after the")
    print("  in-image base64 helper has actually run on them.  [symbolic]")

    print()
    print("-" * 74)
    print("3. FORCING THE CHECKS THAT DO RUN")
    print("-" * 74)
    print(f"  forced symbols: {len(res['clean']['forced'])}")
    for f in res["clean"]["forced"]:
        print(f"      {f}")
    print()
    n, c = res["natural"], res["clean"]
    print(f"  {'arm':<34} {'blocks':>8} {'runtime callees reached':>26}")
    print(f"  {'left to the model':<34} {n['blocks']:>8} {len(n['callees']):>26}")
    print(f"  {'forced: not being analysed':<34} {c['blocks']:>8} "
          f"{len(c['callees']):>26}")
    new = sorted(set(c["callees"]) - set(n["callees"]))
    gone = sorted(set(n["callees"]) - set(c["callees"]))
    print()
    print(f"  reachable only when forced : {', '.join(new) or '(none)'}")
    print(f"  reachable only unforced    : {', '.join(gone) or '(none)'}")
    print()
    print("  Forcing changes nothing that is reachable. The reason is the same as")
    print("  on GravityRat: the checks are backed by calls this analysis models")
    print("  rather than performs, and those models return unconstrained values,")
    print("  so both sides of every check are already explored. Forcing makes the")
    print("  two outcomes separately attributable; it does not unlock anything.")
    print("  Reported as zero, because that is the measurement.  [symbolic]")
    print(ledger.legend())


if __name__ == "__main__":
    main()
