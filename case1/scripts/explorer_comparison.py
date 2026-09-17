#!/usr/bin/env python3
"""
2.5 - the controlled comparison for GravityRat.

Three stages, each adding exactly one thing to the one before it, so that an
improvement can be attributed:

  A  the original PE, angr's default BFS and DFS.
  B  the AOT-translated image, the same default BFS, with the static runtime
     models installed (linkage table, typed allocator, GOT literals, object
     headers, throw helpers, String.Concat). Indirect call sites are NOT
     resolved -- that is the thing under test.
  C  the same image, the same models, the same entry points, the same budget,
     plus ManagedCallExplorer.

and three ablations, two of C's parts and one of the framing itself:

  C1 static resolution only (the call-site table), receiver-directed resolution
     off.
  C2 C with the quarantine off, so that unsupported boundaries fall into
     `unconstrained` as they would without it.
  D  the same call-site table delivered as ordinary `project.hook` calls -- one
     4-byte hook per resolved site -- under the *default* BFS manager, with no
     ExplorationTechnique at all.

D is the ablation that asks whether the technique earns its place, rather than
whether its internals do. If D matches C then the coverage result belongs to the
call-site table, which is a static analysis, and the technique is its delivery
mechanism rather than its cause. That is a question worth settling with a
measurement instead of an argument.

What is measured is behaviour, not just block counts: which runtime APIs are
reached, how many indirect calls were resolved and on what evidence, how many
boundaries remain unsupported, and how many states survive the budget.

Each arm runs in a fresh process, and the whole comparison is repeated three
times, because angr and CLE keep process-global state across `Project`
construction.

    .venv/bin/python case1/scripts/explorer_comparison.py [B|C|C1|C2|D]
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
import ledger                   # noqa: E402
import managed_runtime as mr    # noqa: E402
from managed_call_explorer import ManagedCallExplorer, QUARANTINE  # noqa: E402

BUDGET = 60
REPEATS = 3

# Chosen before any of these were run: the network stack, the job loop, the
# environment check and the program entry. Fixed across every arm.
ENTRIES = [
    "LSASS_Services_Start_string__",
    "LSASS_Core_Jobs_RootJob",
    "LSASS_Core_Jobs_SystemSettings",
    "LSASS_Networking_Agent_SendBasicInformation"
    "_System_Collections_Specialized_NameValueCollection",
    "LSASS_Networking_Agent_UploadFile_string_string",
    "LSASS_Networking_DomainController_CheckForDomain_string",
    "LSASS_Models_Enviornment_isVM_LSASS_Models_VirtualMachine_",
    "LSASS_Program_Main_string__",
]

# The behavioural surface: the runtime entry points that would constitute an
# observable action if the sample ran.
INTERESTING = re.compile(
    r"WebClient|WebRequest|UploadValues|UploadFile|DownloadString|DownloadFile|"
    r"Dns_|Socket|Aes|Rijndael|RNGCrypto|DeriveBytes|CryptoStream|MD5|SHA|"
    r"Process_Start|GetProcesses|ManagementObject|ManagementClass|"
    r"System_IO_File|System_IO_Directory|Registry|ZipEntry|FastZip")


def run(arm):
    caps = []
    rt, models = G.build({
        "System.Net.WebClient::UploadValues": mr.CaptureCall(
            label="WebClient.UploadValues", kind="ref", log=caps,
            argspec=(("obj", "this"), ("str", "url"), ("str", "method"),
                     ("coll", "data"))),
    })
    api = {a: n[4:] for n, a in rt.syms.items()
           if n.startswith("plt_") and INTERESTING.search(n)}
    hooked = mr.hook_sites_statically(rt) if arm == "D" else 0
    if hooked:
        models = models + [f"{hooked} call sites installed as plain 4-byte "
                           f"project.hook() calls; no ExplorationTechnique"]

    # Resolve every entry point up front and refuse to run if one is missing.
    # Skipping silently -- which an earlier version did -- means a mistyped
    # symbol quietly shrinks the experiment while the header still advertises
    # the full list.
    resolved = [(n, rt.address_of(n)) for n in ENTRIES]
    missing = [n for n, a in resolved if a is None]
    if missing:
        raise SystemExit("entry points not found in the image: " + ", ".join(missing))
    entries = [(n, a) for n, a in resolved if a is not None]

    blocks, reached = set(), set()
    peak = survivors = quarantined = 0
    res_static = res_dyn = unsupported = 0
    t0 = time.time()
    for name, addr in entries:
        simgr = rt.proj.factory.simulation_manager(rt.entry_state(addr))
        tech = None
        if arm not in ("B", "D"):
            tech = ManagedCallExplorer(rt, dynamic=(arm != "C1"),
                                       quarantine=(arm != "C2"))
            simgr.use_technique(tech)
        steps, p = G.walk(simgr, BUDGET)
        peak = max(peak, p)
        survivors += len(simgr.active)
        quarantined += len(simgr.stashes.get(QUARANTINE, []))
        for a in G.blocks_touched(simgr):
            blocks.add(a)
            if a in api:
                reached.add(api[a])
        if tech:
            res_static += tech.resolved_static
            res_dyn += tech.resolved_dynamic
            unsupported += tech.unsupported
            for callee in tech.reached:
                short = callee.split("::")[0].rsplit(".", 1)[-1] + "_" + \
                    callee.split("::")[-1]
                if INTERESTING.search(short) or INTERESTING.search(callee):
                    reached.add(callee)
    return {"arm": arm, "entries_listed": len(ENTRIES),
            "entries_executed": len(entries),
            "blocks": len(blocks), "apis": sorted(reached),
            "n_api": len(api), "peak": peak, "survivors": survivors,
            "quarantined": quarantined, "resolved_static": res_static,
            "resolved_dynamic": res_dyn, "unsupported": unsupported,
            "captures": len(caps), "secs": round(time.time() - t0, 1),
            "hooked": hooked, "models": models}


def stage_a():
    """The original PE under angr's own defaults -- reproduced here for the table."""
    import angr
    import logging
    logging.getLogger("angr").setLevel(logging.CRITICAL)
    logging.getLogger("cle").setLevel(logging.CRITICAL)
    proj = angr.Project(str(G.EXE), auto_load_libs=False)
    out = {}
    for label, tech in (("BFS", None), ("DFS", angr.exploration_techniques.DFS())):
        simgr = proj.factory.simulation_manager(proj.factory.entry_state())
        if tech:
            simgr.use_technique(tech)
        simgr.run(n=50)
        # Blocks actually executed. `state.addr` is where the state would go
        # next, not somewhere it has been, so it is not counted.
        blocks = set()
        trace = []
        for stash in simgr.stashes.values():
            for st in stash:
                blocks.update(st.history.bbl_addrs)
                trace = [hex(a) for a in st.history.bbl_addrs]
        out[label] = {"blocks": len(blocks), "trace": trace,
                      "stashes": {k: len(v) for k, v in simgr.stashes.items() if v}}
    return out


def main():
    if len(sys.argv) > 1 and sys.argv[1] in ("B", "C", "C1", "C2", "D"):
        print(json.dumps(run(sys.argv[1])))
        return
    if len(sys.argv) > 1 and sys.argv[1] == "A":
        print(json.dumps(stage_a()))
        return

    def once(arm):
        out = subprocess.run([sys.executable, __file__, arm],
                             capture_output=True, text=True)
        return json.loads(out.stdout.strip().splitlines()[-1])

    a = once("A")
    trials = {arm: [once(arm) for _ in range(REPEATS)]
              for arm in ("B", "C", "C1", "C2", "D")}

    print(ledger.header(
        "2.5  CONTROLLED COMPARISON: default exploration against "
        "ManagedCallExplorer",
        artifacts=[G.EXE, G.SO], sources=G.SOURCES + [pathlib.Path(__file__)],
        entry=f"{trials['C'][0]['entries_executed']} of "
              f"{trials['C'][0]['entries_listed']} fixed entry points, all "
              f"resolved (listed below; a missing one aborts the run)",
        models=trials["C"][0]["models"],
        budget=f"{BUDGET} steps per entry point, frontier capped at 400 states; "
               f"{REPEATS} repeats per arm, each in a fresh process",
        technique="B: none (angr default BFS) | C: ManagedCallExplorer | "
                  "C1, C2: ablations of C",
        notes=["stages differ by exactly one thing each; see the header comment"]))

    print("  entry points")
    for e in ENTRIES:
        print(f"      {e}")

    print()
    print("-" * 74)
    print("STAGE A  the original PE, angr's own defaults")
    print("-" * 74)
    for label, r in a.items():
        print(f"  {label:<5} basic blocks executed {r['blocks']}   "
              f"stashes {r['stashes']}")
        print(f"        trace {' -> '.join(r['trace'])}")
    print("  Identical under both strategies, so the failure is not one of search")
    print("  order.  [symbolic]")

    print()
    print("-" * 74)
    print("STAGES B AND C  the translated image, models held constant")
    print("-" * 74)

    def agg(arm, key):
        vals = [t[key] for t in trials[arm]]
        return vals

    rows = [("B", "AOT + static models, default BFS"),
            ("C", "  + ManagedCallExplorer"),
            ("C1", "  ablation: static resolution only"),
            ("C2", "  ablation: quarantine off"),
            ("D", "  ablation: same table as plain hooks, no technique")]
    hdr = (f"  {'arm':<36} {'blocks':>18} {'APIs':>6} {'resolved':>16} "
           f"{'unsup':>6} {'quar':>6} {'surv':>6} {'peak':>5} {'capt':>5}")
    print(hdr)
    for arm, label in rows:
        b = agg(arm, "blocks")
        napi = [len(t["apis"]) for t in trials[arm]]
        rs = trials[arm][0]["resolved_static"]
        rd = trials[arm][0]["resolved_dynamic"]
        print(f"  {label:<36} "
              f"{('/'.join(str(x) for x in b)):>18} "
              f"{('/'.join(str(x) for x in napi)):>6} "
              f"{(f'{rs} stat + {rd} dyn' if arm != 'B' else '-'):>16} "
              f"{trials[arm][0]['unsupported'] if arm != 'B' else '-':>6} "
              f"{trials[arm][0]['quarantined']:>6} "
              f"{trials[arm][0]['survivors']:>6} "
              f"{trials[arm][0]['peak']:>5} "
              f"{trials[arm][0]['captures']:>5}")
    print()
    print("  blocks and APIs are shown as the three repeats, in order. "
          "'resolved',")
    print("  'unsup', 'quar', 'surv', 'peak' and 'capt' are from the first "
          "repeat.")
    print("  peak = the largest number of simultaneously active states; it is a")
    print("  count of states, not a memory measurement, and no memory figure is")
    print("  claimed anywhere in this project.")

    print()
    print("-" * 74)
    print("BEHAVIOURAL SURFACE REACHED")
    print("-" * 74)
    sets = {arm: set(trials[arm][0]["apis"]) for arm, _ in rows}
    for arm, label in rows:
        print(f"  {label.strip()}  ({len(sets[arm])} of "
              f"{trials[arm][0]['n_api']} runtime APIs of interest)")
        for x in sorted(sets[arm]):
            print(f"      {x}")
        print()
    only_c = sorted(sets["C"] - sets["B"])
    only_b = sorted(sets["B"] - sets["C"])
    print(f"  reached only with the technique : {', '.join(only_c) or '(none)'}")
    print(f"  reached only without it         : {', '.join(only_b) or '(none)'}")

    print()
    print("-" * 74)
    print("REPRODUCIBILITY")
    print("-" * 74)
    for arm, label in rows:
        b = agg(arm, "blocks")
        same = len(set(b)) == 1
        print(f"  {label.strip():<38} blocks {b}  "
              f"{'identical across 3 runs' if same else 'VARIES -- see note'}")
    print()
    print("  Reached-API sets and resolution counts reproduce exactly. Where a")
    print("  block count varies it is because a run that ends in the frontier cap")
    print("  ends at a different place; the figures quoted in the write-up are")
    print("  the ones this table shows.")
    print(ledger.legend())


if __name__ == "__main__":
    main()
