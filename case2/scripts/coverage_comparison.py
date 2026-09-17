#!/usr/bin/env python3
"""
2.5 (case 2) - the controlled comparison for Thanos.

Same three stages as case 1, on a different sample, so that the result is not a
property of one binary:

  A  the original PE, angr's default BFS and DFS.
  B  the AOT image with the static runtime models, default BFS.
  C  the same, plus ManagedCallExplorer.
  C1 ablation: static call-site resolution only.
  C2 ablation: quarantine off.
  D  ablation: the same call-site table delivered as plain 4-byte
     `project.hook` calls under the default BFS manager, with no
     ExplorationTechnique -- the arm that asks whether the technique itself, as
     opposed to the table it carries, is what produces the result.

Every translated method that has a body is used as an entry point, so the
measurement covers the whole image rather than a chosen subset.

    .venv/bin/python case2/scripts/coverage_comparison.py [B|C|C1|C2|D|A]
"""
import json
import pathlib
import re
import subprocess
import sys
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import thanos as T              # noqa: E402
sys.path.insert(0, str(T.ROOT / "tools"))
import ledger                   # noqa: E402
import managed_runtime as mr    # noqa: E402
from managed_call_explorer import ManagedCallExplorer, QUARANTINE  # noqa: E402

BUDGET = 24
REPEATS = 3

INTERESTING = re.compile(
    r"WebClient|WebRequest|Dns_|Socket|UdpClient|TcpClient|"
    r"Aes|Rijndael|RNGCrypto|DeriveBytes|CryptoStream|RSA|MD5|SHA|"
    r"Process_Start|GetProcesses|OpenProcess|ReadProcessMemory|"
    r"NtSetInformationProcess|CheckRemoteDebuggerPresent|EnterDebugMode|"
    r"System_IO_File|System_IO_Directory|FileStream|Registry|Management")


def bodies(rt):
    """Every translated method with a body, excluding PLT and mono internals."""
    out = []
    for sym in rt.proj.loader.main_object.symbols:
        if (sym.name and sym.size and not sym.name.startswith("plt_")
                and not sym.name.startswith("mono_aot")
                and not sym.name.startswith("wrapper_")
                and not sym.name.startswith("_")):
            out.append((sym.name, sym.rebased_addr))
    return sorted(set(out))


def run(arm):
    rt, models = T.build(T.base_models())
    hooked = mr.hook_sites_statically(rt) if arm == "D" else 0
    if hooked:
        models = models + [f"{hooked} call sites installed as plain 4-byte "
                           f"project.hook() calls; no ExplorationTechnique"]
    api = {a: n[4:] for n, a in rt.syms.items()
           if n.startswith("plt_") and INTERESTING.search(n)}
    entries = bodies(rt)
    blocks, reached = set(), set()
    ok = err = peak = quarantined = 0
    res_s = res_d = unsup = 0
    t0 = time.time()
    for _, addr in entries:
        try:
            simgr = rt.proj.factory.simulation_manager(rt.entry_state(addr))
            tech = None
            if arm not in ("B", "D"):
                tech = ManagedCallExplorer(rt, dynamic=(arm != "C1"),
                                           quarantine=(arm != "C2"))
                simgr.use_technique(tech)
            _, p = T.walk(simgr, BUDGET)
            peak = max(peak, p)
            quarantined += len(simgr.stashes.get(QUARANTINE, []))
            for a in T.blocks_touched(simgr):
                blocks.add(a)
                if a in api:
                    reached.add(api[a])
            if tech:
                res_s += tech.resolved_static
                res_d += tech.resolved_dynamic
                unsup += tech.unsupported
            ok += 1
        except Exception:
            err += 1
    return {"arm": arm, "entries": len(entries), "ok": ok, "errored": err,
            "blocks": len(blocks), "apis": sorted(reached), "n_api": len(api),
            "peak": peak, "quarantined": quarantined, "resolved_static": res_s,
            "resolved_dynamic": res_d, "unsupported": unsup,
            "secs": round(time.time() - t0, 1), "hooked": hooked,
            "models": models}


def stage_a():
    import angr
    import logging
    logging.getLogger("angr").setLevel(logging.CRITICAL)
    logging.getLogger("cle").setLevel(logging.CRITICAL)
    proj = angr.Project(str(T.EXE), auto_load_libs=False)
    out = {}
    for label, tech in (("BFS", None), ("DFS", angr.exploration_techniques.DFS())):
        simgr = proj.factory.simulation_manager(proj.factory.entry_state())
        if tech:
            simgr.use_technique(tech)
        simgr.run(n=50)
        blocks, trace = set(), []
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
    c0 = trials["C"][0]

    print(ledger.header(
        "2.5 (case 2)  CONTROLLED COMPARISON ON THANOS",
        artifacts=[T.EXE, T.SO], sources=T.SOURCES + [pathlib.Path(__file__)],
        entry=f"every translated method with a body ({c0['entries']} of them)",
        models=c0["models"],
        budget=f"{BUDGET} steps per entry point; {REPEATS} repeats per arm, "
               f"each in a fresh process",
        technique="B: none (angr default BFS) | C: ManagedCallExplorer | "
                  "C1, C2: ablations of C"))

    print("-" * 74)
    print("STAGE A  the original PE, angr's own defaults")
    print("-" * 74)
    for label, r in a.items():
        print(f"  {label:<5} basic blocks executed {r['blocks']}   "
              f"stashes {r['stashes']}")
        print(f"        trace {' -> '.join(r['trace'])}")

    print()
    print("-" * 74)
    print("STAGES B AND C")
    print("-" * 74)
    rows = [("B", "AOT + static models, default BFS"),
            ("C", "  + ManagedCallExplorer"),
            ("C1", "  ablation: static resolution only"),
            ("C2", "  ablation: quarantine off"),
            ("D", "  ablation: same table as plain hooks, no technique")]
    print(f"  {'arm':<36} {'blocks':>20} {'APIs':>9} {'resolved':>16} "
          f"{'unsup':>6} {'quar':>6} {'peak':>5}")
    for arm, label in rows:
        b = [t["blocks"] for t in trials[arm]]
        na = [f"{len(t['apis'])}" for t in trials[arm]]
        t0 = trials[arm][0]
        res = f"{t0['resolved_static']} stat + {t0['resolved_dynamic']} dyn" \
            if arm != "B" else "-"
        print(f"  {label:<36} {'/'.join(f'{x:,}' for x in b):>20} "
              f"{'/'.join(na):>9} {res:>16} "
              f"{(t0['unsupported'] if arm != 'B' else '-'):>6} "
              f"{t0['quarantined']:>6} {t0['peak']:>5}")
    print()
    b0 = trials["B"][0]
    print(f"  entry points attempted : {c0['entries']}   "
          f"explored cleanly: B {b0['ok']}, C {c0['ok']}   "
          f"errored: B {b0['errored']}, C {c0['errored']}")
    print(f"  runtime APIs of interest in the image : {c0['n_api']}")
    print(f"  reached by B : {len(b0['apis'])}   not reached: "
          f"{c0['n_api'] - len(b0['apis'])}")
    print(f"  reached by C : {len(c0['apis'])}   not reached: "
          f"{c0['n_api'] - len(c0['apis'])}")

    print()
    print("-" * 74)
    print("BEHAVIOURAL SURFACE REACHED ONLY WITH THE TECHNIQUE")
    print("-" * 74)
    only_c = sorted(set(c0["apis"]) - set(b0["apis"]))
    only_b = sorted(set(b0["apis"]) - set(c0["apis"]))
    for x in only_c:
        print(f"      + {x}")
    if not only_c:
        print("      (none)")
    print(f"  reached only without the technique: "
          f"{', '.join(only_b) or '(none)'}")

    print()
    print("-" * 74)
    print("REPRODUCIBILITY")
    print("-" * 74)
    for arm, label in rows:
        b = [t["blocks"] for t in trials[arm]]
        print(f"  {label.strip():<38} blocks {b}  "
              f"{'identical across 3 runs' if len(set(b)) == 1 else 'VARIES'}")
    print(ledger.legend())


if __name__ == "__main__":
    main()
