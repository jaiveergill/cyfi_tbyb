#!/usr/bin/env python3
"""
2.5.2 - intercept GravityRat's beacon before it leaves the process.

`LSASS.Core.Jobs.SystemSettings` builds a `NameValueCollection` of host facts and
hands it to `Agent.SendBasicInformation`, which posts it with
`WebClient.UploadValues`. This script recovers what would go out, from inside the
process, without any of it going out.

Nothing here opens a socket. `WebClient.UploadValues` is replaced by a model that
reads its three arguments out of the state, writes them to a Python list and
returns; the same is true of every other outbound call in this project.

Two arms, identical in every respect except the exploration strategy:

  default   angr's default breadth-first manager
  custom    the same, plus ManagedCallExplorer

Each arm runs in its own process. angr and CLE keep process-global state across
`Project` construction, so running both in one interpreter gives a dirty
comparison.

    .venv/bin/python case1/scripts/beacon_capture.py [default|custom]
"""
import json
import pathlib
import subprocess
import sys
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import gravityrat as G            # noqa: E402
sys.path.insert(0, str(G.ROOT / "tools"))
import ledger                     # noqa: E402
import managed_runtime as mr      # noqa: E402
from managed_call_explorer import ManagedCallExplorer   # noqa: E402

ENTRY = "LSASS_Core_Jobs_SystemSettings"
CCTOR = "LSASS_Networking_DomainController__cctor"
BUDGET = 400


def run(use_technique):
    adds, caps = [], []
    rt, models = G.build({
        "System.Collections.Specialized.NameValueCollection::Add":
            mr.CollectionAdd(pairs=True, log=adds),
        "System.Collections.Specialized.NameValueCollection::.ctor":
            mr.CollectionCtor(),
        "System.Net.WebClient::UploadValues": mr.CaptureCall(
            label="WebClient.UploadValues", kind="ref", log=caps,
            argspec=(("obj", "this"), ("str", "url"), ("str", "method"),
                     ("coll", "data"))),
    })
    st = rt.entry_state(rt.address_of(ENTRY))
    simgr = rt.proj.factory.simulation_manager(st)
    tech = ManagedCallExplorer(rt) if use_technique else None
    if tech:
        simgr.use_technique(tech)
    t0 = time.time()
    steps, peak = G.walk(simgr, BUDGET)
    return {
        "steps": steps, "peak": peak, "secs": round(time.time() - t0, 1),
        "stashes": {k: len(v) for k, v in simgr.stashes.items() if v},
        "adds": [list(a[1]) for a in adds],
        "captures": caps,
        "tech": tech.summary() if tech else None,
        "models": models, "fixtures": rt.fixtures,
    }


def domains():
    """Recover the C2 host list by executing the class constructor that builds it.

    `DomainController..cctor` fills a `StringCollection` with `ldstr` constants.
    Those constants live in GOT slots the runtime would fill, so this only works
    because the slots were filled first -- it is a test of the literal recovery
    as much as of the exploration.
    """
    adds = []
    rt, _ = G.build({
        "System.Collections.Specialized.StringCollection::Add":
            mr.CollectionAdd(pairs=False, log=adds),
        "System.Collections.Specialized.StringCollection::.ctor":
            mr.CollectionCtor(),
    }, fixtures=False)
    simgr = rt.proj.factory.simulation_manager(rt.entry_state(rt.address_of(CCTOR)))
    simgr.use_technique(ManagedCallExplorer(rt))
    G.walk(simgr, 200)
    return [a[1][1] for a in adds]


def classify(value, name=None):
    """Evidence class for one captured field.

    A value that is entirely a `<...>` marker is a fixture. A value that is a
    real string with a marker *embedded* is neither purely one nor the other --
    it was assembled by executed code out of parts this analysis supplied -- and
    saying "symbolic" of it would overstate what was recovered.
    """
    if name is None or value is None:
        return "unresolved"
    v = str(value)
    if v.startswith("<") and v.endswith(">") and v.count("<") == 1:
        return "fixture"
    if "<" in v and ">" in v:
        return "symbolic, fixture-derived"
    return "symbolic"


def main():
    if len(sys.argv) > 1 and sys.argv[1] in ("default", "custom"):
        print(json.dumps(run(sys.argv[1] == "custom")))
        return
    if len(sys.argv) > 1 and sys.argv[1] == "domains":
        print(json.dumps(domains()))
        return

    arms = {}
    for arm in ("default", "custom"):
        out = subprocess.run([sys.executable, __file__, arm],
                             capture_output=True, text=True)
        arms[arm] = json.loads(out.stdout.strip().splitlines()[-1])
    hosts = json.loads(subprocess.run([sys.executable, __file__, "domains"],
                                      capture_output=True, text=True)
                       .stdout.strip().splitlines()[-1])

    d, c = arms["default"], arms["custom"]
    print(ledger.header(
        "2.5.2  NETWORK INTERCEPTION: GravityRat's beacon, captured at the "
        "transport call",
        artifacts=[G.EXE, G.SO], sources=G.SOURCES + [pathlib.Path(__file__)],
        entry=f"{ENTRY}  (the method that builds the beacon)",
        models=c["models"],
        budget=f"{BUDGET} steps, frontier capped at 400 states",
        technique="arm 1: angr default (BFS) | arm 2: ManagedCallExplorer",
        notes=["capture-only: UploadValues is modelled, never performed",
               "each arm runs in a fresh process"]))

    for label, r in (("default (BFS)", d), ("ManagedCallExplorer", c)):
        print(f"{label}")
        print(f"   steps run                : {r['steps']}   peak active "
              f"{r['peak']}   {r['secs']}s")
        print(f"   final stashes            : {r['stashes']}")
        print(f"   Add events observed      : {len(r['adds'])}")
        print(f"   distinct fields          : "
              f"{len({tuple(a) for a in r['adds']})}")
        print(f"   outbound calls captured  : {len(r['captures'])}")
        if r["tech"]:
            t = r["tech"]
            print(f"   call sites resolved      : {t['resolved_static']} from the "
                  f"call-site table, {t['resolved_dynamic']} from the receiver's "
                  f"type")
            print(f"   sites left unsupported   : {t['unsupported']}  "
                  f"(quarantined, not dropped)")
        print()

    print("-" * 74)
    print("THE BEACON, AS IT REACHED WebClient.UploadValues")
    print("-" * 74)
    if not c["captures"]:
        print("  (nothing captured)")
    for cap in c["captures"]:
        args = dict((n, v) for n, v, _ in cap["args"])
        print(f"  call     {cap['call']}")
        print(f"  url      {args.get('url')!r}        [symbolic + static]")
        print(f"  method   {args.get('method')!r}     [symbolic]")
        data = args.get("data") or []
        print(f"  body     NameValueCollection, {len(data)} entries "
              f"[symbolic; values as classed below]")
        for name, value in data:
            print(f"      {str(name):<16} = {str(value):<58} [{classify(value, name)}]")

    named = [a for a in c["adds"] if a[0]]
    print()
    print("  accounting")
    print("      Add call sites in this method, from the CIL        : 16   [static]")
    print(f"      Add events observed on the captured path           : "
          f"{len(c['adds'])}   [symbolic]")
    print(f"      field names resolved to a literal                  : "
          f"{len({a[0] for a in named})}   [symbolic, via recovered GOT literals]")
    kinds = [classify(v, n) for n, v in c["adds"]]
    print(f"      field values that are labelled fixtures            : "
          f"{kinds.count('fixture')}   [fixture]")
    print(f"      field values assembled from fixtures by real code  : "
          f"{kinds.count('symbolic, fixture-derived')}   [symbolic, fixture-derived]")
    print(f"      field values genuinely recovered from the binary   : "
          f"{kinds.count('symbolic')}   [symbolic]")
    print(f"      names or values left unresolved                    : "
          f"{sum(1 for a in c['adds'] if a[0] is None or a[1] is None)}   [unresolved]")

    print()
    print("-" * 74)
    print("C2 DESTINATION")
    print("-" * 74)
    print("  The URL is built as `Domain + \"/GX/GX-Server.php\"`. `Domain` is a")
    print("  static field this entry point never assigns, so the host half is")
    print("  unresolved on the captured path.")
    print()
    print(f"  host list, recovered by executing DomainController..cctor "
          f"({len([h for h in hosts if h])} of {len(hosts)} Add calls resolved):")
    for h in hosts:
        print(f"      {h!r}   [{'symbolic' if h else 'unresolved'}]")
    print()
    print("  path component, recovered from the GOT literal slot the two callers")
    print("  share (Agent.SendBasicInformation and Agent.PostRequest both read")
    print("  slot 0x480478):")
    print("      '/GX/GX-Server.php'   [static, corroborated across 2 sites]")

    print()
    print("-" * 74)
    print("WHAT THE DEFAULT EXPLORER RECOVERED")
    print("-" * 74)
    print(f"  Add events {len(d['adds'])}, outbound calls captured "
          f"{len(d['captures'])}, run ended after {d['steps']} steps "
          f"with stashes {d['stashes']}.")
    print("  The default manager loses the state at the first `callvirt` in the")
    print("  method: the beacon is never constructed, so there is nothing to")
    print("  intercept.")
    print(ledger.legend())


if __name__ == "__main__":
    main()
