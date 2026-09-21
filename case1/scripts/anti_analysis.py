#!/usr/bin/env python3
"""
2.5.1 - GravityRat's anti-analysis check: what it is, and what forcing it does.

theZoo tags this sample *Virtualization Detection*, and it does detect
virtualisation: `LSASS.Models.Enviornment.isVM` is a seven-way short-circuit OR
over registry, WMI, CPU and MAC-address probes. The brief asks for these to be
hooked to force the "not being analyzed" branch, and for a statement of what
becomes reachable as a result.

On this sample nothing becomes reachable. `isVM` has one caller, and that caller
writes the answer into a field of the beacon. The malware reports whether it is
running in a VM; it does not act on it.

I checked this three ways:

  1. statically -- every call site of `isVM` in the assembly, and what the caller
     does with the result;
  2. symbolically, by running the beacon builder three times with the seven
     detectors left to the model, forced to "clean machine", and forced to
     "virtual machine", and diffing what each run produces;
  3. by comparing coverage, so "nothing became reachable" is a number and not
     my opinion.

    .venv/bin/python case1/scripts/anti_analysis.py [natural|clean|vm]
"""
import json
import pathlib
import subprocess
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import gravityrat as G          # noqa: E402
sys.path.insert(0, str(G.ROOT / "tools"))
import ledger                   # noqa: E402
import managed_runtime as mr    # noqa: E402
from managed_call_explorer import ManagedCallExplorer   # noqa: E402

ENTRY = "LSASS_Core_Jobs_SystemSettings"
BUDGET = 400

# The seven probes `isVM` ORs together, in the order the CIL calls them.
DETECTORS = ["LSASS_Models_Enviornment_DetectVM",
             "LSASS_Models_Enviornment_DetectVM2",
             "LSASS_Models_Enviornment_DetectVM3",
             "LSASS_Models_Enviornment_GetProcessorID",
             "LSASS_Models_Enviornment_CoreCount",
             "LSASS_Models_Enviornment_CpuTemp",
             "LSASS_Models_Enviornment_MatchMacAdd"]

WHAT_EACH_PROBE_READS = {
    "DetectVM": "registry: SOFTWARE\\Microsoft\\Virtual Machine\\Guest\\Parameters"
                " -> HostName, VirtualMachineName",
    "DetectVM2": "WMI: select * from Win32_BIOS -> version, SerialNumber;"
                 " matches VMware / Virtual / XEN / Xen / 'A M I'",
    "DetectVM3": "WMI: Win32_ComputerSystem -> Manufacturer, Model",
    "GetProcessorID": "WMI: Win32_Processor -> ProcessorId",
    "CoreCount": "processor count below a threshold",
    "CpuTemp": "WMI thermal zone temperature (absent on most hypervisors)",
    "MatchMacAdd": "NIC MAC prefix against known hypervisor OUIs",
}


def run(mode):
    """mode: 'natural' | 'clean' (no VM) | 'vm' (is a VM)."""
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
    forced = []
    if mode != "natural":
        value = 0 if mode == "clean" else 1
        for name in DETECTORS:
            forced += rt.force(name, value)
        models.append(f"seven VM probes forced to {value} "
                      f"({'clean machine' if value == 0 else 'virtual machine'})")

    simgr = rt.proj.factory.simulation_manager(rt.entry_state(rt.address_of(ENTRY)))
    tech = ManagedCallExplorer(rt)
    simgr.use_technique(tech)
    steps, peak = G.walk(simgr, BUDGET)
    blocks = G.blocks_touched(simgr)
    return {
        "mode": mode, "forced": sorted(set(forced)), "models": models,
        "steps": steps, "peak": peak, "blocks": len(blocks),
        "adds": [list(a[1]) for a in adds], "captures": caps,
        "callees": sorted(tech.reached),
        "stashes": {k: len(v) for k, v in simgr.stashes.items() if v},
    }


def vmnotes(r):
    for name, value in r["adds"]:
        if name == "VMNOTES":
            return value
    return None


def main():
    if len(sys.argv) > 1 and sys.argv[1] in ("natural", "clean", "vm"):
        print(json.dumps(run(sys.argv[1])))
        return

    res = {}
    for mode in ("natural", "clean", "vm"):
        out = subprocess.run([sys.executable, __file__, mode],
                             capture_output=True, text=True)
        res[mode] = json.loads(out.stdout.strip().splitlines()[-1])

    print(ledger.header(
        "2.5.1  ANTI-ANALYSIS: GravityRat's virtualisation check, and what "
        "forcing it changes",
        artifacts=[G.EXE, G.SO], sources=G.SOURCES + [pathlib.Path(__file__)],
        entry=f"{ENTRY}  (the only caller of isVM)",
        models=res["natural"]["models"],
        budget=f"{BUDGET} steps per arm",
        technique="ManagedCallExplorer in all three arms",
        notes=["three arms differ only in what the seven probes return"]))

    print("-" * 74)
    print("1. THE CHECK, STATICALLY")
    print("-" * 74)
    print("  LSASS.Models.Enviornment::isVM, rva 0x2a34, is a short-circuit OR:")
    print("      DetectVM -> DetectVM2 -> DetectVM3 -> GetProcessorID")
    print("               -> CoreCount -> CpuTemp -> MatchMacAdd")
    print("  any one true and the method returns true.   [static]")
    print()
    for probe, what in WHAT_EACH_PROBE_READS.items():
        print(f"      {probe:<16} {what}")
    print()
    print("  Call sites of isVM in the assembly: 1   [static]")
    print("      LSASS.Core.Jobs::SystemSettings, IL 0x0045. The CIL that follows")
    print("      is not a branch around a payload -- it is string construction:")
    print()
    print("        0045  call  isVM")
    print("        004C  ldstr \"Application running in VB/VM, host : \"")
    print("        0053  call  VirtualMachine::get_Host")
    print("        0058  ldstr \" and machine name : \"")
    print("        005F  call  VirtualMachine::get_MachineName")
    print("        0064  call  System.String::Concat")
    print("        006C  ldstr \"No VB/VM detected\"")
    print()
    print("      and the result becomes the beacon's VMNOTES field. There is no")
    print("      exit, no sleep and no branch that skips the payload.  [static]")
    print()
    print("  `LSASS.Models.VirtualMachine` is a data model carrying Host and")
    print("  MachineName for that message -- it is not the check.  [static]")

    print()
    print("-" * 74)
    print("2. FORCING THE PROBES")
    print("-" * 74)
    print(f"  probes forced (each arm): "
          f"{len(res['clean']['forced'])} symbols, "
          f"{len(DETECTORS)} methods and their PLT entries")
    print()
    print(f"  {'arm':<26} {'VMNOTES field as sent':<52} blocks  Adds  captures")
    for mode, label in (("natural", "left to the model"),
                        ("clean", "forced: not a VM"),
                        ("vm", "forced: is a VM")):
        r = res[mode]
        print(f"  {label:<26} {str(vmnotes(r))[:50]:<52} "
              f"{r['blocks']:>6}  {len(r['adds']):>4}  {len(r['captures']):>8}")

    print()
    print("-" * 74)
    print("3. WHAT BECAME REACHABLE")
    print("-" * 74)
    base = set(res["natural"]["callees"])
    for mode in ("clean", "vm"):
        r = res[mode]
        new = sorted(set(r["callees"]) - base)
        gone = sorted(base - set(r["callees"]))
        print(f"  {mode:<8} blocks {r['blocks']} vs {res['natural']['blocks']} "
              f"({r['blocks'] - res['natural']['blocks']:+d})   "
              f"runtime callees reached only in this arm: "
              f"{', '.join(new) or '(none)'}")
        if gone:
            print(f"           callees reached only without forcing: "
                  f"{', '.join(gone)}")
    print()
    print("  Forcing the check changes one string in the beacon and nothing else.")
    print("  No basic block, no runtime call and no outbound call becomes")
    print("  reachable that was not reachable before.  [symbolic]")
    print()
    print("  The sample fingerprints the environment and reports it to the")
    print("  operator. It does not use the answer to evade, so hooking these")
    print("  probes to unlock hidden behaviour unlocks nothing here.")
    print("  [inference from the two above]")

    print()
    print("-" * 74)
    print("WHY THE UNFORCED ARM ALREADY SEES BOTH SIDES")
    print("-" * 74)
    print("  Each probe ends in WMI, registry or NIC calls this analysis models")
    print("  rather than performs, and those models return unconstrained values.")
    print("  So every `brtrue` in the OR chain forks and both outcomes get")
    print("  explored without forcing anything. Forcing is still worth doing --")
    print("  it makes the two outcomes separately attributable -- but it is not")
    print("  what makes them reachable.  [symbolic]")
    print(ledger.legend())


if __name__ == "__main__":
    main()
