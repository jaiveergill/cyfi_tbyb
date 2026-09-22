#!/usr/bin/env python3
"""
2.5.2 (case 2) - intercept what Thanos sends, before it is sent.

Thanos is ransomware, so its outbound traffic is a report rather than a C2
channel. `MufMaOSvGyvz.MfnxCHhUwIjyzc::qkCGSsikzw(url, username, password, body)`
builds an FTP filename out of the victim's user and machine names, opens an
`FtpWebRequest`, and writes the report into the request stream. That routine is
where I intercept.

Nothing here connects to anything. `WebRequest.Create`, `GetRequestStream`,
`Stream.Write`, `GetResponse` and `WebClient.DownloadString` are all replaced by
models that read their arguments out of the state and return; no socket is
opened, no name resolved, no byte sent.

Two arms, differing only in the exploration strategy:

  default   angr's default breadth-first manager
  custom    the same, plus ManagedCallExplorer

    .venv/bin/python case2/scripts/outbound_capture.py [default|custom]
"""
import json
import pathlib
import subprocess
import sys
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import thanos as T              # noqa: E402
sys.path.insert(0, str(T.ROOT / "tools"))

import claripy                  # noqa: E402
import ledger                   # noqa: E402
import managed_runtime as mr    # noqa: E402
from managed_call_explorer import ManagedCallExplorer, QUARANTINE  # noqa: E402

SENDER = "MufMaOSvGyvz_MfnxCHhUwIjyzc_qkCGSsikzw_string_string_string_string"
PROBE = "MufMaOSvGyvz_IyUWqQZlcOSTLhq_LEYLEJpRfEgTMCc"
BUDGET = 400

# The three arguments the caller supplies, read from the CIL in `Main` at IL
# 0x0DE7-0x0DF1 (and again at 0x0218, 0x025B, ...). They are `ldstr` constants:
# the builder that produced this sample never substituted them.
CALLER_ARGS = ["URL", "USERNAME", "ACCESO"]

# The report body is assembled in `Main` out of fourteen array elements. Its
# construction is 4,218 bytes of CIL away from this entry point, so it is
# supplied here as a labelled fixture rather than executed; the elements are
# listed from the CIL in the report below.
BODY_FIXTURE = "<report-body-assembled-in-Main>"

# Host facts, supplied as labelled fixtures.
FIXTURES = {
    "System_Environment_get_UserName": "<Environment.UserName>",
    "System_Environment_get_MachineName": "<Environment.MachineName>",
    # Not a timestamp. The CIL shows this method querying WMI twice and
    # concatenating the results: win32_processor -> processorID, and
    # win32_logicaldisk.deviceid="C:" -> VolumeSerialNumber.
    "MufMaOSvGyvz_MfnxCHhUwIjyzc_HHmRdTUQTZoj": "<cpuid+volumeserial>",
    "System_Net_WebClient_DownloadString_string": "<icanhazip-response>",
}


def run(use_technique):
    caps = []
    models = T.base_models(captures=caps)
    models["System.Net.WebRequest::Create"] = mr.CaptureCall(
        label="WebRequest.Create", kind="ref", log=caps,
        argspec=(("str", "requestUri"),))
    rt, described = T.build(models, FIXTURES)
    # WebRequest.Create is a direct PLT call here, so hook the PLT too.
    for name, addr in rt.syms.items():
        if "System_Net_WebRequest_Create_string" in name:
            rt.proj.hook(addr, mr.CaptureCall(
                label="WebRequest.Create", kind="ref", log=caps,
                argspec=(("str", "requestUri"),)), replace=True)

    state = rt.entry_state(rt.address_of(SENDER))
    for i, text in enumerate(CALLER_ARGS):
        setattr(state.regs, f"x{i}", claripy.BVV(mr.new_string(state, text), 64))
    state.regs.x3 = claripy.BVV(mr.new_string(state, BODY_FIXTURE), 64)

    simgr = rt.proj.factory.simulation_manager(state)
    tech = ManagedCallExplorer(rt) if use_technique else None
    if tech:
        simgr.use_technique(tech)
    t0 = time.time()
    steps, peak = T.walk(simgr, BUDGET)

    # The connectivity probe, a second outbound path.
    probe_caps = []
    rt2, _ = T.build(T.base_models(captures=probe_caps), FIXTURES)
    for name, addr in rt2.syms.items():
        if "System_Net_WebRequest_Create_string" in name:
            rt2.proj.hook(addr, mr.CaptureCall(
                label="WebRequest.Create", kind="ref", log=probe_caps,
                argspec=(("str", "requestUri"),)), replace=True)
    sm2 = rt2.proj.factory.simulation_manager(rt2.entry_state(rt2.address_of(PROBE)))
    if use_technique:
        sm2.use_technique(ManagedCallExplorer(rt2))
    T.walk(sm2, 60)

    return {
        "steps": steps, "peak": peak, "secs": round(time.time() - t0, 1),
        "blocks": len(T.blocks_touched(simgr)),
        "stashes": {k: len(v) for k, v in simgr.stashes.items() if v},
        "captures": caps, "probe": probe_caps,
        "tech": tech.summary() if tech else None,
        "quarantined": len(simgr.stashes.get(QUARANTINE, [])),
        "models": described,
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
        "2.5.2 (case 2)  OUTBOUND INTERCEPTION: Thanos's FTP exfiltration report",
        artifacts=[T.EXE, T.SO], sources=T.SOURCES + [pathlib.Path(__file__)],
        entry=f"{SENDER}\n              (the FTP sender; contrast probe: {PROBE})",
        inputs="x0..x2 = the three `ldstr` constants the caller passes; "
               "x3 = a labelled body fixture",
        models=c["models"],
        budget=f"{BUDGET} steps",
        technique="arm 1: angr default (BFS) | arm 2: ManagedCallExplorer",
        notes=["capture-only: no socket, no DNS, no FTP session",
               "each arm runs in a fresh process"]))

    for label, r in (("default (BFS)", d), ("ManagedCallExplorer", c)):
        print(f"{label}")
        print(f"   steps {r['steps']}   peak {r['peak']}   blocks "
              f"{r['blocks']}   {r['secs']}s   stashes {r['stashes']}")
        print(f"   outbound calls captured : {len(r['captures'])}")
        if r["tech"]:
            t = r["tech"]
            print(f"   call sites resolved     : {t['resolved_static']} static, "
                  f"{t['resolved_dynamic']} by receiver type; "
                  f"{t['unsupported']} unsupported ({r['quarantined']} quarantined)")
        print()

    print("-" * 74)
    print("THE FTP REQUEST, AS IT WAS ASSEMBLED")
    print("-" * 74)
    if not c["captures"]:
        print("  (nothing captured)")
    for cap in c["captures"]:
        print(f"  {cap['call']}")
        for n, v, kind in cap["args"]:
            cls = "unresolved" if v is None else (
                "fixture" if isinstance(v, str) and v.startswith("<") else "symbolic")
            print(f"      {n:<14} = {str(v)[:120]:<62} [{cls}]")
    print()
    print("  So the sample uploads a text file named")
    print("  `UserName=<user>_MachineName=<machine>_<cpuid+volumeserial>.txt`")
    print("  to an FTP server, with the report as the request body.")
    print()
    print("  The third component is a hardware fingerprint, not a timestamp.")
    print("  `MufMaOSvGyvz.MfnxCHhUwIjyzc::HHmRdTUQTZoj` queries WMI for")
    print("  win32_processor -> processorID and for")
    print("  win32_logicaldisk.deviceid=\"C:\" -> VolumeSerialNumber and")
    print("  concatenates them. So the filename alone identifies the machine")
    print("  across reinstalls and across changes of user or hostname.")
    print("  [static, from the CIL at rva 0x7890]")

    print()
    print("-" * 74)
    print("DESTINATION LITERALS")
    print("-" * 74)
    print("  The three arguments the caller passes are `ldstr` constants:")
    for a in CALLER_ARGS:
        print(f"      {a!r}")
    print("  They are the literal strings \"URL\", \"USERNAME\" and \"ACCESO\" --")
    print("  Spanish for \"access\" -- and they appear at ten call sites in the")
    print("  assembly, always as the same three constants.  [static]")
    print()
    print("  So this is builder output with the FTP fields left unfilled --")
    print("  the affiliate never entered a server. No deployed FTP host, user")
    print("  or password comes out of this, and I am not claiming one. What")
    print("  does come out is the exfiltration mechanism and the exact shape of")
    print("  what it would send.  [inference from the two above]")

    print()
    print("-" * 74)
    print("THE REPORT BODY")
    print("-" * 74)
    print("  Assembled in `Main` as a fourteen-element `string[]` joined with")
    print("  `String.Concat(string[])`. The labels are base64 `ldstr` constants")
    print("  decoded at run time by a helper; the decoder is modelled, so they")
    print("  read back as text:  [static, from the CIL at IL 0x0D0B-0x0DD8]")
    print()
    for line in ["Client IP:  ",
                 "<- WebClient.DownloadString(\"http://icanhazip.com\")",
                 "Date of encryption: ", "<- DateTime",
                 "Key Identifier: ", "<- the per-victim key id",
                 "Number of files encrypted: ", "<- a counter",
                 "Possible affected files: ", "<- a counter",
                 "Client Unique Identifier Key: ", "<- the victim key"]:
        print(f"      {line}")
    print()
    print("  The body is a labelled fixture here. Building it for real means")
    print("  executing 4,218 bytes of `Main`'s CIL, which this entry point and")
    print("  budget do not cover. So nothing in the captured request body is")
    print("  victim data.")

    print()
    print("-" * 74)
    print("CONTRAST: THE CONNECTIVITY PROBE")
    print("-" * 74)
    for cap in c["probe"]:
        for n, v, _ in cap["args"]:
            print(f"  {cap['call']:<28} {n} = {v!r}   [symbolic]")
    if not c["probe"]:
        print("  (nothing captured)")
    print("  `LEYLEJpRfEgTMCc` requests https://www.google.com/ and returns")
    print("  whether it succeeded -- an internet-reachability test before the")
    print("  report is attempted.  [symbolic, confirming the CIL]")

    print()
    print("-" * 74)
    print("WHAT THE DEFAULT EXPLORER RECOVERED")
    print("-" * 74)
    print(f"  {len(d['captures'])} outbound calls captured, {d['blocks']} blocks, "
          f"run ended after {d['steps']} steps with stashes {d['stashes']}.")
    print("  The first `stelem.ref` in the routine is an indirect call through")
    print("  the array's vtable, so the default manager loses the state before")
    print("  the filename is assembled, let alone sent.")
    print(ledger.legend())


if __name__ == "__main__":
    main()
