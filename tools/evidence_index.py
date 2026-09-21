#!/usr/bin/env python3
"""
Generate EVIDENCE.md: every result file, its hash, what produced it, and which
section of the write-up rests on it.

The point is that a reader can take any claim in the document, find the artifact
it came from, and check that the artifact on disk is the one the document was
built from.
"""
from __future__ import annotations

import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import ledger   # noqa: E402

# result file -> (section, what it shows, the command that makes it)
INDEX = [
    ("case1/results/2_1_static_triage.txt", "1 / 2.1",
     "identity, hashes, sections, imports, TypeDefs, assembly references",
     "tools/static_triage.py $G"),
    ("case1/results/2_2_native_code_audit.txt", "2.2",
     "how much of the image is native code at all (6 bytes)",
     "tools/native_code_audit.py $G"),
    ("case1/results/2_2_default_explorer.txt", "2.2",
     "default BFS and DFS on the original PE: two blocks, identical",
     "case1/scripts/default_explorer.py"),
    ("case1/results/2_3_translated_explorer.txt", "2.3",
     "what each layer of translation and modelling buys, stage by stage",
     "case1/scripts/translated_explorer.py"),
    ("case1/results/2_3_callsite_map.txt", "2.3 / 2.4",
     "call-site resolution and the two checks on it; GOT literal recovery",
     "tools/callsite_map.py $G"),
    ("case1/results/2_4_diagnosis.txt", "2.4",
     "the failing instruction, the soundness test, the frontier measurement, "
     "and the residual unsupported boundaries",
     "case1/scripts/diagnose.py"),
    ("case1/results/2_5_explorer_comparison.txt", "2.5",
     "stages A/B/C and the two ablations, three repeats each",
     "case1/scripts/explorer_comparison.py"),
    ("case1/results/2_5_1_anti_analysis.txt", "2.5.1",
     "isVM: what it is, its single caller, and what forcing it changes",
     "case1/scripts/anti_analysis.py"),
    ("case1/results/2_5_1_isvm_cil.txt", "2.5.1",
     "the CIL of isVM and the seven probes",
     "tools/cil_disasm.py $G --method isVM"),
    ("case1/results/2_5_2_beacon_capture.txt", "2.5.2",
     "the beacon captured at WebClient.UploadValues, field by field",
     "case1/scripts/beacon_capture.py"),
    ("case1/results/2_5_beacon_cil.txt", "2.5.2",
     "the CIL that builds the beacon",
     "tools/cil_disasm.py $G --type Core.Jobs"),
    ("case1/results/2_5_3_dispatch.txt", "2.5.3",
     "the jump table, its validation, and a witness for each of the 8 handlers",
     "case1/scripts/dispatch_analysis.py"),
    ("case2/results/2_1_static_triage.txt", "3 / 3.2",
     "identity, hashes, sections, imports, TypeDefs",
     "tools/static_triage.py $T"),
    ("case2/results/2_2_native_code_audit.txt", "3.3",
     "native-code inventory",
     "tools/native_code_audit.py $T"),
    ("case2/results/2_2_default_explorer_failure.txt", "3.3",
     "default BFS and DFS, the loader's output, and the .text-is-not-x86 proof",
     "tools/default_explorer_failure.py $T"),
    ("case2/results/2_3_cil_full.txt", "3.4",
     "the whole assembly's CIL, which every static claim about Thanos cites",
     "tools/cil_disasm.py $T"),
    ("case2/results/2_3_decoded_strings.txt", "3.4",
     "the base64 literal heap, decoded and grouped",
     "tools/string_decoder.py $T"),
    ("case2/results/2_3_callsite_map.txt", "3.4 / 3.5",
     "call-site resolution on Thanos and the checks on it",
     "tools/callsite_map.py $T"),
    ("case2/results/2_3_de4dot_detect.txt", "3.4",
     "de4dot's obfuscator identification",
     "dotnet case1/de4dot/.../de4dot.dll -d $T"),
    ("case2/results/2_5_behaviour_map.txt", "3.6",
     "which translated methods touch which runtime APIs",
     "tools/aot_behaviour_map.py $T.so"),
    ("case2/results/2_5_coverage_comparison.txt", "3.6",
     "stages A/B/C and the two ablations over every translated method",
     "case2/scripts/coverage_comparison.py"),
    ("case2/results/2_5_1_anti_analysis.txt", "3.6.1",
     "the build's configuration flags, the decoded command lists, and the "
     "effect of forcing the checks",
     "case2/scripts/anti_analysis.py"),
    ("case2/results/2_5_2_outbound_capture.txt", "3.6.2",
     "the FTP request as assembled, and the placeholder destination",
     "case2/scripts/outbound_capture.py"),
]

CODE = [
    ("tools/callsite_map.py", "resolves each indirect call site to a named "
     "callee, and recovers `ldstr` literals into their GOT slots"),
    ("tools/managed_runtime.py", "the runtime surface: linkage table, typed "
     "allocator, object headers, arrays, strings, collections, capture models"),
    ("tools/managed_call_explorer.py", "the ExplorationTechnique"),
    ("tools/ledger.py", "the experiment header every result file opens with"),
    ("tools/aot_bridge.py", "MonoString/MonoArray layout, PLT resolution, "
     "jump-table reconstruction"),
    ("tools/cil_disasm.py", "CIL disassembler built on dnfile + dncil"),
    ("tools/string_decoder.py", "the #US heap, decoded and grouped"),
    ("tools/static_triage.py", "PE and .NET metadata triage"),
    ("tools/native_code_audit.py", "native-vs-CIL inventory"),
    ("tools/aot_behaviour_map.py", "method -> runtime API map over the AOT image"),
    ("tools/fetch_sample.py", "retrieves a sample from theZoo and checks its hashes"),
]


def main():
    out = ["# Evidence index", "",
           "Every number and behavioural claim in "
           "`CyFI_dotNET_angr_writeup_final.docx` comes from one of the files "
           "below. Each opens with a header giving the artifact hashes and the "
           "tool versions; the symbolic experiments also record the entry "
           "point, the symbolic inputs, the models installed and the step "
           "budget, so any figure can be checked against the conditions that "
           "produced it. The two raw CIL dumps and de4dot's own output have no "
           "header of ours -- they are verbatim tool output.",
           "",
           "Regenerate all of them with `./run_all.sh`, or one group with "
           "`./run_all.sh 2.5.2`.", "",
           "## Evidence classes", ""]
    for k, v in ledger.CLASSES.items():
        out.append(f"- **{k}** — {v}")
    out += ["", "## Result files", "",
            "| file | § | shows | produced by | sha256 |",
            "|---|---|---|---|---|"]
    missing = []
    for path, sec, what, cmd in INDEX:
        p = ROOT / path
        if p.exists():
            h = ledger.sha256(p)[:16]
            out.append(f"| `{path}` | {sec} | {what} | `{cmd}` | `{h}…` |")
        else:
            missing.append(path)
            out.append(f"| `{path}` | {sec} | {what} | `{cmd}` | **MISSING** |")
    out += ["", "## Code", "", "| file | role |", "|---|---|"]
    for path, role in CODE:
        mark = "" if (ROOT / path).exists() else "  **MISSING**"
        out.append(f"| `{path}` | {role}{mark} |")
    out += ["", "## Samples", "", "| file | sha256 |", "|---|---|"]
    for path in ("case1/samples/extracted/Win32.GravityRAT.exe",
                 "case1/samples/extracted/Win32.GravityRAT.exe.so",
                 "case2/samples/extracted/thanos.exe",
                 "case2/samples/extracted/thanos.exe.so"):
        p = ROOT / path
        out.append(f"| `{path}` | `{ledger.sha256(p) if p.exists() else 'MISSING'}` |")
    out += ["", "## Narrative", "",
            "| file | contents |", "|---|---|",
            "| `LOGBOOK.md` | the command log and the decision history: each "
            "design decision with the measurement behind it, the four rejected "
            "designs, and the corrections made after the fact |",
            "", "## Superseded work", "",
            "`archive/superseded/` keeps the two rejected exploration techniques "
            "and the earlier write-up drafts, with a note on why each was "
            "replaced. No number in the results comes from there.", ""]
    (ROOT / "EVIDENCE.md").write_text("\n".join(out) + "\n")
    print(f"wrote EVIDENCE.md  ({len(INDEX)} result files, "
          f"{len(missing)} missing)")
    return 1 if missing else 0


if __name__ == "__main__":
    sys.exit(main())
