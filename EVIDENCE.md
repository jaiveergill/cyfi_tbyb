# Evidence index

Every number and behavioural claim in `CyFI_dotNET_angr_writeup_final.docx` comes from one of the files below. Each opens with a header recording the artifact hashes and the tool versions, and the symbolic experiments additionally record the entry point, the symbolic inputs, the models installed and the step budget, so a figure can be checked against the conditions that produced it. The two raw CIL dumps and de4dot's own output are the exceptions: they are verbatim tool output with no header of ours.

Regenerate all of them with `./run_all.sh`, or one group with `./run_all.sh 2.5.2`.

## Evidence classes

- **static** — static observation - read out of the PE, the metadata or the AOT image
- **symbolic** — symbolic observation - produced by execution under the models listed
- **inference** — inference - argued from the two above, not directly observed
- **fixture** — supplied fixture - a value this analysis provided, not one it recovered
- **unresolved** — unresolved - named here so that it is not mistaken for a result

## Result files

| file | § | establishes | produced by | sha256 |
|---|---|---|---|---|
| `case1/results/2_1_static_triage.txt` | 1 / 2.1 | identity, hashes, sections, imports, TypeDefs, assembly references | `tools/static_triage.py $G` | `ab435faa63439382…` |
| `case1/results/2_2_native_code_audit.txt` | 2.2 | how much of the image is native code at all (6 bytes) | `tools/native_code_audit.py $G` | `5fa81e98208ffbd8…` |
| `case1/results/2_2_default_explorer.txt` | 2.2 | default BFS and DFS on the original PE: two blocks, identical | `case1/scripts/default_explorer.py` | `6e7773eba3caeb25…` |
| `case1/results/2_3_translated_explorer.txt` | 2.3 | what each layer of translation and modelling buys, stage by stage | `case1/scripts/translated_explorer.py` | `891cc9bc9f392976…` |
| `case1/results/2_3_callsite_map.txt` | 2.3 / 2.4 | call-site resolution and the two checks on it; GOT literal recovery | `tools/callsite_map.py $G` | `2e50b374316948e1…` |
| `case1/results/2_4_diagnosis.txt` | 2.4 | the failing instruction, the soundness test, the frontier measurement, and the residual unsupported boundaries | `case1/scripts/diagnose.py` | `97a5f52c72a59b0d…` |
| `case1/results/2_5_explorer_comparison.txt` | 2.5 | stages A/B/C and the two ablations, three repeats each | `case1/scripts/explorer_comparison.py` | `853945936d9702c4…` |
| `case1/results/2_5_1_anti_analysis.txt` | 2.5.1 | isVM: what it is, its single caller, and what forcing it changes | `case1/scripts/anti_analysis.py` | `a35a0f7413fa35ba…` |
| `case1/results/2_5_1_isvm_cil.txt` | 2.5.1 | the CIL of isVM and the seven probes | `tools/cil_disasm.py $G --method isVM` | `c858962d2161c87a…` |
| `case1/results/2_5_2_beacon_capture.txt` | 2.5.2 | the beacon captured at WebClient.UploadValues, field by field | `case1/scripts/beacon_capture.py` | `c3329cd86b951535…` |
| `case1/results/2_5_beacon_cil.txt` | 2.5.2 | the CIL that builds the beacon | `tools/cil_disasm.py $G --type Core.Jobs` | `de6ce21f5a1a3b3a…` |
| `case1/results/2_5_3_dispatch.txt` | 2.5.3 | the jump table, its validation, and a witness for each of the 8 handlers | `case1/scripts/dispatch_analysis.py` | `fabdf54e74e6a79f…` |
| `case2/results/2_1_static_triage.txt` | 3 / 3.2 | identity, hashes, sections, imports, TypeDefs | `tools/static_triage.py $T` | `48966c238723a843…` |
| `case2/results/2_2_native_code_audit.txt` | 3.3 | native-code inventory | `tools/native_code_audit.py $T` | `83889dee064509f4…` |
| `case2/results/2_2_default_explorer_failure.txt` | 3.3 | default BFS and DFS, the loader's output, and the .text-is-not-x86 proof | `tools/default_explorer_failure.py $T` | `0539caccf7cc0091…` |
| `case2/results/2_3_cil_full.txt` | 3.4 | the whole assembly's CIL, which every static claim about Thanos cites | `tools/cil_disasm.py $T` | `dd2d47f30770f468…` |
| `case2/results/2_3_decoded_strings.txt` | 3.4 | the base64 literal heap, decoded and grouped | `tools/string_decoder.py $T` | `37c7423e825812fb…` |
| `case2/results/2_3_callsite_map.txt` | 3.4 / 3.5 | call-site resolution on Thanos and the checks on it | `tools/callsite_map.py $T` | `e70896a5d338aa61…` |
| `case2/results/2_3_de4dot_detect.txt` | 3.4 | de4dot's obfuscator identification | `dotnet case1/de4dot/.../de4dot.dll -d $T` | `92a5e3b8422d549f…` |
| `case2/results/2_5_behaviour_map.txt` | 3.6 | which translated methods touch which runtime APIs | `tools/aot_behaviour_map.py $T.so` | `90e17899ec283791…` |
| `case2/results/2_5_coverage_comparison.txt` | 3.6 | stages A/B/C and the two ablations over every translated method | `case2/scripts/coverage_comparison.py` | `a88d016dff3160cf…` |
| `case2/results/2_5_1_anti_analysis.txt` | 3.6.1 | the build's configuration flags, the decoded command lists, and the effect of forcing the checks | `case2/scripts/anti_analysis.py` | `8be904c1ca0d24d3…` |
| `case2/results/2_5_2_outbound_capture.txt` | 3.6.2 | the FTP request as assembled, and the placeholder destination | `case2/scripts/outbound_capture.py` | `404e17f6912cd80d…` |

## Code

| file | role |
|---|---|
| `tools/callsite_map.py` | resolves each indirect call site to a named callee, and recovers `ldstr` literals into their GOT slots |
| `tools/managed_runtime.py` | the runtime surface: linkage table, typed allocator, object headers, arrays, strings, collections, capture models |
| `tools/managed_call_explorer.py` | the ExplorationTechnique |
| `tools/ledger.py` | the experiment header every result file opens with |
| `tools/aot_bridge.py` | MonoString/MonoArray layout, PLT resolution, jump-table reconstruction |
| `tools/cil_disasm.py` | CIL disassembler built on dnfile + dncil |
| `tools/string_decoder.py` | the #US heap, decoded and grouped |
| `tools/static_triage.py` | PE and .NET metadata triage |
| `tools/native_code_audit.py` | native-vs-CIL inventory |
| `tools/aot_behaviour_map.py` | method -> runtime API map over the AOT image |
| `tools/fetch_sample.py` | retrieves a sample from theZoo and checks its hashes |

## Samples

| file | sha256 |
|---|---|
| `case1/samples/extracted/Win32.GravityRAT.exe` | `1c0ea462f0bbd7acfdf4c6daf3cb8ce09e1375b766fbd3ff89f40c0aa3f4fc96` |
| `case1/samples/extracted/Win32.GravityRAT.exe.so` | `776deb59fbd370cc988f57cb51a12337c59e826d1e185ce6b20b49de8e9e50a4` |
| `case2/samples/extracted/thanos.exe` | `58bfb9fa8889550d13f42473956dc2a7ec4f3abb18fd3faeaa38089d513c171f` |
| `case2/samples/extracted/thanos.exe.so` | `6d1bc4dd02ec8cc450ac17f13a1b62b06c7afaf985dc54f0a267940b25070cbc` |

## Narrative

| file | contents |
|---|---|
| `LOGBOOK.md` | the command log and the decision history: every design decision with the measurement that drove it, the four rejected designs, and the corrections made after the fact |

## Superseded work

`archive/superseded/` keeps the two rejected exploration techniques and the earlier write-up drafts, with a note on why each was replaced. Nothing there contributes a number to the results.

