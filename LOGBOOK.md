# Logbook — commands and decisions

Two parts. **Part 1** is the command sequence that takes a bare checkout to the
final results for both cases, in order. **Part 2** is the decision history: what
was tried, what the measurement said, and what was kept or rejected as a result.

Attribution matters here, so it is marked throughout. Decisions taken **before**
the final rebuild are marked `[prior]` — they come from the project's earlier
working notes and are what set the strategy. Decisions taken during the rebuild
are marked `[rebuild]`. The rebuild starts at commit `f25055e`.

---

# Part 1 — command log

Every command below is real and in dependency order. `$PY` is `.venv/bin/python`.
Nothing here executes a sample.

## 1.1  Environment

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt     # angr 9.3.4, dnfile, dncil, pefile, capstone, python-docx
sudo apt install mono-complete                # 6.8.0.105 — the AOT compiler
```

Optional, only for the obfuscator-identification step:

```bash
curl -fsSL https://dot.net/v1/dotnet-install.sh | bash -s -- --channel 8.0
git clone https://github.com/de4dot/de4dot case1/de4dot
cd case1/de4dot && dotnet build de4dot.netcore.sln -c Release -p:TargetFrameworks=netcoreapp3.1
```

## 1.2  Samples

```bash
python tools/fetch_sample.py Win32.GravityRat  case1/samples
python tools/fetch_sample.py Ransomware.Thanos case2/samples

# Thanos's archive extracts four files named by SHA-256; the one analysed is 58bfb9fa…c171f
mv case2/samples/extracted/58bfb9fa*c171f case2/samples/extracted/thanos.exe

sha256sum case1/samples/extracted/Win32.GravityRAT.exe \
          case2/samples/extracted/thanos.exe
# 1c0ea462f0bbd7acfdf4c6daf3cb8ce09e1375b766fbd3ff89f40c0aa3f4fc96  Win32.GravityRAT.exe
# 58bfb9fa8889550d13f42473956dc2a7ec4f3abb18fd3faeaa38089d513c171f  thanos.exe
```

## 1.3  Translation

```bash
mono --aot=full case1/samples/extracted/Win32.GravityRAT.exe   # -> …exe.so  1,134,552 B
mono --aot=full case2/samples/extracted/thanos.exe            # -> …exe.so    422,600 B
```

`mono --aot` is a compiler. It reads method bodies and emits code; it never
invokes an entry point. This is the only step that touches a sample with
anything other than a parser.

## 1.4  Case 1 — Win32.GravityRat

```bash
G=case1/samples/extracted/Win32.GravityRAT.exe

$PY tools/static_triage.py       "$G"  > case1/results/2_1_static_triage.txt
$PY tools/native_code_audit.py   "$G"  > case1/results/2_2_native_code_audit.txt
$PY case1/scripts/default_explorer.py  > case1/results/2_2_default_explorer.txt
$PY case1/scripts/translated_explorer.py > case1/results/2_3_translated_explorer.txt
$PY tools/callsite_map.py        "$G"  > case1/results/2_3_callsite_map.txt
$PY case1/scripts/diagnose.py          > case1/results/2_4_diagnosis.txt
$PY case1/scripts/explorer_comparison.py > case1/results/2_5_explorer_comparison.txt
$PY case1/scripts/anti_analysis.py     > case1/results/2_5_1_anti_analysis.txt
$PY tools/cil_disasm.py "$G" --method isVM > case1/results/2_5_1_isvm_cil.txt
$PY case1/scripts/beacon_capture.py    > case1/results/2_5_2_beacon_capture.txt
$PY tools/cil_disasm.py "$G" --type Core.Jobs > case1/results/2_5_beacon_cil.txt
$PY case1/scripts/dispatch_analysis.py > case1/results/2_5_3_dispatch.txt
```

## 1.5  Case 2 — Ransomware.Thanos

```bash
T=case2/samples/extracted/thanos.exe

$PY tools/static_triage.py            "$T"     > case2/results/2_1_static_triage.txt
$PY tools/native_code_audit.py        "$T"     > case2/results/2_2_native_code_audit.txt
$PY tools/default_explorer_failure.py "$T"     > case2/results/2_2_default_explorer_failure.txt
$PY tools/cil_disasm.py               "$T"     > case2/results/2_3_cil_full.txt
$PY tools/string_decoder.py           "$T"     > case2/results/2_3_decoded_strings.txt
$PY tools/callsite_map.py             "$T"     > case2/results/2_3_callsite_map.txt
$PY tools/aot_behaviour_map.py        "$T.so"  > case2/results/2_5_behaviour_map.txt
$PY case2/scripts/coverage_comparison.py       > case2/results/2_5_coverage_comparison.txt
$PY case2/scripts/anti_analysis.py             > case2/results/2_5_1_anti_analysis.txt
$PY case2/scripts/outbound_capture.py          > case2/results/2_5_2_outbound_capture.txt

dotnet case1/de4dot/Release/netcoreapp3.1/de4dot.dll -d "$T" \
  > case2/results/2_3_de4dot_detect.txt        # optional
```

## 1.6  Deliverables

```bash
$PY tools/make_paper.py        # -> CyFI_dotNET_angr_writeup_final.docx
$PY tools/evidence_index.py    # -> EVIDENCE.md
$PY tools/inspect_docx.py      # structural review; exits non-zero on a layout fault
```

## 1.7  All of it

```bash
./run_all.sh          # everything above except setup, ~6 min, non-zero exit on failure
./run_all.sh case1    # one case
./run_all.sh 2.5.2    # one experiment group
./run_all.sh docs     # rebuild the document from existing results
```

## 1.8  Individual arms, for checking a comparison by hand

Each comparison forks a subprocess per arm. To run one directly:

```bash
$PY case1/scripts/explorer_comparison.py B     # AOT + models, default BFS
$PY case1/scripts/explorer_comparison.py C     # + ManagedCallExplorer
$PY case1/scripts/explorer_comparison.py C1    # ablation: no receiver-directed resolution
$PY case1/scripts/explorer_comparison.py C2    # ablation: no quarantine
$PY case1/scripts/explorer_comparison.py D     # ablation: same table as plain hooks, no technique
$PY case1/scripts/explorer_comparison.py A     # original PE, angr defaults

$PY case1/scripts/beacon_capture.py default    # one arm of the interception experiment
$PY case1/scripts/beacon_capture.py custom
$PY case1/scripts/beacon_capture.py domains    # C2 host list from DomainController..cctor

$PY case2/scripts/coverage_comparison.py D
$PY case2/scripts/outbound_capture.py custom
$PY case2/scripts/anti_analysis.py tools       # decode .cctor's lists by executing it
```

## 1.9  Verifying a clean checkout is self-contained

```bash
git clone . /tmp/clean && cd /tmp/clean
ln -s /home/jg/cyfi-project/.venv .venv
mkdir -p case1/samples/extracted case2/samples/extracted
cp /home/jg/cyfi-project/case1/samples/extracted/* case1/samples/extracted/
cp /home/jg/cyfi-project/case2/samples/extracted/* case2/samples/extracted/
./run_all.sh 2.5.2
```

Done on 2026-09-15: the beacon result reproduced byte for byte. The venv was
shared rather than rebuilt, so this checks that the *repository* is complete,
not that a fresh machine works.

---

# Part 2 — decision history

## 2.1  Which samples, and why not the obvious ones  `[prior]`

**Question.** theZoo's index tags every entry under `malware/Binaries/` as
`LANGUAGE = 'bin'`, so it cannot be queried for .NET binaries. Candidates were
screened by hand.

**The discriminator that settled it** is the size of the `#US` (user string)
heap. A loader stub has no literals of its own.

| candidate | `#US` heap | verdict |
|---|---|---|
| `Trojan.Bladabindi` (njRAT) | 4 B | the *builder*, not the payload — a WinForms GUI, no command dispatch, so §2.5.2 and §2.5.3 are unsatisfiable |
| `Win32.AgentTesla` | — | VB.NET crypter stub over a 224 KB encrypted blob; the anti-analysis, network and dispatch code is in a stage two not on disk in readable form |
| `Backdoor.MSIL.Tyupkin` | 2,308 B | C++/CLI mixed-mode, real native code, no `System.Net` |
| **`Win32.GravityRat`** | **20,544 B** | **selected** |
| **`Ransomware.Thanos`** | 528 literals | **selected** — different family, author, obfuscation posture and purpose, so it tests the method rather than one binary |

**Cost accepted.** Neither has source in theZoo, and the brief prefers samples
that do. Findings are verified against the CIL instead. AgentTesla *did* have
source, and was rejected anyway because a crypter stub cannot exhibit the
behaviours §2.5 asks for.

## 2.2  Why translation had to come before exploration  `[prior]`

**Question.** Can a custom `ExplorationTechnique` be written against the .NET PE
directly?

**Measurement.** Default BFS and DFS on each original PE execute **2 basic
blocks** and stop, identically, with a clean `deadended` report and no error.
The entry point is one instruction jumping through the import table to
`_CorExeMain`; `mscoree.dll` does not exist on Linux, CLE substitutes a
`ReturnUnconstrained` stub, the stub returns, the state ends.

Supporting: 6 bytes of the 660,480-byte GravityRat image are x86 — one native
instruction per 109,653 executable bytes. The first method body's header reads
coherently as a CIL fat header and as noise when disassembled as x86.

**Verdict.** No. There is one state and one path; nothing to schedule and
nothing to intervene on. Research confirmed there is no route around this:
angr has no CIL lifter, its only non-native backend is Java/DEX via Soot, and
SEMA — an angr extension built for malware — states it handles ELF and PE
"at the exception of .NET files". Building a CIL backend is a paper, not a
two-week task; the Heimdall eBPF backend needed extensions across five layers
and eBPF is far simpler than CIL.

**Kept:** `mono --aot=full` to produce machine code angr can lift.
`--aot=full` rather than plain `--aot` because plain AOT treats the image as a
cache and leaves generic instantiations and wrappers to the JIT; those methods
would be absent from the `.so` and, since the sample is never run, nothing would
ever fill them in. Measured on Thanos: 144/145 methods and 503 text symbols with
plain `--aot`, 200/201 and 616 with `--aot=full`.

## 2.3  Rejected: recover lost states by pinning the program counter  `[prior]`

**Idea.** States that go `unconstrained` at an indirect call are recovered by
setting the program counter to plausible in-image methods.

**It appears to work.** An early run recovered 136 states.

**The test that killed it.** If the solver will accept an address the image has
never contained, the path constraints say nothing about where control goes, so
the pin invents a path rather than recovering one:

```
pc == 0xdeadbeef satisfiable on 23 of the 24 lost states examined   (angr's default memory model)
```

**Verdict.** Rejected — unsound. Any behaviour reported this way could be
behaviour the malware never performs. Kept in
`archive/superseded/tools/managed_explorer.py`.

**Consequence for the final design.** The missing information is not in the
state, so it has to come from outside it — from the original assembly's
metadata. That is the whole idea of §2.6 below.

## 2.4  Rejected: one synthetic vtable for every object  `[prior, re-tested in rebuild]`

**Idea.** Give every allocated object a header pointing at a single synthetic
vtable whose every slot lands on a stub that returns. Measured slot bounds from
the image (`-0x98 … +0x7a0`) and laid out a window covering them.

**It buys reach.** On `Agent.SendBasicInformation` the trace went from 11 blocks
to 18, and `WebClient.UploadValues` was reached for the first time.

**The measurement that killed it.** Slot +0x108 is
`NameValueCollection::Add` on one type — and in the *same corpus*
`TextWriter::WriteLine`, `IntPtr::op_Explicit` and the array-store write barrier
on others. A shared vtable therefore runs the wrong method whenever the receiver
is not the type the slot was measured on, and nothing in the output distinguishes
the two cases.

**Verdict.** Rejected. Kept in `archive/superseded/case1_scripts/model.py`.

## 2.5  Rejected: steer the frontier away from lossy blocks  `[prior]`

**Idea.** `LossAvoidingExplorer` — learn which blocks destroyed states, rank the
frontier away from them.

**Measurement.** Against the default with everything else held constant: same
runtime APIs, same dispatch handlers, slightly *fewer* blocks.

**Verdict.** Rejected — it is sound and it does nothing. It steers around a loss
it cannot repair. Kept in `archive/superseded/case1_scripts/guided_explorer.py`.

**The diagnosis behind all three rejections.** Peak concurrent states never
exceeded 8 on GravityRat or 16 on Thanos anywhere measured. There is no path
explosion to prune and no reordering to do. States are not multiplied here, they
are destroyed — at one instruction shape, the indirect branch a `callvirt`
compiles into.

## 2.6  Kept: call-site resolution by anchored alignment  `[rebuild]`

**The idea.** Two artifacts describe the same method. The AOT image gives the
ordered sequence of calls it makes — direct (`bl plt_FOO`, which names the
callee) and indirect (`blr`, which does not, but the vtable slot offset is
visible). The original PE's metadata gives the ordered sequence of CIL
`call`/`callvirt`/`newobj`/`newarr` instructions with resolved targets.

Direct calls appear in both and carry a name, so they are **anchors**. Aligning
on them confines each indirect site to a gap between two consecutive anchors.
When a gap holds exactly as many indirect sites as unmatched virtual calls, the
pairing inside it is forced. Gaps that do not close are left unresolved rather
than guessed.

`tools/callsite_map.py:259` `align()`.

**Two checks, neither of which is the method itself.**

| | GravityRat | Thanos |
|---|---|---|
| indirect call sites | 611 | 590 |
| resolved | 492 (80.5%) | 401 (68.0%) |
| left unresolved | 119 | 189 |
| distinct callees → exactly one vtable slot | 88 | 46 |
| → more than one (i.e. a misalignment) | **1** | **0** |

The single GravityRat disagreement is `Stream::Write`: 21 sites at slot 0xb0
against one at 0xa0, which is `WriteByte`'s slot. Counted as a miss rather than
explained away. The check is keyed on the metadata token, not the printed name,
so overloads stay apart.

Second check: allocation provenance. Each allocation site pairs with the
`newobj`/`newarr` it belongs to, which names the type constructed — used to type
objects at run time, and a cross-check because a mispaired allocator would break
the surrounding alignment too.

**Refinements added when the base rule left too much open:**

1. *Second pass, slot-narrowed.* A crowded gap narrows using the slot each
   callee is known image-wide to use. 344 → 414 resolved on GravityRat.
2. *Per-site uniqueness.* A single site resolves when exactly one candidate in
   its gap is known to use that slot. This is what recovers `foreach` bodies,
   where mono lays the loop body out after the header and address order stops
   agreeing with IL order.
3. *`MethodDef` owner qualification.* Three unrelated types each declare
   `Start`; tagging each `MethodDef` with its declaring type lifted GravityRat
   from 435 to 452.
4. *`stelem.ref` counted as an indirect call.* Not a call in CIL, but mono
   compiles the array-store write barrier as one, through the array's own vtable.
   Not counting it made every array store steal the identity of the next CIL
   call — **210 sites on Thanos were mislabelled `Add`**. Fixing it also produced
   a real array-store model, which is what makes Thanos's exfil capture possible.
5. *`newarr` as an allocation anchor.* The allocator anchor searched only for
   `newobj`, which sent the cursor past every array store in a method. This
   collapsed Thanos's whole FTP routine into one 9-site gap; fixing it resolved
   15/15 sites there and lifted Thanos from 59.2% to 68.0%.

## 2.7  Kept: recovering string literals into the GOT  `[rebuild]`

**The problem.** Every `ldstr` compiles to a load from a GOT slot the runtime
fills with a `MonoString*`. The image leaves it null, so in a translated .NET
binary **every string constant in the program reads as zero**.

**The same alignment solves it.** GOT loads inside an anchor gap pair with the
`ldstr` literals in the same gap. The slot offset is a stable image-wide
identifier, so the same slot recurring in another method with the same literal
is the check. Instructions that read the GOT without being a call — `ldsfld`,
`castclass`, `ldtoken` — are counted as slot consumers without claiming a
literal, which is what lets a mixed gap add up.

Result: 178 usable slots on GravityRat (40 corroborated by recurrence, 5
discarded for disagreeing with themselves), 256 on Thanos (44 corroborated, 0
discarded).

This is what makes a captured argument legible rather than symbolic. The path
half of GravityRat's C2 URL, `/GX/GX-Server.php`, is recovered this way and
corroborated by appearing at the same slot (0x480478) in two methods.

## 2.8  Runtime models, each added because something measurably broke  `[rebuild]`

| model | the failure that demanded it |
|---|---|
| per-object headers | Null checks and unbox type tests read from address zero and forked into mono's throw helper. The run entered a four-block cycle between `Settings::get_Identified`'s null-check throw and `Settings::set_Identified` and never left. |
| throw helpers as non-returning | Modelled as returning, execution falls out of the bottom of a throw into whatever method the linker laid down next. |
| uninitialised memory reads as zero | angr's default of a fresh symbol per unmapped read is how a null static-field slot becomes a symbolic object, then a symbolic vtable pointer, then a symbolic program counter. The CLR zero-initialises managed memory, so zero is also the *correct* answer. Before: both `SettingsBase::Save` sites reported "receiver symbolic". After: the singleton is null on first read, the property constructs it, and the receiver is a typed object. |
| `AllocVector` writes the element count | An array whose length reads zero fails every bounds check the compiler emits, so the first `stelem` throws. |
| `Convert.FromBase64String` decoded for real | Lets Thanos's own in-image base64 helper run rather than be stubbed — which is what recovers the 73 command strings. |
| `String.Concat`, per arity and for arrays | Left unmodelled it is the single most damaging stub: it builds the C2 URL and the exfil report body. |
| return kind from the metadata signature | A stub must return an object where the caller will dereference and a symbol where the caller will branch. Getting it backwards loses the state either way, so it is read from the signature blob rather than guessed from the method name. |

**Declared, not silently applied.** Host facts (MAC, CPU id, machine name) are
labelled fixtures naming the method they stood in for, so anything that captures
one carries where it came from and cannot be read as recovered victim data.

## 2.9  The technique, and the hook it had to use  `[rebuild]`

`tools/managed_call_explorer.py:130` `successors()`.

**Why that hook.** The intervention has to happen between the vtable load and
the branch, which is *inside* a basic block. `filter()` and `step_state()` both
see the state only after the branch has already destroyed the program counter.
`successors()` truncates the block with `num_inst` so the state lands on the call
instruction, then sets `lr` to the return address and `pc` to the modelled
callee. Constraints, history and memory are the ones the state already had.

`setup()` creates the quarantine stash; `step()` files states and keeps counts.
`filter()`, `selector()` and `complete()` are deliberately **not** overridden —
the technique has no reason to recategorise, skip or halt early, and overriding
them to look thorough would misrepresent it.

**A bug worth recording.** The first version passed `addr=target` to
`simgr.successors()`. angr's hook dispatch keys on `state.addr`, not the `addr`
kwarg, so it lifted the extern stub address as *code* and the states died anyway.
Setting `state.regs.ip` directly fixed it: 7 steps → 200.

## 2.10  The ablation that tests whether the technique earns its place  `[rebuild]`

**Question.** Is the result attributable to the `ExplorationTechnique`, or to
the call-site table it applies? The table is a static analysis computed offline;
an ordinary `project.hook` could deliver it.

**Arm D.** The same table installed as ordinary hooks under the **default** BFS
manager, no technique at all.

**A false start, and why it mattered.** The first arm D used
`proj.hook(site, model, length=4)`. That is wrong: `length` applies to
plain-function hooks, and given a `SimProcedure` angr ignores it — the
procedure's `ret()` returns to the link register. Verified directly by setting
`lr = 0xdeadbeef` and stepping: the successor's program counter was
`0xdeadbeef`, not `site+4`. So at every hooked call site the state was returning
*out of the enclosing method*. Arm D was measuring nothing, and it under-reported
(234 blocks on GravityRat). The correct construction is
`managed_runtime.StaticCallSite`: `IS_FUNCTION = False`, set `lr` to the
instruction after the call, jump to the model — the same call semantics
`ManagedCallExplorer.successors()` arranges, arrived at without a technique.

**Corrected result.** Three repeats per arm, fresh process each, all identical.

| arm | GravityRat | Thanos |
|---|---|---|
| A — original PE, angr defaults | 2 blocks | 2 blocks |
| B — AOT + static models, default BFS | 80 blocks, 8 APIs | 805, 36 |
| C — ManagedCallExplorer | 291, 12 | 1,009, 38 |
| C1 — ablation: no receiver-directed resolution | 291, 12 | 1,009, 38 |
| C2 — ablation: no quarantine | 294, 12 | 1,012, 38 |
| **D — same table as plain hooks, no technique** | **307, 12** | **1,026, 38** |

**Verdict.** Not the one the earlier draft claimed. On both samples the
plain-hook arm **matches the technique on every behavioural measure and covers
slightly more blocks** — 307 against 291, and 1,026 against 1,009. Same APIs,
same captures: D intercepts the GravityRat beacon at `WebClient.UploadValues`
and the Thanos FTP request exactly as C does.

So the substance of this project is the **call-site table**, a static analysis in
`tools/callsite_map.py`. The `ExplorationTechnique` delivers **no coverage
advantage** over applying that table with ordinary hooks, and on these two
samples it is marginally behind. What it still does that a hook cannot is
quarantine: filing a state that reaches an unjustifiable call site into its own
stash with a diagnostic naming why, instead of letting angr lose it. That is a
diagnostic, not coverage, and it is the only thing the measurements back.

**C1 is a flat negative.** Receiver-directed resolution — (recorded object type,
slot) → callee at run time — fires **zero** times on both samples. The receivers
arriving at unresolved sites are objects returned by unmodelled managed calls,
which carry no type, or values read from fields the analysis never wrote.
Implemented, sound when it fires, inert here.

**What this costs the project.** The brief requires a custom
`ExplorationTechnique`, and there is a real one, justified hook by hook. But the
honest answer to "what did your technique buy you" is: a diagnostic, and a
quarantine stash. The coverage came from the table. An earlier draft of the
write-up claimed the technique was worth a fifth more coverage than plain hooks;
that claim came from the broken arm D and does not survive its correction.

## 2.11  Per-case findings, and where each came from

### Case 1 — Win32.GravityRat

| finding | how |
|---|---|
| Beacon of 16 fields captured at `WebClient.UploadValues`, collection intact | symbolic; default captures nothing |
| 15 of 16 field names resolved to real literals | symbolic, via the recovered GOT slots |
| 12 values are labelled fixtures, 2 genuinely recovered | classed per value, never merged |
| C2 URL = `Domain + "/GX/GX-Server.php"`; path recovered and corroborated at two call sites; host unresolved on that path | static + symbolic |
| 5 C2 hosts recovered by *executing* `DomainController..cctor` | symbolic; 5 of 6 `Add` calls resolved |
| 8 dispatch handlers, each with a solver witness (values 0–7) | symbolic, over a jump table reconstructed and validated against the CIL |
| values 8–12 reach no handler; bounds check is `cmp w25,#0xd; b.hs default` | static |
| `isVM` is 7-way OR with **one** caller, which writes the result into the beacon's VMNOTES field | static |
| forcing all 7 probes changes one string and **nothing reachable** | symbolic, three arms |

**The prediction that was wrong.** Static triage said there would be a VM check
gating the payload. It checks, and it does not gate. Only the forced comparison
tells "checks for a VM" apart from "evades a VM".

### Case 2 — Ransomware.Thanos

| finding | how |
|---|---|
| FTP request fully assembled and captured: filename, method, credentials, content length, request stream, body write | symbolic; default captures none of it |
| the filename's third component is a **hardware fingerprint**, not a timestamp: `HHmRdTUQTZoj` queries WMI for `win32_processor` → `processorID` and `win32_logicaldisk.deviceid="C:"` → `VolumeSerialNumber` and concatenates them, so the filename alone identifies the machine across reinstalls and across changes of user or hostname | static, CIL at rva 0x7890 |
| destination is the literal builder placeholder `"URL"` / `"USERNAME"` / `"ACCESO"` at ten call sites — **no deployed server recovered, none claimed** | static |
| 46 boolean feature flags in `.cctor`: 14 on, 32 off; 27 gates in `Main` each resolvable to open or closed | static |
| 73 command strings recovered by *executing* `.cctor` — `net stop` for Veeam/Acronis/BackupExec/QuickBooks, `vssadmin Delete Shadows /all /quiet`, shadowstorage resize across C:–H:, backup wildcards | symbolic, with the in-image base64 helper actually running |
| forcing the anti-analysis checks changes **nothing reachable** | symbolic, two arms |
| no inbound command surface: the assembly's only two `switch` instructions are one OS-version-name helper keyed on `OperatingSystem.Version.Major` | static |

**§2.5.3 does not apply here**, and is recorded as inapplicable rather than
quietly dropped. The nearest structural equivalent — the builder configuration —
is mapped exhaustively instead.

## 2.12  Corrections made after the fact

Things I got wrong and fixed later.

| what was wrong | how it surfaced | fix |
|---|---|---|
| The write-up stated VirusTotal had been searched by hash. **It had not** — this analysis ran with no outbound network access. | Challenged on whether the deliverable met the brief. | Claim retracted; matrix row split into "confirm .NET from the binary" (met) and "VirusTotal upload or hash search" (**not met**); family attribution separated out as partial. |
| Block counts for arm B were undercounted (9 instead of 80). | `blocks_touched()` iterated `simgr.stashes`, which does **not** include `errored` — and an unresolved call branches to address zero, which angr files as an error. | `G.all_states()` added; every figure regenerated. |
| theZoo's tags were asserted as fact. | Audit of action claims. | Re-attributed as theZoo's labelling, carried into §3.2 as a prediction to be checked. |
| Two API counts were hardcoded in prose while the block counts beside them were extracted. | Same audit. | Both extracted; `make_paper.py` now fails the build rather than printing a stale figure. |

## 2.13  Known gaps, carried deliberately

- **VirusTotal not consulted.** One hash search per sample closes it.
- **Neither sample has source.** The brief prefers samples that do.
- **angr-CTF** is a stated project requirement and nothing in this repository
  evidences it.
- **Disassembler**: capstone (via angr) plus the CIL disassembler in
  `tools/cil_disasm.py`. No IDA or Ghidra artifact.
- **Exception handling unmodelled.** A throw ends the path instead of entering
  the handler, which is why the WMI-backed `Identification` getters are fixtures:
  `ProcessorId` calls `ManagementClass.GetInstances` and the implicit null check
  that follows ends the path where the real program would enter a `catch`. This
  is the single highest-value next change — it would replace 12 fixture values in
  the beacon with executed ones.
- **119 and 189 indirect call sites unresolved.** Quarantined with a diagnostic,
  so visible rather than lost, but the code behind them is unexplored.
- **Document never rendered to page images** — no LibreOffice, pandoc or
  pdftoppm in this environment. `tools/inspect_docx.py` checks it structurally
  instead, and the substitution is disclosed in the document.
- **The write-up prose is not the author's.** The project's own working rules
  reserve analysis conclusions and design rationale to the author; the DOCX was
  rebuilt on later instruction. §2.3 and §5 are the two sections worth rewriting
  in the author's voice before submission.

## 2.14  Correctness pass, 2026-09-17  `[rebuild]`

An independent review of the shipped archive found six defects. All six were
reproduced here before being accepted, and two turned out to be worse than
reported. Every generated artifact was then deleted and regenerated from the
corrected source, so no output in the tree predates these fixes.

| # | defect | verification | fix |
|---|---|---|---|
| 1 | The dispatcher's default target was computed as `lo + (IL_DEFAULT - IL_BASE)` — a CIL byte offset added to a native address. | **Worse than reported**: the result, `0x440442`, is not merely invalid, it lands *mid-instruction*, between `add x16,x16,#0x228` and `ldr x2,[x16,#0x10]`. | Read the target off the instruction that already states it: `0x440348 b.hs #0x440668`. No arithmetic. |
| 1b | The arm "validation" was `all(n for _,_,n in checks)` — it only asserted each arm contained *a* call, never that it was the *right* one. The prose claimed the pairing had been checked. | Confirmed. The pairing had been checked by eye, not by the script. | Each arm's first *managed* call (mono-internal helpers skipped) is compared against the CIL callees inside that arm's own IL extent. Tested for teeth: correct pairing 8/8, rotated by one 1/8, by two 0/8. |
| 2 | Arm D hooked call sites with `proj.hook(site, proc, length=4)` assuming fall-through. | **Worse than reported**: not "questionable" but void. With `lr = 0xdeadbeef` the successor's pc was `0xdeadbeef`. `length` applies only to plain-function hooks; a SimProcedure's `ret()` goes to the link register, so every hooked site returned out of the enclosing method. | `managed_runtime.StaticCallSite` — `IS_FUNCTION = False`, set `lr = site+4`, jump to the model. Reverses the finding; see §2.10. |
| 3 | A resolved call site with no dedicated model got one generic `kind="ref"` stub regardless of the callee's return type, despite signature-aware machinery existing for PLT hooks. | Confirmed. Also explains a symptom: `Object::ToString` returned an object, so `read_string` failed and beacon values came back unresolved. | 65 stubs typed from the callee's own metadata signature (20 scalar, 23 void, 17 ref, 5 string). `_generic` is now the last resort, not the default. |
| 4 | The one slot-inconsistent callee found by the validation was reported and then used anyway. | Confirmed: 30 sites. | Sites whose callee resolves to more than one vtable slot image-wide are moved to `unresolved`, so the technique quarantines them with a diagnostic instead of running a mapping that may be wrong. |
| 5 | Thanos's `HHmRdTUQTZoj` was labelled `<timestamp>`. | Confirmed, and the real behaviour is **more** significant: it queries WMI for `win32_processor` → `processorID` and `win32_logicaldisk.deviceid="C:"` → `VolumeSerialNumber` and concatenates them. | Fixture relabelled `<cpuid+volumeserial>`; the finding restated as a hardware fingerprint in the filename. |
| 7 | `diagnose.py` reused one interpreter across several `angr.Project` constructions, making its soundness figure bimodal (24 vs 279 lost states examined). | Found while verifying that a comment-and-dead-code cleanup was behaviour-preserving: 3 of 23 result bodies differed only in wall-clock, and the fourth differed in this figure. | Forks one process per measurement, as the comparison scripts already did. Verified deterministic across three full runs. |
| 6 | The DOCX is 12,937 words with no AI-assistance disclosure. | Confirmed. The accompanying "six comparison entry points" claim did **not** apply to the shipped document — `explorer_comparison.py` lists 8 and the document said 8; `diagnose.py` lists 6 for a different experiment and the document said 6 there. | Document held, not rebuilt, per the decision in §2.15. Entry points are now resolved up front and a missing symbol aborts the run instead of silently shrinking the experiment; the count executed is recorded alongside the count listed. |

**Secondary improvement found while fixing #3.** With `ToString` correctly typed,
GravityRat's VMNOTES field went from an empty-looking
`"Application running in VB/VM, host :  and machine name : "` to
`"… host : <System.Object::ToString> and machine name : <System.Object::ToString>"`.
That is a string assembled by executed code out of parts this analysis supplied,
which is neither a pure fixture nor a recovered value, so the beacon accounting
gained a third class: **symbolic, fixture-derived**. Final split of the 16
fields: 12 fixture, 1 fixture-derived, 1 recovered, 2 unresolved.

**What was purged and regenerated.** All 23 result files, the DOCX and
`EVIDENCE.md` were deleted and rebuilt from corrected source. One exception,
recorded rather than hidden: `case2/results/2_3_de4dot_detect.txt` was preserved,
because `dotnet` is not installed here to regenerate it. It is de4dot's own
output about the unmodified PE and none of the six defects touch it.

**A seventh defect, found while cleaning up afterwards.** `diagnose.py` built
several `angr.Project`s in a single interpreter. The README already warns that
angr and CLE keep process-global state across `Project` construction, and the
comparison scripts fork per arm because of it -- but this script did not, so its
soundness figure was unstable. Measured: three fresh processes gave
`(24 examined, 23 free, 1 narrowed)` every time; three runs inside one process
gave 24, then **279**, then 24. It now forks one process per measurement and is
byte-identical across three full runs. The correct figure is the fresh-process
one, 23 of 24, which is what the results and this logbook carry. Nothing was
wrong with the *claim* -- the program counter is wholly free either way -- but
the number behind it was a coin toss.

**What did not change.** The static findings — the call-site and literal tables
and their two validity checks, Thanos's builder configuration, `isVM`'s single
caller, every CIL reading — come from parsing, not execution, and none of the six
defects reaches them.

## 2.15  What is deliberately not rebuilt

The write-up was **not** regenerated in this pass. The evidence it quotes has
changed substantially — arm D reverses, the beacon accounting gains a class, the
dispatcher default is a different address — and its §5 argument was built on the
broken comparison. `run_all.sh` no longer rebuilds it by default; `./run_all.sh
docs` does so deliberately. When it is rebuilt it needs, at minimum:

- §5 rewritten around the corrected §2.10 verdict;
- the dispatcher section corrected to `0x440668` and to the real validation;
- Thanos's filename restated as a hardware fingerprint;
- an explicit AI-assistance disclosure;
- §2.3 and §5 rewritten in the author's voice, per the project's own rule that
  conclusions and design rationale belong to the author.
