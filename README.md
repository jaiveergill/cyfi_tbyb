# Symbolic execution of .NET malware with angr

Two case studies — **Win32.GravityRat** and **Ransomware.Thanos**, both from
[theZoo](https://github.com/ytisf/theZoo) — on getting a .NET binary into angr
at all, and then on what kind of `ExplorationTechnique` the failure that is left
over actually needs.

The write-up is **`CyFI_dotNET_angr_writeup_final.docx`**. Every figure in it is
pulled out of `case*/results/` when the document is built, so it cannot quote a
stale number; `EVIDENCE.md` maps each claim to the file it came from, and
`LOGBOOK.md` is the command log and decision history — what was tried, what the
measurement said, and what was kept or rejected because of it.

| | sample | theZoo path | sha256 |
|---|---|---|---|
| case 1 | Win32.GravityRat | `malware/Binaries/Win32.GravityRat` | `1c0ea462f0bbd7acfdf4c6daf3cb8ce09e1375b766fbd3ff89f40c0aa3f4fc96` |
| case 2 | Ransomware.Thanos | `malware/Binaries/Ransomware.Thanos` | `58bfb9fa8889550d13f42473956dc2a7ec4f3abb18fd3faeaa38089d513c171f` |

> **Never execute anything under `case*/samples/`.** Every script here parses the
> PE and its metadata, or runs angr against the AOT-translated image with the
> models in `tools/managed_runtime.py` standing in for the mono runtime. Those
> models are Python: a network call reads its arguments out of the state,
> appends them to a list and returns. No socket is opened, no name resolved, no
> file written, no process started. `mono --aot` is a compiler — it reads method
> bodies and emits code, and never invokes an entry point.

## The short version of what this does

angr lifts machine code, and a .NET executable has six bytes of it. So:

1. **Translate.** `mono --aot=full` compiles the assembly's CIL to a native
   `.so` that angr can lift.
2. **Supply the runtime.** The `.so` expects the mono runtime underneath it.
   `tools/managed_runtime.py` provides the linkage table, a typed allocator,
   object headers, throw helpers, arrays, strings and collections.
3. **Resolve the calls.** A `callvirt` compiles to an indirect branch through a
   vtable that does not exist, and that is where every state dies.
   `tools/callsite_map.py` recovers what each call site invokes by aligning the
   AOT image's call sequence against the original metadata's, and recovers the
   `ldstr` literals into their GOT slots at the same time.
4. **Act on it.** `tools/managed_call_explorer.py` is the
   `angr.ExplorationTechnique`: it intervenes between the vtable load and the
   branch, enters the resolved callee with the path intact, and quarantines with
   a diagnostic the sites it cannot justify.

## Setup

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

| tool | purpose | install |
|---|---|---|
| Python 3.12 | | |
| mono 6.8+ | AOT-compiles CIL to a native `.so` angr can lift | `apt install mono-complete` |
| .NET SDK 8 | only needed to build de4dot (§2.3 of the write-up) | `curl -fsSL https://dot.net/v1/dotnet-install.sh \| bash -s -- --channel 8.0` |
| de4dot | obfuscator identification | `git clone https://github.com/de4dot/de4dot case1/de4dot && cd case1/de4dot && dotnet build de4dot.netcore.sln -c Release -p:TargetFrameworks=netcoreapp3.1` |

Pinned Python dependencies are in `requirements.txt`; the versions actually used
are recorded in the header of every file under `case*/results/`.

**Architecture.** The analysis was run on Linux aarch64, so the translated
images are AArch64 and the register names throughout are `x0`, `x1`, `lr`.
Nothing in the method depends on that — on x86-64 the call-site map and the
models read the same information out of different registers — but the *result
files* are AArch64-specific, so regenerating them on another architecture will
produce different addresses and slot offsets.

## Samples

```bash
python tools/fetch_sample.py Win32.GravityRat  case1/samples
python tools/fetch_sample.py Ransomware.Thanos case2/samples
# Thanos extracts four files named by SHA-256; the one analysed is 58bfb9fa…c171f
mv case2/samples/extracted/58bfb9fa*c171f case2/samples/extracted/thanos.exe

sha256sum case1/samples/extracted/Win32.GravityRAT.exe \
          case2/samples/extracted/thanos.exe   # must match the table above

mono --aot=full case1/samples/extracted/Win32.GravityRAT.exe
mono --aot=full case2/samples/extracted/thanos.exe
```

Archives are theZoo's, password `infected`. The fetcher prints the hashes and
compares them with theZoo's published `.md5` / `.shasum`. Note that the theZoo
directory is `Win32.GravityRat` but the archive inside is `Win32.GravityRAT.zip`
— the spelling differs, which is why the fetcher resolves the real filename from
the GitHub API rather than assuming `<name>/<name>.zip`.

`mono --aot=full` writes `<sample>.so` beside each sample. Both `.so` files must
exist before anything else will run; `run_all.sh` checks and exits 2 if not.

## Reproducing everything

```bash
./run_all.sh              # every experiment, then rebuild the write-up
./run_all.sh case1        # just case 1
./run_all.sh 2.5.2        # just the interception experiments
./run_all.sh docs         # just rebuild the write-up from existing results
```

It prints one line per experiment with a timing, and exits non-zero if any step
fails or produces an empty file. A full run takes roughly 25 minutes on four
cores, most of it in the two coverage comparisons, which each run twelve
processes.

Then:

```bash
.venv/bin/python tools/evidence_index.py   # regenerate EVIDENCE.md
.venv/bin/python tools/inspect_docx.py     # structural review of the .docx
```

### A note on measurement

Run each comparison arm in its own process. angr and CLE keep process-global
state across `Project` construction, and two arms in one interpreter gives
bimodal results. So every comparison script forks a subprocess per arm, and
reports three repeats so you can see whether the figures are stable. In the
current tree all three repeats of every arm agree exactly.

## Layout

| path | contents |
|---|---|
| `tools/callsite_map.py` | resolves each indirect call site to a named callee by anchored alignment; recovers `ldstr` literals into their GOT slots |
| `tools/managed_runtime.py` | the runtime surface — linkage table, typed allocator, object headers, arrays, strings, collections, capture-only network models |
| `tools/managed_call_explorer.py` | the `ExplorationTechnique` |
| `tools/ledger.py` | the header every result file opens with: artifact hashes, tool versions, entry point, models, budget |
| `tools/aot_bridge.py` | MonoString/MonoArray layout, PLT resolution, jump-table reconstruction |
| `tools/cil_disasm.py` | CIL disassembler on dnfile + dncil (monodis aborts on both samples) |
| `tools/static_triage.py`, `native_code_audit.py`, `string_decoder.py`, `aot_behaviour_map.py`, `find_dotnet_binaries.py`, `fetch_sample.py` | triage, inventory, literal decoding, behaviour mapping, sample retrieval |
| `tools/make_paper.py`, `inspect_docx.py`, `evidence_index.py` | build and check the deliverables |
| `case1/scripts/`, `case2/scripts/` | the per-sample experiments; `gravityrat.py` and `thanos.py` hold the shared model setup so the comparison scripts can say the two arms differ only in the technique |
| `case*/results/` | generated evidence, one file per experiment |
| `archive/superseded/` | the two rejected exploration techniques and the earlier drafts, with a note on why each was replaced |
| `LOGBOOK.md` | command log (part 1) and decision history (part 2), including the rejections and the corrections made after the fact |
| `EVIDENCE.md` | every result file with its sha256, the command that makes it, and the section that rests on it |

## What this does and does not cover

The write-up's §6 is a requirements matrix with four rows that are not fully
met, listed rather than omitted. Three worth knowing before you read it:

- **VirusTotal was never consulted.** I ran this without outbound network
  access, so I did neither the upload nor the hash search the brief offers, and
  no report is reproduced here. It is one hash search per sample and the hashes
  are in the table above. The .NET classification does not depend on it — CLI
  header, single `_CorExeMain` import, metadata tables — but the *family*
  attribution for GravityRat rests on theZoo's labelling and nothing else.
- **The document was not rendered to page images.** This environment has no
  LibreOffice, pandoc or pdftoppm. `tools/inspect_docx.py` checks it
  structurally instead — heading tree, table shapes, overlong unbreakable
  tokens, placeholder text, cross-references — and the substitution is disclosed
  in the document.
- **No clean-machine reproduction was performed.** `./run_all.sh` ran end to
  end in this workspace, and again from a fresh `git clone` with only the samples
  copied in, so the committed tree is self-contained and reproduces byte for
  byte. But I shared the Python environment rather than rebuilding it, and never
  tried a second machine.

Host facts (MAC address, CPU id, machine name) are **labelled fixtures**, never
recovered data, and every capture in the results marks which values are which.
Thanos's FTP destination is the literal builder placeholder
`"URL"`/`"USERNAME"`/`"ACCESO"`. No deployed server comes out of this and I do
not claim one.
