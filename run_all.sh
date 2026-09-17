#!/usr/bin/env bash
# Regenerate every result file for both case studies from the samples on disk.
#
# Nothing here executes a sample. Every step either parses the PE/metadata or
# runs angr against the AOT-translated image with the runtime models in
# tools/managed_runtime.py, which are Python stand-ins, never real syscalls.
# `mono --aot` is a compiler: it reads method bodies and emits code, and never
# invokes an entry point.
#
#   ./run_all.sh              regenerate everything
#   ./run_all.sh case1        just case 1
#   ./run_all.sh 2.5.2        just the experiments whose id starts with 2.5.2
#
# Exits non-zero if any required step fails.
set -uo pipefail
cd "$(dirname "$0")"
PY=.venv/bin/python
G=case1/samples/extracted/Win32.GravityRAT.exe
T=case2/samples/extracted/thanos.exe
FILTER="${1:-}"
FAIL=0

run () {  # run <id> <case> <output> <command...>
  local id="$1" c="$2" out="$3"; shift 3
  if [ -n "$FILTER" ] && [[ "$id" != "$FILTER"* ]] && [ "$c" != "$FILTER" ]; then
    return 0
  fi
  printf '  %-9s %-44s ' "$id" "$out"
  local t0=$SECONDS
  if "$@" > "$out" 2>/dev/null && [ -s "$out" ]; then
    printf 'ok   %ss\n' "$((SECONDS - t0))"
  else
    printf 'FAILED\n'; FAIL=1
  fi
}

for f in "$G" "$T" "$G.so" "$T.so"; do
  [ -f "$f" ] || { echo "missing $f -- see README.md, 'Samples'"; exit 2; }
done

echo "=== case 1: Win32.GravityRat ==="
run 2.1   case1 case1/results/2_1_static_triage.txt      $PY tools/static_triage.py "$G"
run 2.2a  case1 case1/results/2_2_native_code_audit.txt  $PY tools/native_code_audit.py "$G"
run 2.2b  case1 case1/results/2_2_default_explorer.txt   $PY case1/scripts/default_explorer.py
run 2.3a  case1 case1/results/2_3_translated_explorer.txt $PY case1/scripts/translated_explorer.py
run 2.3b  case1 case1/results/2_3_callsite_map.txt       $PY tools/callsite_map.py "$G"
run 2.4   case1 case1/results/2_4_diagnosis.txt          $PY case1/scripts/diagnose.py
run 2.5   case1 case1/results/2_5_explorer_comparison.txt $PY case1/scripts/explorer_comparison.py
run 2.5.1 case1 case1/results/2_5_1_anti_analysis.txt    $PY case1/scripts/anti_analysis.py
run 2.5.1 case1 case1/results/2_5_1_isvm_cil.txt         $PY tools/cil_disasm.py "$G" --method isVM
run 2.5.2 case1 case1/results/2_5_2_beacon_capture.txt   $PY case1/scripts/beacon_capture.py
run 2.5.2 case1 case1/results/2_5_beacon_cil.txt         $PY tools/cil_disasm.py "$G" --type Core.Jobs
run 2.5.3 case1 case1/results/2_5_3_dispatch.txt         $PY case1/scripts/dispatch_analysis.py

echo "=== case 2: Ransomware.Thanos ==="
run 2.1   case2 case2/results/2_1_static_triage.txt      $PY tools/static_triage.py "$T"
run 2.2a  case2 case2/results/2_2_native_code_audit.txt  $PY tools/native_code_audit.py "$T"
run 2.2b  case2 case2/results/2_2_default_explorer_failure.txt $PY tools/default_explorer_failure.py "$T"
run 2.3a  case2 case2/results/2_3_cil_full.txt           $PY tools/cil_disasm.py "$T"
run 2.3b  case2 case2/results/2_3_decoded_strings.txt    $PY tools/string_decoder.py "$T"
run 2.3c  case2 case2/results/2_3_callsite_map.txt       $PY tools/callsite_map.py "$T"
run 2.5   case2 case2/results/2_5_behaviour_map.txt      $PY tools/aot_behaviour_map.py "$T.so"
run 2.5   case2 case2/results/2_5_coverage_comparison.txt $PY case2/scripts/coverage_comparison.py
run 2.5.1 case2 case2/results/2_5_1_anti_analysis.txt    $PY case2/scripts/anti_analysis.py
run 2.5.2 case2 case2/results/2_5_2_outbound_capture.txt $PY case2/scripts/outbound_capture.py

# de4dot needs the .NET SDK and a built checkout; it is the one step that can be
# absent on a fresh machine, so it is optional and never fails the run. The
# result file it produces is kept in the repository either way.
DE4DOT=case1/de4dot/Release/netcoreapp3.1/de4dot.dll
if { [ -z "$FILTER" ] || [ "$FILTER" = case2 ] || [ "$FILTER" = 2.3 ]; } \
   && command -v dotnet >/dev/null && [ -f "$DE4DOT" ]; then
  run 2.3d  case2 case2/results/2_3_de4dot_detect.txt dotnet "$DE4DOT" -d "$T"
else
  printf '  %-9s %-44s %s\n' 2.3d case2/results/2_3_de4dot_detect.txt \
    "skipped (needs dotnet + a built de4dot; existing file kept)"
fi

if [ -z "$FILTER" ]; then
  echo "=== evidence index ==="
  $PY tools/evidence_index.py || FAIL=1
fi

[ $FAIL -eq 0 ] && echo "all results regenerated" || echo "one or more steps FAILED"
exit $FAIL
