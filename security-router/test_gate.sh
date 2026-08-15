#!/usr/bin/env bash
# Exercise every branch of the "Gate on high/critical findings" step, extracted verbatim
# from the workflow. This is what makes the timeout path testable in seconds rather than
# by waiting out a 90-minute step budget.
set -uo pipefail

WF="${1:?usage: test_gate.sh <path to claude-security.yml>}"
TMP="$(mktemp -d)"
GATE="$TMP/gate.sh"

python3 - "$WF" > "$GATE" <<'PY'
import sys, yaml
d = yaml.safe_load(open(sys.argv[1], encoding='utf-8'))
step = next(s for s in d['jobs']['scan']['steps'] if s.get('name', '').startswith('Gate on'))
sys.stdout.write(step['run'])
PY

pass=0; fail=0

# want_exit, label, report_findings ("none"|"clean"|"high"), then env assignments
run_case() {
  local want="$1" label="$2" findings="$3"; shift 3
  local dir="$TMP/case-$RANDOM"; mkdir -p "$dir"
  case "$findings" in
    clean) mkdir -p "$dir/CLAUDE-SECURITY-20260814-000000"
           : > "$dir/CLAUDE-SECURITY-20260814-000000/CLAUDE-SECURITY-RESULTS.jsonl" ;;
    high)  mkdir -p "$dir/CLAUDE-SECURITY-20260814-000000"
           printf '%s\n' '{"severity":"HIGH","id":"F1","title":"URL-userinfo identity bypass"}' \
             > "$dir/CLAUDE-SECURITY-20260814-000000/CLAUDE-SECURITY-RESULTS.jsonl" ;;
    medium) mkdir -p "$dir/CLAUDE-SECURITY-20260814-000000"
           printf '%s\n' '{"severity":"MEDIUM","id":"F9","title":"advisory only"}' \
             > "$dir/CLAUDE-SECURITY-20260814-000000/CLAUDE-SECURITY-RESULTS.jsonl" ;;
    # A scan killed mid-write leaves a truncated final line. This used to raise out of the
    # parser, leave stdout empty, and print "gate passed" with a CRITICAL sitting on disk one
    # line above.
    truncated) mkdir -p "$dir/CLAUDE-SECURITY-20260814-000000"
           printf '%s\n%s' '{"severity":"CRITICAL","id":"F1","title":"real finding"}' \
             '{"severity":"HIGH","id":"F2","tit' \
             > "$dir/CLAUDE-SECURITY-20260814-000000/CLAUDE-SECURITY-RESULTS.jsonl" ;;
    array) mkdir -p "$dir/CLAUDE-SECURITY-20260814-000000"
           printf '%s\n' '[{"severity":"HIGH","id":"F3","title":"wrong shape, real finding"}]' \
             > "$dir/CLAUDE-SECURITY-20260814-000000/CLAUDE-SECURITY-RESULTS.jsonl" ;;
    garbage) mkdir -p "$dir/CLAUDE-SECURITY-20260814-000000"
           printf '%s\n' 'not json at all' \
             > "$dir/CLAUDE-SECURITY-20260814-000000/CLAUDE-SECURITY-RESULTS.jsonl" ;;
    # A record that PARSES but does not say what we expect. Failing closed only on "the line
    # won't parse" is the same polarity error one layer in.
    listsev) mkdir -p "$dir/CLAUDE-SECURITY-20260814-000000"
           printf '%s\n' '{"severity":["HIGH"],"id":"F4","title":"severity as a list"}' \
             > "$dir/CLAUDE-SECURITY-20260814-000000/CLAUDE-SECURITY-RESULTS.jsonl" ;;
    prosesev) mkdir -p "$dir/CLAUDE-SECURITY-20260814-000000"
           printf '%s\n' '{"severity":"Critical (CVSS 9.1)","id":"F5","title":"decorated severity"}' \
             > "$dir/CLAUDE-SECURITY-20260814-000000/CLAUDE-SECURITY-RESULTS.jsonl" ;;
    nested) mkdir -p "$dir/CLAUDE-SECURITY-20260814-000000"
           printf '%s\n' '{"finding":{"severity":"CRITICAL","id":"F6","title":"schema moved"}}' \
             > "$dir/CLAUDE-SECURITY-20260814-000000/CLAUDE-SECURITY-RESULTS.jsonl" ;;
    dupkey) mkdir -p "$dir/CLAUDE-SECURITY-20260814-000000"
           printf '%s\n' '{"severity":"HIGH","id":"F7","severity":"LOW","title":"last key wins"}' \
             > "$dir/CLAUDE-SECURITY-20260814-000000/CLAUDE-SECURITY-RESULTS.jsonl" ;;
    wrongcase) mkdir -p "$dir/CLAUDE-SECURITY-20260814-000000"
           printf '%s\n' '{"Severity":"CRITICAL","id":"F8","title":"capitalised key"}' \
             > "$dir/CLAUDE-SECURITY-20260814-000000/CLAUDE-SECURITY-RESULTS.jsonl" ;;
    lowercase) mkdir -p "$dir/CLAUDE-SECURITY-20260814-000000"
           printf '%s\n' '{"severity":"critical","id":"F10","title":"lowercase severity"}' \
             > "$dir/CLAUDE-SECURITY-20260814-000000/CLAUDE-SECURITY-RESULTS.jsonl" ;;
    tabtitle) mkdir -p "$dir/CLAUDE-SECURITY-20260814-000000"
           printf '%s\n' '{"severity":"HIGH","id":"F11","title":"tab\there\nand a newline"}' \
             > "$dir/CLAUDE-SECURITY-20260814-000000/CLAUDE-SECURITY-RESULTS.jsonl" ;;
    # Two results directories: the gate used to read only the lexicographically earliest.
    twodirs) mkdir -p "$dir/CLAUDE-SECURITY-20260814-010000" "$dir/CLAUDE-SECURITY-20260814-020000"
           : > "$dir/CLAUDE-SECURITY-20260814-010000/CLAUDE-SECURITY-RESULTS.jsonl"
           printf '%s\n' '{"severity":"CRITICAL","id":"F12","title":"in the later directory"}' \
             > "$dir/CLAUDE-SECURITY-20260814-020000/CLAUDE-SECURITY-RESULTS.jsonl" ;;
  esac

  local out rc
  out="$( cd "$dir" && env -i PATH="$PATH" HOME="$HOME" \
      GITHUB_OUTPUT="$dir/out" GITHUB_STEP_SUMMARY="$dir/sum" \
      "$@" bash "$GATE" 2>&1 )"
  rc=$?

  if [ "$rc" -eq "$want" ]; then
    printf 'ok   exit=%d  %s\n' "$rc" "$label"; pass=$((pass+1))
  else
    printf 'FAIL want=%d got=%d  %s\n' "$want" "$rc" "$label"
    printf '%s\n' "$out" | sed 's/^/       | /'
    fail=$((fail+1))
  fi
  # Surface the operator-facing line so the message, not just the code, is reviewed.
  printf '%s\n' "$out" | grep -oE '::(error|warning|notice) title=[^:]*::.*' | head -1 | sed 's/^/       > /'
}

NOW=$(date +%s)

echo "--- (1) nothing to scan ---"
run_case 0 "data-only PR: router said should_scan=false" none \
  SHOULD_SCAN=false SCAN_OUTCOME=skipped EXECUTION_FILE= BLOCKING=true STEP_TIMEOUT=90 TIMEOUT_POLICY=warn

echo "--- (2) step timeout ---"
run_case 0 "timeout, policy=warn (default): does NOT block" none \
  SHOULD_SCAN=true SCAN_OUTCOME=failure EXECUTION_FILE= BLOCKING=true STEP_TIMEOUT=90 \
  START_EPOCH=$((NOW - 90*60)) TIMEOUT_POLICY=warn EFFORT=medium
run_case 1 "timeout, policy=block: blocks" none \
  SHOULD_SCAN=true SCAN_OUTCOME=failure EXECUTION_FILE= BLOCKING=true STEP_TIMEOUT=90 \
  START_EPOCH=$((NOW - 90*60)) TIMEOUT_POLICY=block EFFORT=medium
run_case 0 "timeout on the 30m advisory tier, policy=warn" none \
  SHOULD_SCAN=true SCAN_OUTCOME=failure EXECUTION_FILE= BLOCKING=false STEP_TIMEOUT=30 \
  START_EPOCH=$((NOW - 30*60)) TIMEOUT_POLICY=warn EFFORT=low

echo "--- (3) genuine scan failure, NOT a timeout ---"
run_case 1 "crashed at 5m of a 90m budget: fails closed" none \
  SHOULD_SCAN=true SCAN_OUTCOME=failure EXECUTION_FILE= BLOCKING=true STEP_TIMEOUT=90 \
  START_EPOCH=$((NOW - 300)) TIMEOUT_POLICY=warn EFFORT=medium

echo "--- (4) workflow-validation self-skip ---"
# WORKFLOW_REF entirely unset: must still take the benign path. `${WORKFLOW_REF%%...}` on an
# unset variable is an unbound-variable error under `set -u` in bash 4.4+, so this case failed
# on the runner while passing on macOS bash 3.2.
run_case 1 "self-skip with WORKFLOW_REF unset: fails closed" none \
  SHOULD_SCAN=true SCAN_OUTCOME=success EXECUTION_FILE= BLOCKING=true STEP_TIMEOUT=90 \
  START_EPOCH=$NOW TIMEOUT_POLICY=warn EFFORT=medium
# Committed copy: the workflow lives in the PR's own repo, so failing closed would block the
# PR that fixes it. Fail open, loudly.
run_case 0 "self-skip on a committed copy: warns and passes" none \
  SHOULD_SCAN=true SCAN_OUTCOME=success EXECUTION_FILE= BLOCKING=true STEP_TIMEOUT=90 \
  START_EPOCH=$NOW TIMEOUT_POLICY=warn EFFORT=medium \
  GITHUB_REPOSITORY=NC-DIT-Open-Source/mock-carolina \
  WORKFLOW_REF="NC-DIT-Open-Source/mock-carolina/.github/workflows/claude-security.yml@refs/pull/9/merge"
# Org-injected copy: a PR in this repo cannot have changed that file, so a skip is unexplained.
run_case 1 "self-skip on an org-injected copy: fails closed" none \
  SHOULD_SCAN=true SCAN_OUTCOME=success EXECUTION_FILE= BLOCKING=true STEP_TIMEOUT=90 \
  START_EPOCH=$NOW TIMEOUT_POLICY=warn EFFORT=medium \
  GITHUB_REPOSITORY=NC-DIT-Open-Source/mock-carolina \
  WORKFLOW_REF="NC-DIT-Open-Source/.github/.github/workflows/claude-security.yml@refs/heads/main"

echo "--- (5) unexplained missing report ---"
run_case 1 "no report, outcome=cancelled: fails closed" none \
  SHOULD_SCAN=true SCAN_OUTCOME=cancelled EXECUTION_FILE=exec.json BLOCKING=true STEP_TIMEOUT=90 \
  START_EPOCH=$NOW TIMEOUT_POLICY=warn EFFORT=medium

echo "--- findings gate ---"
run_case 0 "clean report: passes" clean \
  SHOULD_SCAN=true SCAN_OUTCOME=success EXECUTION_FILE=exec.json BLOCKING=true STEP_TIMEOUT=90 \
  START_EPOCH=$NOW TIMEOUT_POLICY=warn EFFORT=medium
run_case 0 "MEDIUM only: stays advisory, passes" medium \
  SHOULD_SCAN=true SCAN_OUTCOME=success EXECUTION_FILE=exec.json BLOCKING=true STEP_TIMEOUT=90 \
  START_EPOCH=$NOW TIMEOUT_POLICY=warn EFFORT=medium
run_case 1 "HIGH into default branch: blocks" high \
  SHOULD_SCAN=true SCAN_OUTCOME=success EXECUTION_FILE=exec.json BLOCKING=true STEP_TIMEOUT=90 \
  START_EPOCH=$NOW TIMEOUT_POLICY=warn EFFORT=medium
run_case 0 "HIGH into a feature branch: advisory, passes" high \
  SHOULD_SCAN=true SCAN_OUTCOME=success EXECUTION_FILE=exec.json BLOCKING=false STEP_TIMEOUT=30 \
  START_EPOCH=$NOW TIMEOUT_POLICY=warn EFFORT=low

echo "--- unreadable results must never read as clean (OAIP-479 review, HIGH) ---"
run_case 1 "truncated final line + CRITICAL above it: blocks" truncated \
  SHOULD_SCAN=true SCAN_OUTCOME=success EXECUTION_FILE=exec.json BLOCKING=true STEP_TIMEOUT=90 \
  START_EPOCH=$NOW TIMEOUT_POLICY=warn EFFORT=medium
run_case 1 "pretty-printed array instead of JSONL: still gated" array \
  SHOULD_SCAN=true SCAN_OUTCOME=success EXECUTION_FILE=exec.json BLOCKING=true STEP_TIMEOUT=90 \
  START_EPOCH=$NOW TIMEOUT_POLICY=warn EFFORT=medium
run_case 1 "wholly unparseable results: fails closed" garbage \
  SHOULD_SCAN=true SCAN_OUTCOME=success EXECUTION_FILE=exec.json BLOCKING=true STEP_TIMEOUT=90 \
  START_EPOCH=$NOW TIMEOUT_POLICY=warn EFFORT=medium

echo "--- a report on disk always wins over a why-no-scan branch (review, MEDIUM) ---"
run_case 1 "report present but SHOULD_SCAN=false: still gated" high \
  SHOULD_SCAN=false SCAN_OUTCOME=success EXECUTION_FILE=exec.json BLOCKING=true STEP_TIMEOUT=90 \
  START_EPOCH=$NOW TIMEOUT_POLICY=warn EFFORT=medium
run_case 1 "report present but execution_file empty: still gated" high \
  SHOULD_SCAN=true SCAN_OUTCOME=success EXECUTION_FILE= BLOCKING=true STEP_TIMEOUT=90 \
  START_EPOCH=$NOW TIMEOUT_POLICY=warn EFFORT=medium
run_case 1 "report present at a timeout: findings win over the timeout note" high \
  SHOULD_SCAN=true SCAN_OUTCOME=failure EXECUTION_FILE= BLOCKING=true STEP_TIMEOUT=90 \
  START_EPOCH=$((NOW - 90*60)) TIMEOUT_POLICY=warn EFFORT=medium

echo "--- STEP_TIMEOUT must not be able to zero out the budget (review, LOW) ---"
run_case 1 "STEP_TIMEOUT=0 does not reclassify a crash as a timeout" none \
  SHOULD_SCAN=true SCAN_OUTCOME=failure EXECUTION_FILE= BLOCKING=true STEP_TIMEOUT=0 \
  START_EPOCH=$((NOW - 5)) TIMEOUT_POLICY=warn EFFORT=medium
run_case 1 "non-numeric STEP_TIMEOUT falls back to 90m" none \
  SHOULD_SCAN=true SCAN_OUTCOME=failure EXECUTION_FILE= BLOCKING=true STEP_TIMEOUT=abc \
  START_EPOCH=$((NOW - 5)) TIMEOUT_POLICY=warn EFFORT=medium

echo "--- a record that parses but is unrecognized must block too (2nd review, MEDIUM) ---"
STD="SHOULD_SCAN=true SCAN_OUTCOME=success EXECUTION_FILE=exec.json BLOCKING=true STEP_TIMEOUT=90 TIMEOUT_POLICY=warn EFFORT=medium"
run_case 1 "severity as a list: blocks" listsev $STD START_EPOCH=$NOW
run_case 1 "severity as decorated prose: blocks" prosesev $STD START_EPOCH=$NOW
run_case 1 "severity moved into a nested object: blocks" nested $STD START_EPOCH=$NOW
run_case 1 "duplicate severity key: blocks" dupkey $STD START_EPOCH=$NOW
run_case 1 "severity under a differently-cased key: blocks" wrongcase $STD START_EPOCH=$NOW
run_case 1 "lowercase 'critical' is recognized and blocks" lowercase $STD START_EPOCH=$NOW
run_case 1 "tab/newline in a title does not break the read-back" tabtitle $STD START_EPOCH=$NOW

echo "--- every results directory is gated, not just the first (2nd review, MEDIUM) ---"
run_case 1 "CRITICAL in the later of two directories: blocks" twodirs $STD START_EPOCH=$NOW

echo
echo "gate: $pass passed, $fail failed"
rm -rf "$TMP"
[ "$fail" -eq 0 ]
