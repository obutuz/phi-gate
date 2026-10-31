#!/usr/bin/env bash
# Replays the hook calls Claude Code would make, against a throwaway project
# with synthetic data, and prints what phi-gate decides. No API key needed.
set -u
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUN="$ROOT/hooks/run.sh"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

cd "$WORK" || exit 1
git init -q && git config user.email demo@example.com && git config user.name demo
mkdir -p data src
cat > data/denials-export.csv <<'CSV'
patient_name,dob,member_id,carc,amount
Maria Lopez,1984-02-17,W483920175,CO-197,412.50
Kevin Osei,1979-09-03,W582910446,CO-16,98.00
CSV
printf 'def total(rows):\n    return sum(r.amount for r in rows)\n' > src/report.py

FAILED=0
bold() { printf '\n\033[1m%s\033[0m\n' "$*"; }
# Each call states the decision it expects, so a broken demo fails loudly
# instead of printing tracebacks and exiting 0.
call() {  # expected (block|allow), event, json payload, label
  local out rc
  out="$(printf '%s' "$3" | bash "$RUN" "$2" 2>&1)"; rc=$?
  if [ $rc -eq 2 ]; then
    printf '\033[1;31mBLOCKED\033[0m  %s\n' "$4"
    printf '%s' "$out" | python3 -c 'import sys, textwrap; print("\033[2m" + textwrap.fill(sys.stdin.read().strip(), width=96, initial_indent=" " * 9, subsequent_indent=" " * 9) + "\033[0m")'
    [ "$1" = block ] || FAILED=$((FAILED + 1))
  else
    printf '\033[1;32mALLOWED\033[0m  %s\n' "$4"
    [ "$1" = allow ] || FAILED=$((FAILED + 1))
  fi
}
# Payloads are built here rather than inside "$(...)" at each call: bash 3.2,
# which macOS ships, misreads an apostrophe nested that way.
prompt() {  # expected, prompt text, label
  call "$1" UserPromptSubmit "$(python3 -c 'import json,sys; print(json.dumps({"cwd": sys.argv[1], "prompt": sys.argv[2]}))' "$WORK" "$2")" "$3"
}
tool() {  # expected, tool name, tool_input as JSON, label
  call "$1" PreToolUse "$(python3 -c 'import json,sys; print(json.dumps({"cwd": sys.argv[1], "session_id": "demo", "tool_name": sys.argv[2], "tool_input": json.loads(sys.argv[3])}))' "$WORK" "$2" "$3")" "$4"
}

bold "1. Prompts"
prompt block "Why was the claim for Maria Lopez, DOB 02/17/1984, denied?" "prompt with a patient name and DOB"
prompt allow "Group denials by CARC code and chart them by payer" "prompt about the task, no identifiers"

bold "2. Reading files"
tool block Read '{"file_path":"data/denials-export.csv"}' "Read data/denials-export.csv"
tool block Bash '{"command":"head -3 data/denials-export.csv"}' "Bash: head -3 data/denials-export.csv"
tool allow Read '{"file_path":"src/report.py"}' "Read src/report.py"
tool allow Bash '{"command":"phi-gate redact data/denials-export.csv"}' "Bash: phi-gate redact data/denials-export.csv"

bold "3. Writing code and fixtures"
tool block Write '{"file_path":"src/seed.py","content":"PATIENT = {\"ssn\": \"123-45-6789\"}"}' "Write a seed file with a real-format SSN"
tool allow Write '{"file_path":"src/seed.py","content":"PATIENT = {\"ssn\": \"999-12-3456\", \"phone\": \"412-555-0142\"}"}' "Write a seed file with synthetic values"

bold "4. Guardrail integrity"
tool block Edit '{"file_path":".phi-gate.toml","old_string":"block","new_string":"audit"}' "Edit .phi-gate.toml"
tool block Bash '{"command":"git commit --no-verify -m wip"}' "git commit --no-verify"

bold "5. Outbound"
tool block mcp__slack__post_message '{"channel":"#billing","text":"Kevin Osei, member ID W582910446, needs a callback"}' "Slack MCP message with a member ID"

bold "Audit log (categories only, never values)"
python3 - "$WORK/.phi-gate/audit.jsonl" <<'PY'
import json, sys
for e in map(json.loads, open(sys.argv[1])):
    found = ", ".join(f"{k} x{v}" for k, v in e.get("categories", {}).items()) or e.get("note", "")
    print(f"  {e['decision']:6} {e['event']:17} {e.get('tool', ''):26} {found}")
PY

if [ "$FAILED" -ne 0 ]; then
  printf '\n\033[1;31mdemo failed: %s decision(s) did not match\033[0m\n' "$FAILED" >&2
  exit 1
fi
