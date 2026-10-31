#!/usr/bin/env bash
# Replays the hook calls Claude Code would make, against a throwaway project
# with synthetic data, and prints what phi-gate decides. No API key needed.
set -u
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUN="$ROOT/hooks/run.sh"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

cd "$WORK"
git init -q && git config user.email demo@example.com && git config user.name demo
mkdir -p data src
cat > data/denials-export.csv <<'CSV'
patient_name,dob,member_id,carc,amount
Maria Lopez,1984-02-17,W483920175,CO-197,412.50
Kevin Osei,1979-09-03,W582910446,CO-16,98.00
CSV
printf 'def total(rows):\n    return sum(r.amount for r in rows)\n' > src/report.py

bold() { printf '\n\033[1m%s\033[0m\n' "$*"; }
call() {  # event, json payload, label
  local out rc
  out="$(printf '%s' "$2" | bash "$RUN" "$1" 2>&1)"; rc=$?
  if [ $rc -eq 2 ]; then
    printf '\033[1;31mBLOCKED\033[0m  %s\n' "$3"
    printf '%s' "$out" | python3 -c 'import sys, textwrap; print("\033[2m" + textwrap.fill(sys.stdin.read().strip(), width=96, initial_indent=" " * 9, subsequent_indent=" " * 9) + "\033[0m")'
  else printf '\033[1;32mALLOWED\033[0m  %s\n' "$3"; fi
}
J() { python3 -c 'import json,sys; print(json.dumps({"cwd": sys.argv[1], "session_id": "demo", "tool_name": sys.argv[2], "tool_input": json.loads(sys.argv[3])}))' "$WORK" "$1" "$2"; }

bold "1. Prompts"
call UserPromptSubmit "{\"cwd\":\"$WORK\",\"prompt\":\"Why was the claim for Maria Lopez, DOB 02/17/1984, denied?\"}" "prompt with a patient name and DOB"
call UserPromptSubmit "{\"cwd\":\"$WORK\",\"prompt\":\"Group denials by CARC code and chart them by payer\"}" "prompt about the task, no identifiers"

bold "2. Reading files"
call PreToolUse "$(J Read "{\"file_path\":\"$WORK/data/denials-export.csv\"}")" "Read data/denials-export.csv"
call PreToolUse "$(J Bash '{"command":"head -3 data/denials-export.csv"}')" "Bash: head -3 data/denials-export.csv"
call PreToolUse "$(J Read "{\"file_path\":\"$WORK/src/report.py\"}")" "Read src/report.py"
call PreToolUse "$(J Bash '{"command":"phi-gate redact data/denials-export.csv"}')" "Bash: phi-gate redact data/denials-export.csv"

bold "3. Writing code and fixtures"
call PreToolUse "$(J Write "{\"file_path\":\"$WORK/src/seed.py\",\"content\":\"PATIENT = {'ssn': '123-45-6789'}\"}")" "Write a seed file with a real-format SSN"
call PreToolUse "$(J Write "{\"file_path\":\"$WORK/src/seed.py\",\"content\":\"PATIENT = {'ssn': '999-12-3456', 'phone': '412-555-0142'}\"}")" "Write a seed file with synthetic values"

bold "4. Guardrail integrity"
call PreToolUse "$(J Edit "{\"file_path\":\"$WORK/.phi-gate.toml\",\"old_string\":\"block\",\"new_string\":\"audit\"}")" "Edit .phi-gate.toml"
call PreToolUse "$(J Bash '{"command":"git commit --no-verify -m wip"}')" "git commit --no-verify"

bold "5. Outbound"
call PreToolUse "$(J mcp__slack__post_message '{"channel":"#billing","text":"Kevin Osei, member ID W582910446, needs a callback"}')" "Slack MCP message with a member ID"

bold "Audit log (categories only, never values)"
python3 - "$WORK/.phi-gate/audit.jsonl" <<'PY'
import json, sys
for e in map(json.loads, open(sys.argv[1])):
    found = ", ".join(f"{k} x{v}" for k, v in e.get("categories", {}).items()) or e.get("note", "")
    print(f"  {e['decision']:6} {e['event']:17} {e.get('tool', ''):26} {found}")
PY
