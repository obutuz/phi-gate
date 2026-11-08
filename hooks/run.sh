#!/usr/bin/env bash
# phi-gate hook wrapper. Fail-closed: an action is allowed only when the
# checker exits 0 AND writes the allow token to file descriptor 3, which
# phi_gate.cli.hook_entry does only after deciding to allow. A missing
# interpreter, a crash, any other program that exits 0, or a checker that
# runs longer than LIMIT seconds blocks the action (exit 2). LIMIT stays
# below the 30-second hook timeout in hooks.json, at which Claude Code would
# let the action through.
#
# Without a managed policy, PHI_GATE_FAIL_OPEN=1 lets actions through when the
# checker is broken and PHI_GATE_PYTHON chooses the interpreter. When a
# managed policy is installed, those variables and PHI_GATE_CONFIG and
# PHI_GATE_MANAGED_CONFIG are ignored unless the policy sets
# allow_env_overrides = true.
EVENT="${1:-}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)" || exit 2
TOKEN="PHI-GATE-ALLOW-1"
LIMIT=25

POLICY=""
for candidate in "/etc/phi-gate/policy.toml" "/Library/Application Support/phi-gate/policy.toml"; do
  if [ -e "$candidate" ]; then
    POLICY="$candidate"
    break
  fi
done
if [ -n "$POLICY" ] && ! grep -Eq '^[[:space:]]*allow_env_overrides[[:space:]]*=[[:space:]]*true[[:space:]]*(#.*)?$' "$POLICY" 2>/dev/null; then
  unset PHI_GATE_FAIL_OPEN PHI_GATE_PYTHON PHI_GATE_CONFIG PHI_GATE_MANAGED_CONFIG
fi

PY="${PHI_GATE_PYTHON:-python3}"

# Runs a command, killing it after LIMIT seconds. Uses timeout(1) or
# gtimeout(1) when present, else a watchdog process (macOS without coreutils).
with_deadline() {
  if command -v timeout >/dev/null 2>&1; then
    timeout "$LIMIT" "$@"
    return $?
  fi
  if command -v gtimeout >/dev/null 2>&1; then
    gtimeout "$LIMIT" "$@"
    return $?
  fi
  # Job control gives the checker its own process group, so the watchdog
  # stops it together with anything it started.
  set -m
  exec 5<&0
  "$@" <&5 &
  local pid=$! watcher rc
  set +m
  ( sleep "$LIMIT"; kill -TERM -- "-$pid" 2>/dev/null; sleep 2; kill -KILL -- "-$pid" 2>/dev/null ) \
    </dev/null >/dev/null 2>&1 3>&- 5<&- &
  watcher=$!
  wait "$pid"
  rc=$?
  kill "$watcher" 2>/dev/null
  return "$rc"
}

# -I: isolated mode, so a phi_gate/ folder in the project cannot shadow ours.
# File descriptor 3 carries the allow token into $token; the checker's own
# stdout (JSON for Claude Code) passes through on descriptor 4.
exec 4>&1
token="$(with_deadline "$PY" -I -c 'import sys; sys.path.insert(0, sys.argv[1]); from phi_gate.cli import hook_entry; sys.exit(hook_entry(sys.argv[2]))' \
  "$ROOT/src" "$EVENT" 3>&1 1>&4 4>&-)"
rc=$?
exec 4>&-

if [ "$rc" -eq 0 ] && [ "$token" = "$TOKEN" ]; then
  exit 0
fi
if [ "$rc" -eq 2 ]; then
  exit 2
fi
if [ "$rc" -eq 0 ]; then
  reason="'$PY' exited 0 without confirming a decision"
elif [ "$rc" -eq 124 ] || [ "$rc" -eq 143 ] || [ "$rc" -eq 137 ]; then
  reason="the check did not finish within ${LIMIT}s"
else
  reason="checker failed to run (exit $rc)"
fi
if [ "${PHI_GATE_FAIL_OPEN:-}" = "1" ]; then
  echo "phi-gate: $reason; PHI_GATE_FAIL_OPEN=1 so allowing." >&2
  exit 0
fi
echo "phi-gate: $reason, blocking by default (fail-closed). Check that '$PY' is Python 3.11+." >&2
exit 2
