#!/usr/bin/env bash
# phi-gate hook wrapper. Fail-closed: if the checker cannot run for any reason
# (missing python3, crash, bad install), the action is blocked (exit 2).
# Set PHI_GATE_FAIL_OPEN=1 to let actions through when the checker is broken.
EVENT="${1:-}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PY="${PHI_GATE_PYTHON:-python3}"

# -I: isolated mode, so a phi_gate/ folder in the project cannot shadow ours.
"$PY" -I -c 'import sys; sys.path.insert(0, sys.argv[1]); from phi_gate.hooks import main; sys.exit(main(sys.argv[2]))' \
  "$ROOT/src" "$EVENT"
rc=$?

if [ "$rc" -eq 0 ] || [ "$rc" -eq 2 ]; then
  exit "$rc"
fi
if [ "${PHI_GATE_FAIL_OPEN:-}" = "1" ]; then
  echo "phi-gate: checker failed (exit $rc); PHI_GATE_FAIL_OPEN=1 so allowing." >&2
  exit 0
fi
echo "phi-gate: checker failed to run (exit $rc), blocking by default (fail-closed). Check that '$PY' is Python 3.11+." >&2
exit 2
