# Deploying phi-gate across a team

For the security or platform team rolling phi-gate out to developers.

## Roll out in stages

1. **Measure.** Set `mode = "audit"` in each repository. Nothing is blocked and
   everything that would have been is logged. Run for a week, then review
   `.phi-gate/audit.jsonl`.
2. **Clear the noise.** Move synthetic fixtures under `allow_paths`, and list
   known test values in `allow_values`. `python3 bench/false_positive_sweep.py
   <repo>` shows what would block without running a session.
3. **Enforce.** Switch to `mode = "block"`.

## Set a policy floor

A managed policy applies to every repository on a machine and cannot be
loosened by one. Install it where developers and agents cannot write:

| Platform | Path |
|---|---|
| Linux | `/etc/phi-gate/policy.toml` |
| macOS | `/Library/Application Support/phi-gate/policy.toml` |

It takes the same keys as `.phi-gate.toml`:

```toml
[phi-gate]
mode = "block"
opaque = "block"              # refuse PDFs and images instead of allowing them
prompt_override_token = ""    # no override at all
allow_values = []             # repositories cannot add their own
```

| Setting | Rule |
|---|---|
| `mode`, `oversize`, `opaque` | The stricter of the two values wins |
| `max_bytes` | The smaller wins |
| `record_window` | The larger wins |
| `protect_config`, `scan_tool_output` | `true` in the policy cannot be switched off |
| `allow_paths`, `allow_values`, `disable` | If the policy sets a list, the repository's is ignored |
| Anything else | The policy's value wins |

An unreadable or invalid policy blocks everything until it is fixed.
`phi-gate status` shows which policy is in force.

## Keep the audit trail

Every block, warning and override is appended to `.phi-gate/audit.jsonl`: event,
tool, target and categories, never values. Each event carries the hash of the one
before it, and `phi-gate audit verify` exits 1 at the first line that has been
edited, removed or reordered.

A chain cannot show that its newest lines were removed, so copy events somewhere
the developer cannot write. Point your log forwarder at the file. The event
format is versioned by its `v` field.

## When phi-gate reports exposure

A `flagged` event means tool output held likely PHI, so it reached the model.

1. Find the session in the audit log, then the command that produced the output.
2. Remove the source from the developer's machine.
3. Follow your organisation's incident process. Whether an exposure is reportable
   depends on your agreement with the model provider, which is a question for your
   privacy officer, not a tool.

## Keep it working

- Python 3.11 or newer must be on `PATH`, or set `PHI_GATE_PYTHON`. If it is
  missing, every action is blocked. That is deliberate.
- `PHI_GATE_FAIL_OPEN=1` lets actions through when the checker is broken. Treat
  it as an incident, not a setting.
