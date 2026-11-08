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

It takes the same keys as `.phi-gate.toml`, plus two that only a policy can set:

```toml
[phi-gate]
mode = "block"
opaque = "block"                       # refuse PDFs and images instead of allowing them
prompt_override_token = ""             # no override at all
audit_key_file = "/etc/phi-gate/audit.key"   # makes the audit chain an HMAC
audit_targets = "category"             # log extensions, not file names
allow_repo_allowlists = false          # projects cannot add allow_paths or allow_values
allow_env_overrides = false            # PHI_GATE_* variables are ignored
```

Under a policy, a project's `.phi-gate.toml` can only make each setting
stricter: the stricter mode wins, the smaller `max_bytes`, the larger
`record_window`, and protections switched on stay on. A project's
`allow_paths` and `allow_values` are ignored unless the policy sets
`allow_repo_allowlists = true`, and its `disable` list, `audit_log` and
`audit_key_file` are always ignored. The full rules are in the
[configuration reference](CONFIGURATION.md#how-layers-combine).

`PHI_GATE_MANAGED_CONFIG` can add a further layer for testing, but it can only
tighten an installed policy, never replace it.

An unreadable or invalid policy blocks everything until it is fixed.
`phi-gate status` shows which policy is in force.

### Audit key

Create the key once per machine, readable by the developer account but outside
any repository:

```bash
sudo install -m 0644 /dev/null /etc/phi-gate/audit.key
head -c 32 /dev/urandom | sudo tee /etc/phi-gate/audit.key > /dev/null
```

The hooks refuse agent reads of the key. A process running as the developer
can still read it, so treat the chain as protection against the agent, and
forward events off the machine for protection against the developer.

## Keep the audit trail

Every block, warning and override is appended to `.phi-gate/audit.jsonl`: event,
tool, target and categories, never values. File names are recorded as a keyed
hash by default (see [data handling](DATA-HANDLING.md#the-audit-log)). Each event
carries the hash, or with an audit key the HMAC, of the one before it, and
`phi-gate audit verify` exits 1 at the first line that has been edited, removed
or reordered.

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

- Python 3.11 or newer must be on `PATH` as `python3` (or set `PHI_GATE_PYTHON`
  where the policy permits it). If it is missing, every action is blocked. That
  is deliberate.
- `PHI_GATE_FAIL_OPEN=1` lets actions through when the checker is broken. It is
  ignored under a policy unless the policy sets `allow_env_overrides = true`.
  Treat its use as an incident, not a setting.
- Install the plugin from a pinned release tag, and verify the release's build
  provenance with `gh attestation verify <file> --repo obutuz/phi-gate`.
