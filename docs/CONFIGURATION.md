# Configuration reference

phi-gate reads up to three layers, strongest first:

1. **The managed policy**, installed by a security team at
   `/etc/phi-gate/policy.toml` (Linux) or
   `/Library/Application Support/phi-gate/policy.toml` (macOS). See the
   [deployment guide](DEPLOYMENT.md#set-a-policy-floor).
2. **The project configuration**, `.phi-gate.toml` at the project root.
3. **Nested configurations**, `.phi-gate.toml` in a folder below the root. A
   nested file can only make the rules stricter for its folder.

Every layer uses the same keys inside a `[phi-gate]` table. An unknown key, a
key outside the table, a wrong type or an invalid value is an error, and an
error blocks every action until it is fixed: a silently ignored typo in an
allowlist would be a hole nobody sees.

## The project root

The project root is `CLAUDE_PROJECT_DIR` when the working directory lies
inside it, otherwise the nearest folder holding `.git`, otherwise the working
directory. The configuration is read from the root, not from the folder the
agent happens to be in, so a `.phi-gate.toml` written into a subfolder cannot
switch protection off there.

## Keys

| Key | Default | Meaning |
|---|---|---|
| `mode` | `"block"` | `block` denies the action, `warn` allows it with a message, `audit` allows it and only logs |
| `allow_paths` | `[]` | Paths holding synthetic data, read and written freely. See [Path patterns](#path-patterns) |
| `allow_values` | `[]` | Known test values. See [Value patterns](#value-patterns) |
| `disable` | `[]` | Categories to switch off. `phi-gate explain` lists them |
| `record_window` | `400` | Characters within which a clinical fact and an identity make a patient record |
| `max_bytes` | `5000000` | Largest file scanned |
| `oversize` | `"block"` | A larger file is blocked (`block`) or scanned up to `max_bytes` (`scan_head`) |
| `opaque` | `"allow"` | A format phi-gate cannot read (PDF, image) is noted (`allow`) or refused (`block`) |
| `audit_log` | `".phi-gate/audit.jsonl"` | Where events are written, relative to the root. `""` disables logging |
| `audit_targets` | `"hash"` | How file names are logged: `hash`, `category` or `path`. See [data handling](DATA-HANDLING.md#the-audit-log) |
| `audit_key_file` | `""` | Absolute path to a key that makes the audit chain an HMAC. In a project configuration it must lie outside the project |
| `protect_config` | `true` | Refuse agent writes to phi-gate's configuration and state, agent settings and git hooks |
| `prompt_override_token` | `"#phi-ok"` | A prompt starting with it is sent even if it holds identifiers, and the override is logged. `""` disables it |
| `scan_tool_output` | `true` | Scan tool output after it arrives and tell the agent not to propagate PHI |
| `warn_in_hooks` | `false` | Show non-blocking warnings in the session |
| `allow_repo_allowlists` | `false` | Managed policy only: let projects add `allow_paths` and `allow_values` entries |
| `allow_env_overrides` | `false` | Managed policy only: let the `PHI_GATE_*` variables below take effect |

## Path patterns

`allow_paths` entries are relative to the project root and use gitignore-style
globs:

| Pattern | Matches |
|---|---|
| `tests/fixtures/*` | Files directly in `tests/fixtures` |
| `tests/fixtures/**` or `tests/fixtures/` | Everything under `tests/fixtures` |
| `*.synthetic.csv` | That name at any depth (no slash) |
| `/seed.csv` | `seed.csv` at the root only (leading slash) |
| `data/{a,b}/*.csv` | Brace alternatives |

`*` and `?` never cross a `/`. A path outside the project root never matches,
whatever the pattern. A pattern containing `..` or a backslash, or an empty
pattern, is an error.

## Value patterns

`allow_values` entries are matched exactly against a finding's text. An entry
starting with `re:` is a regular expression that must match the whole value.
To keep a configuration from stalling the scanner, a regular expression may be
at most 200 characters and may not nest a quantifier inside another, repeat an
alternation, or use a backreference.

```toml
allow_values = [
  "1EG4-TE5-MK73",          # exact
  "re:TEST-[0-9]{6}",       # regular expression
]
```

## How layers combine

A layer below the managed policy can make each setting stricter, never looser.

| Setting | Rule |
|---|---|
| `mode`, `oversize`, `opaque`, `audit_targets` | The stricter value wins (`block` over `warn` over `audit`; `category` over `hash` over `path`) |
| `max_bytes` | The smaller wins |
| `record_window` | The larger wins |
| `protect_config`, `scan_tool_output`, `warn_in_hooks` | `true` in any layer stays `true` |
| `prompt_override_token` | A lower layer may switch it off (`""`), never set a token |
| `allow_paths`, `allow_values` | Only the managed policy's, unless it sets `allow_repo_allowlists = true`; then the project's entries are added |
| `disable`, `audit_log`, `audit_key_file` | Only the managed policy's |

Without a managed policy the project configuration applies as written, and
nested configurations can still only tighten it.

## Environment variables

| Variable | Effect |
|---|---|
| `PHI_GATE_PYTHON` | The interpreter the hook runs (default `python3`) |
| `PHI_GATE_CONFIG` | Read this file instead of the project's `.phi-gate.toml` |
| `PHI_GATE_MANAGED_CONFIG` | Without a system policy, the policy to apply; with one, an extra layer that can only tighten it |
| `PHI_GATE_FAIL_OPEN` | `1` lets actions through when the checker cannot run. For recovering a broken install, never as a setting |

When a system managed policy is installed, all four are ignored unless the
policy sets `allow_env_overrides = true`.

## What the agent cannot change

With `protect_config = true` (the default, and always on under a managed policy
that sets it), the hooks refuse agent writes, edits, shell commands and tool
calls that would change:

- any `.phi-gate.toml`, the `.phi-gate/` folder, the audit log, its salt and
  the audit key;
- `.claude/` (Claude Code settings, which can set environment variables and
  switch plugins off), `~/.claude.json` and `.mcp.json`;
- `.git/config`, `.git/hooks/`, and `.pre-commit-config.yaml`;
- any file named `phi-gate`.

Reads of the audit key and the salt are refused as well.
