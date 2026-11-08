# Data handling

What phi-gate reads, what it writes, and what leaves the machine. Written for
privacy, security and procurement reviews.

## Summary

- phi-gate makes **no network connections**. It has no telemetry, no update
  check and no runtime dependencies; it is Python standard library code that
  runs locally inside each hook call and exits.
- It **never records a matched value**, a hash of a value or the text around
  it: not in messages to the agent, not on the terminal, not in the audit log.
- The only file it writes on its own is the audit log (and a salt beside it).
  `phi-gate redact --map` writes a redaction map only when asked.

## What it reads

| Source | When |
|---|---|
| Hook payloads from Claude Code (tool name, tool input, prompt, tool output) | Every hook call |
| Files a tool call would read, write or send | Before the call runs |
| Staged and committed git objects | On a commit, and on git commands that print history |
| `.phi-gate.toml` files and the managed policy | Every hook call |

Content is held in memory for the length of one check and is not cached or
written anywhere.

## What it tells the agent and the user

A decision names the file, the line numbers and the **categories** found
(`ssn x1; line 4`), never the values. The agent is told not to copy the data
another way and how to work with a redacted copy instead.

## The audit log

`.phi-gate/audit.jsonl`, created with mode `0600`, one JSON event per line:
time, event, tool, decision, target, categories and a reason code. It never
contains matched values or their hashes, because a 9-digit SSN space is small
enough that a hash is as good as the value.

A file name can itself identify a patient (`JaneDoe_labs.csv`), so the last
component of a target path is recorded according to `audit_targets`:

| `audit_targets` | Recorded as | Use when |
|---|---|---|
| `hash` (default) | `data/#3f2a9c1d0b7e4a65.csv`: a keyed hash of the name, plus its extension | The same file should be recognisable across events without revealing its name |
| `category` | `data/[csv]` | No file-level correlation is needed |
| `path` | `data/denials-export.csv` | File names are known not to carry identifiers |

Folder names are recorded as they are. Where folders are named after patients,
use `category`. The hash key is the audit key when one is configured, otherwise
a random salt kept beside the log (`audit.jsonl.salt`, mode `0600`), which the
agent is refused read access to.

**Integrity.** Each event carries the hash of the one before it, so editing,
removing or reordering a line breaks the chain and `phi-gate audit verify`
reports where. Without a key, anyone who can write the file can rebuild the
chain, so it only shows accidental damage. With `audit_key_file` each link is
an HMAC-SHA256 under that key, which an agent cannot forge because it cannot
read the key. A local process running as the same user can read the key; where
that matters, ship events off the machine as they are written. No chain can
show that its newest lines were removed.

**Write failures.** If the log cannot be written, phi-gate prints a warning.
In `audit` mode, where the log is the only control, and for a prompt override
in any mode, the action is blocked instead.

## The redaction map

`phi-gate redact --map m.json` writes a map from placeholders back to the
original values, so that `phi-gate restore` can put them back into a reply.
**The map contains PHI.** phi-gate creates it with mode `0600`, never follows a
symlink to it, and inside a git repository refuses a path that git would not
ignore (outside git, the name must end in `.map.json`). Delete it when the
task is done.

## Retention

phi-gate deletes nothing. The audit log grows until it is rotated or removed by
the organisation's own tooling; rotate it by moving the file aside, after which
a new chain starts.
