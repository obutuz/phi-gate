# Threat model

phi-gate sits between an AI coding agent and the data on a developer's machine.
This document says what it defends, against whom, and where that defence stops.

## What is being protected

Patient identifiers in a repository, in local exports, or in the output of a
command: names, dates of birth, SSNs, MRNs, member IDs and the health facts
attached to them.

## Who it defends against

| Actor | Assumption | Coverage |
|---|---|---|
| A well-meaning agent | It reads whatever the task seems to need | Primary case. Reads, writes, commits and outbound calls are checked first |
| An agent routing around a block | It retries through another tool, or tries to loosen the rules | Covered for known routes. Shell analysis is best-effort; see below |
| A developer pasting data by accident | A prompt or a commit holds an identifier | Covered, with a logged override for prompts |
| A malicious insider | They control the machine | Out of scope. They can disable the plugin |
| A hostile file | It is built to crash or stall the scanner | Covered. Crashes and time-outs block rather than allow |

## Trust boundaries

1. **Hook payloads** come from Claude Code and are trusted to describe the tool
   call. A malformed payload blocks.
2. **Repository content** is untrusted. A `.phi-gate.toml` in a repository is
   read, but a [managed policy](DEPLOYMENT.md#set-a-policy-floor) outranks it, and
   `python -I` stops a `phi_gate/` folder in the project from shadowing the real code.
3. **Hook configuration** belongs to Claude Code, which takes a snapshot at
   startup, so an agent editing settings mid-session does not change what runs.
4. **The model provider** is outside the boundary. Anything that reaches it has
   left the organisation's control, which is why checks run before the tool does.

## How each failure is handled

| Failure | Result |
|---|---|
| Checker crashes, or Python is missing | Blocked by the `hooks/run.sh` wrapper |
| Check runs past the internal deadline | Blocked, before Claude Code's own hook timeout could let it through |
| Malformed payload or configuration | Blocked |
| File over `max_bytes`, or a container that will not parse | Blocked |
| File cannot be read | Blocked |
| Format phi-gate cannot read (PDF, image) | Allowed and noted, or blocked with `opaque = "block"` |
| Audit log cannot be written | The decision still stands; the event is lost |

## Known gaps

- **Shell analysis is static.** A path assembled at run time, or a query against
  a database server, is seen only when its output is scanned afterwards, and by
  then the data is already in the session. This is detection, not prevention.
- **Patterns, not understanding.** A name in free text with no label is missed.
  So are the identifiers in the formats listed under Limitations in the README.
- **The audit chain shows tampering, not truncation.** Removing the newest lines
  leaves a valid chain, so events should also be shipped off the machine.
- **Evasion by encoding.** Base64, or identifiers split by invisible characters,
  are not decoded. An agent trying to hide data from phi-gate is not the case it
  was built for.

Report a way past these controls through [SECURITY.md](../SECURITY.md).
