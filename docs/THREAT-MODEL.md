# Threat model

phi-gate sits between an AI coding agent and the data on a developer's machine.
This document says what it defends, against whom, and where that defence stops.

## What is being protected

Patient identifiers in a repository, in local exports, in git history, or in
the output of a command: names, dates of birth, SSNs, MRNs, member IDs and the
health facts attached to them.

## Who it defends against

| Actor | Assumption | Coverage |
|---|---|---|
| A well-meaning agent | It reads whatever the task seems to need | Primary case. Reads, writes, commits and outbound calls are checked before they run |
| An agent routing around a block | It retries through another tool, encodes a path, or tries to loosen the rules | Covered for the routes listed below. Shell analysis is static and has limits |
| A developer pasting data by accident | A prompt or a commit holds an identifier | Covered, with a logged override for prompts |
| A malicious insider | They control the machine | Out of scope. They can uninstall the plugin |
| A hostile file or configuration | It is built to crash or stall the scanner | Covered. Patterns run in linear time, regular expressions in configuration are restricted, and a crash or time-out blocks |

## Trust boundaries

1. **Hook payloads** come from Claude Code and are trusted to describe the tool
   call. A malformed payload, or one whose event does not match the hook it was
   sent to, blocks.
2. **Repository content** is untrusted. A `.phi-gate.toml` in a repository is
   read, but a [managed policy](DEPLOYMENT.md#set-a-policy-floor) outranks it,
   nested configuration files can only tighten it, and `python -I` stops a
   `phi_gate/` folder in the project from shadowing the real code.
3. **Agent settings** are protected. Claude Code settings can set environment
   variables and switch plugins off, so agent writes to `.claude/`,
   `.mcp.json`, git hooks and git configuration are refused, and under a
   managed policy the `PHI_GATE_*` environment variables are ignored.
4. **The model provider** is outside the boundary. Anything that reaches it has
   left the organisation's control, which is why checks run before the tool does.

## Routes covered before the action runs

| Route | Control |
|---|---|
| `Read`, `NotebookRead`, `Grep` (including brace and path globs) | The files are scanned first |
| Shell reads: `cat`, `head`, redirections, globs, `cd`/`pushd`, variables and `export`, ANSI-C quoting, `bash -c`, recursive `grep`/`rg`/`find`/`tar`, copies (`cp`, `mv` out of the project, `ln`, `rsync`), interpreter one-liners and heredoc scripts | The files are resolved and scanned first |
| A path known only when the command runs (`$(...)`, `xargs`, a computed path in a script) | Blocked when the project holds PHI; when the project is too large to check, blocked if the command sends data off the machine |
| A directory too large to check first, piped or copied off the machine (`tar ... \| curl -T -`, `scp -r`, `nc`) | Blocked |
| Git history: `show`, `log -p`, `diff` between revisions, `stash show`, `grep`, `archive`, `cat-file`, `blame`, `format-patch`, `bundle` | The objects the command would print are scanned; a set too large to list blocks |
| Commits, including `git add -A && git commit`, `commit -a`, aliases, `-c alias.*` and plumbing (`commit-tree`, `merge`, `cherry-pick`, `rebase`, ...) | The changes are scanned and judged by the findings they introduce |
| `--no-verify` in any spelling, `core.hooksPath` overrides | Refused |
| Writes, edits and notebook edits | The new content is scanned |
| `WebFetch`, `WebSearch`, MCP tools, sub-agent prompts and any other tool | The input, and any file it names, is scanned |
| Prompts, including `@file` mentions | The prompt and the mentioned files are scanned |
| phi-gate's own configuration, state, audit key, and agent settings | Writes refused; key reads refused |

## How each failure is handled

| Failure | Result |
|---|---|
| Checker crashes, Python is missing, or another program stands in for it | Blocked: `hooks/run.sh` allows only an exit code of 0 together with a token the checker writes after deciding to allow |
| Check runs past 25 seconds | Blocked by the wrapper, before Claude Code's 30-second hook timeout could let it through; an internal 15-second deadline normally blocks first |
| Malformed payload, unknown event, or invalid configuration | Blocked |
| File over `max_bytes`, a container that will not parse, an unreadable file | Blocked |
| Format phi-gate cannot read (PDF, image) | Allowed and noted, or blocked with `opaque = "block"` |
| Audit log cannot be written | A warning; blocked in `audit` mode and for prompt overrides |

## Known limits

- **Shell analysis is static.** A program or script file that opens files
  itself (`python tool.py`, `make`) is not analysed; only its output is scanned
  afterwards, when the data is already in the session. A computed path in a
  project too large to check first is allowed when its output stays local.
  Pattern-based reading of inline scripts can be defeated by deliberate
  obfuscation.
- **Folders skipped by default** (`node_modules`, `.venv`, build output) are not
  scanned when a command reads a whole tree, unless the command names them.
- **Git LFS content** printed by history commands is not fetched and scanned.
- **Patterns, not understanding.** A name in free text with no label is missed,
  and so are the formats listed under Limitations in the README.
- **The audit key is readable by the developer's own account.** An HMAC chain
  stops an agent forging the log through its tools, not a local process running
  as the same user, and no chain shows that its newest lines were removed. Ship
  events off the machine where that matters.
- **`PostToolUse` cannot un-send.** It flags output that has already reached
  the model, and never sees data a command sent elsewhere.

Report a way past these controls through [SECURITY.md](../SECURITY.md).
