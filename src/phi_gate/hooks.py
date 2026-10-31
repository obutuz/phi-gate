"""Claude Code hook handlers.

Contract (see https://code.claude.com/docs/en/hooks):
- The hook receives a JSON payload on stdin.
- Exit 2 blocks. For PreToolUse the tool call is denied and stderr is shown
  to Claude; for UserPromptSubmit the prompt is rejected before the model
  sees it; for PostToolUse stderr is fed back to Claude.
- Exit 0 allows. A JSON object on stdout can attach a `systemMessage`.

Fail-closed: every error path here returns 2, an internal deadline returns 2
before Claude Code's own hook timeout (which would let the action through),
and hooks/run.sh turns any other non-zero exit (crash, missing interpreter)
into 2 as well.
"""

from __future__ import annotations

import json
import os
import re
import signal
import sys
from dataclasses import dataclass
from pathlib import Path

from . import audit, shell
from .config import CONFIG_NAME, Config, ConfigError, load
from .policy import ALLOW, BLOCK, WARN, Verdict
from .scanner import MAX_DIR_FILES, FileResult, scan_commit, scan_file, scan_text, walk

MAX_BASH_FILES = 200
DEFAULT_DEADLINE = 15  # seconds; hooks.json gives each hook 30
EDIT_TOOLS = {"Write", "Edit", "MultiEdit", "NotebookEdit"}
TOOL_EVENTS = {"PreToolUse", "PostToolUse"}

REDACT_HINT = (
    "Work with redacted or synthetic data instead: `phi-gate redact <file>` prints a copy with "
    "typed placeholders. If this is synthetic test data, ask the user to add its path to "
    f"allow_paths in {CONFIG_NAME} (agents cannot edit that file)."
)

# Read-only phi-gate invocations are exempt from the file pre-scan: they print
# locations or redacted text, and their output is still scanned afterwards.
_PHI_GATE_CMD = re.compile(r"\s*(?:[\w./~-]*/)?phi-gate\s+(?:scan|redact|status|explain)\b[^;&|`$<>\n\r]*")


@dataclass
class Outcome:
    code: int
    stdout: str = ""
    stderr: str = ""


class Deadline(Exception):
    pass


def _fail_open() -> bool:
    return os.environ.get("PHI_GATE_FAIL_OPEN") == "1"


def _strings(obj) -> list[str]:
    """String leaves of a JSON value, so multi-line content keeps its line
    structure instead of being escaped by json.dumps."""
    if isinstance(obj, str):
        return [obj]
    if isinstance(obj, dict):
        return [s for v in obj.values() for s in _strings(v)]
    if isinstance(obj, list):
        return [s for v in obj for s in _strings(v)]
    if isinstance(obj, (int, float)) and not isinstance(obj, bool):
        return [str(obj)]
    return []


def _text(value) -> str:
    return "\n".join(_strings(value))


def _describe(verdict: Verdict, with_lines: bool = True) -> str:
    parts = [verdict.summary()]
    where = verdict.lines() if with_lines else ""
    if where:
        parts.append(where)
    return "; ".join(parts)


def _why(r: FileResult) -> str:
    return _describe(r.verdict) if r.verdict.findings else "; ".join(r.verdict.reasons)


def _abs(path: str, cwd: Path) -> Path:
    p = Path(path).expanduser()
    return p if p.is_absolute() else cwd / p


# --------------------------------------------------------------------------
# PreToolUse
# --------------------------------------------------------------------------


def _bash(command: str, cfg: Config, cwd: Path) -> tuple[str, str, Verdict | None, str | None]:
    a = shell.analyze(command, cwd)

    if cfg.protect_config:
        hit = next((p for p in a.writes if cfg.is_protected_path(p)), None)
        if hit is not None:
            return BLOCK, (
                f"phi-gate blocked a shell command that modifies {cfg.relpath(hit)}: phi-gate configuration "
                "and audit files are human-managed. Ask the user to make this change themselves."
            ), None, cfg.relpath(hit)

    if a.disables_hooks:
        return BLOCK, "phi-gate blocked a command that changes core.hooksPath (it can disable commit checks).", None, None

    if a.shows_staged and not a.commits:
        bad = [r for r in scan_commit(cfg, cwd, broad=False) if r.blocking]
        if bad:
            return BLOCK, (
                f"phi-gate blocked a command that prints staged changes: {bad[0].path} contains likely PHI "
                f"({_why(bad[0])}). " + REDACT_HINT
            ), bad[0].verdict, bad[0].path

    if a.commits:
        if any(c.bypass for c in a.commits):
            return BLOCK, (
                "phi-gate blocked `git commit --no-verify`: skipping hooks would skip the PHI check on this "
                "commit. Commit without --no-verify."
            ), None, None
        broad = a.stages_changes or any(c.include_all for c in a.commits)
        bad = [r for r in scan_commit(cfg, cwd, broad) if r.blocking]
        if bad:
            detail = "; ".join(f"{r.path} ({_why(r)})" for r in bad[:5])
            return BLOCK, (
                f"phi-gate blocked this commit: the changes it would include contain likely PHI in {detail}. "
                "Remove or replace those values (or unstage those files) before committing. " + REDACT_HINT
            ), bad[0].verdict, bad[0].path

    v = scan_text(command, cfg)
    if v.blocking:
        return BLOCK, (
            f"phi-gate blocked a shell command that contains likely PHI ({_describe(v, with_lines=False)}). "
            "Do not put identifiers in commands, URLs, or request bodies."
        ), v, None

    if _PHI_GATE_CMD.fullmatch(command) and "--map" not in command:
        return ALLOW, "", v, None

    files = list(a.read_files)
    tree_files: list[Path] = []
    for d in a.read_dirs:
        if cfg.is_allowed_path(d):
            continue
        listed = walk(d, MAX_DIR_FILES)
        if listed is None:  # big trees are left to the PostToolUse output scan
            tree_files = []
            break
        tree_files += listed
    if len(files) > MAX_BASH_FILES:
        return BLOCK, (
            f"phi-gate blocked a shell command that reads more than {MAX_BASH_FILES} files; it cannot check "
            "them all before the command runs. Narrow the command to specific paths."
        ), None, None
    if len(tree_files) <= MAX_DIR_FILES:
        files += tree_files
    for p in files:
        r = scan_file(p, cfg)
        if r.blocking:
            return BLOCK, (
                f"phi-gate blocked a shell command that reads {r.path}, which contains likely PHI ({_why(r)}). "
                "Do not try to access, print, or copy this data another way. " + REDACT_HINT
            ), r.verdict, r.path
    return ALLOW, "", v, None


def _pre_tool(payload: dict, cfg: Config, cwd: Path) -> tuple[str, str, Verdict | None, str | None]:
    """Returns (decision, message, verdict, target)."""
    tool = payload["tool_name"]
    ti = payload.get("tool_input") or {}
    if not isinstance(ti, dict):
        raise ValueError("tool_input is not an object")

    if tool in EDIT_TOOLS:
        raw_targets = [ti.get("file_path"), ti.get("notebook_path")]
        raw_targets += [e.get("file_path") for e in (ti.get("edits") or []) if isinstance(e, dict)]
        targets = [_abs(t, cwd) for t in raw_targets if isinstance(t, str) and t]
        for t in targets:
            if cfg.is_protected_path(t):
                return BLOCK, (
                    f"phi-gate blocked {tool} on {cfg.relpath(t)}: phi-gate configuration and audit files are "
                    "human-managed. Ask the user to make this change themselves."
                ), None, cfg.relpath(t)
        target = targets[0] if targets else None
        if target is not None and cfg.is_allowed_path(target):
            return ALLOW, "", None, cfg.relpath(target)
        if tool == "Write":
            text = _text(ti.get("content"))
        elif tool == "Edit":
            text = _text(ti.get("new_string"))
        elif tool == "MultiEdit":
            text = "\n".join(_text(e.get("new_string")) for e in (ti.get("edits") or []) if isinstance(e, dict))
        else:
            text = _text(ti.get("new_source"))
        v = scan_text(text, cfg)
        rel = cfg.relpath(target) if target is not None else None
        if v.blocking:
            return BLOCK, (
                f"phi-gate blocked {tool} to {rel or 'a file'}: the new content contains likely PHI "
                f"({_describe(v, with_lines=False)}). Use placeholders or synthetic values instead (SSNs "
                "starting with 9, 555-0100 to 555-0199 phone numbers, example.com emails). If this path holds "
                f"synthetic fixtures, ask the user to add it to allow_paths in {CONFIG_NAME}."
            ), v, rel
        return (WARN if v.decision == WARN else ALLOW), "", v, rel

    if tool == "Bash":
        command = ti.get("command")
        if not isinstance(command, str):
            raise ValueError("Bash tool_input.command is not a string")
        return _bash(command, cfg, cwd)

    if tool == "Read":
        path = ti.get("file_path")
        if not isinstance(path, str) or not path:
            raise ValueError("Read tool_input.file_path is missing")
        r = scan_file(_abs(path, cwd), cfg)
        if r.blocking:
            return BLOCK, (
                f"phi-gate blocked Read of {r.path}: likely PHI ({_why(r)}). "
                "Do not try to access, print, or copy this data another way. " + REDACT_HINT
            ), r.verdict, r.path
        if r.verdict.decision == WARN:
            return WARN, f"phi-gate: {r.path} may contain identifiers ({_describe(r.verdict)}).", r.verdict, r.path
        return ALLOW, "", r.verdict, r.path

    if tool == "Grep":
        v = scan_text(_text(ti.get("pattern")), cfg)
        if v.blocking:
            return BLOCK, (
                f"phi-gate blocked Grep: the search pattern contains likely PHI ({_describe(v, with_lines=False)})."
            ), v, None
        path = ti.get("path")
        root = _abs(path, cwd) if isinstance(path, str) and path else cwd
        if root.is_file():
            targets = [root]
        elif root.is_dir() and not cfg.is_allowed_path(root):
            targets = walk(root, MAX_DIR_FILES) or []  # big trees: rely on the output scan
            pattern = ti.get("glob")
            if isinstance(pattern, str) and pattern:
                import fnmatch

                pats = [x.strip() for x in re.split(r"[,{}]", pattern) if x.strip()]
                targets = [t for t in targets if any(fnmatch.fnmatch(t.name, x) or fnmatch.fnmatch(str(t), x) for x in pats)]
        else:
            targets = []
        for t in targets:
            r = scan_file(t, cfg)
            if r.blocking:
                return BLOCK, (
                    f"phi-gate blocked Grep over {r.path}: the file contains likely PHI ({_why(r)}). " + REDACT_HINT
                ), r.verdict, r.path
        return ALLOW, "", v, None

    if tool in ("WebFetch", "WebSearch") or tool.startswith("mcp__"):
        v = scan_text(_text(ti), cfg)
        if v.blocking:
            return BLOCK, (
                f"phi-gate blocked {tool}: its input contains likely PHI ({_describe(v, with_lines=False)}). "
                "Do not send identifiers to external tools or services."
            ), v, None
        return ALLOW, "", v, None

    return ALLOW, "", None, None


# --------------------------------------------------------------------------
# Dispatcher
# --------------------------------------------------------------------------


def decide(event: str, payload: dict, cfg: Config) -> Outcome:
    cwd = Path(payload.get("cwd") or os.getcwd())
    session = payload.get("session_id")
    tool = payload.get("tool_name")
    if event in TOOL_EVENTS and not (isinstance(tool, str) and tool):
        raise ValueError(f"{event} payload has no tool_name")

    v: Verdict | None
    if event == "UserPromptSubmit":
        prompt = payload.get("prompt")
        if not isinstance(prompt, str):
            raise ValueError("UserPromptSubmit payload has no prompt")
        token = cfg.prompt_override_token
        if token and prompt.lstrip().startswith(token):
            audit.record(cfg, event=event, decision="override", session_id=session, note="user override token")
            return Outcome(0)
        v = scan_text(prompt, cfg)
        decision, target = v.decision, None
        msg = (
            "phi-gate blocked this prompt before it reached the model: it looks like it contains PHI "
            f"({_describe(v, with_lines=False)}). Replace identifiers with placeholders (`phi-gate redact` can "
            "do it)" + (f", or start the prompt with {token} to send it anyway (this is logged)." if token else ".")
        )
    elif event == "PreToolUse":
        decision, msg, v, target = _pre_tool(payload, cfg, cwd)
    elif event == "PostToolUse":
        if not cfg.scan_tool_output:
            return Outcome(0)
        output = payload.get("tool_response", payload.get("tool_output", ""))
        v = scan_text(_text(output), cfg)
        decision, target = v.decision, None
        msg = (
            f"phi-gate: the output of this {tool} call contained likely PHI ({_describe(v, with_lines=False)}). "
            "It is now in context. Do not repeat, quote, summarize, or copy these values into code, files, "
            "commits, or messages; refer to records by placeholder or row number. Tell the user that PHI was "
            "exposed in this session so they can review it."
        )
    else:
        return Outcome(0)

    if decision == BLOCK:
        if event == "PostToolUse":
            effective = {"block": "flagged", "warn": WARN, "audit": "audited"}[cfg.mode]
        else:
            effective = {"block": BLOCK, "warn": WARN, "audit": "audited"}[cfg.mode]
        note = None
        if not (v and v.findings):
            if "human-managed" in msg:
                note = "config is human-managed"
            elif "--no-verify" in msg:
                note = "hook bypass: --no-verify"
            elif "core.hooksPath" in msg:
                note = "hook bypass: core.hooksPath"
            else:
                m = re.match(r"phi-gate blocked (.+?): ", msg)
                note = (m.group(1) if m else msg)[:60]
        audit.record(cfg, event=event, decision=effective, verdict=v, tool=tool, target=target,
                     session_id=session, note=note)
        if cfg.mode == "block":
            return Outcome(2, stderr=msg)
        if cfg.mode == "warn":
            return Outcome(0, stdout=json.dumps({"systemMessage": msg}))
        return Outcome(0)

    if decision == WARN and cfg.warn_in_hooks and msg:
        audit.record(cfg, event=event, decision=WARN, verdict=v, tool=tool, target=target, session_id=session)
        return Outcome(0, stdout=json.dumps({"systemMessage": msg}))
    return Outcome(0)


def _arm_deadline() -> None:
    seconds = int(os.environ.get("PHI_GATE_DEADLINE", DEFAULT_DEADLINE))
    if seconds > 0 and hasattr(signal, "SIGALRM"):
        def _expired(signum, frame):
            raise Deadline(f"check did not finish within {seconds}s")

        signal.signal(signal.SIGALRM, _expired)
        signal.alarm(seconds)


def main(event: str | None = None) -> int:
    event = event or (sys.argv[1] if len(sys.argv) > 1 else "")
    try:
        _arm_deadline()
        raw = sys.stdin.read()
        if not raw.strip():
            raise ValueError("empty hook payload")
        payload = json.loads(raw)
        if not isinstance(payload, dict):
            raise ValueError("hook payload is not a JSON object")
        event = event or payload.get("hook_event_name", "")
        cwd = payload.get("cwd") or os.getcwd()
        try:
            cfg = load(cwd)
        except ConfigError as exc:
            if _fail_open():
                return 0
            print(f"phi-gate configuration error, blocking until fixed: {exc}", file=sys.stderr)
            return 2
        outcome = decide(event, payload, cfg)
    except BaseException as exc:  # fail-closed on anything unexpected, including the deadline
        if _fail_open():
            return 0
        kind = "took too long" if isinstance(exc, Deadline) else "internal error"
        print(f"phi-gate {kind}, blocking by default (fail-closed): {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
    finally:
        if hasattr(signal, "SIGALRM"):
            signal.alarm(0)
    if outcome.stdout:
        print(outcome.stdout)
    if outcome.stderr:
        print(outcome.stderr, file=sys.stderr)
    return outcome.code


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
