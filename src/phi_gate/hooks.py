"""Claude Code hook handlers.

Contract (see https://code.claude.com/docs/en/hooks):
- The hook receives a JSON payload on stdin.
- Exit 2 blocks. For PreToolUse the tool call is denied and stderr is shown
  to Claude; for UserPromptSubmit the prompt is rejected before the model
  sees it; for PostToolUse stderr is fed back to Claude.
- Exit 0 allows. A JSON object on stdout can attach a `systemMessage`.

Fail-closed: every error path here returns 2, an internal deadline returns 2
before Claude Code's own hook timeout (which would let the action through),
an event this module does not handle, or one that disagrees with the event
the hook was registered for, returns 2, and hooks/run.sh turns any other
non-zero exit (crash, missing interpreter) into 2 as well.
"""

from __future__ import annotations

import json
import os
import re
import signal
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import unquote, urlparse

from . import audit, config, globs, shell
from .config import CONFIG_NAME, Config, ConfigError
from .policy import ALLOW, BLOCK, WARN, Verdict
from .scanner import MAX_DIR_FILES, FileResult, git_toplevel, scan_commit, scan_file, scan_text, walk

MAX_BASH_FILES = 200
MAX_TREE_FILES = 2 * MAX_DIR_FILES  # files scanned across all directories one command reads
MAX_HISTORY_BLOBS = 500
MAX_HISTORY_BYTES = 64 * 1024 * 1024
MAX_REFERENCED_FILES = 50
DEFAULT_DEADLINE = 15  # seconds; hooks.json gives each hook 30
EDIT_TOOLS = {"Write", "Edit", "MultiEdit", "NotebookEdit"}
READ_TOOLS = {"Read", "NotebookRead"}
TOOL_EVENTS = {"PreToolUse", "PostToolUse"}
EVENTS = {"UserPromptSubmit", "PreToolUse", "PostToolUse"}
# Tools whose output repeats content the PreToolUse check already decided on.
POST_SKIP = EDIT_TOOLS | {"KillShell", "TodoWrite"}

REDACT_HINT = (
    "Work with redacted or synthetic data instead: `phi-gate redact <file>` prints a copy with "
    "typed placeholders. If this is synthetic test data, ask the user to add its path to "
    f"allow_paths in {CONFIG_NAME} (agents cannot edit that file)."
)
PROTECTED_HINT = "phi-gate configuration, audit files and its command are human-managed. Ask the user to make this change themselves."


@dataclass
class Outcome:
    code: int
    stdout: str = ""
    stderr: str = ""


@dataclass
class Decision:
    """A PreToolUse decision. `reason` is a stable code for the audit log."""

    decision: str
    message: str = ""
    verdict: Verdict | None = None
    target: str | None = None
    reason: str = ""


class Deadline(Exception):
    pass


def _fail_open() -> bool:
    """The explicit escape hatch for a broken install. A managed policy
    switches it off unless the policy itself permits environment overrides."""
    return os.environ.get("PHI_GATE_FAIL_OPEN") == "1" and config.env_overrides_permitted()


def _secret_block(cfg: Config, paths: list[Path], what: str) -> Decision | None:
    """A block when any path is a secret phi-gate relies on (the audit key or
    the salt that keys hashed audit targets)."""
    hit = next((p for p in paths if config.is_secret(p, cfg)), None)
    if hit is None:
        return None
    return Decision(BLOCK, f"phi-gate blocked {what} {cfg.relpath(hit)}: " + PROTECTED_HINT,
                    None, cfg.relpath(hit), "secret_read")


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


def _protected(cfg: Config, path: Path) -> bool:
    """Configuration, audit files, and any file named like phi-gate's command
    (a program by that name could otherwise pose as it)."""
    return cfg.is_protected_path(path) or path.name.lower() == shell.ENTRY_NAME


def _file_block(r: FileResult, what: str) -> Decision:
    return Decision(BLOCK, (
        f"phi-gate blocked {what} {r.path}, which contains likely PHI ({_why(r)}). "
        "Do not try to access, print, or copy this data another way. " + REDACT_HINT
    ), r.verdict, r.path, "phi_in_file")


# --------------------------------------------------------------------------
# Bash
# --------------------------------------------------------------------------


def _scan_tree(cfg: Config, root: Path) -> tuple[FileResult | None, bool]:
    """(first file with likely PHI under root, whether the whole tree was scanned)."""
    listed = walk(root, MAX_DIR_FILES)
    if listed is None:
        return None, False
    for p in listed:
        if cfg.is_allowed_path(p):
            continue
        r = scan_file(p, cfg)
        if r.blocking:
            return r, True
    return None, True


def _scan_blobs(cfg: Config, top: Path, blobs: list[shell.Blob]) -> FileResult | None:
    """Scan the repository objects and working-tree files a git command would print."""
    by_sha: dict[str, str] = {}
    for b in blobs:
        if cfg.is_allowed_path(top / b.path):
            continue
        if b.sha is None:
            r = scan_file(top / b.path, cfg)
            if r.blocking:
                return r
        else:
            by_sha.setdefault(b.sha, b.path)
    if len(by_sha) > MAX_HISTORY_BLOBS:
        raise shell.Undetermined(f"it would print more than {MAX_HISTORY_BLOBS} files")
    if not by_sha:
        return None
    shas = list(by_sha)
    sizes: dict[str, int] = {}
    check = subprocess.run(["git", "cat-file", "--batch-check"], cwd=top, input="\n".join(shas) + "\n",
                           capture_output=True, text=True, timeout=shell.GIT_TIMEOUT)
    for line in check.stdout.splitlines():
        parts = line.split()
        if len(parts) == 3 and parts[1] == "blob":
            sizes[parts[0]] = int(parts[2])
    fetch: list[str] = []
    for sha in shas:
        rel = cfg.relpath(top / by_sha[sha])
        if sha not in sizes:
            continue  # not a blob, or not present locally
        if sizes[sha] > cfg.max_bytes and cfg.oversize == "block":
            reason = f"file in git history is {sizes[sha]} bytes, over max_bytes={cfg.max_bytes}; not scanned"
            return FileResult(rel, Verdict(BLOCK, [], [reason]), "oversize")
        fetch.append(sha)
    if sum(min(sizes[s], cfg.max_bytes) for s in fetch) > MAX_HISTORY_BYTES:
        raise shell.Undetermined("the files it would print are too large to check in time")
    for sha in fetch:
        proc = subprocess.run(["git", "cat-file", "blob", sha], cwd=top, capture_output=True, timeout=shell.GIT_TIMEOUT)
        if proc.returncode != 0:
            raise shell.Undetermined("git could not read an object it would print")
        with tempfile.TemporaryDirectory(prefix="phi-gate-") as tmp:
            copy = Path(tmp) / (Path(by_sha[sha]).name or "blob")
            copy.write_bytes(proc.stdout[: cfg.max_bytes])
            r = scan_file(copy, cfg)
        r.path = f"{cfg.relpath(top / by_sha[sha])} (git object {sha[:10]})"
        if r.blocking:
            return r
    return None


def _bash(command: str, cfg: Config, cwd: Path) -> Decision:
    a = shell.analyze(command, cwd)

    hit = next((p for p in a.writes if cfg.protect_config and cfg.is_protected_path(p)), None)
    if hit is None:
        hit = next((p for p in a.created if p.name.lower() == shell.ENTRY_NAME), None)
    if hit is not None:
        return Decision(BLOCK, f"phi-gate blocked a shell command that modifies {cfg.relpath(hit)}: " + PROTECTED_HINT,
                        None, cfg.relpath(hit), "config_protected")

    if a.disables_hooks:
        return Decision(BLOCK, "phi-gate blocked a command that changes core.hooksPath (it can disable commit checks).",
                        reason="hook_bypass_hooks_path")

    if a.shows_staged and not a.commits:
        bad = [r for r in scan_commit(cfg, cwd, broad=False) if r.blocking]
        if bad:
            return Decision(BLOCK, (
                f"phi-gate blocked a command that prints staged changes: {bad[0].path} contains likely PHI "
                f"({_why(bad[0])}). " + REDACT_HINT
            ), bad[0].verdict, bad[0].path, "phi_in_staged_changes")

    if a.commits:
        if any(c.bypass for c in a.commits):
            return Decision(BLOCK, (
                "phi-gate blocked `git commit --no-verify`: skipping hooks would skip the PHI check on this "
                "commit. Commit without --no-verify."
            ), reason="hook_bypass_no_verify")
        broad = a.stages_changes or any(c.include_all for c in a.commits)
        bad = [r for r in scan_commit(cfg, cwd, broad) if r.blocking]
        if bad:
            detail = "; ".join(f"{r.path} ({_why(r)})" for r in bad[:5])
            return Decision(BLOCK, (
                f"phi-gate blocked this commit: the changes it would include contain likely PHI in {detail}. "
                "Remove or replace those values (or unstage those files) before committing. " + REDACT_HINT
            ), bad[0].verdict, bad[0].path, "phi_in_commit")

    v = scan_text(command, cfg)
    if v.blocking:
        return Decision(BLOCK, (
            f"phi-gate blocked a shell command that contains likely PHI ({_describe(v, with_lines=False)}). "
            "Do not put identifiers in commands, URLs, or request bodies."
        ), v, None, "phi_in_command")

    files = list(a.read_files)
    secret = _secret_block(cfg, files + list(a.read_dirs), "a shell command that reads")
    if secret is not None:
        return secret
    root = (git_toplevel(cwd) or cfg.root).resolve() if a.moves else cfg.root
    for move in a.moves:
        dest = move.dest.resolve() if move.dest.exists() else move.dest.parent.resolve() / move.dest.name
        if dest != root and root not in dest.parents:  # moved out of the project: a copy elsewhere
            for src in move.sources:
                (files if src.is_file() else a.read_dirs).append(src)
    if len(files) > MAX_BASH_FILES:
        return Decision(BLOCK, (
            f"phi-gate blocked a shell command that reads more than {MAX_BASH_FILES} files; it cannot check "
            "them all before the command runs. Narrow the command to specific paths."
        ), reason="too_many_files")

    unscanned: list[Path] = []
    tree_files: list[Path] = []
    for d in a.read_dirs:
        if cfg.is_allowed_path(d):
            continue
        listed = walk(d, MAX_DIR_FILES)
        if listed is None or len(tree_files) + len(listed) > MAX_TREE_FILES:
            unscanned.append(d)
            continue
        tree_files += listed
    secret = _secret_block(cfg, tree_files, "a shell command that reads")
    if secret is not None:
        return secret
    for p in files + tree_files:
        r = scan_file(p, cfg)
        if r.blocking:
            return _file_block(r, "a shell command that reads")

    egress = ", ".join(dict.fromkeys(a.egress))
    if unscanned and egress:
        return Decision(BLOCK, (
            f"phi-gate blocked a shell command that reads {cfg.relpath(unscanned[0])}, a directory too large to "
            f"check before the command runs, and sends data off this machine ({egress}). Name specific files, or "
            "scan the directory first with `phi-gate scan`."
        ), None, cfg.relpath(unscanned[0]), "unscanned_egress")

    for read in a.git_reads:
        top = git_toplevel(read.cwd)
        if top is None:
            continue
        try:
            printed = _scan_blobs(cfg, top, shell.history_blobs(read))
        except (shell.Undetermined, subprocess.SubprocessError, OSError) as exc:
            return Decision(BLOCK, (
                f"phi-gate blocked `git {read.sub}`: it prints file content from the repository, and phi-gate "
                f"could not determine which files ({exc}). Name a specific commit and path."
            ), reason="history_undetermined")
        if printed is not None and printed.blocking:
            return Decision(BLOCK, (
                f"phi-gate blocked `git {read.sub}`: it would print {printed.path}, which contains likely PHI "
                f"({_why(printed)}). Files removed from the working tree remain in git history. " + REDACT_HINT
            ), printed.verdict, printed.path, "phi_in_history")

    if a.unresolved:
        start = git_toplevel(cwd) or cfg.root
        found, complete = _scan_tree(cfg, start)
        if found is not None:
            return Decision(BLOCK, (
                f"phi-gate blocked a shell command that reads a path known only when it runs ({a.unresolved[0]}), "
                f"and this project holds likely PHI in {found.path} ({_why(found)}). Use literal paths so they "
                "can be checked first. " + REDACT_HINT
            ), found.verdict, found.path, "unresolved_read")
        if not complete and egress:
            return Decision(BLOCK, (
                f"phi-gate blocked a shell command that reads a path known only when it runs ({a.unresolved[0]}) "
                f"and sends data off this machine ({egress}); the project is too large to rule out PHI first. "
                "Use literal paths."
            ), reason="unresolved_egress")
    return Decision(ALLOW, verdict=v)


# --------------------------------------------------------------------------
# PreToolUse
# --------------------------------------------------------------------------


def _referenced_files(value, cwd: Path) -> list[Path]:
    """Existing files named by string values in a tool input (paths or file:// URIs)."""
    out: list[Path] = []
    for s in _strings(value):
        if not s or len(s) > 4096 or "\n" in s:
            continue
        candidate = s
        if s.startswith("file://"):
            candidate = unquote(urlparse(s).path)
        elif "://" in s:
            continue
        try:
            p = _abs(candidate, cwd)
            if p.is_file():
                out.append(p)
        except (OSError, ValueError):
            continue
        if len(out) >= MAX_REFERENCED_FILES:
            break
    return out


def _scan_input(tool: str, ti: dict, cfg: Config, cwd: Path, files: bool) -> Decision:
    """Scan a tool's whole input, and with `files`, any file it names."""
    v = scan_text(_text(ti), cfg)
    if v.blocking:
        return Decision(BLOCK, (
            f"phi-gate blocked {tool}: its input contains likely PHI ({_describe(v, with_lines=False)}). "
            "Do not send identifiers to other tools, agents or services."
        ), v, None, "phi_in_input")
    if files:
        referenced = _referenced_files(ti, cwd)
        secret = _secret_block(cfg, referenced, f"{tool} on")
        if secret is not None:
            return secret
        for p in referenced:
            r = scan_file(p, cfg)
            if r.blocking:
                return _file_block(r, f"{tool} on")
    return Decision(ALLOW, verdict=v)


def _read(tool: str, path, cwd: Path, cfg: Config) -> Decision:
    if not isinstance(path, str) or not path:
        raise ValueError(f"{tool} tool_input has no path")
    secret = _secret_block(cfg, [_abs(path, cwd)], f"{tool} of")
    if secret is not None:
        return secret
    r = scan_file(_abs(path, cwd), cfg)
    if r.blocking:
        return Decision(BLOCK, (
            f"phi-gate blocked {tool} of {r.path}: likely PHI ({_why(r)}). "
            "Do not try to access, print, or copy this data another way. " + REDACT_HINT
        ), r.verdict, r.path, "phi_in_file")
    if r.verdict.decision == WARN:
        return Decision(WARN, f"phi-gate: {r.path} may contain identifiers ({_describe(r.verdict)}).", r.verdict, r.path)
    return Decision(ALLOW, verdict=r.verdict, target=r.path)


def _pre_tool(payload: dict, cfg: Config, cwd: Path) -> Decision:
    tool = payload["tool_name"]
    ti = payload.get("tool_input") or {}
    if not isinstance(ti, dict):
        raise ValueError("tool_input is not an object")

    if tool in EDIT_TOOLS:
        raw_targets = [ti.get("file_path"), ti.get("notebook_path")]
        raw_targets += [e.get("file_path") for e in (ti.get("edits") or []) if isinstance(e, dict)]
        targets = [_abs(t, cwd) for t in raw_targets if isinstance(t, str) and t]
        for t in targets:
            if _protected(cfg, t):
                return Decision(BLOCK, f"phi-gate blocked {tool} on {cfg.relpath(t)}: " + PROTECTED_HINT,
                                None, cfg.relpath(t), "config_protected")
        target = targets[0] if targets else None
        if target is not None and cfg.is_allowed_path(target):
            return Decision(ALLOW, target=cfg.relpath(target))
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
            return Decision(BLOCK, (
                f"phi-gate blocked {tool} to {rel or 'a file'}: the new content contains likely PHI "
                f"({_describe(v, with_lines=False)}). Use placeholders or synthetic values instead (SSNs "
                "starting with 9, 555-0100 to 555-0199 phone numbers, example.com emails). If this path holds "
                f"synthetic fixtures, ask the user to add it to allow_paths in {CONFIG_NAME}."
            ), v, rel, "phi_in_content")
        return Decision(WARN if v.decision == WARN else ALLOW, verdict=v, target=rel)

    if tool == "Bash":
        command = ti.get("command")
        if not isinstance(command, str):
            raise ValueError("Bash tool_input.command is not a string")
        return _bash(command, cfg, cwd)

    if tool == "Read":
        return _read(tool, ti.get("file_path"), cwd, cfg)
    if tool == "NotebookRead":
        return _read(tool, ti.get("notebook_path"), cwd, cfg)

    if tool == "Grep":
        v = scan_text(_text(ti.get("pattern")), cfg)
        if v.blocking:
            return Decision(BLOCK, (
                f"phi-gate blocked Grep: the search pattern contains likely PHI ({_describe(v, with_lines=False)})."
            ), v, None, "phi_in_input")
        path = ti.get("path")
        root = _abs(path, cwd) if isinstance(path, str) and path else cwd
        if root.is_file():
            targets = [root]
        elif root.is_dir() and not cfg.is_allowed_path(root):
            glob = ti.get("glob")
            pattern = glob if isinstance(glob, str) else None
            # Large trees rely on the output scan. The glob narrows what is
            # scanned, and one that cannot be followed scans everything.
            found = walk(root, MAX_DIR_FILES, keep=globs.named_segments(pattern)) or []
            targets = globs.select(found, pattern)
        else:
            targets = []
        secret = _secret_block(cfg, [root, *targets], "Grep over")
        if secret is not None:
            return secret
        for t in targets:
            r = scan_file(t, cfg)
            if r.blocking:
                return Decision(BLOCK, (
                    f"phi-gate blocked Grep over {r.path}: the file contains likely PHI ({_why(r)}). " + REDACT_HINT
                ), r.verdict, r.path, "phi_in_file")
        return Decision(ALLOW, verdict=v)

    # Inputs that only describe work (agent prompts, search patterns, shell
    # ids) are scanned as text; tools that may open what their input names
    # (MCP tools, resources, tools phi-gate does not know) also have the
    # files their input names scanned.
    text_only = tool in ("Task", "Agent", "Glob", "LS", "BashOutput", "KillShell", "WebFetch", "WebSearch",
                         "TodoWrite", "ExitPlanMode")
    return _scan_input(tool, ti, cfg, cwd, files=not text_only)


# --------------------------------------------------------------------------
# UserPromptSubmit
# --------------------------------------------------------------------------

_MENTION = re.compile(r"(?:(?<=\s)|^)@(?:\"([^\"\n]+)\"|([^\s\"'<>|;,]+))")


def _mentions(prompt: str, cwd: Path) -> list[Path]:
    out: list[Path] = []
    for m in _MENTION.finditer(prompt):
        raw = (m.group(1) or m.group(2)).split("#", 1)[0].rstrip(".,:;!?)]}")
        if not raw:
            continue
        try:
            p = _abs(raw, cwd)
            if p.is_file():
                out.append(p)
        except (OSError, ValueError):
            continue
    return out[:MAX_REFERENCED_FILES]


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
    target: str | None = None
    reason = ""
    if event == "UserPromptSubmit":
        prompt = payload.get("prompt")
        if not isinstance(prompt, str):
            raise ValueError("UserPromptSubmit payload has no prompt")
        token = cfg.prompt_override_token
        if token and prompt.lstrip().startswith(token):
            audit.record(cfg, event=event, decision="override", session_id=session, note="user override token")
            return Outcome(0)
        v = scan_text(prompt, cfg)
        decision, reason = v.decision, "phi_in_prompt"
        override = f", or start the prompt with {token} to send it anyway (this is logged)." if token else "."
        msg = (
            "phi-gate blocked this prompt before it reached the model: it looks like it contains PHI "
            f"({_describe(v, with_lines=False)}). Replace identifiers with placeholders (`phi-gate redact` can "
            "do it)" + override
        )
        if decision != BLOCK:
            for p in _mentions(prompt, cwd):
                r = scan_file(p, cfg)
                if r.blocking:
                    decision, v, target, reason = BLOCK, r.verdict, r.path, "phi_in_mention"
                    msg = (
                        f"phi-gate blocked this prompt before it reached the model: it attaches {r.path}, which "
                        f"contains likely PHI ({_why(r)}). " + REDACT_HINT + override
                    )
                    break
    elif event == "PreToolUse":
        d = _pre_tool(payload, cfg, cwd)
        decision, msg, v, target, reason = d.decision, d.message, d.verdict, d.target, d.reason
    elif event == "PostToolUse":
        if not cfg.scan_tool_output or tool in POST_SKIP:
            return Outcome(0)
        ti = payload.get("tool_input") or {}
        if tool in READ_TOOLS and isinstance(ti, dict):
            path = ti.get("file_path") or ti.get("notebook_path")
            if isinstance(path, str) and path and cfg.is_allowed_path(_abs(path, cwd)):
                return Outcome(0)
        output = payload.get("tool_response", payload.get("tool_output", ""))
        v = scan_text(_text(output), cfg)
        decision, reason = v.decision, "phi_in_output"
        msg = (
            f"phi-gate: the output of this {tool} call contained likely PHI ({_describe(v, with_lines=False)}). "
            "It is now in context. Do not repeat, quote, summarize, or copy these values into code, files, "
            "commits, or messages; refer to records by placeholder or row number. Tell the user that PHI was "
            "exposed in this session so they can review it."
        )
    else:
        raise ValueError(f"unhandled hook event {event!r}")

    if decision == BLOCK:
        if event == "PostToolUse":
            effective = {"block": "flagged", "warn": WARN, "audit": "audited"}[cfg.mode]
        else:
            effective = {"block": BLOCK, "warn": WARN, "audit": "audited"}[cfg.mode]
        audit.record(cfg, event=event, decision=effective, verdict=v, tool=tool, target=target,
                     session_id=session, note=reason or None)
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


def _event(registered: str, payload: dict) -> str:
    """The event to handle. The event the hook was registered for must be
    named, known, and agree with the payload's hook_event_name when the
    payload carries one."""
    named = payload.get("hook_event_name")
    if registered not in EVENTS:
        raise ValueError(f"hook registered for unknown event {registered!r}")
    if named is not None and named != registered:
        raise ValueError(f"payload event {named!r} does not match the registered event {registered!r}")
    return registered


def main(event: str | None = None) -> int:
    registered = event if event is not None else (sys.argv[1] if len(sys.argv) > 1 else "")
    try:
        _arm_deadline()
        raw = sys.stdin.read()
        if not raw.strip():
            raise ValueError("empty hook payload")
        payload = json.loads(raw)
        if not isinstance(payload, dict):
            raise ValueError("hook payload is not a JSON object")
        resolved = _event(registered, payload)
        try:
            cfg = config.load_for_payload(payload)
        except ConfigError as exc:
            if _fail_open():
                return 0
            print(f"phi-gate configuration error, blocking until fixed: {exc}", file=sys.stderr)
            return 2
        outcome = decide(resolved, payload, cfg)
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
