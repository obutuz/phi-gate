"""Best-effort static analysis of Bash tool commands.

Answers four questions about a command before it runs:
- which existing files could it print or read (so they can be scanned first)?
- does it run `git commit`, and with which flags?
- does it try to switch off git hooks?
- does it write to phi-gate's own configuration or audit files?

Shell is a full programming language, so this cannot be complete. It aims to
close the cheap bypasses (cd, $PWD, globs, braces, operators glued to paths,
paths inside `python -c` / `node -e`, `bash -c`). Whatever it misses is still
caught after the fact by the PostToolUse scan of the command's output.
"""

from __future__ import annotations

import glob
import os
import re
import shlex
from dataclasses import dataclass, field
from pathlib import Path

SEPARATORS = {";", "&&", "||", "|", "&", "\n", "(", ")", "|&", ";;", "`"}
SHELLS = {"bash", "sh", "zsh", "dash", "ksh"}
WRAPPERS = {"sudo", "env", "nice", "nohup", "time", "command", "exec", "xargs", "timeout", "stdbuf"}

# Commands that change files without printing their content. A segment run by
# one of these does not count as reading the files it names (so `rm` or
# `git rm --cached` on a PHI file, the remediation, is allowed).
NON_READING = {
    "rm", "mv", "cp", "ls", "stat", "touch", "chmod", "chown", "shred", "unlink",
    "mkdir", "rmdir", "cd", "ln", "du", "wc", "basename", "dirname", "realpath", "test", "[",
    "echo", "printf", "true", "false", "sleep", "export", "set", "unset", "which", "type",
    "pwd", "date", "whoami",
}
GIT_NON_READING = {"rm", "mv", "add", "restore", "reset", "status", "ls-files", "stash", "checkout", "switch", "commit"}

# Commands that walk directories given as arguments.
RECURSIVE_READERS = {"grep", "egrep", "fgrep", "rg", "ag", "ack", "find", "tar", "zip", "7z", "zgrep"}

WRITE_WORDS = {
    "tee", "sed", "rm", "mv", "cp", "truncate", "chmod", "chown", "ln", "dd", "install", "shred", "unlink",
    "python", "python3", "perl", "ruby", "node", "deno", "bun", "awk", "gawk", "echo", "printf", "touch",
    "vi", "vim", "nano", "ed", "rsync", "git",
}

MAX_EMBEDDED_SCAN = 20_000
MAX_BRACE_EXPANSIONS = 64

_EMBEDDED_PATH = re.compile(
    r"(?<![\w~./-])(?:[\w~./-]{0,200}[\w-]\.[A-Za-z0-9]{1,8}\b|[\w~.-]{0,200}/[\w~./-]{1,300})"
)
_BRACE = re.compile(r"^(.*?)\{([^{}]*,[^{}]*)\}(.*)$")


def tokenize(command: str) -> list[str]:
    try:
        lex = shlex.shlex(command.replace("`", " ` "), posix=True, punctuation_chars="();<>|&\n")
        lex.whitespace = " \t\r"
        lex.whitespace_split = True
        return list(lex)
    except ValueError:  # unbalanced quotes: fall back to a crude split
        return re.findall(r"[^\s;&|<>()]+|[;&|<>()\n]+", command)


def segments(tokens: list[str]) -> list[list[str]]:
    out: list[list[str]] = [[]]
    for tok in tokens:
        if tok in SEPARATORS:
            out.append([])
        else:
            out[-1].append(tok)
    return [s for s in out if s]


def _expand_vars(word: str, cwd: Path) -> str:
    home = str(Path.home())
    word = re.sub(r"\$\{PWD\}|\$PWD\b", str(cwd), word)
    word = re.sub(r"\$\{HOME\}|\$HOME\b", home, word)
    if word == "~" or word.startswith("~/"):
        word = home + word[1:]
    return word


def _expand_braces(word: str) -> list[str]:
    results = [word]
    for _ in range(3):
        nxt: list[str] = []
        changed = False
        for w in results:
            m = _BRACE.match(w)
            if m:
                changed = True
                nxt.extend(m.group(1) + alt + m.group(3) for alt in m.group(2).split(","))
            else:
                nxt.append(w)
        results = nxt[:MAX_BRACE_EXPANSIONS]
        if not changed:
            break
    return results


def _command_word(seg: list[str]) -> tuple[str, int]:
    """Basename of the command a segment runs, skipping VAR=x and wrappers."""
    i = 0
    while i < len(seg):
        w = seg[i]
        if re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", w):
            i += 1
            continue
        name = os.path.basename(w)
        if name in WRAPPERS:
            i += 1
            while i < len(seg) and seg[i].startswith("-"):
                i += 1
            continue
        return name, i
    return "", len(seg)


@dataclass
class Commit:
    args: list[str]
    bypass: bool = False
    include_all: bool = False


@dataclass
class Analysis:
    read_files: list[Path] = field(default_factory=list)
    read_dirs: list[Path] = field(default_factory=list)
    commits: list[Commit] = field(default_factory=list)
    stages_changes: bool = False  # `git add` somewhere in the command
    disables_hooks: bool = False
    shows_staged: bool = False  # `git diff --cached` prints staged content
    writes: list[Path] = field(default_factory=list)  # paths a writing command names


def commit_flags(args: list[str]) -> tuple[bool, bool]:
    """(bypasses_hooks, includes_unstaged) for `git commit` arguments."""
    bypass = include_all = False
    skip_next = False
    takes_value = {"-m", "--message", "-F", "--file", "-C", "-c", "--author", "--date", "-t", "--template",
                   "--reuse-message", "--reedit-message", "--fixup", "--squash", "--cleanup", "--trailer"}
    for tok in args:
        if skip_next:
            skip_next = False
            continue
        if tok in takes_value:
            skip_next = True
            continue
        if tok.startswith("--"):
            name = tok[2:].split("=", 1)[0]
            if len(name) >= 4 and "no-verify".startswith(name):  # git accepts unambiguous prefixes
                bypass = True
            elif len(name) >= 2 and "all".startswith(name):
                include_all = True
            continue
        if tok.startswith("-") and len(tok) > 1:
            for k, ch in enumerate(tok[1:]):
                if ch in "mFCct":  # option with a value: rest of cluster, or the next token
                    if k == len(tok) - 2:
                        skip_next = True
                    break
                if ch == "n":
                    bypass = True
                if ch == "a":
                    include_all = True
    return bypass, include_all


def _git_subcommand(seg: list[str], start: int) -> tuple[str, list[str]]:
    rest = seg[start + 1:]
    j = 0
    while j < len(rest) and rest[j].startswith("-"):
        if rest[j] in ("-C", "-c", "--git-dir", "--work-tree", "--namespace"):
            j += 2
        else:
            j += 1
    if j < len(rest):
        return rest[j], rest[j + 1:]
    return "", []


_GIT_OBJECT_PATH = re.compile(r"^[\w./@^~{}-]*:(?!//)(.+)$")
_DEV_STREAM = re.compile(r"^/(?:dev/(?:std(?:out|err)|fd/|tty)|proc/self/fd/)")
FIND_EXEC = {"-exec", "-execdir", "-ok", "-okdir"}
PHI_GATE_SAFE = {"scan", "redact", "status", "explain", "--version", "--help", "-h"}


def analyze(command: str, cwd: Path, depth: int = 0) -> Analysis:
    result = Analysis()
    if "core.hookspath" in command.lower():
        result.disables_hooks = True
    # Output of a listing command that feeds $(...), backticks or xargs is
    # used as file names by another command, so listed files count as read.
    feeds = any(x in command for x in ("$(", "`", "xargs"))
    bases = [cwd]
    variables: dict[str, str] = {}
    reading_text: list[str] = []

    for seg in segments(tokenize(command)):
        name, idx = _command_word(seg)
        args = seg[idx + 1:]
        for w in seg[:idx]:  # VAR=value prefixes and bare assignments
            m = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)=(.*)$", w, re.S)
            if m:
                variables[m.group(1)] = m.group(2)

        # nested shells: bash -c "...", eval "..."
        if depth < 2 and (name in SHELLS or name == "eval"):
            inner = [a for a in args if " " in a or "\n" in a] or args[-1:]
            for script in inner:
                sub = analyze(script, bases[-1], depth + 1)
                result.read_files += sub.read_files
                result.read_dirs += sub.read_dirs
                result.commits += sub.commits
                result.writes += sub.writes
                result.stages_changes |= sub.stages_changes
                result.disables_hooks |= sub.disables_hooks
                result.shows_staged |= sub.shows_staged

        if name == "cd" and args:
            target = Path(_expand_vars(args[0], bases[-1]))
            target = target if target.is_absolute() else bases[-1] / target
            bases.append(target)
            continue

        reading = bool(name) and (name not in NON_READING or feeds)
        if name == "phi-gate":
            # phi-gate's own read-only commands print locations or redacted
            # text, so the files they name are not exposed. --map writes the
            # original values out, so it counts as a read.
            action = args[0] if args else ""
            reading = action not in PHI_GATE_SAFE or any(a.startswith("--map") for a in args)
        extra_bases: list[Path] = []
        if name == "git":
            git_cmd, sub_args = _git_subcommand(seg, idx)
            if git_cmd == "commit":
                bypass, include_all = commit_flags(sub_args)
                result.commits.append(Commit(sub_args, bypass, include_all))
            if git_cmd == "add":
                result.stages_changes = True
            if git_cmd == "diff" and ("--cached" in sub_args or "--staged" in sub_args):
                result.shows_staged = True
            if git_cmd == "clean" and any(a.startswith("-") and not a.startswith("--") and ("x" in a or "X" in a)
                                      for a in sub_args):
                result.writes.append(bases[-1] / ".phi-gate")
            reading = git_cmd not in GIT_NON_READING or feeds
            top = _git_top(bases[-1])
            if top is not None:
                extra_bases.append(top)
        if name == "find":
            reading = feeds or any(a in FIND_EXEC for a in args)
            if "-delete" in args:
                result.writes += _resolve([a for a in args if not a.startswith("-")], bases, must_exist=False)

        # split redirections from words
        words: list[str] = []
        inputs: list[str] = []
        outputs: list[str] = []
        i = idx + 1
        while i < len(seg):
            tok = seg[i]
            if re.fullmatch(r"\d*[<>]+&?|&>>?|>\|", tok):
                if i + 1 < len(seg):
                    (inputs if "<" in tok else outputs).append(seg[i + 1])
                i += 2
                continue
            if tok.isdigit() and i + 1 < len(seg) and re.fullmatch(r"[<>]+&?", seg[i + 1]):
                i += 1  # "2" in "2>/dev/null"
                continue
            words.append(_expand_user_vars(tok, variables))
            i += 1

        if any(_DEV_STREAM.match(w) for w in words + outputs):
            reading = True  # cp file /dev/stdout prints it

        candidates: list[str] = []
        for w in words:
            if w.startswith("-"):
                if "=" in w:
                    candidates.append(w.split("=", 1)[1])
                continue
            candidates.append(w.split("=", 1)[1] if re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", w) else w)
            m = _GIT_OBJECT_PATH.match(w)
            if name == "git" and m:
                candidates.append(m.group(1))
            if " " in w or "(" in w or "'" in w or '"' in w:  # inline script: look for paths inside
                candidates += [m.group(0) for m in _EMBEDDED_PATH.finditer(w[:MAX_EMBEDDED_SCAN])]

        search = bases + extra_bases
        resolved_reads = _resolve(candidates + inputs, search)
        if name in WRITE_WORDS:
            result.writes += _resolve(candidates, bases, must_exist=False)
        result.writes += _resolve(outputs, bases, must_exist=False)

        input_paths = {os.path.normpath(str(_abs(x, bases[-1]))) for x in inputs}
        recursive = name in RECURSIVE_READERS or any(a in ("-r", "-R", "--recursive") for a in args)
        if reading:
            reading_text.append(" ".join(seg))
        for p in resolved_reads:
            try:
                if p.is_file():
                    if reading or os.path.normpath(str(p)) in input_paths:
                        result.read_files.append(p)
                elif p.is_dir() and reading and recursive:
                    result.read_dirs.append(p)
            except OSError:
                continue

    # Paths anywhere in the text of reading segments: heredoc bodies, inline
    # scripts, arguments the per-word analysis could not attribute.
    if reading_text:
        joined = "\n".join(reading_text)[:MAX_EMBEDDED_SCAN]
        embedded = [m.group(0) for m in _EMBEDDED_PATH.finditer(joined)]
        for p in _resolve(embedded, bases):
            try:
                if p.is_file():
                    result.read_files.append(p)
            except OSError:
                continue

    result.read_files = _dedupe(result.read_files)
    result.read_dirs = _dedupe(result.read_dirs)
    return result


def _expand_user_vars(word: str, variables: dict[str, str]) -> str:
    if "$" not in word or not variables:
        return word
    return re.sub(
        r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)",
        lambda m: variables.get(m.group(1) or m.group(2), m.group(0)),
        word,
    )


def _git_top(cwd: Path) -> Path | None:
    import subprocess

    try:
        res = subprocess.run(["git", "rev-parse", "--show-toplevel"], cwd=cwd, capture_output=True, text=True, timeout=5)
    except (OSError, subprocess.SubprocessError):
        return None
    return Path(res.stdout.strip()) if res.returncode == 0 and res.stdout.strip() else None


def _abs(word: str, base: Path) -> Path:
    p = Path(word)
    return p if p.is_absolute() else base / p


def _resolve(words: list[str], bases: list[Path], must_exist: bool = True) -> list[Path]:
    out: list[Path] = []
    for raw in words:
        if not raw:
            continue
        for base in bases:
            word = _expand_vars(raw, base)
            for w in _expand_braces(word):
                if any(ch in w for ch in "*?["):
                    pattern = w if os.path.isabs(w) else str(base / w)
                    try:
                        out += [Path(m) for m in glob.glob(pattern)[:500]]
                    except (OSError, ValueError):
                        pass
                    if not must_exist:
                        out.append(_abs(w, base))
                else:
                    try:
                        p = _abs(w, base)
                        if not must_exist or p.exists():
                            out.append(p)
                    except (OSError, ValueError):
                        continue
    return out


def _dedupe(paths: list[Path]) -> list[Path]:
    seen: set[str] = set()
    out = []
    for p in paths:
        key = os.path.normpath(str(p))
        if key not in seen:
            seen.add(key)
            out.append(Path(key))
    return out
