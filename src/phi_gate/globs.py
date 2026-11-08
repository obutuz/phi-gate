"""Which files a Grep's `glob` lets it search, read the way ripgrep reads it.

The Grep pre-check scans those files before the search runs. The glob only
narrows that set, so whatever this cannot follow must widen it to every file
under the search root, never empty it: a file left out here is a file of PHI
searched unchecked.

Understood:

* commas between globs (`*.py,*.csv`), but not inside braces;
* brace alternatives, nested too (`*.{csv,txt}`, `*.{json,{csv,tsv}}`);
* `*` and `?` within a path segment, `[...]` classes, and `**` across them;
* a glob without a slash matches the file's name at any depth; one with a
  slash matches its path under the search root (`2026/**/*.csv`).

Anything else (a negation `!`, a backslash escape, unbalanced braces, more
alternatives than `MAX_ALTERNATIVES`) gives `None`: search everything.
"""

from __future__ import annotations

import re
from pathlib import Path

MAX_ALTERNATIVES = 256


class _Unsupported(Exception):
    pass


def _split_top(text: str) -> list[str]:
    """Split on commas outside braces."""
    parts, depth, start = [], 0, 0
    for i, ch in enumerate(text):
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth < 0:
                raise _Unsupported("unbalanced braces")
        elif ch == "," and depth == 0:
            parts.append(text[start:i])
            start = i + 1
    if depth != 0:
        raise _Unsupported("unbalanced braces")
    parts.append(text[start:])
    return parts


def _expand(glob: str) -> list[str]:
    """Every alternative a brace glob stands for."""
    open_at = glob.find("{")
    if open_at < 0:
        if "}" in glob:
            raise _Unsupported("unbalanced braces")
        return [glob]
    depth = 0
    for i in range(open_at, len(glob)):
        if glob[i] == "{":
            depth += 1
        elif glob[i] == "}":
            depth -= 1
            if depth == 0:
                close_at = i
                break
    else:
        raise _Unsupported("unbalanced braces")
    head, body, tail = glob[:open_at], glob[open_at + 1:close_at], glob[close_at + 1:]
    out: list[str] = []
    for choice in _split_top(body):
        for rest in _expand(head + choice + tail):
            out.append(rest)
            if len(out) > MAX_ALTERNATIVES:
                raise _Unsupported("too many alternatives")
    return out


def _to_regex(glob: str) -> re.Pattern[str]:
    out, i = [], 0
    while i < len(glob):
        ch = glob[i]
        if glob.startswith("**/", i):
            out.append("(?:.*/)?")
            i += 3
        elif glob.startswith("**", i):
            out.append(".*")
            i += 2
        elif ch == "*":
            out.append("[^/]*")
            i += 1
        elif ch == "?":
            out.append("[^/]")
            i += 1
        elif ch == "[":
            close = glob.find("]", i + 2 if glob[i + 1:i + 2] in ("!", "^") else i + 1)
            if close < 0:
                raise _Unsupported("unclosed class")
            body = glob[i + 1:close]
            if body[:1] in ("!", "^"):
                body = "^" + body[1:]
            out.append("[" + body.replace("\\", "\\\\") + "]")
            i = close + 1
        else:
            out.append(re.escape(ch))
            i += 1
    return re.compile("".join(out) + r"\Z")


def compile_glob(pattern: str) -> list[tuple[re.Pattern[str], bool]] | None:
    """(regex, matches the full relative path) for each alternative of a Grep
    glob, or None when it cannot be followed and every file must be scanned."""
    if "\\" in pattern:
        return None
    try:
        globs = [g.strip() for g in _split_top(pattern)]
        if any(g.startswith("!") for g in globs):
            return None
        alternatives = [a for g in globs if g for a in _expand(g)]
        if not alternatives or len(alternatives) > MAX_ALTERNATIVES:
            return None
        compiled = []
        for alt in alternatives:
            anchored = "/" in alt.rstrip("/")
            compiled.append((_to_regex(alt.lstrip("/").removeprefix("./")), anchored))
        return compiled
    except (_Unsupported, re.error):
        return None


def select(files: list[Path], root: Path, pattern: str | None) -> list[Path]:
    """The files a Grep over `root` with `pattern` would search. Every file
    when there is no glob, or one this cannot follow."""
    if not pattern:
        return files
    compiled = compile_glob(pattern)
    if compiled is None:
        return files
    chosen = []
    for f in files:
        try:
            rel = f.relative_to(root).as_posix()
        except ValueError:
            rel = f.as_posix()
        if any(rx.match(rel if anchored else f.name) for rx, anchored in compiled):
            chosen.append(f)
    return chosen


__all__ = ["compile_glob", "select", "MAX_ALTERNATIVES"]
