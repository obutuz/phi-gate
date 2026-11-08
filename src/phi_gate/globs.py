"""Which files a Grep's `glob` lets it search.

The Grep pre-check scans those files before the search runs. The glob only
narrows that set, so where its meaning is uncertain the set is made larger,
never smaller: a file left out here is a file searched unchecked.

Read as ripgrep reads a glob:

* commas between globs (`*.py,*.csv`), but not inside braces;
* brace alternatives, nested too (`*.{csv,txt}`, `*.{json,{csv,tsv}}`);
* `*` and `?` within a path segment, `[...]` classes, and `**` across segments.

Matched generously: each alternative is tried against every run of
consecutive segments of a file's path (`visits.csv`, `nov/visits.csv`,
`2026/nov`, ...), so a glob relative to the search root or to the working
directory, or one naming a directory, selects the file either way. Matching
ignores case and Unicode normalisation (macOS stores names decomposed), and
its cost is bounded by the glob's and the path's length: no pattern can make
it backtrack.

A glob that cannot be followed (a negation `!`, a backslash escape,
unbalanced or empty braces, more than `MAX_ALTERNATIVES` alternatives, an
overlong pattern) gives `None`: every file is searched, so every file is
scanned.
"""

from __future__ import annotations

import fnmatch
import re
import unicodedata
from pathlib import Path

MAX_ALTERNATIVES = 256
MAX_PATTERN = 4096
MAX_DOUBLE_STARS = 8


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
    close_at = -1
    for i in range(open_at, len(glob)):
        if glob[i] == "{":
            depth += 1
        elif glob[i] == "}":
            depth -= 1
            if depth == 0:
                close_at = i
                break
    if close_at < 0:
        raise _Unsupported("unbalanced braces")
    head, body, tail = glob[:open_at], glob[open_at + 1:close_at], glob[close_at + 1:]
    if not body:
        raise _Unsupported("empty braces")
    out: list[str] = []
    for choice in _split_top(body):
        for rest in _expand(head + choice + tail):
            out.append(rest)
            if len(out) > MAX_ALTERNATIVES:
                raise _Unsupported("too many alternatives")
    return out


def _normal(text: str) -> str:
    return unicodedata.normalize("NFC", text)


def _alternatives(pattern: str) -> list[str]:
    if len(pattern) > MAX_PATTERN or "\\" in pattern:
        raise _Unsupported("escape or overlong pattern")
    globs = [g.strip() for g in _split_top(pattern)]
    if any(g.startswith("!") for g in globs):
        raise _Unsupported("negation")
    alternatives = []
    for glob in globs:
        for alt in _expand(glob):
            alt = alt.strip().removeprefix("./").strip("/")
            if alt:
                alternatives.append(alt)
    if not alternatives or len(alternatives) > MAX_ALTERNATIVES:
        raise _Unsupported("no usable alternatives")
    if any(alt.count("**") > MAX_DOUBLE_STARS for alt in alternatives):
        raise _Unsupported("too many **")
    if not all(_classes_closed(alt) for alt in alternatives):
        raise _Unsupported("unclosed class")
    return alternatives


def _classes_closed(glob: str) -> bool:
    """Whether every `[` opens a class that closes. A `]` straight after the
    opening (or after its `!` or `^`) is a member, not the end."""
    i = 0
    while i < len(glob):
        if glob[i] == "[":
            j = i + 1
            if glob[j:j + 1] in ("!", "^"):
                j += 1
            if glob[j:j + 1] == "]":
                j += 1
            close = glob.find("]", j)
            if close < 0:
                return False
            i = close + 1
        else:
            i += 1
    return True


Compiled = list[tuple[str, ...]]


def compile_glob(pattern: str) -> Compiled | None:
    """Each alternative of a Grep glob as path segments, lower-cased, with
    `**` standing for any number of segments; None when every file must be
    scanned."""
    try:
        alternatives = _alternatives(_normal(pattern))
    except _Unsupported:
        return None
    compiled = []
    for alt in alternatives:
        segments: list[str] = []
        for seg in alt.lower().split("/"):
            if not seg:
                continue
            if seg == "**":
                if segments[-1:] != ["**"]:
                    segments.append("**")
            else:
                segments.append(re.sub(r"\*{2,}", "*", seg).replace("[^", "[!"))
        compiled.append(tuple(segments))
    return compiled


def _segment_match(name: str, pattern: str, cache: dict[tuple[str, str], bool]) -> bool:
    """One path segment against one glob segment. fnmatch translates to a
    regular expression with atomic groups, so no pattern backtracks badly."""
    key = (name, pattern)
    if key not in cache:
        cache[key] = fnmatch.fnmatchcase(name, pattern)
    return cache[key]


def _matches(segments: tuple[str, ...], parts: list[str], cache: dict[tuple[str, str], bool]) -> bool:
    """Whether the glob matches some run of consecutive path segments: a
    dynamic programme over (glob segment, path segment), so its cost is their
    product however many `**` the glob holds."""
    full = ("**", *segments, "**")
    n, m = len(full), len(parts)
    # reach[j]: the glob's first i segments can match parts[:j].
    reach = [True] + [False] * m
    for i in range(n):
        seg = full[i]
        nxt = [False] * (m + 1)
        if seg == "**":
            seen = False
            for j in range(m + 1):
                seen = seen or reach[j]
                nxt[j] = seen
        else:
            for j in range(m):
                if reach[j] and _segment_match(parts[j], seg, cache):
                    nxt[j + 1] = True
        reach = nxt
    return reach[m]


def named_segments(pattern: str | None) -> set[str]:
    """Path segments a glob names literally, such as `build` in
    `build/**/*.csv`. A directory skipped by default is still walked when a
    glob names it."""
    if not pattern:
        return set()
    try:
        alternatives = _alternatives(_normal(pattern))
    except _Unsupported:
        return set()
    return {seg for alt in alternatives for seg in alt.split("/") if seg and not set(seg) & set("*?[]")}


def select(files: list[Path], pattern: str | None) -> list[Path]:
    """The files a Grep with `pattern` would search, or more. Every file when
    there is no glob, or one this cannot follow."""
    if not pattern:
        return files
    compiled = compile_glob(pattern)
    if compiled is None:
        return files
    cache: dict[tuple[str, str], bool] = {}
    chosen = []
    for f in files:
        parts = [_normal(p).lower() for p in f.parts if p not in ("/", "")]
        if any(_matches(segments, parts, cache) for segments in compiled):
            chosen.append(f)
    return chosen


__all__ = ["compile_glob", "named_segments", "select", "MAX_ALTERNATIVES"]
