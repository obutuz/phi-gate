"""Scan text, files, directories and git changes."""

from __future__ import annotations

import bisect
import codecs
import gzip
import html
import os
import re
import sqlite3
import stat
import subprocess
import tempfile
import zipfile
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from .config import Config
from .detectors import LOW, MEDIUM, Finding, run_detectors
from .policy import ALLOW, BLOCK, WARN, Verdict, evaluate

SNIFF = 4096
MAX_DIR_FILES = 300
MAX_UNTRACKED = 300

# Formats phi-gate cannot read without third-party libraries. Files with these
# signatures are reported as "not inspected" (see README, Limitations).
OPAQUE_MAGIC = (
    b"%PDF", b"\x89PNG", b"\xff\xd8\xff", b"GIF8", b"SQLite format 3", b"\xd0\xcf\x11\xe0",
    b"\x1f\x8b", b"PAR1", b"II*\x00", b"MM\x00*", b"RIFF", b"7z\xbc\xaf", b"Rar!",
)
SKIP_DIRS = {
    ".git", "node_modules", ".venv", "venv", "__pycache__", ".next", "dist", "build", ".phi-gate", ".svelte-kit",
    ".mypy_cache", ".ruff_cache", ".pytest_cache", ".hypothesis", ".tox",
}


def _line_index(text: str) -> list[int]:
    starts = [0]
    for m in re.finditer("\r\n|\r|\n", text):
        starts.append(m.end())
    return starts


def _locate(findings: list[Finding], text: str, line_map: list[int] | None = None) -> list[Finding]:
    starts = _line_index(text)
    out = []
    for f in findings:
        idx = bisect.bisect_right(starts, f.start) - 1
        line = line_map[idx] if line_map and idx < len(line_map) else idx + 1
        out.append(Finding(f.category, f.severity, f.group, f.start, f.end, line, f.start - starts[idx] + 1))
    return out


def _findings(text: str, cfg: Config, line_map: list[int] | None = None) -> list[Finding]:
    findings = run_detectors(text, frozenset(cfg.disable))
    if cfg.allow_values:
        findings = [f for f in findings if not cfg.is_allowed_value(text[f.start:f.end])]
    return _locate(findings, text, line_map)


def scan_text(text: str, cfg: Config, line_map: list[int] | None = None) -> Verdict:
    return evaluate(_findings(text, cfg, line_map), cfg.record_window)


@dataclass
class FileResult:
    path: str
    verdict: Verdict
    note: str = ""
    skipped: bool = False

    @property
    def blocking(self) -> bool:
        return self.verdict.blocking


# --------------------------------------------------------------------------
# Decoding
# --------------------------------------------------------------------------


def _utf16_guess(head: bytes) -> str | None:
    if len(head) < 64:
        return None
    even = head[0::2]
    odd = head[1::2]
    if odd.count(0) > 0.4 * len(odd) and even.count(0) < 0.05 * len(even):
        return "utf-16-le"
    if even.count(0) > 0.4 * len(even) and odd.count(0) < 0.05 * len(odd):
        return "utf-16-be"
    return None


def _looks_binary(head: bytes) -> bool:
    if not head:
        return False
    control = sum(1 for b in head if b < 9 or 13 < b < 32 and b != 27)
    return control > 0.10 * len(head)


def decode_bytes(raw: bytes) -> str | None:
    """Decode text in UTF-8/16/32 (BOM or heuristics). None means binary."""
    for bom, enc in (
        (codecs.BOM_UTF32_LE, "utf-32"), (codecs.BOM_UTF32_BE, "utf-32"),
        (codecs.BOM_UTF8, "utf-8-sig"), (codecs.BOM_UTF16_LE, "utf-16"), (codecs.BOM_UTF16_BE, "utf-16"),
    ):
        if raw.startswith(bom):
            return raw.decode(enc, errors="replace")
    guessed = _utf16_guess(raw[:SNIFF])
    if guessed:
        return raw.decode(guessed, errors="replace")
    if _looks_binary(raw[:SNIFF]):
        return None
    return raw.decode("utf-8", errors="replace")


# --------------------------------------------------------------------------
# Office Open XML (xlsx, docx, pptx): stdlib only
# --------------------------------------------------------------------------

_NS = "{http://schemas.openxmlformats.org/spreadsheetml/2006/main}"


def _xlsx_text(zf: zipfile.ZipFile) -> str:
    import xml.etree.ElementTree as ET

    names = zf.namelist()
    shared: list[str] = []
    if "xl/sharedStrings.xml" in names:
        root = ET.fromstring(zf.read("xl/sharedStrings.xml"))
        for si in root.iter(_NS + "si"):
            shared.append("".join(t.text or "" for t in si.iter(_NS + "t")))
    lines: list[str] = []
    sheets = sorted(n for n in names if n.startswith("xl/worksheets/") and n.endswith(".xml"))
    for name in sheets:
        root = ET.fromstring(zf.read(name))
        for row in root.iter(_NS + "row"):
            vals = []
            for c in row.iter(_NS + "c"):
                kind = c.get("t")
                v = c.find(_NS + "v")
                index = v.text if v is not None and v.text else ""
                if kind == "s" and index.isdigit() and int(index) < len(shared):
                    val = shared[int(index)]
                elif kind == "inlineStr":
                    val = "".join(t.text or "" for t in c.iter(_NS + "t"))
                else:
                    val = v.text if v is not None and v.text else ""
                vals.append(val.replace(",", " ").replace("\n", " "))
            lines.append(",".join(vals))
        lines.append("")
    return "\n".join(lines)


def _wordml_text(xml: str, para: str, cell: str | None, row: str | None) -> str:
    if cell:
        xml = re.sub(rf"</{para}>(?=\s*</{cell}>)", "", xml)
        xml = xml.replace(f"</{cell}>", ",")
    if row:
        xml = xml.replace(f"</{row}>", "\n")
    xml = xml.replace(f"</{para}>", "\n")
    return html.unescape(re.sub(r"<[^>]+>", "", xml))


class Unreadable(Exception):
    """A container phi-gate should be able to read but cannot: fail closed."""


def archive_text(path: Path, max_bytes: int) -> str:
    """Text inside a zip container: Office Open XML, OpenDocument, or plain
    text members of an ordinary zip archive."""
    import xml.etree.ElementTree as ET

    try:
        with zipfile.ZipFile(path) as zf:
            infos = zf.infolist()
            if sum(i.file_size for i in infos) > 4 * max_bytes:
                raise Unreadable(f"archive expands beyond 4 x max_bytes ({max_bytes})")
            text = _zip_text(zf, infos, max_bytes)
    except Unreadable:
        raise
    except (zipfile.BadZipFile, zipfile.LargeZipFile, ET.ParseError, KeyError, ValueError, EOFError,
            RuntimeError, NotImplementedError, OSError, IndexError) as exc:
        raise Unreadable(f"cannot parse archive: {type(exc).__name__}") from exc
    return text


def _zip_text(zf: zipfile.ZipFile, infos: list, max_bytes: int) -> str:
    names = {i.filename for i in infos}
    if "xl/workbook.xml" in names:
        return _xlsx_text(zf)
    if "word/document.xml" in names:
        return _wordml_text(zf.read("word/document.xml").decode("utf-8", "replace"), "w:p", "w:tc", "w:tr")
    slides = sorted(n for n in names if n.startswith("ppt/slides/slide") and n.endswith(".xml"))
    if slides:
        return "\n".join(
            _wordml_text(zf.read(s).decode("utf-8", "replace"), "a:p", "a:tc", "a:tr") for s in slides
        )
    if "content.xml" in names:  # OpenDocument (ods, odt, odp)
        xml = zf.read("content.xml").decode("utf-8", "replace")
        xml = re.sub(r"</text:p>(?=\s*</table:table-cell>)", "", xml)
        xml = xml.replace("</table:table-cell>", ",").replace("</table:table-row>", "\n")
        xml = xml.replace("</text:p>", "\n")
        return html.unescape(re.sub(r"<[^>]+>", "", xml))
    parts = []
    for info in infos[:500]:
        if info.is_dir():
            continue
        data = zf.read(info)
        if data.startswith(b"PK\x03\x04"):
            parts.append(f"(nested archive {info.filename} not inspected)")
            continue
        decoded = decode_bytes(data[:max_bytes])
        if decoded is not None:
            parts.append(decoded)
    return "\n".join(parts)


def sqlite_text(path: Path, rows_per_table: int = 500) -> str:
    """Header plus the first rows of every table, as CSV-like text."""
    try:
        conn = sqlite3.connect(f"file:{path}?mode=ro&immutable=1", uri=True, timeout=1)
    except sqlite3.Error as exc:
        raise Unreadable(f"cannot open database: {exc}") from exc
    try:
        tables = [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()][:100]
        out = []
        for t in tables:
            cur = conn.execute(f'SELECT * FROM "{t.replace(chr(34), chr(34) * 2)}" LIMIT {int(rows_per_table)}')
            out.append(",".join(d[0] for d in cur.description))
            for row in cur.fetchall():
                out.append(",".join("" if v is None else str(v).replace(",", " ").replace("\n", " ") for v in row))
            out.append("")
        return "\n".join(out)
    except sqlite3.Error as exc:
        raise Unreadable(f"cannot read database: {exc}") from exc
    finally:
        conn.close()


# --------------------------------------------------------------------------
# Files and directories
# --------------------------------------------------------------------------


def _extract(p: Path, raw: bytes, cfg: Config, oversize: bool) -> tuple[str | None, str]:
    """The text a file holds, whatever it is wrapped in, and a note saying how
    it was read. The text is None when phi-gate cannot read the format."""
    if raw.startswith(b"PK\x03\x04") and not oversize:
        return archive_text(p, cfg.max_bytes), "archive contents"
    if raw.startswith(b"\x1f\x8b"):
        with gzip.open(p, "rb") as gz:
            decoded = decode_bytes(gz.read(cfg.max_bytes))
        return decoded, "gzip contents" if decoded is not None else "gzip of binary data, not inspected"
    if raw.startswith(b"SQLite format 3\x00"):
        return sqlite_text(p), "sqlite tables"
    if raw.startswith(OPAQUE_MAGIC):
        return None, "binary format, content not inspected"
    text = decode_bytes(raw)
    if text is None:
        return None, "binary, not inspected"
    return text, f"scanned first {cfg.max_bytes} bytes only" if oversize else ""


def read_text(path: str | Path, cfg: Config) -> str:
    """Decode a file the way the scanner does, for commands that must see the
    same text it saw. Raises Unreadable rather than returning garbage."""
    p = Path(path)
    with p.open("rb") as fh:
        raw = fh.read(cfg.max_bytes)
    try:
        text, note = _extract(p, raw, cfg, p.stat().st_size > cfg.max_bytes)
    except (EOFError, gzip.BadGzipFile) as exc:
        raise Unreadable(f"cannot read {p.name}: {exc}") from exc
    if text is None:
        raise Unreadable(f"cannot read {p.name}: {note}")
    return text


def scan_file(path: str | Path, cfg: Config, base: Path | None = None) -> FileResult:
    p = Path(path)
    if not p.is_absolute():
        p = (base or cfg.root) / p
    rel = cfg.relpath(p)
    if cfg.is_allowed_path(p):
        return FileResult(rel, Verdict(ALLOW), "allowlisted path", skipped=True)
    try:
        if p.is_dir():
            return FileResult(rel, Verdict(ALLOW), "directory", skipped=True)
        size = p.stat().st_size
        oversize = size > cfg.max_bytes
        if oversize and cfg.oversize == "block":
            reason = f"file is {size} bytes, over max_bytes={cfg.max_bytes}; not scanned"
            return FileResult(rel, Verdict(BLOCK, [], [reason]), "oversize")
        with p.open("rb") as fh:
            raw = fh.read(cfg.max_bytes)
    except FileNotFoundError:
        return FileResult(rel, Verdict(ALLOW), "file not found", skipped=True)
    except OSError as exc:
        return FileResult(rel, Verdict(BLOCK, [], [f"cannot read file ({exc.strerror}); not inspected"]), "unreadable")

    if raw[128:132] == b"DICM":  # the patient's name and ID are in the header of every image
        return FileResult(rel, Verdict(BLOCK, [], ["DICOM file; patient metadata not inspected"]), "dicom")
    try:
        text, note = _extract(p, raw, cfg, oversize)
    except (Unreadable, OSError, EOFError, gzip.BadGzipFile) as exc:
        return FileResult(rel, Verdict(BLOCK, [], [f"unreadable container ({exc}); not inspected"]), "unreadable")
    if text is None:
        if cfg.opaque == "block":
            return FileResult(rel, Verdict(BLOCK, [], [f"{note} (opaque = block)"]), "opaque")
        return FileResult(rel, Verdict(ALLOW), note, skipped=True)
    return FileResult(rel, scan_text(text, cfg), note)


SKIP_ABS = {"/proc", "/sys", "/dev", "/run"}


def walk(root: Path, limit: int, keep: set[str] | frozenset[str] = frozenset()) -> list[Path] | None:
    """Files under root, skipping vendored and build directories other than
    those named in `keep` (`.git` is always skipped). Stops early and returns
    None as soon as there are more than `limit` files."""
    skip = SKIP_DIRS - (set(keep) - {".git"})
    out: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(
            d for d in dirnames
            if d not in skip and not d.endswith(".egg-info") and os.path.join(dirpath, d) not in SKIP_ABS
        )
        for name in sorted(filenames):
            p = Path(dirpath) / name
            if p.is_file():
                out.append(p)
                if len(out) > limit:
                    return None
    return out


def iter_files(paths: list[str], cfg: Config):
    for raw in paths:
        p = Path(raw)
        if not p.is_absolute():
            p = Path.cwd() / p
        if p.is_file():
            yield p
        elif p.is_dir():
            yield from walk(p, 10**9) or []
        else:  # a gate must not report a clean scan of a path it never saw
            raise FileNotFoundError(raw)


# --------------------------------------------------------------------------
# git
# --------------------------------------------------------------------------


def _git(args: list[str], cwd: Path) -> str:
    """Run git and return its output. The bytes are decoded without newline
    translation: a carriage return inside a changed line is part of that line,
    and turning it into a line break would throw off the hunk line counts."""
    res = subprocess.run(["git", "-c", "core.quotepath=off", *args], cwd=cwd, capture_output=True, timeout=15)
    if res.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)} failed: {res.stderr.decode('utf-8', 'replace').strip()}")
    return res.stdout.decode("utf-8", "replace")


def git_toplevel(cwd: Path) -> Path | None:
    try:
        return Path(_git(["rev-parse", "--show-toplevel"], cwd).strip())
    except (RuntimeError, OSError, subprocess.TimeoutExpired):
        return None


_HUNK = re.compile(r"^@@ -\d+(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")
_ESCAPES = {"a": "\a", "b": "\b", "t": "\t", "n": "\n", "v": "\v", "f": "\f", "r": "\r", '"': '"', "\\": "\\"}


def _unquote(path: str) -> str:
    """A path as git prints it: C-quoted when it holds a quote, a backslash or
    a control character, with octal escapes for the bytes of other characters."""
    if not (len(path) >= 2 and path[0] == '"' and path[-1] == '"'):
        return path
    raw = bytearray()
    body, i = path[1:-1], 0
    while i < len(body):
        ch = body[i]
        if ch == "\\" and i + 1 < len(body):
            nxt = body[i + 1]
            if nxt in "01234567" and re.match(r"[0-7]{3}", body[i + 1:i + 4]):
                raw.append(int(body[i + 1:i + 4], 8))
                i += 4
                continue
            raw += _ESCAPES.get(nxt, nxt).encode()
            i += 2
            continue
        raw += ch.encode()
        i += 1
    return raw.decode("utf-8", "replace")


def added_lines_by_file(diff: str) -> dict[str, list[tuple[int, str]]]:
    """Parse `git diff -U0` output into {path: [(new_line_no, text), ...]}.

    Hunk headers say how many lines follow, and those are counted rather than
    recognised by their prefix: an added line reading `++ /dev/null` appears in
    the diff as `+++ /dev/null` and must not be taken for a file header."""
    files: dict[str, list[tuple[int, str]]] = {}
    current: str | None = None
    lineno = old_left = new_left = 0
    for line in diff.split("\n"):
        if old_left or new_left:
            if line.startswith("+"):
                new_left -= 1
                if current is not None:
                    files[current].append((lineno, line[1:]))
                lineno += 1
            elif line.startswith("-"):
                old_left -= 1
            continue
        if line.startswith("+++ "):
            target = _unquote(line[4:].rstrip("\t"))
            current = None if target == "/dev/null" else target[2:] if target.startswith("b/") else target
            if current is not None:
                files.setdefault(current, [])
        elif m := _HUNK.match(line):
            old_left = int(m.group(1) or 1)
            lineno = int(m.group(2))
            new_left = int(m.group(3) or 1)
    return files


# Prefixes are fixed so that diff.noprefix and diff.mnemonicPrefix cannot change
# how paths read, and renames are a deletion plus an addition, so a file moved
# out of an allowed path is checked as the new file it is.
DIFF_FLAGS = [
    "--no-color", "--no-ext-diff", "--no-renames", "--src-prefix=a/", "--dst-prefix=b/", "-U0", "--diff-filter=ACM",
]

# How much of a file is read for its first line when the whole of it is not.
HEAD_BYTES = 65536
# Total bytes read whole for one check, old and new versions together, as a
# multiple of max_bytes. Past it, a file is judged from its added lines.
READ_BUDGET_FILES = 8
# Bytes requested from git in one `cat-file --batch` call.
BATCH_BYTES = 16 * 1024 * 1024

_LFS_POINTER = re.compile(rb"\Aversion https://git-lfs\.github\.com/spec/v1\n(?:[a-z0-9.-]+ [^\n]*\n)*?oid sha256:([0-9a-f]{64})\n")


@dataclass
class _Budget:
    remaining: int

    def take(self, size: int) -> bool:
        if size > self.remaining:
            return False
        self.remaining -= size
        return True


@dataclass
class _Content:
    """What was read of one version of a file."""

    data: bytes
    whole: bool


def _read_objects(top: Path, names: list[str], max_bytes: int, budget: _Budget) -> dict[str, _Content]:
    """Blobs named like `:path` or `HEAD:path`, read whole when they fit
    max_bytes and the budget, otherwise only their first HEAD_BYTES. A name
    git cannot resolve to a blob (a deleted file, a submodule, no HEAD yet) is
    left out."""
    names = [n for n in names if "\n" not in n and "\r" not in n]
    if not names:
        return {}
    checked = subprocess.run(
        ["git", "cat-file", "--batch-check"], cwd=top, capture_output=True, timeout=15,
        input="".join(f"{n}\n" for n in names).encode(),
    )
    if checked.returncode != 0:
        return {}
    sizes: dict[str, int] = {}
    for name, line in zip(names, checked.stdout.split(b"\n"), strict=False):
        fields = line.split()
        if len(fields) == 3 and fields[1] == b"blob" and fields[2].isdigit():
            sizes[name] = int(fields[2])
    whole = [n for n in sizes if sizes[n] <= max_bytes and budget.take(sizes[n])]
    out = {n: _Content(_blob_head(top, n), False) for n in sizes if n not in set(whole)}
    group: list[str] = []
    group_bytes = 0
    for name in whole + [""]:
        if name and group_bytes + sizes[name] <= BATCH_BYTES:
            group.append(name)
            group_bytes += sizes[name]
            continue
        out.update(_batch(top, group))
        group, group_bytes = ([name], sizes[name]) if name else ([], 0)
    return out


def _batch(top: Path, names: list[str]) -> dict[str, _Content]:
    if not names:
        return {}
    res = subprocess.run(
        ["git", "cat-file", "--batch"], cwd=top, capture_output=True, timeout=60,
        input="".join(f"{n}\n" for n in names).encode(),
    )
    if res.returncode != 0:
        return {}
    out: dict[str, _Content] = {}
    data, pos = res.stdout, 0
    for name in names:
        header_end = data.find(b"\n", pos)
        if header_end < 0:
            break
        header = data[pos:header_end].split()
        pos = header_end + 1
        if len(header) != 3 or not header[2].isdigit():
            continue
        size = int(header[2])
        out[name] = _Content(data[pos:pos + size], True)
        pos += size + 1
    return out


def _blob_head(top: Path, name: str) -> bytes:
    """The first HEAD_BYTES of a blob, without reading the rest."""
    with subprocess.Popen(["git", "cat-file", "blob", name], cwd=top, stdout=subprocess.PIPE,
                          stderr=subprocess.DEVNULL) as proc:
        assert proc.stdout is not None
        head = proc.stdout.read(HEAD_BYTES)
        proc.kill()
    return head


def _worktree_content(top: Path, path: str, max_bytes: int, budget: _Budget) -> _Content | None:
    """A file as `git commit -a` would stage it. A symbolic link is its target
    path, as git stores it, and is never followed; anything that is not a
    regular file or a link (a FIFO, a device) is not read at all."""
    full = top / path
    try:
        st = os.lstat(full)
        if stat.S_ISLNK(st.st_mode):
            return _Content(os.fsencode(os.readlink(full)), True)
        if not stat.S_ISREG(st.st_mode):
            return None
        if st.st_size <= max_bytes and budget.take(st.st_size):
            with full.open("rb") as fh:
                data = fh.read(max_bytes + 1)
            return _Content(data, len(data) <= max_bytes)
        with full.open("rb") as fh:
            return _Content(fh.read(HEAD_BYTES), False)
    except OSError:
        return None


def _text_of(content: _Content | None) -> str | None:
    if content is None or not content.whole:
        return None
    text = decode_bytes(content.data)
    return None if text is None else text.removeprefix("﻿")


def _first_line(content: _Content | None) -> str | None:
    if content is None:
        return None
    decoded = decode_bytes(content.data[:HEAD_BYTES])
    return None if decoded is None else decoded.removeprefix("﻿").split("\n", 1)[0].rstrip("\r")


def _introduced(new: list[Finding], old: list[Finding], new_text: str, old_text: str) -> set[int]:
    """Findings the new version has that the old one did not: the ids of those
    in `new` left over once each is matched to an old finding of the same
    category and value. A finding can be new on a line the change never
    touched: rows that a new header makes into a patient table, a resource
    that new evidence makes into a FHIR Patient."""
    remaining = Counter((f.category, old_text[f.start:f.end]) for f in old)
    fresh = set()
    for f in new:
        key = (f.category, new_text[f.start:f.end])
        if remaining[key]:
            remaining[key] -= 1
        else:
            fresh.add(id(f))
    return fresh


def _member_of(ids: set[int]) -> Callable[[Finding], bool]:
    return lambda f: id(f) in ids


def _from_added_lines(added: list[tuple[int, str]], head: str | None, cfg: Config) -> Verdict:
    """A change judged from its added lines alone, read under the file's first
    line, which is where a table's header is. For a file too large to read
    whole within max_bytes and the read budget, or one that is not text."""
    rows = ([(1, head)] if head is not None and added[0][0] != 1 else []) + added
    text = "\n".join(t for _, t in rows)
    findings = _findings(text, cfg, [n for n, _ in rows])
    first_added = len(rows) - len(added)
    starts = _line_index(text)
    added_from = starts[first_added] if first_added < len(starts) else len(text)
    return evaluate(findings, cfg.record_window, changed=lambda f: f.end > added_from)


def _lfs_object(top: Path, data: bytes) -> Path | None:
    m = _LFS_POINTER.match(data)
    if m is None:
        return None
    oid = m.group(1).decode()
    try:
        common = Path(_git(["rev-parse", "--git-common-dir"], top).strip())
    except (RuntimeError, OSError, subprocess.TimeoutExpired):
        return Path("/nonexistent")
    common = common if common.is_absolute() else top / common
    return common / "lfs" / "objects" / oid[:2] / oid[2:4] / oid


def _scan_lfs(cfg: Config, top: Path, path: str, data: bytes) -> FileResult | None:
    """A file stored with git-lfs: git holds a pointer, and the content that
    leaves with a push is the object it names. That object is scanned whole."""
    obj = _lfs_object(top, data)
    if obj is None:
        return None
    rel = cfg.relpath(top / path)
    if obj.is_file():
        result = scan_file(obj, cfg)
        result.path, result.note = rel, "git-lfs object"
        return result
    note = "git-lfs object not in this clone, not inspected"
    if cfg.opaque == "block":
        return FileResult(rel, Verdict(BLOCK, [], [f"{note} (opaque = block)"]), "opaque")
    return FileResult(rel, Verdict(ALLOW), note, skipped=True)


def _changed_paths(top: Path, staged: bool) -> tuple[list[str], list[str]]:
    """(text, binary) paths added, copied or modified, renames counted as new
    files. Text paths include those with deletions only: removing the blank
    line between a header and its rows makes a table out of both."""
    args = ["diff", *(["--cached"] if staged else []), "--numstat", "-z", "--no-renames", "--diff-filter=ACM"]
    text: list[str] = []
    binary: list[str] = []
    for record in _git(args, top).split("\0"):
        fields = record.split("\t", 2)
        if len(fields) == 3 and fields[2]:
            (binary if fields[0] == "-" else text).append(fields[2])
    return text, binary


def _scan_changes(cfg: Config, top: Path, staged: bool) -> list[FileResult]:
    """Every text file the change touches, judged by the findings it
    introduces: the new version is scanned whole, so an added line is read
    with the header or name that gives it meaning, and compared with the old
    one, so PHI the file already held is not reported again."""
    text_paths, _binary = _changed_paths(top, staged)
    budget = _Budget(READ_BUDGET_FILES * cfg.max_bytes)
    results: list[FileResult] = []
    todo = []
    for path in text_paths:
        if cfg.is_allowed_path(top / path):
            results.append(FileResult(cfg.relpath(top / path), Verdict(ALLOW), "allowlisted path", skipped=True))
        else:
            todo.append(path)
    if not todo:
        return results
    if staged:
        new_side = _read_objects(top, [f":{p}" for p in todo], cfg.max_bytes, budget)
        new = {p: new_side.get(f":{p}") for p in todo}
    else:
        new = {p: _worktree_content(top, p, cfg.max_bytes, budget) for p in todo}
    base = "HEAD:" if staged else ":"
    old_side = _read_objects(top, [f"{base}{p}" for p in todo], cfg.max_bytes, budget)
    added = added_lines_by_file(_git(["diff", *(["--cached"] if staged else []), *DIFF_FLAGS], top))
    for path in todo:
        rel = cfg.relpath(top / path)
        content = new.get(path)
        if content is not None:
            lfs = _scan_lfs(cfg, top, path, content.data)
            if lfs is not None:
                results.append(lfs)
                continue
        new_text = _text_of(content)
        old_content = old_side.get(f"{base}{path}")
        old_text = _text_of(old_content) if old_content is not None else ""
        if new_text is not None and old_text is not None:
            findings = _findings(new_text, cfg)
            fresh = _introduced(findings, _findings(old_text, cfg), new_text, old_text)
            verdict = evaluate(findings, cfg.record_window, changed=_member_of(fresh))
            results.append(FileResult(rel, verdict))
        elif added.get(path):
            results.append(FileResult(rel, _from_added_lines(added[path], _first_line(content), cfg), "added lines"))
    return results


def _binary_paths(top: Path, staged: bool) -> list[str]:
    """Changed files git treats as binary. They have no added lines in a diff,
    and that is every spreadsheet, archive, database and UTF-16 export."""
    return _changed_paths(top, staged)[1]


def _scan_staged_blob(cfg: Config, top: Path, path: str) -> FileResult:
    """Scan what the commit would contain, which can differ from the working tree."""
    full = top / path
    rel = cfg.relpath(full)
    if cfg.is_allowed_path(full):
        return FileResult(rel, Verdict(ALLOW), "allowlisted path", skipped=True)
    size = int(_git(["cat-file", "-s", f":{path}"], top))
    if size > cfg.max_bytes:
        reason = f"staged file is {size} bytes, over max_bytes={cfg.max_bytes}; not scanned"
        return FileResult(rel, Verdict(BLOCK, [], [reason]), "oversize")
    blob = subprocess.run(["git", "cat-file", "blob", f":{path}"], cwd=top, capture_output=True, timeout=15)
    if blob.returncode != 0:
        return FileResult(rel, Verdict(BLOCK, [], ["cannot read staged file; not inspected"]), "unreadable")
    with tempfile.TemporaryDirectory(prefix="phi-gate-") as tmp:
        copy = Path(tmp) / Path(path).name
        copy.write_bytes(blob.stdout)
        result = scan_file(copy, cfg)
    result.path = rel
    return result


def _scan_staged(cfg: Config, top: Path) -> list[FileResult]:
    results = _scan_changes(cfg, top, staged=True)
    return results + [_scan_staged_blob(cfg, top, p) for p in _binary_paths(top, staged=True)]


def _scan_unstaged(cfg: Config, top: Path) -> list[FileResult]:
    results = _scan_changes(cfg, top, staged=False)
    return results + [scan_file(top / p, cfg) for p in _binary_paths(top, staged=False)]


def scan_git_diff(cfg: Config, cwd: Path, staged: bool = True) -> list[FileResult]:
    top = git_toplevel(cwd)
    if top is None:
        raise RuntimeError("not a git repository")
    return _scan_staged(cfg, top) if staged else _scan_unstaged(cfg, top)


def scan_commit(cfg: Config, cwd: Path, broad: bool) -> list[FileResult]:
    """What a commit about to run could include. `broad` covers commands that
    stage files first (`git add -A && git commit`, `git commit -a`): unstaged
    changes and untracked files are checked too."""
    top = git_toplevel(cwd)
    if top is None:
        return []
    results = _scan_staged(cfg, top)
    if broad:
        results += _scan_unstaged(cfg, top)
        untracked = [u for u in _git(["ls-files", "-o", "--exclude-standard", "-z"], top).split("\0") if u]
        if len(untracked) > MAX_UNTRACKED:
            results.append(FileResult(
                "untracked files",
                Verdict(BLOCK, [], [f"there are {len(untracked)} untracked files, too many to check before "
                                    "`git add`; stage specific paths instead"]),
            ))
        else:
            results += [scan_file(top / u, cfg) for u in untracked]
    return results


def worst(results: list[FileResult]) -> str:
    if any(r.verdict.decision == BLOCK for r in results):
        return BLOCK
    if any(r.verdict.decision == WARN for r in results):
        return WARN
    return ALLOW


__all__ = [
    "FileResult", "Unreadable", "scan_text", "scan_file", "scan_git_diff", "scan_commit", "iter_files", "walk",
    "added_lines_by_file", "worst", "decode_bytes", "archive_text", "sqlite_text", "read_text", "LOW", "MEDIUM",
    "MAX_DIR_FILES",
]
