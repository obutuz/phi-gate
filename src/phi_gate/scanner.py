"""Scan text, files, directories and git changes."""

from __future__ import annotations

import bisect
import codecs
import gzip
import html
import os
import re
import sqlite3
import subprocess
import tempfile
import zipfile
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


def scan_text(text: str, cfg: Config, line_map: list[int] | None = None) -> Verdict:
    findings = run_detectors(text, frozenset(cfg.disable))
    if cfg.allow_values:
        findings = [f for f in findings if not cfg.is_allowed_value(text[f.start:f.end])]
    return evaluate(_locate(findings, text, line_map), cfg.record_window)


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


def walk(root: Path, limit: int) -> list[Path] | None:
    """Files under root, skipping vendored/build dirs. Stops early and returns
    None as soon as there are more than `limit` files."""
    out: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(
            d for d in dirnames
            if d not in SKIP_DIRS and not d.endswith(".egg-info") and os.path.join(dirpath, d) not in SKIP_ABS
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
    res = subprocess.run(
        ["git", "-c", "core.quotepath=off", *args],
        cwd=cwd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=15,
    )
    if res.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)} failed: {res.stderr.strip()}")
    return res.stdout


def git_toplevel(cwd: Path) -> Path | None:
    try:
        return Path(_git(["rev-parse", "--show-toplevel"], cwd).strip())
    except (RuntimeError, OSError):
        return None


_HUNK = re.compile(r"^@@ -\d+(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")


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
            target = line[4:].rstrip("\t")
            current = None if target == "/dev/null" else target[2:] if target.startswith("b/") else target
            if current is not None:
                files.setdefault(current, [])
        elif m := _HUNK.match(line):
            old_left = int(m.group(1) or 1)
            lineno = int(m.group(2))
            new_left = int(m.group(3) or 1)
    return files


DIFF_FLAGS = ["--no-color", "--no-ext-diff", "-U0", "--diff-filter=ACMR"]


def _scan_diff(diff: str, top: Path, cfg: Config) -> list[FileResult]:
    results = []
    for path, added in added_lines_by_file(diff).items():
        if not added:
            continue
        full = top / path
        if cfg.is_allowed_path(full):
            results.append(FileResult(cfg.relpath(full), Verdict(ALLOW), "allowlisted path", skipped=True))
            continue
        text = "\n".join(t for _, t in added)
        results.append(FileResult(cfg.relpath(full), scan_text(text, cfg, [n for n, _ in added])))
    return results


def _binary_paths(top: Path, staged: bool) -> list[str]:
    """Changed files git treats as binary. They have no added lines in a diff,
    and that is every spreadsheet, archive, database and UTF-16 export."""
    args = ["diff", *(["--cached"] if staged else []), "--numstat", "-z", "--no-renames", "--diff-filter=ACM"]
    fields = (record.split("\t", 2) for record in _git(args, top).split("\0"))
    return [f[2] for f in fields if len(f) == 3 and f[0] == "-"]


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
    blob = subprocess.run(["git", "show", f":{path}"], cwd=top, capture_output=True, timeout=15)
    if blob.returncode != 0:
        return FileResult(rel, Verdict(BLOCK, [], ["cannot read staged file; not inspected"]), "unreadable")
    with tempfile.TemporaryDirectory(prefix="phi-gate-") as tmp:
        copy = Path(tmp) / Path(path).name
        copy.write_bytes(blob.stdout)
        result = scan_file(copy, cfg)
    result.path = rel
    return result


def _scan_staged(cfg: Config, top: Path) -> list[FileResult]:
    results = _scan_diff(_git(["diff", "--cached", *DIFF_FLAGS], top), top, cfg)
    return results + [_scan_staged_blob(cfg, top, p) for p in _binary_paths(top, staged=True)]


def _scan_unstaged(cfg: Config, top: Path) -> list[FileResult]:
    results = _scan_diff(_git(["diff", *DIFF_FLAGS], top), top, cfg)
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
