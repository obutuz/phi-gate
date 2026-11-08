"""Reversible, typed redaction.

`redact("DOB: <a date>, SSN <an SSN>")` returns
`"DOB: [DOB_1], SSN [SSN_1]"` plus a mapping from placeholder to original
value. The same value always gets the same placeholder within one call, so
relationships survive ("[PERSON_NAME_1] called back about [MRN_1]").

A placeholder is never one that the input already contains as literal text:
numbering skips any `[NAME_N]` already present. `restore` substitutes only the
placeholders in its mapping, in one pass, so it cannot write a value where
the document had only text.

The mapping contains the original PHI. Keep it local and never commit it.
"""

from __future__ import annotations

import bisect
import re

from .config import Config
from .detectors import (
    DIRECT,
    FIRST_NAME_COLUMNS,
    HIGH,
    LAST_NAME_COLUMNS,
    LOW,
    QUASI_COLUMNS,
    SEVERITY_RANK,
    Finding,
    Table,
    cell_spans,
    detect,
    find_tables,
    is_direct_column,
    is_rule_row,
    normalize,
)

# Columns that describe care or an organisation rather than a person. Safe
# Harbor removes identifiers; this content can stay, which is what keeps a
# redacted export useful ("group denials by diagnosis").
_KEEP_COLUMNS = frozenset({"diagnosis", "dx", "icd10", "icd_10", "icd10_code", "diagnosis_code"})
_KEEP_TOKENS = frozenset({"payer", "plan", "provider", "facility", "clinic", "carrier", "organization"})

# Words that mark a column as identifying someone. This list errs on the side
# of redacting: the cost of a false match is one less useful column.
_IDENTIFIER_TOKENS = frozenset({
    "name", "first", "last", "given", "family", "surname", "patient", "pt", "client", "member", "mbr",
    "subscriber", "insured", "beneficiary", "guarantor", "contact", "address", "address1", "address2",
    "street", "city", "zip", "zipcode", "postal", "phone", "mobile", "fax", "email", "ssn", "dob", "mrn",
    "mbi", "hicn", "birth", "birthdate", "account", "acct", "policy", "medicaid", "medicare", "claim",
    "encounter", "note", "notes", "comment", "comments", "memo", "narrative",
})

_PLACEHOLDER_TOKEN = re.compile(r"\[[A-Z][A-Z0-9_]*_\d+\]")


def is_identifier_column(col: str) -> bool:
    """Whether redaction removes a column's values. A column that identifies
    someone on its own always goes, even when it also names a payer or plan."""
    if is_direct_column(col):
        return True
    if col in _KEEP_COLUMNS:
        return False
    tokens = set(col.split("_"))
    if tokens & _KEEP_TOKENS:
        return False
    return col in FIRST_NAME_COLUMNS or col in LAST_NAME_COLUMNS or col in QUASI_COLUMNS or bool(tokens & _IDENTIFIER_TOKENS)


def _value_bounds(text: str, a: int, b: int) -> tuple[int, int]:
    """A cell's value without its padding or quotes, so they survive."""
    while a < b and text[a] in ' \t"':
        a += 1
    while b > a and text[b - 1] in ' \t"':
        b -= 1
    return a, b


def _cell_finding(text: str, a: int, b: int, category: str) -> Finding | None:
    """A finding for a cell's value, or None for an empty cell."""
    a, b = _value_bounds(text, a, b)
    return Finding(category, HIGH, DIRECT, a, b) if a < b else None


# A table row redacted column by column: its offsets and its cells' offsets.
_Row = tuple[int, int, list[tuple[int, int]]]


def _table_cells(text: str, table: Table) -> tuple[list[Finding], list[_Row]]:
    """Turn one table into per-cell findings for identifier columns, so the
    redacted table keeps its shape and its non-identifying columns. A row that
    does not line up with the header cannot be trusted column by column, so
    all of it goes. Also returns the rows handled cell by cell."""
    cols = table.header.columns
    targets = [i for i, c in enumerate(cols) if is_identifier_column(c)]
    if not targets:
        return [Finding("tabular_phi", HIGH, DIRECT, table.start, table.end)], []
    cells: list[Finding] = []
    rows: list[_Row] = []
    for start, end in table.rows:
        row = text[start:end]
        if is_rule_row(row):
            continue
        spans = cell_spans(row, table.header.delimiter)
        if len(spans) != len(cols):
            found = _cell_finding(text, start, end, "row")
            cells += [found] if found else []
            continue
        rows.append((start, end, [(start + a, start + b) for a, b in spans]))
        for idx in targets:
            a, b = spans[idx]
            found = _cell_finding(text, start + a, start + b, cols[idx])
            cells += [found] if found else []
    return cells, rows


def _piece(text: str, f: Finding, a: int, b: int) -> list[Finding]:
    """The part of `f` in [a, b) without surrounding whitespace, if any."""
    while a < b and text[a].isspace():
        a += 1
    while b > a and text[b - 1].isspace():
        b -= 1
    return [Finding(f.category, f.severity, f.group, a, b)] if a < b else []


def _within_cells(text: str, f: Finding, rows: list[_Row]) -> list[Finding]:
    """A finding that overlaps table rows, cut at the cell boundaries: every
    cell it touches goes whole, and the delimiters and line breaks stay, so
    each row keeps its width and the rest of its columns stay readable."""
    k = max(bisect.bisect_right(rows, (f.start, float("inf"))) - 1, 0)
    out: list[Finding] = []
    cursor = f.start
    while k < len(rows) and rows[k][0] < f.end:
        start, end, cells = rows[k]
        k += 1
        if end <= f.start:
            continue
        out += _piece(text, f, cursor, start)
        for a, b in cells:
            if a < f.end and f.start < b:
                out += _piece(text, f, *_value_bounds(text, a, b))
        cursor = max(cursor, end)
    return out + _piece(text, f, cursor, f.end)


def _select(findings: list[Finding], include_low: bool) -> list[Finding]:
    """Non-overlapping spans to replace. Overlapping findings merge into one
    span covering both, so no part of either value is left behind; it takes
    the category of the wider finding, or the more severe one on a tie."""
    chosen: list[Finding] = []
    for f in sorted(findings, key=lambda f: (f.start, -(f.end - f.start), -SEVERITY_RANK[f.severity])):
        if f.severity == LOW and not include_low:
            continue
        if chosen and f.start < chosen[-1].end:
            prev = chosen[-1]
            wider = (f.end - f.start, SEVERITY_RANK[f.severity]) > (prev.end - prev.start, SEVERITY_RANK[prev.severity])
            kind = f if wider else prev
            chosen[-1] = Finding(kind.category, kind.severity, kind.group, prev.start, max(prev.end, f.end))
            continue
        chosen.append(f)
    return chosen


def _findings(text: str, cfg: Config | None) -> list[Finding]:
    """Findings in original-text offsets, with tables split into cells."""
    disabled = frozenset(cfg.disable) if cfg else frozenset()
    view = normalize(text)
    found = detect(view.text, disabled)
    tables = {(t.start, t.end): t for t in find_tables(view.text)} if any(
        f.category == "tabular_phi" for f in found
    ) else {}
    kept = []
    for f in found:
        s, e = view.to_original(f.start, f.end)
        if not (cfg and cfg.allow_values and cfg.is_allowed_value(text[s:e])):
            kept.append(f)
    parts: list[Finding] = []
    rows: list[_Row] = []
    for f in kept:
        table = tables.get((f.start, f.end)) if f.category == "tabular_phi" else None
        if table is not None:
            cells, table_rows = _table_cells(view.text, table)
            parts += cells
            rows += table_rows
    rows.sort()
    for f in kept:
        if f.category == "tabular_phi" and (f.start, f.end) in tables:
            continue
        parts += _within_cells(view.text, f, rows) if rows else [f]
    out: list[Finding] = []
    for part in parts:
        ps, pe = view.to_original(part.start, part.end)
        out.append(Finding(part.category, part.severity, part.group, ps, pe))
    return out


def redact(text: str, cfg: Config | None = None, include_low: bool = False) -> tuple[str, dict[str, str]]:
    """A copy of `text` with every finding replaced by a typed placeholder,
    and the mapping from placeholder to original value. LOW findings stay
    unless `include_low`."""
    chosen = _select(_findings(text, cfg), include_low)
    literal = set(_PLACEHOLDER_TOKEN.findall(text))

    by_value: dict[tuple[str, str], str] = {}
    counters: dict[str, int] = {}
    mapping: dict[str, str] = {}
    out: list[str] = []
    cursor = 0
    for f in chosen:
        value = text[f.start:f.end]
        key = (f.category, value)
        if key not in by_value:
            label = f.category.upper()
            placeholder = ""
            while not placeholder or placeholder in literal:
                counters[label] = counters.get(label, 0) + 1
                placeholder = f"[{label}_{counters[label]}]"
            by_value[key] = placeholder
            mapping[placeholder] = value
        out.append(text[cursor:f.start])
        out.append(by_value[key])
        cursor = f.end
    out.append(text[cursor:])
    return "".join(out), mapping


def restore(text: str, mapping: dict[str, str]) -> str:
    """Put the original values back. Only the placeholders in `mapping` are
    replaced, in a single pass, so a restored value that happens to contain
    placeholder-like text is never substituted again."""
    if not mapping:
        return text
    pattern = re.compile("|".join(re.escape(p) for p in sorted(mapping, key=len, reverse=True)))
    return pattern.sub(lambda m: mapping[m.group(0)], text)
