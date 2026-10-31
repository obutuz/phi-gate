"""Reversible, typed redaction.

`redact("DOB: <a date>, SSN <an SSN>")` returns
`"DOB: [DOB_1], SSN [SSN_1]"` plus a mapping from placeholder to original
value. The same value always gets the same placeholder within one call, so
relationships survive ("[PERSON_NAME_1] called back about [MRN_1]").

The mapping contains the original PHI. Keep it local and never commit it.
"""

from __future__ import annotations

from .config import Config
from .detectors import (
    _FIRST,
    _LAST,
    _QUASI,
    _RULE_ROW,
    DIRECT,
    HIGH,
    LOW,
    SEVERITY_RANK,
    Finding,
    _norm_col,
    cell_spans,
    header_delimiter,
    is_direct_column,
    logical_rows,
    run_detectors,
)

# Columns that describe care or an organisation rather than a person. Safe
# Harbor removes identifiers; this content can stay, which is what keeps a
# redacted export useful ("group denials by diagnosis").
_KEEP_COLUMNS = {"diagnosis", "dx", "icd10", "icd_10", "icd10_code", "diagnosis_code"}
_KEEP_TOKENS = {"payer", "plan", "provider", "facility", "clinic", "carrier", "organization"}

# Words that mark a column as identifying someone. This list errs on the side
# of redacting: the cost of a false match is one less useful column.
_IDENTIFIER_TOKENS = {
    "name", "patient", "client", "member", "subscriber", "insured", "beneficiary",
    "guarantor", "contact", "address", "address1", "address2", "street", "city", "zip", "zipcode",
    "postal", "phone", "mobile", "fax", "email", "ssn", "dob", "mrn", "mbi", "birth", "birthdate",
    "note", "notes", "comment", "comments", "memo", "narrative",
}


def is_identifier_column(col: str) -> bool:
    if col in _KEEP_COLUMNS:
        return False
    tokens = set(col.split("_"))
    if tokens & _KEEP_TOKENS:
        return False
    return is_direct_column(col) or col in _FIRST or col in _LAST or col in _QUASI or bool(tokens & _IDENTIFIER_TOKENS)


def _cell_finding(row: str, offset: int, span: tuple[int, int], category: str) -> Finding | None:
    """The cell's value without its padding or quotes, so they survive."""
    a, b = span
    while a < b and row[a] in ' \t"':
        a += 1
    while b > a and row[b - 1] in ' \t"':
        b -= 1
    return Finding(category, HIGH, DIRECT, offset + a, offset + b) if a < b else None


def _table_cells(text: str, f: Finding) -> list[Finding]:
    """Turn one tabular finding into per-cell findings for identifier columns,
    so the redacted table keeps its shape and its non-identifying columns. A
    row that does not line up with the header cannot be trusted column by
    column, so all of it goes."""
    header_end = text.rfind("\n", 0, f.start)
    header_start = text.rfind("\n", 0, max(header_end, 0)) + 1
    header = text[header_start:max(header_end, 0)].rstrip("\r")
    delim = header_delimiter(header)
    if delim is None:
        return [f]
    cols = [_norm_col(header[a:b]) for a, b in cell_spans(header, delim)]
    targets = {i for i, c in enumerate(cols) if is_identifier_column(c)}
    if not targets:
        return [f]
    lines = text[f.start:f.end].splitlines(keepends=True)
    offsets = [f.start]
    for line in lines:
        offsets.append(offsets[-1] + len(line))
    cells: list[Finding] = []
    for first, last in logical_rows(lines, 0, len(lines)):
        row = "".join(lines[first:last + 1]).rstrip("\r\n")
        if _RULE_ROW.match(row):
            continue
        spans = cell_spans(row, delim)
        if len(spans) != len(cols):
            found = _cell_finding(row, offsets[first], (0, len(row)), "row")
            cells += [found] if found else []
            continue
        for idx in targets:
            found = _cell_finding(row, offsets[first], spans[idx], cols[idx])
            cells += [found] if found else []
    return cells


def _select(findings: list[Finding], include_low: bool) -> list[Finding]:
    chosen: list[Finding] = []
    for f in sorted(findings, key=lambda f: (f.start, -(f.end - f.start), -SEVERITY_RANK[f.severity])):
        if f.severity == LOW and not include_low:
            continue
        if chosen and f.start < chosen[-1].end:
            prev = chosen[-1]
            # keep the wider span, or the more severe one on a tie
            if (f.end - f.start, SEVERITY_RANK[f.severity]) > (prev.end - prev.start, SEVERITY_RANK[prev.severity]):
                chosen[-1] = f
            continue
        chosen.append(f)
    return chosen


def redact(text: str, cfg: Config | None = None, include_low: bool = False) -> tuple[str, dict[str, str]]:
    disabled = frozenset(cfg.disable) if cfg else frozenset()
    findings = run_detectors(text, disabled)
    if cfg and cfg.allow_values:
        findings = [f for f in findings if not cfg.is_allowed_value(text[f.start:f.end])]
    expanded: list[Finding] = []
    for f in findings:
        expanded += _table_cells(text, f) if f.category == "tabular_phi" else [f]
    chosen = _select(expanded, include_low)

    by_value: dict[tuple[str, str], str] = {}
    counters: dict[str, int] = {}
    mapping: dict[str, str] = {}
    out: list[str] = []
    cursor = 0
    for f in chosen:
        value = text[f.start:f.end]
        key = (f.category, value)
        if key not in by_value:
            counters[f.category] = counters.get(f.category, 0) + 1
            placeholder = f"[{f.category.upper()}_{counters[f.category]}]"
            by_value[key] = placeholder
            mapping[placeholder] = value
        out.append(text[cursor:f.start])
        out.append(by_value[key])
        cursor = f.end
    out.append(text[cursor:])
    return "".join(out), mapping


def restore(text: str, mapping: dict[str, str]) -> str:
    for placeholder in sorted(mapping, key=len, reverse=True):
        text = text.replace(placeholder, mapping[placeholder])
    return text
