"""Reversible, typed redaction.

`redact("DOB: <a date>, SSN <an SSN>")` returns
`"DOB: [DOB_1], SSN [SSN_1]"` plus a mapping from placeholder to original
value. The same value always gets the same placeholder within one call, so
relationships survive ("[PERSON_NAME_1] called back about [MRN_1]").

The mapping contains the original PHI. Keep it local and never commit it.
"""

from __future__ import annotations

from .config import Config
from .detectors import LOW, SEVERITY_RANK, Finding, run_detectors


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
    chosen = _select(findings, include_low)

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
