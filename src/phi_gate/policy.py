"""Turn findings into a decision: allow, warn or block.

Rules, in order:
1. Any HIGH finding blocks. These identify a person on their own.
2. A clinical fact (a labelled diagnosis code, a date of service) blocks
   when an identifier (a labelled name, phone, email, address) sits within
   `record_window` characters. PHI is identity plus health information:
   "Jane Doe ... Dx: F84.0" is a patient record.
3. Other MEDIUM findings warn. A name next to an email is a package.json
   author field or a staff directory, not PHI by itself.
4. LOW findings (provider NPI/DEA, public IPs) are reported, never blocking.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field

from .detectors import CLINICAL, CONTACT, HIGH, LOW, MEDIUM, PERSON, Finding

ALLOW, WARN, BLOCK = "allow", "warn", "block"
IDENTITY_GROUPS = (PERSON, CONTACT)


@dataclass
class Verdict:
    decision: str
    findings: list[Finding] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)

    @property
    def blocking(self) -> bool:
        return self.decision == BLOCK

    def counts(self, include_low: bool = False) -> Counter:
        return Counter(
            f.category for f in self.findings if include_low or f.severity != LOW
        )

    def summary(self, include_low: bool = False) -> str:
        c = self.counts(include_low)
        return ", ".join(f"{k} x{v}" for k, v in sorted(c.items())) or "none"

    def lines(self, limit: int = 8) -> str:
        nums = sorted({f.line for f in self.findings if f.severity != LOW and f.line})
        if not nums:
            return ""
        shown = ", ".join(str(n) for n in nums[:limit])
        more = f" (+{len(nums) - limit} more)" if len(nums) > limit else ""
        label = "line" if len(nums) == 1 else "lines"
        return f"{label} {shown}{more}"


def evaluate(findings: list[Finding], record_window: int = 400) -> Verdict:
    reasons: list[str] = []
    high = [f for f in findings if f.severity == HIGH]
    if high:
        reasons.append("direct identifiers: " + ", ".join(sorted({f.category for f in high})))
        return Verdict(BLOCK, findings, reasons)

    medium = sorted((f for f in findings if f.severity == MEDIUM), key=lambda f: f.start)
    for anchor in medium:
        if anchor.group != CLINICAL:
            continue
        for other in medium:
            if other.group not in IDENTITY_GROUPS:
                continue
            gap = max(other.start - anchor.end, anchor.start - other.end, 0)
            if gap <= record_window:
                reasons.append(f"record-like: {anchor.category} near {other.category}")
                return Verdict(BLOCK, findings, reasons)

    if medium:
        reasons.append("possible identifiers: " + ", ".join(sorted({f.category for f in medium})))
        return Verdict(WARN, findings, reasons)
    return Verdict(ALLOW, findings, reasons)
