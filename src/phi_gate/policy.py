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

A change to a file (a commit) is judged by what it adds, read in the context
of the whole file: `changed` says which findings the change touched. Only
those block or warn, so a file already holding PHI that was allowed in before
does not block every later edit; but a record pair counts when either side is
new, because a diagnosis added next to a patient's name makes a record even
though the name was there already.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Callable
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


def evaluate(
    findings: list[Finding],
    record_window: int = 400,
    changed: Callable[[Finding], bool] | None = None,
) -> Verdict:
    """The decision for `findings`. With `changed`, only the findings it
    accepts are judged, and the rest are context for the record rule."""
    new = findings if changed is None else [f for f in findings if changed(f)]
    reasons: list[str] = []
    high = [f for f in new if f.severity == HIGH]
    if high:
        reasons.append("direct identifiers: " + ", ".join(sorted({f.category for f in high})))
        return Verdict(BLOCK, new, reasons)

    medium = sorted((f for f in findings if f.severity == MEDIUM), key=lambda f: f.start)
    # An identifier a clinical fact can pair with. A HIGH one has blocked on its
    # own already unless it was in the file before the change, and then it is
    # the strongest identifier a new diagnosis could sit beside.
    identities = [f for f in findings if f.severity == HIGH or (f.severity == MEDIUM and f.group in IDENTITY_GROUPS)]
    fresh = {id(f) for f in new}
    for anchor in medium:
        if anchor.group != CLINICAL:
            continue
        for other in identities:
            if id(anchor) not in fresh and id(other) not in fresh:
                continue
            gap = max(other.start - anchor.end, anchor.start - other.end, 0)
            if gap <= record_window:
                reasons.append(f"record-like: {anchor.category} near {other.category}")
                pair = [f for f in (anchor, other) if id(f) not in fresh]
                return Verdict(BLOCK, new + pair, reasons)

    if any(f.severity == MEDIUM for f in new):
        reasons.append("possible identifiers: " + ", ".join(sorted({f.category for f in new if f.severity == MEDIUM})))
        return Verdict(WARN, new, reasons)
    return Verdict(ALLOW, new, reasons)
