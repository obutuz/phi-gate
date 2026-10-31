"""Pattern-based PHI/PII detectors.

Design rule: a Finding never carries the matched value. Anything that needs
the value (redaction) slices it from the original text itself, so findings
can be printed, logged, or serialized without leaking what they found.

Each detector returns character spans. Labelled detectors (for example
"DOB: <date>") return the span of the value only, not the label, so that
redaction keeps the surrounding text readable.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Callable, Iterator

HIGH = "high"
MEDIUM = "medium"
LOW = "low"
SEVERITY_RANK = {LOW: 0, MEDIUM: 1, HIGH: 2}

# Groups drive the record-likeness rule in policy.py.
DIRECT = "direct"  # identifies a person on its own (SSN, MRN, DOB...)
PERSON = "person"  # a person's name in a labelled field
CLINICAL = "clinical"  # diagnosis codes, dates of service
CONTACT = "contact"  # phone, email, street address
PROVIDER = "provider"  # provider identifiers (NPI, DEA): not PHI on their own
NETWORK = "network"  # IP addresses

Span = tuple[int, int]
Finder = Callable[[str], Iterator[Span]]


@dataclass(frozen=True)
class Detector:
    name: str
    severity: str
    group: str
    description: str
    find: Finder


@dataclass(frozen=True)
class Finding:
    category: str
    severity: str
    group: str
    start: int
    end: int
    line: int = 0
    col: int = 0

    def to_dict(self) -> dict:
        return {
            "category": self.category,
            "severity": self.severity,
            "group": self.group,
            "line": self.line,
            "col": self.col,
        }


# --------------------------------------------------------------------------
# Validators
# --------------------------------------------------------------------------


def luhn_ok(digits: str) -> bool:
    if not digits.isdigit():
        return False
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def npi_ok(value: str) -> bool:
    """NPI check digit: Luhn over the number prefixed with 80840."""
    return len(value) == 10 and value[0] in "12" and luhn_ok("80840" + value)


def dea_ok(value: str) -> bool:
    digits = value[2:]
    if len(digits) != 7 or not digits.isdigit():
        return False
    d = [int(c) for c in digits]
    check = (d[0] + d[2] + d[4]) + 2 * (d[1] + d[3] + d[5])
    return check % 10 == d[6]


def ssn_area_ok(area: str, group: str, serial: str) -> bool:
    # 000, 666 and 900-999 are never issued. Treat them as synthetic so that
    # test data (Synthea uses 999-xx-xxxx) passes without allowlisting.
    if area in ("000", "666") or area[0] == "9":
        return False
    return group != "00" and serial != "0000"


# Publicly documented processor test card numbers: synthetic by definition.
TEST_CARDS = {
    "4242424242424242",
    "4111111111111111",
    "4012888888881881",
    "4000056655665556",
    "5555555555554444",
    "5105105105105100",
    "2223003122003222",
    "378282246310005",
    "371449635398431",
    "6011111111111117",
    "6011000990139424",
    "3056930009020004",
    "36227206271667",
    "3566002020360505",
}


def card_ok(raw: str) -> bool:
    digits = re.sub(r"[ -]", "", raw)
    if not (13 <= len(digits) <= 19) or digits in TEST_CARDS:
        return False
    if not re.match(r"^(4|5[1-5]|2[2-7]|3[47]|6011|65|3[068]|35)", digits):
        return False
    if len(set(digits)) <= 2:  # 4444 4444 ... style filler
        return False
    return luhn_ok(digits)


TOLL_FREE = {"800", "833", "844", "855", "866", "877", "888"}

SAFE_EMAIL_DOMAINS = re.compile(
    r"(?:^|\.)(?:example\.(?:com|org|net)|example|test|invalid|localhost|"
    r"users\.noreply\.github\.com|noreply\.github\.com)$",
    re.I,
)


ORG_WORDS = {
    "inc", "llc", "ltd", "corp", "co", "company", "group", "partners", "labs",
    "health", "healthcare", "care", "services", "solutions", "financial",
    "medical", "clinic", "center", "centre", "hospital", "agency", "therapy",
    "pharmacy", "supply", "systems", "technologies", "foundation", "network",
}


def not_org_name(value: str) -> bool:
    last = re.split(r"[\s,]+", value.strip())[-1].lower().strip(".")
    return last not in ORG_WORDS


def has_digit(value: str) -> bool:
    return any(ch.isdigit() for ch in value)


# --------------------------------------------------------------------------
# Finder helpers
# --------------------------------------------------------------------------


def regex_finder(
    pattern: str,
    flags: int = 0,
    group: int | str = 0,
    validate: Callable[[re.Match], bool] | None = None,
) -> Finder:
    rx = re.compile(pattern, flags)

    def find(text: str) -> Iterator[Span]:
        for m in rx.finditer(text):
            if validate is not None and not validate(m):
                continue
            s, e = m.span(group)
            if s < e:
                yield (s, e)

    return find


MONTHS = r"(?:jan|feb|mar|apr|may|jun|jul|aug|sep|sept|oct|nov|dec)[a-z]*\.?"
DATE = (
    r"(?:\d{1,2}[/.-]\d{1,2}[/.-](?:\d{4}|\d{2})"
    r"|\d{4}-\d{1,2}-\d{1,2}"
    r"|(?:19|20)\d{6}"
    rf"|{MONTHS}\s+\d{{1,2}},?\s+\d{{4}}"
    rf"|\d{{1,2}}\s+{MONTHS},?\s+\d{{4}})"
)
# Separator between a label and its value: handles `DOB: x`, `dob = "x"`,
# `"birthDate": "x"` and `'dob': 'x'`.
SEP = r"""["']?\s*[:=#]?\s*["']?\s*"""

NAME = r"[A-Z][a-z'\-]+(?:\s+[A-Z]\.?)?(?:\s+[A-Z][a-z'\-]+){1,2}|[A-Z][a-z'\-]+,\s*[A-Z][a-z'\-]+"

US_STATES = (
    "AL|AK|AZ|AR|CA|CO|CT|DE|DC|FL|GA|HI|ID|IL|IN|IA|KS|KY|LA|ME|MD|MA|MI|MN|MS|"
    "MO|MT|NE|NV|NH|NJ|NM|NY|NC|ND|OH|OK|OR|PA|RI|SC|SD|TN|TX|UT|VT|VA|WA|WV|WI|WY|PR"
)
STREET_SUFFIX = (
    "Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Court|Ct|Way|"
    "Place|Pl|Terrace|Ter|Parkway|Pkwy|Circle|Cir|Highway|Hwy"
)

MBI_L = "AC-HJKMNP-RT-Y"  # letters allowed in an MBI (no S, L, O, I, B, Z)


def _ssn_valid(m: re.Match) -> bool:
    return ssn_area_ok(m.group("a"), m.group("g"), m.group("s"))


def _ssn_bare_valid(m: re.Match) -> bool:
    v = m.group("v")
    return ssn_area_ok(v[:3], v[3:5], v[5:])


def _phone_valid(m: re.Match) -> bool:
    area = m.group("area1") or m.group("area2")
    exch, line = m.group("exch"), m.group("line")
    if area in TOLL_FREE:
        return False
    if exch == "555" and 100 <= int(line) <= 199:  # reserved fictional range
        return False
    return True


def _email_valid(m: re.Match) -> bool:
    return not SAFE_EMAIL_DOMAINS.search(m.group("domain"))


def _ip_valid(m: re.Match) -> bool:
    try:
        ip = ipaddress.ip_address(m.group(0))
    except ValueError:
        return False
    return ip.is_global


def _group_has_digit(name: str) -> Callable[[re.Match], bool]:
    return lambda m: has_digit(m.group(name))


# --------------------------------------------------------------------------
# Structured-format detectors
# --------------------------------------------------------------------------

_DIRECT_COLUMNS = {
    "ssn", "social_security_number", "social_security", "ss_number",
    "dob", "date_of_birth", "birth_date", "birthdate",
    "mrn", "medical_record_number", "medical_record_no", "chart_number",
    "member_id", "subscriber_id", "medicaid_id", "medicare_id", "mbi",
    "medicaid_number", "medicare_number", "insurance_id", "policy_number",
    "patient_name", "patient_full_name", "client_name", "beneficiary_name",
    "insured_name", "patient_id", "client_id_number",
}
_FIRST = {"first_name", "firstname", "fname", "given_name", "patient_first_name"}
_LAST = {"last_name", "lastname", "lname", "family_name", "surname", "patient_last_name"}
_QUASI = {
    "diagnosis", "dx", "icd10", "icd_10", "icd10_code", "diagnosis_code",
    "address", "street", "street_address", "address1", "address_line_1",
    "phone", "phone_number", "mobile", "email", "zip", "zipcode", "zip_code",
    "date_of_service", "dos", "admit_date", "admission_date", "discharge_date",
}


def _norm_col(col: str) -> str:
    col = re.sub(r"\(.*?\)", "", col.strip().strip("\"'").lower())  # "DOB (mm/dd/yyyy)" -> "dob"
    return re.sub(r"[^a-z0-9]+", "_", col).strip("_")


def _split_row(line: str, delim: str) -> list[str]:
    return line.split(delim)


_RULE_ROW = re.compile(r"^[\s|:+\-=]*$")
_COLUMN_NAME = re.compile(r"^[a-z][a-z0-9_]{0,40}$")
_PLACEHOLDER = re.compile(r"^\[[A-Z0-9_]+_\d+\]$")
_LIST_ITEM = re.compile(r"^\s*(?:[-*+]|\d+[.)])\s")


def tabular_finder(text: str) -> Iterator[Span]:
    """CSV/TSV/pipe tables whose header names patient identifiers and which
    contain at least one data row."""
    lines = text.splitlines(keepends=True)
    offsets = []
    pos = 0
    for ln in lines:
        offsets.append(pos)
        pos += len(ln)
    i = 0
    n = len(lines)
    while i < n:
        raw = lines[i].rstrip("\r\n")
        delim = None
        for d in (",", "\t", "|", ";"):
            if raw.count(d) >= 2:
                delim = d
                break
        if delim is None:
            i += 1
            continue
        raw_cells = [c for c in _split_row(raw, delim) if c.strip()]
        cells = [_norm_col(c) for c in raw_cells]
        looks_like_header = (
            len(cells) >= 2
            and not _LIST_ITEM.match(raw)
            and all(_COLUMN_NAME.match(c) for c in cells)
            and all(len(c.split()) <= 4 for c in raw_cells)
        )
        if not looks_like_header:  # prose with commas, not a header row
            i += 1
            continue
        cols = set(cells)
        direct = cols & _DIRECT_COLUMNS
        name_pair = bool(cols & _FIRST) and bool(cols & _LAST)
        if not (direct or (name_pair and cols & _QUASI)):
            i += 1
            continue
        width = raw.count(delim)
        j = i + 1
        while j < n and lines[j].strip() and abs(lines[j].count(delim) - width) <= 1:
            j += 1
        rows = lines[i + 1: j]
        all_cols = [_norm_col(c) for c in _split_row(raw, delim)]  # keeps empty edge cells aligned
        id_cols = [k for k, c in enumerate(all_cols) if c in _DIRECT_COLUMNS or c in _FIRST or c in _LAST]

        def live(row: str) -> bool:
            """A data row whose identifier cells hold real values (not placeholders)."""
            if _RULE_ROW.match(row) or not any(ch.isdigit() for ch in row):
                return False
            parts = row.rstrip("\r\n").split(delim)
            vals = [parts[k].strip().strip("\"'") for k in id_cols if k < len(parts)]
            return any(v and not _PLACEHOLDER.match(v) for v in vals) or not id_cols

        if rows and any(live(r) for r in rows):
            start = offsets[i + 1]
            end = offsets[j - 1] + len(lines[j - 1].rstrip("\r\n"))
            yield (start, end)
            i = j
        else:
            i += 1


_FHIR_PATIENT = re.compile(r'"resourceType"\s*:\s*"Patient"')
_FHIR_EVIDENCE = re.compile(r'"birthDate"\s*:\s*"\d|"family"\s*:\s*"[A-Za-z]|"given"\s*:\s*\[\s*"[A-Za-z]')


def fhir_patient_finder(text: str) -> Iterator[Span]:
    for m in _FHIR_PATIENT.finditer(text):
        window = text[max(0, m.start() - 3000): m.end() + 3000]
        if _FHIR_EVIDENCE.search(window):
            yield m.span()


# --------------------------------------------------------------------------
# Registry
# --------------------------------------------------------------------------

DETECTORS: list[Detector] = [
    Detector(
        "ssn", HIGH, DIRECT, "US Social Security number (issued ranges only)",
        regex_finder(r"(?<![\d-])(?P<a>\d{3})-(?P<g>\d{2})-(?P<s>\d{4})(?![\d-])", validate=_ssn_valid),
    ),
    Detector(
        "ssn", HIGH, DIRECT, "Labelled 9-digit SSN",
        regex_finder(
            r"(?i)\b(?:ssn|social\s+security(?:\s+(?:number|no\.?|#))?)" + SEP + r"(?P<v>\d{9})\b",
            group="v", validate=_ssn_bare_valid,
        ),
    ),
    Detector(
        "medicare_mbi", HIGH, DIRECT, "Medicare Beneficiary Identifier",
        regex_finder(
            rf"\b[1-9][{MBI_L}][{MBI_L}0-9]\d-?[{MBI_L}][{MBI_L}0-9]\d-?[{MBI_L}]{{2}}\d{{2}}\b"
        ),
    ),
    Detector(
        "mrn", HIGH, DIRECT, "Labelled medical record / patient / chart number",
        regex_finder(
            r"(?i)\b(?:mrn|medical\s+record(?:\s*(?:number|no\.?|#))?|patient\s*(?:id|#|no\.?|number)"
            r"|chart\s*(?:#|no\.?|number))" + SEP + r"(?P<v>[A-Z0-9][A-Z0-9-]{3,19})\b",
            group="v", validate=_group_has_digit("v"),
        ),
    ),
    Detector(
        "member_id", HIGH, DIRECT, "Labelled health plan member / subscriber / Medicaid ID",
        regex_finder(
            r"(?i)\b(?:member|subscriber|beneficiary|policy(?:holder)?|insurance|medicaid|medicare)"
            r"\s*(?:id|#|no\.?|number)" + SEP + r"(?P<v>[A-Z0-9][A-Z0-9-]{4,19})\b",
            group="v", validate=_group_has_digit("v"),
        ),
    ),
    Detector(
        "dob", HIGH, DIRECT, "Labelled date of birth",
        regex_finder(
            r"(?i)\b(?:dob|d\.o\.b\.?|date\s+of\s+birth|birth\s*date|birthdate|born(?:\s+on)?)"
            + SEP + rf"(?P<v>{DATE})",
            group="v",
        ),
    ),
    Detector(
        "account_number", HIGH, DIRECT, "Labelled financial account number",
        regex_finder(
            r"(?i)\b(?:account|acct|bank\s+account|iban)\s*(?:number|no\.?|#)" + SEP + r"(?P<v>\d[\d -]{5,24}\d)",
            group="v",
        ),
    ),
    Detector(
        "payment_card", HIGH, DIRECT, "Payment card number (Luhn-valid, test cards excluded)",
        regex_finder(r"(?<![\w-])\d(?:[ -]?\d){12,18}(?![\w-])", validate=lambda m: card_ok(m.group(0))),
    ),
    Detector(
        "x12_patient", HIGH, DIRECT, "X12 EDI patient or subscriber name segment (NM1*QC / NM1*IL)",
        regex_finder(r"NM1\*(?:QC|IL)\*1\*[^*~\n]+\*[^~\n]+"),
    ),
    Detector(
        "x12_dob", HIGH, DIRECT, "X12 EDI demographic segment with birth date (DMG*D8)",
        regex_finder(r"DMG\*D8\*\d{8}"),
    ),
    Detector(
        "hl7_pid", HIGH, DIRECT, "HL7 v2 PID segment with a patient name",
        regex_finder(r"(?m)^PID\|[^\r\n]*\^[^\r\n]*$"),
    ),
    Detector("fhir_patient", HIGH, DIRECT, "FHIR Patient resource with name or birthDate", fhir_patient_finder),
    Detector("tabular_phi", HIGH, DIRECT, "Delimited table with patient identifier columns and data rows", tabular_finder),
    Detector(
        "person_name", HIGH, PERSON, "Patient/member/client name in a labelled field",
        regex_finder(
            r"\b(?i:patient|pt|client|member|beneficiary|resident|insured|subscriber|guarantor)(?:'s)?"
            r"\s*_?(?i:full\s*_?)?(?i:name)" + SEP + rf"(?P<v>{NAME})",
            group="v", validate=lambda m: not_org_name(m.group("v")),
        ),
    ),
    Detector(
        "person_name", MEDIUM, PERSON, "Generic labelled full name",
        regex_finder(
            r"\b(?i:full\s*_?name|name)" + SEP + rf"(?P<v>{NAME})",
            group="v", validate=lambda m: not_org_name(m.group("v")),
        ),
    ),
    Detector(
        "diagnosis", MEDIUM, CLINICAL, "Labelled ICD-10 diagnosis code",
        regex_finder(
            r"(?i)\b(?:dx|diagnosis|diag|icd-?10)(?:\s*code)?" + SEP
            + r"(?P<v>(?-i:[A-TV-Z]\d[0-9AB](?:\.[0-9A-TV-Z]{1,4})?))\b",
            group="v",
        ),
    ),
    Detector(
        "clinical_date", MEDIUM, CLINICAL, "Labelled admission, discharge, service or death date",
        regex_finder(
            r"(?i)\b(?:date\s+of\s+service|dos|admi(?:t|ssion)\s+date|discharge\s+date|date\s+of\s+death|dod)"
            + SEP + rf"(?P<v>{DATE})",
            group="v",
        ),
    ),
    Detector(
        "phone", MEDIUM, CONTACT, "US phone number (toll-free and 555-01xx excluded)",
        regex_finder(
            r"(?<![\w.-])(?:\+?1[\s.-]?)?(?:\((?P<area1>[2-9]\d{2})\)\s?|(?P<area2>[2-9]\d{2})[.-])"
            r"(?P<exch>[2-9]\d{2})[.-](?P<line>\d{4})(?![\w-])",
            validate=_phone_valid,
        ),
    ),
    Detector(
        "email", MEDIUM, CONTACT, "Email address (example/test domains excluded)",
        regex_finder(r"(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]{1,64}@(?P<domain>[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,})\b", validate=_email_valid),
    ),
    Detector(
        "street_address", MEDIUM, CONTACT, "Street address",
        regex_finder(
            rf"\b\d{{1,6}}\s+(?:[NSEW]\.?\s+)?(?:[A-Z][a-z]+\s+){{1,3}}(?:{STREET_SUFFIX})\b\.?"
            r"(?:,?\s+(?:Apt|Unit|Suite|Ste|#)\.?\s*[\w-]+)?"
        ),
    ),
    Detector(
        "city_state_zip", MEDIUM, CONTACT, "City, state and ZIP code",
        regex_finder(rf"\b[A-Z][a-z]+(?:\s[A-Z][a-z]+){{0,3}},\s*(?:{US_STATES})\s+\d{{5}}(?:-\d{{4}})?\b"),
    ),
    Detector(
        "provider_npi", LOW, PROVIDER, "National Provider Identifier (check digit valid)",
        regex_finder(r"(?<![\d-])[12]\d{9}(?![\d-])", validate=lambda m: npi_ok(m.group(0))),
    ),
    Detector(
        "provider_dea", LOW, PROVIDER, "DEA registration number (checksum valid)",
        regex_finder(r"\b[ABCDEFGHJKLMPRSTUX][A-Z9]\d{7}\b", validate=lambda m: dea_ok(m.group(0))),
    ),
    Detector(
        "ip_address", LOW, NETWORK, "Public IPv4 address",
        regex_finder(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])", validate=_ip_valid),
    ),
]

CATEGORIES = sorted({d.name for d in DETECTORS})


def run_detectors(text: str, disabled: set[str] | frozenset[str] = frozenset()) -> list[Finding]:
    """Run every enabled detector. Line and column are filled in by the scanner."""
    out: list[Finding] = []
    seen: set[tuple[str, int, int]] = set()
    for det in DETECTORS:
        if det.name in disabled:
            continue
        for s, e in det.find(text):
            key = (det.name, s, e)
            if key in seen:
                continue
            seen.add(key)
            out.append(Finding(det.name, det.severity, det.group, s, e))
    out.sort(key=lambda f: (f.start, -SEVERITY_RANK[f.severity]))
    return out
