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
from collections.abc import Callable, Iterator
from dataclasses import dataclass

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
    # Lowercase substrings, at least one of which any match must contain. A
    # substring test is far cheaper than a regex tried at every position, and
    # most source files contain none of these words.
    hints: tuple[str, ...] = ()


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
# Where a label can start. `\b` would miss `patient_dob` (underscore) and
# `patientDob` (a lower-to-upper camelCase step).
LB = r"(?:(?<![A-Za-z0-9])|(?-i:(?<=[a-z])(?=[A-Z])))"
# Between the words of a label: `date of birth`, `date_of_birth`, `dateOfBirth`.
W = r"[\s_-]*"
NUM = r"(?:\#|no\.?|num(?:ber)?)"

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
    v = re.sub(r"\D", "", m.group("v"))
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


# Column types and encodings that follow an id in schemas and code, such as
# `patient_id INT8`. They contain digits but they are not identifiers.
_TYPE_NAME = re.compile(r"(?i)^(?:u?int|float|serial|char|varchar|sha|md|utf|base|uuid|bytea)-?\d*$")


def _id_value(name: str) -> Callable[[re.Match], bool]:
    def valid(m: re.Match) -> bool:
        value = m.group(name)
        return has_digit(value) and not _TYPE_NAME.match(value)

    return valid


# --------------------------------------------------------------------------
# Structured-format detectors
# --------------------------------------------------------------------------

_DIRECT_COLUMNS = {
    "social_security_number", "social_security", "ss_number",
    "date_of_birth", "birth_date", "birthdate",
    "medical_record_number", "medical_record_no", "chart_number",
    "member_id", "member_number", "member_name", "subscriber_id", "subscriber_name",
    "medicaid_id", "medicare_id", "medicaid_number", "medicare_number",
    "insurance_id", "policy_number",
    "patient_name", "patient_full_name", "client_name", "beneficiary_name",
    "insured_name", "patient_id", "client_id_number",
}
# Any column with one of these words, such as `patient_dob` or `ssn_last4`.
_DIRECT_TOKENS = {"ssn", "dob", "mrn", "mbi"}
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


def cell_spans(row: str, delim: str) -> list[tuple[int, int]]:
    """(start, end) of each cell. A delimiter inside double quotes is data."""
    spans = []
    start = 0
    if '"' not in row:
        for piece in row.split(delim):
            spans.append((start, start + len(piece)))
            start += len(piece) + len(delim)
        return spans
    quoted = False
    for i, ch in enumerate(row):
        if ch == '"':
            quoted = not quoted
        elif ch == delim and not quoted:
            spans.append((start, i))
            start = i + 1
    spans.append((start, len(row)))
    return spans


def header_delimiter(row: str) -> str | None:
    return next((d for d in (",", "\t", "|", ";") if d in row), None)


def logical_rows(lines: list[str], start: int, stop: int) -> Iterator[tuple[int, int]]:
    """(first, last) line indexes of each row. A quoted cell can span lines, so
    a line with an unbalanced quote continues on the next one."""
    i = start
    while i < stop:
        last = i
        open_quote = lines[i].count('"') % 2 == 1
        while open_quote and last + 1 < stop and last - i < MAX_ROW_LINES:
            last += 1
            open_quote ^= lines[last].count('"') % 2 == 1
        yield i, last
        i = last + 1


MAX_ROW_LINES = 50
_RULE_ROW = re.compile(r"^[\s|:+\-=]*$")
_COLUMN_NAME = re.compile(r"^[a-z][a-z0-9_]{0,40}$")
_PLACEHOLDER = re.compile(r"^\[[A-Z0-9_]+_\d+\]$")
_LIST_ITEM = re.compile(r"^\s*(?:[-*+]|\d+[.)])\s")
_PERSON_NAME = re.compile(rf"(?:{NAME})$")
# A tuple, or a line of a list of strings. Not any trailing comma: spreadsheets
# and many real exports end every row with a delimiter.
_CODE_LINE = re.compile(r"""^\s*\(|^\s*["'][^"']*["'],\s.*,\s*$""")
# Quick rejections, so that ordinary lines of code never reach the cell logic.
_NOT_A_HEADER = re.compile(r"[={}\[\]<>:]")
_HEADER_WORD = re.compile(r"(?i)ssn|dob|mrn|mbi|name|patient|birth|member|subscriber|medic|insur|polic|chart|social|client|benefic")


def is_direct_column(col: str) -> bool:
    return col in _DIRECT_COLUMNS or bool(_DIRECT_TOKENS & set(col.split("_")))


def _is_header(raw: str, delim: str, cells: list[str]) -> bool:
    """Whether a row reads as column names rather than prose with commas.
    Two columns are weak evidence, so a table that narrow must not contain a
    multi-word cell that is not a known column."""
    names = [_norm_col(c) for c in cells]
    if len(names) < 2 or _LIST_ITEM.match(raw) or _CODE_LINE.search(raw):
        return False
    if not all(_COLUMN_NAME.match(c) for c in names) or any(len(c.split()) > 4 for c in cells):
        return False
    return len(names) > 2 or all(is_direct_column(n) or len(c.split()) == 1 for n, c in zip(names, cells, strict=True))


def _live_row(row: str, delim: str, id_cols: list[int], name_cols: set[int]) -> bool:
    """A data row whose identifier cells hold real values, not placeholders."""
    if _RULE_ROW.match(row):
        return False
    parts = [row[a:b].strip(" \t\"'") for a, b in cell_spans(row, delim)]
    values = [(k, parts[k]) for k in id_cols if k < len(parts)]
    if not any(v and not _PLACEHOLDER.match(v) for _, v in values):
        return False
    # A table of pure text can still be a patient list: its digit-free rows
    # count when a name column holds what looks like a person's name.
    return any(ch.isdigit() for ch in row) or any(k in name_cols and _PERSON_NAME.match(v) for k, v in values)


def tabular_finder(text: str) -> Iterator[Span]:
    """CSV/TSV/pipe tables whose header names patient identifiers and which
    contain at least one data row. A table runs to the next blank line; rows
    of the wrong width stay in the span, so redaction can deal with them."""
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
        delim = header_delimiter(raw)
        if delim is None or _NOT_A_HEADER.search(raw) or not _HEADER_WORD.search(raw):
            i += 1
            continue
        raw_cells = [raw[a:b] for a, b in cell_spans(raw, delim)]
        present = [c for c in raw_cells if c.strip()]
        if not _is_header(raw, delim, present):
            i += 1
            continue
        cells = [_norm_col(c) for c in raw_cells]
        cols = set(cells)
        direct = any(is_direct_column(c) for c in cols)
        name_pair = bool(cols & _FIRST) and bool(cols & _LAST)
        if not (direct or (name_pair and cols & _QUASI)):
            i += 1
            continue
        j = i + 1
        while j < n and lines[j].strip():
            j += 1
        id_cols = [k for k, c in enumerate(cells) if is_direct_column(c) or c in _FIRST or c in _LAST]
        name_cols = {k for k in id_cols if "name" in cells[k].split("_")}
        # A wide header is rare enough in code to trust on its own, so a
        # malformed row in that table still counts. A narrow one is not: `dob,
        # mrn` could be a line of a program, so its rows must line up.
        width = len(raw_cells)
        live = False
        for first, last in logical_rows(lines, i + 1, j):
            row = "".join(lines[first:last + 1]).rstrip("\r\n")
            lines_up = width > 3 or len(cell_spans(row, delim)) == width
            if lines_up and _live_row(row, delim, id_cols, name_cols):
                live = True
                break
        if live:
            yield offsets[i + 1], offsets[j - 1] + len(lines[j - 1].rstrip("\r\n"))
        # The rows are consumed either way, so input of repeated header-like
        # lines stays linear.
        i = max(j, i + 1)


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
        "ssn", HIGH, DIRECT, "Labelled SSN (bare, spaced or dotted digits)",
        regex_finder(
            rf"(?i){LB}(?:ssn|social{W}security(?:{W}{NUM})?)" + SEP + r"(?P<v>\d{3}[ .-]?\d{2}[ .-]?\d{4})(?![\d-])",
            group="v", validate=_ssn_bare_valid,
        ),
        ("ssn", "social"),
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
            rf"(?i){LB}(?:mrn|medical{W}record(?:{W}{NUM})?|patient{W}(?:id|{NUM})"
            rf"|chart{W}{NUM})" + SEP + r"(?P<v>[A-Z0-9][A-Z0-9-]{3,19})\b",
            group="v", validate=_id_value("v"),
        ),
        ("mrn", "medical", "patient", "chart"),
    ),
    Detector(
        "member_id", HIGH, DIRECT, "Labelled health plan member / subscriber / Medicaid ID",
        regex_finder(
            rf"(?i){LB}(?:(?:member|subscriber|beneficiary|policy{W}holder|insurance|medicaid|medicare)"
            rf"{W}(?:id|{NUM})|policy{W}{NUM})" + SEP + r"(?P<v>[A-Z0-9][A-Z0-9-]{4,19})\b",
            group="v", validate=_id_value("v"),
        ),
        ("member", "subscriber", "beneficiary", "policy", "insurance", "medicaid", "medicare"),
    ),
    Detector(
        "dob", HIGH, DIRECT, "Labelled date of birth",
        regex_finder(
            rf"(?i){LB}(?:dob|d\.o\.b\.?|date{W}of{W}birth|birth{W}date|born(?:\s+on)?)"
            + SEP + rf"(?P<v>{DATE})",
            group="v",
        ),
        ("dob", "d.o.b", "birth", "born"),
    ),
    Detector(
        "account_number", HIGH, DIRECT, "Labelled financial account number",
        regex_finder(
            rf"(?i){LB}(?:account|acct|bank{W}account|iban){W}{NUM}" + SEP + r"(?P<v>\d[\d -]{5,24}\d)",
            group="v",
        ),
        ("account", "acct", "iban"),
    ),
    Detector(
        "payment_card", HIGH, DIRECT, "Payment card number (Luhn-valid, test cards excluded)",
        # Unbroken, or grouped the way cards are printed (4-4-4-4, 4-6-5). The
        # guards skip the fractional digits of a float.
        regex_finder(
            r"(?<![\w.-])(?:\d{13,19}|\d{4}([ -])\d{4}\1\d{4}\1\d{1,7}|\d{4}([ -])\d{6}\2\d{5})(?![\w-]|\.\d)",
            validate=lambda m: card_ok(m.group(0)),
        ),
    ),
    Detector(
        "x12_patient", HIGH, DIRECT, "X12 EDI patient or subscriber name segment (NM1*QC / NM1*IL)",
        regex_finder(r"NM1([*|^])(?:QC|IL)\1(?:1)\1[^~\r\n]+"),
        ("nm1",),
    ),
    Detector(
        "x12_dob", HIGH, DIRECT, "X12 EDI demographic segment with birth date (DMG*D8)",
        regex_finder(r"DMG([*|^])D8\1\d{8}"),
        ("dmg",),
    ),
    Detector(
        "hl7_pid", HIGH, DIRECT, "HL7 v2 PID segment with a patient name",
        # Real HL7 separates segments with CR, not LF.
        regex_finder(r"(?<![^\r\n])PID\|[^\r\n]*\^[^\r\n]*"),
        ("pid|",),
    ),
    Detector(
        "fhir_patient", HIGH, DIRECT, "FHIR Patient resource with name or birthDate", fhir_patient_finder,
        ('"resourcetype"',),
    ),
    Detector("tabular_phi", HIGH, DIRECT, "Delimited table with patient identifier columns and data rows", tabular_finder),
    Detector(
        "person_name", HIGH, PERSON, "Patient/member/client name in a labelled field",
        regex_finder(
            rf"{LB}(?i:patient|pt|client|member|beneficiary|resident|insured|subscriber|guarantor)(?:'s)?"
            rf"{W}(?i:full{W})?(?i:name)" + SEP + rf"(?P<v>{NAME})",
            group="v", validate=lambda m: not_org_name(m.group("v")),
        ),
        ("name",),
    ),
    Detector(
        "person_name", MEDIUM, PERSON, "Generic labelled full name",
        regex_finder(
            r"\b(?i:full\s*_?name|name)" + SEP + rf"(?P<v>{NAME})",
            group="v", validate=lambda m: not_org_name(m.group("v")),
        ),
        ("name",),
    ),
    Detector(
        "diagnosis", MEDIUM, CLINICAL, "Labelled ICD-10 diagnosis code",
        regex_finder(
            rf"(?i){LB}(?:dx|diagnosis|diag|icd{W}10)(?:{W}code)?" + SEP
            + r"(?P<v>(?-i:[A-TV-Z]\d[0-9AB](?:\.[0-9A-TV-Z]{1,4})?))\b",
            group="v",
        ),
        ("dx", "diag", "icd"),
    ),
    Detector(
        "clinical_date", MEDIUM, CLINICAL, "Labelled admission, discharge, service or death date",
        regex_finder(
            rf"(?i){LB}(?:date{W}of{W}service|dos|admi(?:t|ssion){W}date|discharge{W}date|date{W}of{W}death|dod)"
            + SEP + rf"(?P<v>{DATE})",
            group="v",
        ),
        ("service", "dos", "admi", "discharge", "death", "dod"),
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
    lowered = text.lower()
    for det in DETECTORS:
        if det.name in disabled or (det.hints and not any(hint in lowered for hint in det.hints)):
            continue
        for s, e in det.find(text):
            key = (det.name, s, e)
            if key in seen:
                continue
            seen.add(key)
            out.append(Finding(det.name, det.severity, det.group, s, e))
    out.sort(key=lambda f: (f.start, -SEVERITY_RANK[f.severity]))
    return out
