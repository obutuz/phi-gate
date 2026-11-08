"""Pattern-based PHI/PII detectors.

Design rule: a Finding never carries the matched value. Anything that needs
the value (redaction) slices it from the original text itself, so findings
can be printed, logged, or serialized without leaking what they found.

Each detector returns character spans. Labelled detectors (for example
"DOB: <date>") return the span of the value only, not the label, so that
redaction keeps the surrounding text readable.

Detection runs on a normalised view of the text (see `normalize`): Unicode
compatibility forms are folded, invisible format characters are removed, and
look-alike letters are mapped to ASCII, so that a zero-width space inside an
SSN or a Cyrillic letter inside a label cannot hide a value. Spans are mapped
back to the original text before they are returned.

Every pattern is written to run in linear time on hostile input: repetition
next to an optional separator uses possessive quantifiers or a fixed bound, so
a long run of spaces, digits or label words cannot make the engine backtrack.
"""

from __future__ import annotations

import bisect
import ipaddress
import re
import unicodedata
from array import array
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from typing import Final, Literal

Severity = Literal["high", "medium", "low"]
Group = Literal["direct", "person", "clinical", "contact", "provider", "network"]

HIGH: Final[Severity] = "high"
MEDIUM: Final[Severity] = "medium"
LOW: Final[Severity] = "low"
SEVERITY_RANK: Final[dict[Severity, int]] = {LOW: 0, MEDIUM: 1, HIGH: 2}

# Groups drive the record-likeness rule in policy.py.
DIRECT: Final[Group] = "direct"  # identifies a person on its own (SSN, MRN, DOB...)
PERSON: Final[Group] = "person"  # a person's name in a labelled field
CLINICAL: Final[Group] = "clinical"  # diagnosis codes, dates of service
CONTACT: Final[Group] = "contact"  # phone, email, street address
PROVIDER: Final[Group] = "provider"  # provider identifiers (NPI, DEA): not PHI on their own
NETWORK: Final[Group] = "network"  # IP addresses

Span = tuple[int, int]
Finder = Callable[[str], Iterator[Span]]
Validator = Callable[[re.Match[str]], bool]


@dataclass(frozen=True)
class Detector:
    """One kind of identifier: its category, severity, group and finder."""

    name: str
    severity: Severity
    group: Group
    description: str
    find: Finder
    # Lowercase substrings, at least one of which any match must contain. A
    # substring test is far cheaper than a regex tried at every position, and
    # most source files contain none of these words.
    hints: tuple[str, ...] = ()


@dataclass(frozen=True)
class Finding:
    """Where a detector matched. Never the matched value itself."""

    category: str
    severity: Severity
    group: Group
    start: int
    end: int
    line: int = 0
    col: int = 0

    def to_dict(self) -> dict[str, str | int]:
        """The finding as JSON-ready data, without offsets into the text."""
        return {
            "category": self.category,
            "severity": self.severity,
            "group": self.group,
            "line": self.line,
            "col": self.col,
        }


# --------------------------------------------------------------------------
# Normalisation
# --------------------------------------------------------------------------

# Letters from other scripts that render like ASCII letters. Folding them lets a
# label such as "SSN" written with a Cyrillic first letter still read as a label.
_CONFUSABLES: Final[dict[int, str]] = {
    # Cyrillic capitals and small letters
    0x0410: "A", 0x0412: "B", 0x0421: "C", 0x0415: "E", 0x041D: "H", 0x0406: "I",
    0x0408: "J", 0x041A: "K", 0x041C: "M", 0x041E: "O", 0x0420: "P", 0x0405: "S",
    0x0422: "T", 0x0425: "X", 0x0423: "Y", 0x04AE: "Y",
    0x0430: "a", 0x0441: "c", 0x0501: "d", 0x0435: "e", 0x0456: "i", 0x0458: "j",
    0x043E: "o", 0x0440: "p", 0x051B: "q", 0x0455: "s", 0x051D: "w", 0x0445: "x",
    0x0443: "y",
    # Greek capitals and small omicron
    0x0391: "A", 0x0392: "B", 0x0395: "E", 0x0396: "Z", 0x0397: "H", 0x0399: "I",
    0x039A: "K", 0x039C: "M", 0x039D: "N", 0x039F: "O", 0x03A1: "P", 0x03A4: "T",
    0x03A5: "Y", 0x03A7: "X", 0x03BF: "o",
}
# Characters outside the dash punctuation category that are used as hyphens.
_EXTRA_DASHES: Final = frozenset("\u2212\u2043\ufe63\uff0d")
_NON_ASCII_RUN: Final = re.compile(r"[^\x00-\x7f]+")


def _fold_char(ch: str) -> str:
    """The normalised form of one non-ASCII character (possibly empty)."""
    out = []
    for c in unicodedata.normalize("NFKC", ch):
        if c < "\x80":
            out.append(c)
            continue
        category = unicodedata.category(c)
        if category == "Cf":  # zero-width characters, soft hyphen, BOM
            continue
        if category == "Pd" or c in _EXTRA_DASHES:
            out.append("-")
        elif category == "Zs":
            out.append(" ")
        else:
            out.append(_CONFUSABLES.get(ord(c), c))
    return "".join(out)


@dataclass(frozen=True)
class NormalizedText:
    """A normalised view of a text, with a map from view offsets back to it.

    `offsets[i]` is the index in the original text of the character that
    produced view character `i`; `offsets` is None when the view is the text.
    """

    text: str
    offsets: array[int] | None = None

    def to_original(self, start: int, end: int) -> Span:
        """The original span covering view span [start, end)."""
        if self.offsets is None or start >= end:
            return start, end
        return self.offsets[start], self.offsets[end - 1] + 1


def normalize(text: str) -> NormalizedText:
    """Fold the text so that visually equivalent spellings match the same way.

    Applies NFKC per character (fullwidth letters and digits, ligatures, NBSP),
    removes format characters (zero-width space and joiner, soft hyphen), maps
    every Unicode dash to "-" and every space separator to " ", and folds
    common Cyrillic and Greek look-alikes to ASCII. Line breaks are kept, so
    line-based detectors see the same lines.
    """
    if text.isascii():
        return NormalizedText(text)
    pieces: list[str] = []
    offsets: array[int] = array("q")
    cursor = 0
    for m in _NON_ASCII_RUN.finditer(text):
        pieces.append(text[cursor:m.start()])
        offsets.extend(range(cursor, m.start()))
        for i in range(m.start(), m.end()):
            folded = _fold_char(text[i])
            pieces.append(folded)
            offsets.extend([i] * len(folded))
        cursor = m.end()
    pieces.append(text[cursor:])
    offsets.extend(range(cursor, len(text)))
    view = "".join(pieces)
    if view == text:
        return NormalizedText(text)
    return NormalizedText(view, offsets)


# --------------------------------------------------------------------------
# Validators
# --------------------------------------------------------------------------


def luhn_ok(digits: str) -> bool:
    """Whether a digit string passes the Luhn (mod 10) check."""
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
    """Whether a DEA registration number has a valid check digit."""
    digits = value[2:]
    if len(digits) != 7 or not digits.isdigit():
        return False
    d = [int(c) for c in digits]
    check = (d[0] + d[2] + d[4]) + 2 * (d[1] + d[3] + d[5])
    return check % 10 == d[6]


# SSNs printed in documentation, advertising and training material for decades.
# They identify nobody and appear in ordinary code and docs, so they are treated
# as synthetic.
DUMMY_SSNS: Final = frozenset({
    "078051120",  # printed on a wallet insert sold in 1938, later voided
    "219099999",  # printed in a Social Security Administration pamphlet
    "123456789",  # the sequential example used in forms, documentation and tests
})


def is_dummy_ssn(digits: str) -> bool:
    """Whether a nine-digit SSN is a well-known example rather than a real one:
    a published example number, or three groups that each repeat one digit
    (111-22-3333)."""
    if digits in DUMMY_SSNS:
        return True
    return all(len(set(part)) == 1 for part in (digits[:3], digits[3:5], digits[5:]))


def ssn_area_ok(area: str, group: str, serial: str) -> bool:
    """Whether an SSN could have been issued, and is not a well-known example."""
    # 000, 666 and 900-999 are never issued. Treat them as synthetic so that
    # test data (Synthea uses 999-xx-xxxx) passes without allowlisting.
    if area in ("000", "666") or area[0] == "9":
        return False
    if group == "00" or serial == "0000":
        return False
    return not is_dummy_ssn(area + group + serial)


# Publicly documented processor test card numbers: synthetic by definition.
TEST_CARDS: Final = frozenset({
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
})
_CARD_PREFIX: Final = re.compile(r"^(4|5[1-5]|2[2-7]|3[47]|6011|65|3[068]|35)")


def card_ok(raw: str) -> bool:
    """Whether a card-shaped number could be a real payment card: issuer
    prefix, length, Luhn, and not a published test number or filler."""
    digits = re.sub(r"[ -]", "", raw)
    if not (13 <= len(digits) <= 19) or digits in TEST_CARDS:
        return False
    if not _CARD_PREFIX.match(digits):
        return False
    if len(set(digits)) <= 2:  # 4444 4444 ... style filler
        return False
    return luhn_ok(digits)


TOLL_FREE: Final = frozenset({"800", "833", "844", "855", "866", "877", "888"})

SAFE_EMAIL_DOMAINS: Final = re.compile(
    r"(?:^|\.)(?:example\.(?:com|org|net)|example|test|invalid|localhost|"
    r"users\.noreply\.github\.com|noreply\.github\.com)$",
    re.I,
)


ORG_WORDS: Final = frozenset({
    "inc", "llc", "ltd", "corp", "co", "company", "group", "partners", "labs",
    "health", "healthcare", "care", "services", "solutions", "financial",
    "medical", "clinic", "center", "centre", "hospital", "agency", "therapy",
    "pharmacy", "supply", "systems", "technologies", "foundation", "network",
})


def not_org_name(value: str) -> bool:
    """False when the last word marks the value as an organisation."""
    last = re.split(r"[\s,]+", value.strip())[-1].lower().strip(".")
    return last not in ORG_WORDS


def has_digit(value: str) -> bool:
    """Whether the value contains at least one digit."""
    return any(ch.isdigit() for ch in value)


# --------------------------------------------------------------------------
# Finder helpers
# --------------------------------------------------------------------------


def regex_finder(
    pattern: str,
    flags: int = 0,
    group: int | str = 0,
    validate: Validator | None = None,
) -> Finder:
    """A finder yielding the span of `group` for every match that `validate`
    accepts."""
    rx = re.compile(pattern, flags)

    def find(text: str) -> Iterator[Span]:
        for m in rx.finditer(text):
            if validate is not None and not validate(m):
                continue
            s, e = m.span(group)
            if s < e:
                yield (s, e)

    return find


# A labelled value may wrap onto the next line right after a separator, as in
# "SSN: 234-56-" followed by "7891" on the next line.
BR = r"(?:\r?\n[ \t]*+)?"
ORDINAL = r"(?:st|nd|rd|th)?"
MONTHS = r"(?:jan|feb|mar|apr|may|jun|jul|aug|sep|sept|oct|nov|dec)[a-z]*+\.?"
DATE = (
    rf"(?:\d{{1,2}}[/.-]{BR}\d{{1,2}}[/.-]{BR}(?:\d{{4}}|\d{{2}})"
    r"|\d{4}-\d{1,2}-\d{1,2}"
    r"|(?:19|20)\d{6}"
    r"|\d{1,2} \d{1,2} (?:19|20)\d{2}"
    rf"|{MONTHS}\s++\d{{1,2}}{ORDINAL},?\s++\d{{4}}"
    rf"|\d{{1,2}}{ORDINAL}(?:\s++|-){MONTHS}(?:,?\s++|-)\d{{4}})"
)
# Separator between a label and its value: handles `DOB: x`, `dob = "x"`,
# `"birthDate": "x"`, `'dob': 'x'`, `DOB#x`, `SSN#: x` and `DOB x`. The value
# may start on the next line only after a colon or equals sign, so the last
# column name of a table header is not read as a label for the first cell
# below it. Every quantifier is possessive, so a long run of spaces after a
# label is read once.
SEP = r"""[ \t]*+(?:["'][ \t]*+)?(?:#[ \t]*+)?(?:[:=]\s*+)?(?:["']\s*+)?"""
# A parenthesised note between a label and its value: `DOB (MM/DD/YYYY): x`.
NOTE = r"(?:\s*+\([^()\r\n]{0,40}+\))?"
# Where a label can start. `\b` would miss `patient_dob` (underscore) and
# `patientDob` (a lower-to-upper camelCase step).
LB = r"(?:(?<![A-Za-z0-9])|(?-i:(?<=[a-z])(?=[A-Z])))"
# Between the words of a label: `date of birth`, `date_of_birth`, `dateOfBirth`.
W = r"[\s_-]*+"
NUM = r"(?:\#|no\.?|num(?:ber)?)"
# An XML element used as a label: `<SSN>x`, `<ns:MemberId type="a">x`, and the
# FHIR attribute form `<birthDate value="x"/>`.
XML_OPEN = r"<(?:[A-Za-z][\w.-]{0,40}:)?"
XML_CLOSE = r"""(?:\s[^<>]{0,300}?\bvalue\s*+=\s*+["']|(?:\s[^<>]{0,300}+)?>\s*+)"""


def labelled(label: str, value: str) -> str:
    """A pattern for `value` after `label`, as a key, a field or an XML
    element. The value is the named group `v`."""
    return rf"(?:{XML_OPEN}(?:{label}){XML_CLOSE}|{LB}(?:{label}){NOTE}{SEP})(?P<v>{value})"


_XML_OPEN_BEFORE: Final = re.compile(XML_OPEN + r"\Z")


def labelled_finder(
    label: str, value: str, starts: str, validate: Validator | None = None, ignore_case: bool = True
) -> Finder:
    """A finder for `labelled(label, value)` that yields the span of the value.

    `starts` lists every letter a spelling of the label can begin with. The
    full pattern is tried only where the label itself occurs (or at the `<`
    opening an XML element around it): scanning for the label behind a
    one-character lookahead is several times cheaper than trying the label
    boundary and the XML form at every position.
    """
    flags = "(?i)" if ignore_case else ""
    rx = re.compile(flags + labelled(label, value))
    trigger = re.compile(f"{flags}(?=[{starts.lower()}{starts.upper()}])(?:{label})")

    def find(text: str) -> Iterator[Span]:
        end = 0
        for hit in trigger.finditer(text):
            p = hit.start()
            if p < end:
                continue
            m = None
            if p and text[p - 1] in "<:":
                xml = _XML_OPEN_BEFORE.search(text, max(end, p - 42), p)
                if xml is not None:
                    m = rx.match(text, xml.start())
            if m is None:
                m = rx.match(text, p)
            if m is None:
                continue
            end = m.end()
            if validate is not None and not validate(m):
                continue
            s, e = m.span("v")
            if s < e:
                yield (s, e)

    return find


NAME = r"[A-Z][a-z'\-]++(?:\s++[A-Z]\.?)?(?:\s++[A-Z][a-z'\-]++){1,2}|[A-Z][a-z'\-]++,\s*+[A-Z][a-z'\-]++"
# In a field that names a patient or member, also capitals (`JOHN SMITH`), the
# `SMITH, JOHN` order and names such as `McDonald`. Words stay on one line.
_NAME_WORD = r"[A-Z][A-Za-z'\-]++"
PATIENT_NAME = (
    rf"{_NAME_WORD}(?:[ \t]++[A-Z]\.?)?(?:[ \t]++{_NAME_WORD}){{1,2}}|{_NAME_WORD},[ \t]*+{_NAME_WORD}"
)

US_STATES = (
    "AL|AK|AZ|AR|CA|CO|CT|DE|DC|FL|GA|HI|ID|IL|IN|IA|KS|KY|LA|ME|MD|MA|MI|MN|MS|"
    "MO|MT|NE|NV|NH|NJ|NM|NY|NC|ND|OH|OK|OR|PA|RI|SC|SD|TN|TX|UT|VT|VA|WA|WV|WI|WY|PR"
)
STREET_SUFFIX = (
    "Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Court|Ct|Way|"
    "Place|Pl|Terrace|Ter|Parkway|Pkwy|Circle|Cir|Highway|Hwy"
)
# A capitalised word, or one in capitals as on mailing labels.
_PLACE_WORD = r"(?:[A-Z][a-z]++|[A-Z]{2,}+)"

MBI_L = "AC-HJKMNP-RT-Y"  # letters allowed in an MBI (no S, L, O, I, B, Z)


def _ssn_valid(m: re.Match[str]) -> bool:
    return ssn_area_ok(m.group("a"), m.group("g"), m.group("s"))


def _ssn_bare_valid(m: re.Match[str]) -> bool:
    v = re.sub(r"\D", "", m.group("v"))
    return ssn_area_ok(v[:3], v[3:5], v[5:])


def _mbi_valid(m: re.Match[str]) -> bool:
    """One case throughout. A random mixed-case token is far more often an
    opaque id than an MBI typed in lowercase."""
    letters = [c for c in m.group(0) if c.isalpha()]
    return all(c.isupper() for c in letters) or all(c.islower() for c in letters)


def _phone_valid(m: re.Match[str]) -> bool:
    area = m.group("area1") or m.group("area2")
    exch, line = m.group("exch"), m.group("line")
    if area in TOLL_FREE:
        return False
    if exch == "555" and 100 <= int(line) <= 199:  # reserved fictional range
        return False
    return True


def _email_valid(m: re.Match[str]) -> bool:
    return not SAFE_EMAIL_DOMAINS.search(m.group("domain"))


def _ip_valid(m: re.Match[str]) -> bool:
    try:
        ip = ipaddress.ip_address(m.group(0))
    except ValueError:
        return False
    return ip.is_global


def _card_valid(m: re.Match[str]) -> bool:
    return card_ok(m.group(0))


def _npi_valid(m: re.Match[str]) -> bool:
    return npi_ok(m.group(0))


def _dea_valid(m: re.Match[str]) -> bool:
    return dea_ok(m.group(0))


def _person_valid(m: re.Match[str]) -> bool:
    return not_org_name(m.group("v"))


def _x12_ref_valid(m: re.Match[str]) -> bool:
    return has_digit(m.group("v"))


# Column types and encodings that follow an id in schemas and code, such as
# `patient_id INT8`. They contain digits but they are not identifiers.
_TYPE_NAME = re.compile(r"(?i)^(?:u?int|float|serial|char|varchar|sha|md|utf|base|uuid|bytea)-?\d*$")


def _id_value(name: str, min_length: int = 4) -> Validator:
    """A validator for an identifier in group `name`: at least `min_length`
    letters and digits, at least one digit, and not a type name."""

    def valid(m: re.Match[str]) -> bool:
        value = m.group(name)
        compact = value.replace(" ", "")
        return len(compact) >= min_length and has_digit(value) and not _TYPE_NAME.match(compact)

    return valid


# --------------------------------------------------------------------------
# Delimited tables
# --------------------------------------------------------------------------

MAX_ROW_LINES: Final = 50  # how far a quoted cell may run across lines

_DIRECT_COLUMNS: Final = frozenset({
    "social_security_number", "social_security", "ss_number",
    "date_of_birth", "birth_date", "birthdate",
    "medical_record_number", "medical_record_no", "chart_number",
    "member_id", "member_number", "member_name", "subscriber_id", "subscriber_name",
    "medicaid_id", "medicare_id", "medicaid_number", "medicare_number",
    "insurance_id", "policy_number",
    "patient_name", "patient_full_name", "client_name", "beneficiary_name",
    "insured_name", "patient_id", "client_id_number",
})
# Any column with one of these words, such as `patient_dob` or `ssn_last4`.
_DIRECT_TOKENS: Final = frozenset({"ssn", "dob", "mrn", "mbi", "hicn"})
# A column naming the person a row is about, combined with an identifier or name
# word: `Mbr_ID`, `Subscriber No`, `Insured ID`, `Patient Acct #`.
_SUBJECT_TOKENS: Final = frozenset({
    "member", "mbr", "subscriber", "insured", "patient", "pt", "medicaid", "medicare", "beneficiary",
})
_ID_TOKENS: Final = frozenset({"id", "no", "num", "number", "nbr", "nr", "identifier", "name"})
FIRST_NAME_COLUMNS: Final = frozenset({
    "first_name", "firstname", "fname", "given_name", "patient_first_name", "first", "given",
})
LAST_NAME_COLUMNS: Final = frozenset({
    "last_name", "lastname", "lname", "family_name", "surname", "patient_last_name", "last", "family",
})
QUASI_COLUMNS: Final = frozenset({
    "diagnosis", "dx", "icd10", "icd_10", "icd10_code", "diagnosis_code",
    "address", "street", "street_address", "address1", "address_line_1",
    "phone", "phone_number", "mobile", "email", "zip", "zipcode", "zip_code",
    "date_of_service", "dos", "admit_date", "admission_date", "discharge_date",
})

_CAMEL_STEP: Final = re.compile(r"(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])")
_PARENTHESISED: Final = re.compile(r"\([^()]*\)")


def normalize_column(col: str) -> str:
    """A header cell as a snake_case column name.

    `DOB (mm/dd/yyyy)` gives `dob`, `[Patient Name]` gives `patient_name`,
    `MemberID` gives `member_id` and `Member #` gives `member_no`.
    """
    col = col.strip().strip("\"'").strip()
    if col.endswith(":"):
        col = col[:-1].rstrip()
    if col.startswith("[") and col.endswith("]"):
        col = col[1:-1]
    col = _PARENTHESISED.sub("", col).replace("#", " no ")
    col = _CAMEL_STEP.sub("_", col).lower()
    return re.sub(r"[^a-z0-9]+", "_", col).strip("_")


def cell_spans(row: str, delim: str) -> list[Span]:
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
    """The first of comma, tab, pipe and semicolon that the row contains."""
    return next((d for d in (",", "\t", "|", ";") if d in row), None)


def logical_rows(lines: list[str], start: int, stop: int) -> Iterator[Span]:
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


_RULE_ROW: Final = re.compile(r"^[\s|:+\-=]*$")
_COLUMN_NAME: Final = re.compile(r"^[a-z][a-z0-9_]{0,40}$")
_PLACEHOLDER: Final = re.compile(r"^\[[A-Z0-9_]+_\d+\]$")
_LIST_ITEM: Final = re.compile(r"^\s*(?:[-*+]|\d+[.)])\s")
_PERSON_NAME: Final = re.compile(rf"(?:{NAME})$")
# A tuple, or a line of a list of strings. Not any trailing comma: spreadsheets
# and many real exports end every row with a delimiter.
_CODE_LINE: Final = re.compile(r"""^\s*\(|^\s*["'][^"']*["'],\s.*,\s*$""")
# Quick rejections, so that ordinary lines of code never reach the cell logic.
_NOT_A_HEADER: Final = re.compile(r"[={}<>]")
# A colon other than at the end of a cell, or a subscript: code, not a header.
_CODE_PUNCTUATION: Final = re.compile(r"""\w\[|\]\w|:(?![ \t]*+(?:[,\t|;"']|$))""")
_HEADER_WORD: Final = re.compile(
    r"(?i)(?=[bcdhimnps])(?:ssn|dob|mrn|mbi|hicn|name|patient|birth|member|mbr|subscriber|medic|insur|polic|chart"
    r"|social|client|benefic)"
)


def is_rule_row(row: str) -> bool:
    """Whether a row is a separator such as `|---|---|`, not data."""
    return bool(_RULE_ROW.match(row))


def is_direct_column(col: str) -> bool:
    """Whether a normalised column name holds an identifier on its own."""
    tokens = set(col.split("_"))
    if col in _DIRECT_COLUMNS or tokens & _DIRECT_TOKENS:
        return True
    return bool(tokens & _SUBJECT_TOKENS) and bool(tokens & _ID_TOKENS)


def _header_cell_ok(cell: str) -> bool:
    """A cell that can be a column name: brackets only around the whole name,
    a colon only at its end, and balanced parentheses."""
    c = cell.strip().strip("\"'").strip()
    if c.endswith(":"):
        c = c[:-1].rstrip()
    if _PLACEHOLDER.match(c):  # a redacted value, not a column name
        return False
    if c.startswith("[") and c.endswith("]"):
        c = c[1:-1]
    if any(ch in c for ch in "[]:"):
        return False
    return not any(ch in _PARENTHESISED.sub("", c) for ch in "()")


def _is_header(raw: str, cells: list[str]) -> bool:
    """Whether a row reads as column names rather than prose with commas.
    Two columns are weak evidence, so a table that narrow must not contain a
    multi-word cell that is not a known column."""
    if len(cells) < 2 or _LIST_ITEM.match(raw) or _CODE_LINE.search(raw):
        return False
    if not all(_header_cell_ok(c) for c in cells):
        return False
    names = [normalize_column(c) for c in cells]
    if not all(_COLUMN_NAME.match(c) for c in names) or any(len(c.split()) > 4 for c in cells):
        return False
    return len(names) > 2 or all(is_direct_column(n) or len(c.split()) == 1 for n, c in zip(names, cells, strict=True))


@dataclass(frozen=True)
class TableHeader:
    """The layout a header line gives the rows below it."""

    delimiter: str
    columns: tuple[str, ...]  # normalised names, one per cell, empty cells included

    @property
    def identifier_columns(self) -> list[int]:
        """Indexes of columns that identify the person a row is about."""
        return [
            k for k, c in enumerate(self.columns)
            if is_direct_column(c) or c in FIRST_NAME_COLUMNS or c in LAST_NAME_COLUMNS
        ]


def parse_header(raw: str) -> TableHeader | None:
    """The header a line declares, when it names patient identifier columns."""
    delim = header_delimiter(raw)
    if delim is None or _NOT_A_HEADER.search(raw) or not _HEADER_WORD.search(raw) or _CODE_PUNCTUATION.search(raw):
        return None
    raw_cells = [raw[a:b] for a, b in cell_spans(raw, delim)]
    if not _is_header(raw, [c for c in raw_cells if c.strip()]):
        return None
    columns = tuple(normalize_column(c) for c in raw_cells)
    cols = set(columns)
    direct = any(is_direct_column(c) for c in cols)
    name_pair = bool(cols & FIRST_NAME_COLUMNS) and bool(cols & LAST_NAME_COLUMNS)
    if not (direct or (name_pair and cols & QUASI_COLUMNS)):
        return None
    return TableHeader(delim, columns)


@dataclass(frozen=True)
class Table:
    """A delimited table: its header and the offsets of its rows.

    `start` and `end` bound the body, from the line after the header. `rows` are the (start, end) offsets of
    each logical row, without its line terminator; blank lines are not rows.
    """

    header: TableHeader
    start: int
    end: int
    rows: tuple[Span, ...]


def _live_row(row: str, delim: str, id_cols: list[int], name_cols: set[int]) -> bool:
    """A data row whose identifier cells hold real values, not placeholders."""
    if _RULE_ROW.match(row):
        return False
    parts = [row[a:b].strip(" \t\"'") for a, b in cell_spans(row, delim)]
    values = [(k, parts[k]) for k in id_cols if k < len(parts)]
    if not any(v and not _PLACEHOLDER.match(v) for _, v in values):
        return False
    # A table of pure text can still be a patient list: its digit-free rows
    # count when a name column holds what looks like a person's name. Digits
    # inside placeholders are not data.
    return any(has_digit(p) for p in parts if not _PLACEHOLDER.match(p)) or any(
        k in name_cols and _PERSON_NAME.match(v) for k, v in values
    )


def _continues(line: str, header: TableHeader) -> bool:
    """Whether a row after a blank line still belongs to the table above: it
    has the header's width and does not start a table of its own."""
    raw = line.rstrip("\r\n")
    width = len(header.columns)
    if len(cell_spans(raw, header.delimiter)) != width or parse_header(raw) is not None:
        return False
    return width > 2 or has_digit(raw)


def _blocks(lines: list[str], header_line: int, header: TableHeader) -> list[Span]:
    """(first, stop) line ranges of the table's row blocks. Rows run to a blank
    line; after a single blank line, rows of the header's width continue the
    table (an export with a blank line after its header, or between pages)."""
    n = len(lines)
    blocks: list[Span] = []
    pos = header_line + 1
    while pos < n:
        k = pos
        while k < n and not lines[k].strip() and k - pos < 2:
            k += 1
        gap = k - pos
        if k >= n or gap > 1 or not lines[k].strip():
            break
        if gap == 1 and not _continues(lines[k], header):
            break
        if blocks and gap == 0:
            break
        stop = k
        while stop < n and lines[stop].strip():
            stop += 1
        blocks.append((k, stop))
        pos = stop
    return blocks


def find_tables(text: str, live_only: bool = True) -> Iterator[Table]:
    """CSV/TSV/pipe tables whose header names patient identifiers. With
    `live_only`, only tables with at least one data row holding a value.
    Rows of the wrong width stay in the table, so redaction can deal with
    them."""
    lines = text.splitlines(keepends=True)
    offsets = []
    pos = 0
    for ln in lines:
        offsets.append(pos)
        pos += len(ln)
    i = 0
    n = len(lines)
    while i < n:
        header = parse_header(lines[i].rstrip("\r\n"))
        if header is None:
            i += 1
            continue
        blocks = _blocks(lines, i, header)
        if not blocks:
            i += 1
            continue
        id_cols = header.identifier_columns
        name_cols = {k for k in id_cols if "name" in header.columns[k].split("_")}
        # A wide header is rare enough in code to trust on its own, so a
        # malformed row in that table still counts. A narrow one is not: `dob,
        # mrn` could be a line of a program, so its rows must line up.
        width = len(header.columns)
        rows: list[Span] = []
        live = not live_only
        for first, stop in blocks:
            for a, b in logical_rows(lines, first, stop):
                row = "".join(lines[a:b + 1]).rstrip("\r\n")
                rows.append((offsets[a], offsets[a] + len(row)))
                if not live:
                    lines_up = width > 3 or len(cell_spans(row, header.delimiter)) == width
                    live = lines_up and _live_row(row, header.delimiter, id_cols, name_cols)
        if live:
            # The body starts on the line after the header, a blank one included,
            # so that removing that blank line changes the finding.
            yield Table(header, offsets[i + 1], rows[-1][1], tuple(rows))
        # The rows are consumed either way, so input of repeated header-like
        # lines stays linear.
        i = max(blocks[-1][1], i + 1)


def tabular_finder(text: str) -> Iterator[Span]:
    """The body of every live patient table (see `find_tables`)."""
    for table in find_tables(text):
        yield table.start, table.end


# --------------------------------------------------------------------------
# FHIR
# --------------------------------------------------------------------------

_FHIR_WINDOW: Final = 3000
_FHIR_PATIENT: Final = re.compile(r'"resourceType"\s*+:\s*+"Patient"')
_FHIR_EVIDENCE: Final = re.compile(
    r'"birthDate"\s*+:\s*+"\d|"family"\s*+:\s*+"[A-Za-z]|"given"\s*+:\s*+\[\s*+"[A-Za-z]'
    r'|"name"\s*+:\s*+\[\s*+\{[^\]]{0,500}?"text"\s*+:\s*+"[A-Za-z]'
    r'|"system"\s*+:\s*+"[^"]{0,200}?us-ssn'
)
_FHIR_XML_PATIENT: Final = re.compile(r"<(?:[A-Za-z][\w.-]{0,40}:)?Patient(?:\s[^<>]{0,500}+)?>")
_FHIR_XML_EVIDENCE: Final = re.compile(
    r"""<(?:[A-Za-z][\w.-]{0,40}:)?(?:birthDate\s++value\s*+=\s*+["']\d|(?:family|given|text)\s++value\s*+=\s*+["'][A-Za-z])"""
    r"|us-ssn"
)


def _anchored_finder(anchor: re.Pattern[str], evidence: re.Pattern[str]) -> Finder:
    """Spans of `anchor` with a match of `evidence` starting within the window
    around it. Evidence is located once, so many anchors stay linear."""

    def find(text: str) -> Iterator[Span]:
        marks: list[int] | None = None
        for m in anchor.finditer(text):
            if marks is None:
                marks = [e.start() for e in evidence.finditer(text)]
            k = bisect.bisect_left(marks, m.start() - _FHIR_WINDOW)
            if k < len(marks) and marks[k] <= m.end() + _FHIR_WINDOW:
                yield m.span()

    return find


fhir_patient_finder = _anchored_finder(_FHIR_PATIENT, _FHIR_EVIDENCE)
fhir_xml_patient_finder = _anchored_finder(_FHIR_XML_PATIENT, _FHIR_XML_EVIDENCE)


# --------------------------------------------------------------------------
# Labels
# --------------------------------------------------------------------------

SSN_LABEL = rf"ssn|ss{W}{NUM}|social{W}security(?:{W}{NUM})?|tin"
SSN_VALUE = rf"\d{{3}}(?:[ .-]{BR})?\d{{2}}(?:[ .-]{BR})?\d{{4}}(?![\d-])"
MRN_LABEL = (
    rf"mrn|mr{W}{NUM}|medical{W}record(?:{W}{NUM})?|p(?:atien)?t{W}(?:id(?:entifier)?|{NUM})"
    rf"|chart{W}{NUM}|encounter{W}(?:id|{NUM})"
)
MRN_VALUE = r"[A-Z0-9][A-Z0-9-]{3,19}\b"
MEMBER_LABEL = (
    rf"(?:member|mbr|subscriber|beneficiary|policy{W}holder|insurance|insured|medicaid|medicare)"
    rf"{W}(?:id(?:entifier)?|{NUM})|policy{W}{NUM}|hicn|hic{W}{NUM}"
)
# An identifier, optionally printed in space-separated groups (`XYZ 1234 5678`).
# Groups after the first are capitals and digits with at least one digit, so a
# following word of prose does not join the value.
MEMBER_VALUE = r"[A-Z0-9][A-Z0-9-]{1,19}(?-i:(?:[ ](?=[A-Z0-9]{0,9}\d)[A-Z0-9]{2,10}\b){0,3})\b"
DOB_LABEL = rf"dob|d\.o\.b\.?|date{W}of{W}birth|birth{W}(?:date|day)|born(?:\s++on)?"
PATIENT_NAME_LABEL = (
    r"(?i:patient|pt|client|member|beneficiary|resident|insured|subscriber|guarantor)(?:'s)?"
    rf"{W}(?i:full{W})?(?i:name)"
)
ACCOUNT_LABEL = rf"(?:account|acct|bank{W}account|iban){W}{NUM}"
ACCOUNT_VALUE = r"\d[\d -]{5,24}\d"
CLINICAL_DATE_LABEL = (
    rf"date{W}of{W}service|dos|admi(?:t|ssion){W}date|discharge{W}date|date{W}of{W}death|dod"
)
DIAGNOSIS_LABEL = rf"(?:dx|diagnosis|diag|icd{W}10(?:{W}cm)?)(?:{W}codes?)?"
ICD10 = r"(?-i:[A-TV-Z]\d[0-9AB](?:\.?[0-9A-TV-Z]{1,4})?)\b"

# HL7 v2: real feeds separate segments with CR; logs and JSON often carry the
# separator as a literal `\r` or `\n` escape, and samples are often indented.
_HL7_CHAR = r"(?:[^\r\n\\]|\\(?![rn]))"
_HL7_FIELD_CHAR = r"(?:[^\r\n\\^]|\\(?![rn]))"


# --------------------------------------------------------------------------
# Registry
# --------------------------------------------------------------------------

DETECTORS: list[Detector] = [
    Detector(
        "ssn", HIGH, DIRECT, "US Social Security number (issued ranges only)",
        regex_finder(r"(?<![\d-])(?P<a>\d{3})-(?P<g>\d{2})-(?P<s>\d{4})(?![\d-])", validate=_ssn_valid),
    ),
    Detector(
        "ssn", HIGH, DIRECT, "Labelled SSN or TIN (bare, spaced or dotted digits)",
        labelled_finder(SSN_LABEL, SSN_VALUE, "st", _ssn_bare_valid),
        ("ss", "social", "tin"),
    ),
    Detector(
        "medicare_mbi", HIGH, DIRECT, "Medicare Beneficiary Identifier",
        regex_finder(
            rf"(?i)\b[1-9][{MBI_L}][{MBI_L}0-9]\d[- ]?[{MBI_L}][{MBI_L}0-9]\d[- ]?[{MBI_L}]{{2}}\d{{2}}\b",
            validate=_mbi_valid,
        ),
    ),
    Detector(
        "mrn", HIGH, DIRECT, "Labelled medical record, patient, chart or encounter number",
        labelled_finder(MRN_LABEL, MRN_VALUE, "mpce", _id_value("v")),
        ("mr", "medical", "pt", "patient", "chart", "encounter"),
    ),
    Detector(
        "member_id", HIGH, DIRECT, "Labelled health plan member / subscriber / Medicaid / Medicare ID",
        labelled_finder(MEMBER_LABEL, MEMBER_VALUE, "msbpih", _id_value("v", 5)),
        ("member", "mbr", "subscriber", "beneficiary", "policy", "insur", "medicaid", "medicare", "hic"),
    ),
    Detector(
        "dob", HIGH, DIRECT, "Labelled date of birth",
        labelled_finder(DOB_LABEL, DATE, "db"),
        ("dob", "d.o.b", "birth", "born"),
    ),
    Detector(
        "account_number", HIGH, DIRECT, "Labelled financial account number",
        labelled_finder(ACCOUNT_LABEL, ACCOUNT_VALUE, "abi"),
        ("account", "acct", "iban"),
    ),
    Detector(
        "payment_card", HIGH, DIRECT, "Payment card number (Luhn-valid, test cards excluded)",
        # Unbroken, or grouped the way cards are printed (4-4-4-4, 4-6-5). The
        # guards skip the fractional digits of a float.
        regex_finder(
            r"(?<![\w.-])(?:\d{13,19}|\d{4}([ -])\d{4}\1\d{4}\1\d{1,7}|\d{4}([ -])\d{6}\2\d{5})(?![\w-]|\.\d)",
            validate=_card_valid,
        ),
    ),
    Detector(
        "x12_patient", HIGH, DIRECT, "X12 EDI patient, subscriber or dependent name segment (NM1*QC / IL / 03)",
        regex_finder(r"(?i)NM1(?P<d>[*|^])(?:QC|IL|03)(?P=d)1(?P=d)[^~\r\n]++"),
        ("nm1",),
    ),
    Detector(
        "x12_patient", HIGH, DIRECT, "X12 EDI reference segment with a person's identifier (REF*SY / 0F / 1L / 1W / EA)",
        regex_finder(
            r"(?i)REF(?P<d>[*|^])(?:SY|0F|1L|1W|EA)(?P=d)(?P<v>[^~\r\n*|^]{2,50}+)",
            validate=_x12_ref_valid,
        ),
        ("ref",),
    ),
    Detector(
        "x12_dob", HIGH, DIRECT, "X12 EDI demographic segment with birth date (DMG*D8)",
        regex_finder(r"(?i)DMG(?P<d>[*|^])D8(?P=d)\d{8}"),
        ("dmg",),
    ),
    Detector(
        "hl7_pid", HIGH, DIRECT, "HL7 v2 PID segment with a patient name",
        regex_finder(
            rf"(?:(?<![^\r\n])[ \t]*+|(?<=\\[rn]))(?P<v>PID\|{_HL7_FIELD_CHAR}{{0,300}}+\^{_HL7_CHAR}*+)",
            group="v",
        ),
        ("pid|",),
    ),
    Detector(
        "fhir_patient", HIGH, DIRECT, "FHIR Patient resource with name, birthDate or SSN", fhir_patient_finder,
        ('"resourcetype"',),
    ),
    Detector(
        "fhir_patient", HIGH, DIRECT, "FHIR Patient resource in XML with name, birthDate or SSN",
        fhir_xml_patient_finder,
        ("patient",),
    ),
    Detector("tabular_phi", HIGH, DIRECT, "Delimited table with patient identifier columns and data rows", tabular_finder),
    Detector(
        "person_name", HIGH, PERSON, "Patient/member/client name in a labelled field",
        labelled_finder(PATIENT_NAME_LABEL, PATIENT_NAME, "pcmbrisg", _person_valid, ignore_case=False),
        ("name",),
    ),
    Detector(
        "person_name", MEDIUM, PERSON, "Generic labelled full name",
        regex_finder(r"\b(?i:full\s*+_?name|name)" + SEP + rf"(?P<v>{NAME})", group="v", validate=_person_valid),
        ("name",),
    ),
    Detector(
        "diagnosis", MEDIUM, CLINICAL, "Labelled ICD-10 diagnosis code",
        labelled_finder(DIAGNOSIS_LABEL, ICD10, "di"),
        ("dx", "diag", "icd"),
    ),
    Detector(
        "clinical_date", MEDIUM, CLINICAL, "Labelled admission, discharge, service or death date",
        labelled_finder(CLINICAL_DATE_LABEL, DATE, "da"),
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
        regex_finder(
            r"(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]{1,64}@(?P<domain>[A-Za-z0-9-]++(?:\.[A-Za-z0-9-]++)*\.[A-Za-z]{2,}+)\b",
            validate=_email_valid,
        ),
    ),
    Detector(
        "street_address", MEDIUM, CONTACT, "Street address",
        regex_finder(
            rf"\b\d{{1,6}}\s++(?:[NSEW]\.?\s++)?(?:{_PLACE_WORD}\s++){{1,3}}(?:{STREET_SUFFIX}|{STREET_SUFFIX.upper()})\b\.?"
            r"(?:,?\s++(?:Apt|Unit|Suite|Ste|APT|UNIT|SUITE|STE|#)\.?\s*+[\w-]+)?"
        ),
    ),
    Detector(
        "city_state_zip", MEDIUM, CONTACT, "City, state and ZIP code",
        regex_finder(rf"\b{_PLACE_WORD}(?:\s{_PLACE_WORD}){{0,3}},\s*+(?:{US_STATES})\s++\d{{5}}(?:-\d{{4}})?\b"),
    ),
    Detector(
        "provider_npi", LOW, PROVIDER, "National Provider Identifier (check digit valid)",
        regex_finder(r"(?<![\d-])[12]\d{9}(?![\d-])", validate=_npi_valid),
    ),
    Detector(
        "provider_dea", LOW, PROVIDER, "DEA registration number (checksum valid)",
        regex_finder(r"\b[ABCDEFGHJKLMPRSTUX][A-Z9]\d{7}\b", validate=_dea_valid),
    ),
    Detector(
        "ip_address", LOW, NETWORK, "Public IPv4 address",
        regex_finder(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])", validate=_ip_valid),
    ),
]

CATEGORIES = sorted({d.name for d in DETECTORS})


def _sort_key(f: Finding) -> tuple[int, int]:
    return f.start, -SEVERITY_RANK[f.severity]


def detect(text: str, disabled: set[str] | frozenset[str] = frozenset()) -> list[Finding]:
    """Run every enabled detector over `text` exactly as given, without
    normalising it. Spans are offsets into `text`."""
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
    out.sort(key=_sort_key)
    return out


def run_detectors(text: str, disabled: set[str] | frozenset[str] = frozenset()) -> list[Finding]:
    """Run every enabled detector over the normalised view of `text`. Spans are
    offsets into the original text. Line and column are filled in by the
    scanner."""
    view = normalize(text)
    findings = detect(view.text, disabled)
    if view.offsets is None:
        return findings
    out: list[Finding] = []
    seen: set[tuple[str, int, int]] = set()
    for f in findings:
        s, e = view.to_original(f.start, f.end)
        if (f.category, s, e) not in seen:
            seen.add((f.category, s, e))
            out.append(Finding(f.category, f.severity, f.group, s, e))
    out.sort(key=_sort_key)
    return out
