"""Detector and redaction hardening: evasions, formats and edge cases that
earlier versions missed. Every identifier below is synthetic, and every name
is a placeholder name."""

import sys
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from phi_gate import detectors  # noqa: E402
from phi_gate.config import Config  # noqa: E402
from phi_gate.detectors import HIGH, run_detectors  # noqa: E402
from phi_gate.redact import redact, restore  # noqa: E402
from phi_gate.scanner import scan_text  # noqa: E402

CFG = Config()


def decision(text):
    return scan_text(text, CFG).decision


def categories(text):
    return {f.category for f in run_detectors(text)}


def values(text, category):
    return [text[f.start:f.end] for f in run_detectors(text) if f.category == category]


class BlockCase(unittest.TestCase):
    BLOCK: dict[str, str] = {}
    ALLOW: dict[str, str] = {}

    def test_blocks(self):
        for label, text in self.BLOCK.items():
            with self.subTest(label):
                self.assertEqual(decision(text), "block", text)

    def test_near_misses_do_not_block(self):
        for label, text in self.ALLOW.items():
            with self.subTest(label):
                self.assertNotEqual(decision(text), "block", text)


class Linear(unittest.TestCase):
    """No detector may backtrack its way into seconds on hostile input."""

    N = 20_000
    BOUND = 2.0  # seconds per detector per input: generous, the real cost is milliseconds

    LABELS = (
        "dob", "DOB#", "ssn", "SS#", "tin", "mrn", "MR#", "pt id", "member id", "Mbr ID", "policy #",
        "hicn", "name", "patient name", "dx", "icd-10-cm", "dos", "account #", "date of birth",
        "<ssn", "<DateOfBirth ", "encounter #", "birthday",
    )

    def inputs(self):
        n = self.N
        for label in self.LABELS:
            yield f"{label} x{n}", label + " " * n + "x"
            yield f"{label} repeated", (label + " ") * (n // len(label))
            yield f"{label} tabs and newlines", label + " \t\n" * (n // 3) + "x"
            yield f"{label} quotes", label + "\" ' # : = " * (n // 10) + "x"
            yield f"{label} paren", label + " (" * (n // 2)
            yield f"<{label}> attributes", f"<{label}" + " a=1" * (n // 4)
        yield "digits", "1" * n
        yield "dashed digits", "12-" * (n // 3)
        yield "spaced digits", "1 " * (n // 2)
        yield "slashed digits", "1/" * (n // 2)
        yield "letters", "A" * n
        yield "capital words", "Jane " * (n // 5)
        yield "capital words in a name field", "Patient Name: " + "JANE " * (n // 5) + "1"
        yield "email dots", "a@" + "a." * (n // 2) + "!"
        yield "email ats", "a@" * (n // 2)
        yield "x12 names", "NM1*QC*1*" * (n // 9)
        yield "x12 refs", "REF*SY*" * (n // 7)
        yield "hl7 escaped segments", "\\nPID|" * (n // 6)
        yield "hl7 lines", "PID|" + "a" * n
        yield "fhir anchors", '"resourceType":"Patient",' * (n // 25)
        yield "fhir xml anchors", "<Patient " + "a " * (n // 2)
        yield "fhir name objects", '"name":[{' * (n // 9)
        yield "street numbers", "12 " * (n // 3)
        yield "header rows", "patient_name,dob,mrn\n" * (n // 21)
        yield "quoted header rows", 'patient_name,dob,mrn\n"' * (n // 22)
        yield "unicode spaces", "SSN:" + "\u00a0" * n + "x"
        yield "zero-width", "S\u200bS\u200bN" * (n // 5)

    def test_every_detector_is_fast_on_hostile_input(self):
        for label, text in self.inputs():
            for det in detectors.DETECTORS:
                start = time.perf_counter()
                for _ in det.find(text):
                    pass
                elapsed = time.perf_counter() - start
                self.assertLess(elapsed, self.BOUND, f"{det.name} ({det.description}) on {label}: {elapsed:.2f}s")

    def test_the_label_separator_reported_slow(self):
        start = time.perf_counter()
        run_detectors("dob" + " " * 5000 + "x")
        self.assertLess(time.perf_counter() - start, 1.0)


class XmlLabels(BlockCase):
    BLOCK = {
        "ssn element": "<SSN>234567891</SSN>",
        "mrn element": "<mrn>1234567</mrn>",
        "member id element": "<MemberId>XYZ123456</MemberId>",
        "dob element": "<DateOfBirth>1961-03-14</DateOfBirth>",
        "name element": "<PatientName>Jane Doe</PatientName>",
        "element with attributes": '<ns:SSN type="primary">234-56-7891</ns:SSN>',
        "fhir xml patient": '<Patient xmlns="http://hl7.org/fhir"><id value="p1"/><birthDate value="1961-03-14"/></Patient>',
        "fhir xml name": '<Patient xmlns="http://hl7.org/fhir"><name><family value="Doe"/></name></Patient>',
    }
    ALLOW = {
        "element without a value": "<SSN></SSN>",
        "element holding a word": "<MemberId>unknown</MemberId>",
        "other element": "<SSNType>234567891</SSNType>",
        "fhir xml patient with only an id": '<Patient xmlns="http://hl7.org/fhir"><id value="p1"/></Patient>',
    }

    def test_value_attribute_is_the_value(self):
        text = '<birthDate value="1961-03-14"/>'
        self.assertEqual(values(text, "dob"), ["1961-03-14"])


class HashThenColon(BlockCase):
    BLOCK = {
        "ssn": "SSN#: 234567891",
        "mrn": "MRN#: 1234567",
        "member id": "Member ID #: XYZ123456789",
        "spaced": "SSN #: 234-56-7891",
    }
    ALLOW = {
        "hash then a word": "SSN#: required",
        "hash then too few digits": "MRN#: 12",
    }


class UnicodeEvasion(BlockCase):
    BLOCK = {
        "zero-width space in the value": "SSN: 234\u200b-56-7891",
        "zero-width joiner in the value": "234-56\u200d-7891",
        "soft hyphen in the value": "234-56-78\u00ad91",
        "zero-width space in the label": "D\u200bOB: 03/14/1961",
        "soft hyphen in the label": "S\u00adSN: 234567891",
        "en dash separators": "234\u201356\u20137891",
        "minus sign separators": "234\u221256\u22127891",
        "fullwidth hyphen separators": "234\uff0d56\uff0d7891",
        "no-break space separators": "SSN:\u00a0234\u00a056\u00a07891",
        "fullwidth digits": "SSN: \uff12\uff13\uff14\uff15\uff16\uff17\uff18\uff19\uff11",
        "fullwidth letters in an MBI": "\uff11\uff25\uff27\uff14\uff34\uff25\uff15\uff2d\uff2b\uff17\uff12",
        "cyrillic letter in the label": "\u0405SN: 234567891",
        "greek letter in the label": "\u039cRN: 1234567",
        "cyrillic letters in a name label": "P\u0430tient Name: Jane Doe",
    }
    ALLOW = {
        "accented prose": "Caf\u00e9 r\u00e9sum\u00e9, na\u00efve co\u00f6perate 12",
        "cyrillic prose": "\u041f\u0440\u0438\u0432\u0435\u0442, \u043c\u0438\u0440 2024",
        "an invalid SSN with an en dash": "999\u201312\u20133456",
    }

    def test_spans_point_at_the_original_characters(self):
        text = "x SSN: 234\u200b-56-7891 y"
        (finding,) = [f for f in run_detectors(text) if f.category == "ssn"]
        self.assertEqual(text[finding.start:finding.end], "234\u200b-56-7891")

    def test_expanded_characters_map_back(self):
        text = "SSN: \uff12\uff13\uff14\uff15\uff16\uff17\uff18\uff19\uff11 end"
        (finding,) = [f for f in run_detectors(text) if f.category == "ssn"]
        self.assertEqual(finding.start, 5)
        self.assertEqual(text[finding.end:], " end")

    def test_redaction_removes_the_original_characters(self):
        text = "SSN: 234\u200b-56-7891 and D\u200bOB: 03\u201314\u20131961."
        out, mapping = redact(text)
        for fragment in ("234", "7891", "1961"):
            self.assertNotIn(fragment, out)
        self.assertEqual(restore(out, mapping), text)

    def test_ascii_text_is_not_copied(self):
        view = detectors.normalize("plain ascii")
        self.assertIsNone(view.offsets)


class TableHeaders(BlockCase):
    BLOCK = {
        "camelCase": "PatientName,MemberID,DateOfBirth\nJane Doe,XYZ123456,1961-03-14\n",
        "member hash": "Member #,Plan,Amount\nXYZ123456,Gold,12.00\n",
        "mbr_id": "Mbr_ID,Plan,Amount\nXYZ123456,Gold,12.00\n",
        "subscriber no": "Subscriber No,Plan,Amount\nXYZ123456,Gold,12.00\n",
        "insured id": "Insured ID,Plan,Amount\nXYZ123456,Gold,12.00\n",
        "patient account": "Patient Acct #,Service,Amount\nA1234567,Office visit,12.00\n",
        "bracketed": "[MRN],[Patient Name],[DOB]\n1234567,Jane Doe,1961-03-14\n",
        "colon": "DOB:,Plan,Amount\n03/14/1961,Gold,12.00\n",
        "blank line after the header": "patient_name,dob,mrn\n\nJane Doe,1961-03-14,1234567\n",
    }
    ALLOW = {
        "a function signature": "def lookup(name, dob, ssn, mrn):\n    return 12\n",
        "a list literal": '["mrn", "dob", "ssn"]\nx = 12\n',
        "prose with a colon": "Note: patient, dob, mrn\n12 visits\n",
        "counts are not identifiers": "member_count,plan,total\n12,Gold,3\n",
        "two blank lines end a header": "patient_name,dob,mrn\n\n\nSee 12 notes, 3 files, 4 rows\n",
        "camelCase without identifiers": "UserName,CreatedAt,Total\nadmin,2024-01-02,12\n",
        "a call with arguments named like columns": "dups.append((name, member.name))\nx = 12\n",
        "subscripts": "row[mrn], row[dob], row[ssn]\n1, 2, 3\n",
    }

    def test_column_names(self):
        for raw, name in (
            ("PatientName", "patient_name"), ("MemberID", "member_id"), ("DateOfBirth", "date_of_birth"),
            ("Member #", "member_no"), ("[Patient Name]", "patient_name"), ("DOB:", "dob"),
            ("DOB (mm/dd/yyyy)", "dob"), ("Mbr_ID", "mbr_id"), ('"Patient Acct #"', "patient_acct_no"),
        ):
            with self.subTest(raw):
                self.assertEqual(detectors.normalize_column(raw), name)

    def test_public_header_api(self):
        header = detectors.parse_header("First,Last,DOB,Payer")
        self.assertIsNotNone(header)
        assert header is not None
        self.assertEqual(header.columns, ("first", "last", "dob", "payer"))
        self.assertEqual(header.identifier_columns, [0, 1, 2])
        self.assertIsNone(detectors.parse_header("a,b,c"))


class TableRedaction(unittest.TestCase):
    def assertGone(self, text, *gone):
        out, mapping = redact(text, CFG)
        for value in gone:
            self.assertNotIn(value, out)
        self.assertEqual(restore(out, mapping), text)
        self.assertNotIn(HIGH, {f.severity for f in scan_text(out, CFG).findings})
        return out

    def test_identifier_columns_beyond_the_old_vocabulary(self):
        text = "First,Last,DOB,Account #,Policy #,Medicaid #,Payer\nJane,Doe,1961-03-14,A1234567,P7654321,M1234567,Aetna\n"
        out = self.assertGone(text, "Jane", "Doe", "1961-03-14", "A1234567", "P7654321", "M1234567")
        self.assertIn(",Aetna", out)

    def test_claim_and_encounter_columns(self):
        text = "patient_name,claim_id,encounter_no,amount\nJane Doe,C1234567,E7654321,12.00\n"
        out = self.assertGone(text, "Jane Doe", "C1234567", "E7654321")
        self.assertIn("12.00", out)

    def test_rows_after_a_blank_line(self):
        text = (
            "patient_name,dob,member_id,amount\nJane Doe,1961-03-14,W483920175,1.00\n\n"
            "John Smith,1962-04-15,W582910446,2.00\n"
        )
        self.assertGone(text, "Jane Doe", "John Smith", "W582910446", "1962-04-15")

    def test_rows_after_a_blank_line_under_the_header(self):
        self.assertGone("patient_name,dob,mrn\n\nJane Doe,1961-03-14,1234567\n", "Jane Doe", "1234567")

    def test_a_second_table_keeps_its_own_layout(self):
        text = (
            "patient_name,dob,amount\nJane Doe,1961-03-14,1.00\n\n"
            "amount,mrn,patient_name\n2.00,1234567,John Smith\n"
        )
        out = self.assertGone(text, "Jane Doe", "John Smith", "1234567")
        self.assertIn("2.00", out)

    def test_a_member_column_that_also_names_a_plan(self):
        self.assertGone("patient_name,plan_member_id,amount\nJane Doe,W483920175,1.00\n", "W483920175")

    def test_the_last_column_name_is_not_a_label_for_the_next_line(self):
        out = self.assertGone("Payer,MRN,amount,patient_name\nAetna,AA000000,12.00,Jane Doe\n", "AA000000", "Jane Doe")
        self.assertEqual(out.splitlines()[1], "Aetna,[MRN_1],12.00,[PATIENT_NAME_1]")

    def test_a_finding_inside_a_kept_column_keeps_the_row_shape(self):
        text = "patient_name,remark,amount\nJane Doe,SSN 234-56-7891 on file,12.00\n"
        out = self.assertGone(text, "234-56-7891", "Jane Doe")
        self.assertEqual(out.splitlines()[1].count(","), 2)


class PlaceholderCollision(unittest.TestCase):
    TEXT = "Note: see [SSN_1]. SSN 234-56-7891"

    def test_a_literal_placeholder_is_not_reused(self):
        out, mapping = redact(self.TEXT)
        self.assertNotIn("[SSN_1]", mapping)
        self.assertEqual(out.count("[SSN_1]"), 1)
        self.assertNotIn("234-56-7891", out)

    def test_restore_gives_back_exactly_the_document(self):
        out, mapping = redact(self.TEXT)
        self.assertEqual(restore(out, mapping), self.TEXT)

    def test_restore_never_substitutes_a_value_it_did_not_replace(self):
        self.assertEqual(restore("see [SSN_1]", {"[SSN_2]": "234-56-7891"}), "see [SSN_1]")

    def test_restore_is_one_pass(self):
        mapping = {"[ROW_1]": "contains [SSN_1] as text", "[SSN_1]": "234-56-7891"}
        self.assertEqual(restore("[ROW_1]", mapping), "contains [SSN_1] as text")

    def test_overlapping_findings_leave_nothing_behind(self):
        text = "Patient Name: Jane Doe SSN 234-56-7891"
        out, _ = redact(text)
        self.assertNotIn("Doe", out)
        self.assertNotIn("7891", out)


class CaseAndFormatVariants(BlockCase):
    BLOCK = {
        "name in capitals": "Patient Name: JOHN SMITH",
        "surname first in capitals": "Patient Name: SMITH, JOHN",
        "lowercase mbi": "1eg4te5mk72",
        "spaced mbi": "1EG4 TE5 MK72",
        "lowercase x12 name": "nm1*qc*1*doe*john****mi*w123456789~",
        "lowercase x12 dob": "dmg*d8*19610314*f~",
        "icd without the dot, with a name": "Name: Jane Doe, Diagnosis: F840",
        "icd-10-cm label, with a name": "Name: Jane Doe\nICD-10-CM: F84.0",
        "dx codes label, with a name": "Name: Jane Doe\nDx Codes: F84.0",
        "ssn split across lines": "SSN: 234-56-\n7891",
        "dob split across lines": "DOB: 03/14/\n1961",
    }
    ALLOW = {
        "mixed-case token shaped like an mbi": "id = 1Eg4tE5mK72",
        "ten characters": "1EG4TE5MK7",
        "name placeholder": "Patient Name: N/A",
        "single word": "Patient Name: UNKNOWN",
        "organisation in capitals": "Patient Name: ACME HEALTH",
        "dx with a number only": "dx: 10",
    }

    def test_address_in_capitals(self):
        found = categories("123 MAIN ST, SPRINGFIELD, IL 62701")
        self.assertIn("street_address", found)
        self.assertIn("city_state_zip", found)

    def test_icd_variants(self):
        for text in ("Diagnosis: F840", "ICD-10-CM: F84.0", "Dx Codes: F84.0"):
            with self.subTest(text):
                self.assertIn("diagnosis", categories(text))

    def test_name_does_not_run_into_the_next_line(self):
        self.assertEqual(values("Patient Name: Jane Doe\nDOB: 03/14/1961", "person_name"), ["Jane Doe"])


class StructuredFormats(BlockCase):
    BLOCK = {
        "hl7 after a literal \\r": "MSH|^~\\&|A|B\\rPID|1||12345^^^MRN||DOE^JOHN||19610314|M",
        "hl7 after a literal \\n": '{"msg": "MSH|^~\\&|A|B\\nPID|1||12345^^^MRN||DOE^JOHN||19610314|M"}',
        "indented hl7": "sample:\n    PID|1||12345^^^MRN||DOE^JOHN||19610314|M\n",
        "x12 ssn reference": "REF*SY*234567891~",
        "x12 subscriber reference": "REF*0F*XYZ123456~",
        "x12 group or policy reference": "REF*1L*GRP12345~",
        "x12 dependent name": "NM1*03*1*DOE*JANE~",
        "fhir name text": '{"resourceType": "Patient", "name": [{"text": "Jane Doe"}]}',
        "fhir ssn identifier": (
            '{"resourceType": "Patient", "identifier": [{"system": "http://hl7.org/fhir/sid/us-ssn", '
            '"value": "999-12-3456"}]}'
        ),
    }
    ALLOW = {
        "x12 claim reference": "REF*D9*12345~",
        "x12 reference without digits": "REF*SY*NONE~",
        "pid in prose": "the PID| prefix marks a segment",
        "fhir patient with only an id": '{"resourceType": "Patient", "id": "p1"}',
        "fhir name text outside a name": '{"resourceType": "Patient", "maritalStatus": {"text": "Married"}}',
    }


class Labels(BlockCase):
    BLOCK = {
        "ss#": "SS#: 234567891",
        "tin": "TIN: 234 56 7891",
        "mr#": "MR#: 1234567",
        "pt id": "Pt ID: 1234567",
        "encounter #": "Encounter #: E1234567",
        "patientIdentifier": "patientIdentifier: 1234567",
        "mbr id": "Mbr ID: XYZ123456",
        "insured id": "Insured ID: XYZ123456",
        "hicn": "HICN: 234567891A",
        "birthday": "birthday: 1961-03-14",
        "dob with a format note": "DOB (MM/DD/YYYY): 03/14/1961",
        "day-month-year": "DOB: 14-Mar-1961",
        "ordinal date": "DOB: March 14th, 1961",
        "spaced date": "DOB: 03 14 1961",
        "member id in groups": "Member ID: XYZ 1234 5678",
    }
    ALLOW = {
        "tin as a word": "tin = 12",
        "pt id without digits": "Pt ID: abc",
        "birthday as prose": "birthday party on Saturday",
        "partial spaced date": "DOB: 03 14",
        "receipt id": "receipt id: 1234567",
        "option id": "opt_id: 1234567",
    }

    def test_grouped_member_id_is_one_value(self):
        self.assertEqual(values("Member ID: XYZ 1234 5678 on file", "member_id"), ["XYZ 1234 5678"])

    def test_prose_after_a_member_id_is_not_part_of_it(self):
        self.assertEqual(values("Member ID: W12345 is pending", "member_id"), ["W12345"])


class DummySsns(BlockCase):
    BLOCK = {
        "an ordinary valid ssn": "234-56-7891",
        "nearly repeated": "111-22-3334",
        "labelled ordinary": "SSN: 234567891",
    }
    ALLOW = {
        "woolworth wallet card": "078-05-1120",
        "ssa advertisement": "219-09-9999",
        "repeated digits": "111-22-3333",
        "repeated digits labelled": "SSN: 444-55-6666",
        "dummy labelled bare": "SSN: 078051120",
        "sequential example": "123-45-6789",
        "sequential example labelled": "SSN: 123456789",
    }


class Hints(unittest.TestCase):
    """Hints are an optimisation: they must never change what is found."""

    def test_same_findings_without_them(self):
        import dataclasses
        from unittest import mock

        bare = [dataclasses.replace(d, hints=()) for d in detectors.DETECTORS]
        cases = (XmlLabels, HashThenColon, UnicodeEvasion, TableHeaders, CaseAndFormatVariants, StructuredFormats,
                 Labels, DummySsns)
        texts = [t for case in cases for t in (*case.BLOCK.values(), *case.ALLOW.values())]
        for text in texts:
            hinted = detectors.run_detectors(text)
            with mock.patch.object(detectors, "DETECTORS", bare):
                self.assertEqual(hinted, detectors.run_detectors(text), text)


class PublicShape(unittest.TestCase):
    def test_severity_and_group_stay_strings_in_json(self):
        (finding,) = scan_text("SSN: 234-56-7891", CFG).findings
        self.assertEqual(
            finding.to_dict(), {"category": "ssn", "severity": "high", "group": "direct", "line": 1, "col": 6}
        )
        self.assertIsInstance(finding.severity, str)


if __name__ == "__main__":
    unittest.main()
