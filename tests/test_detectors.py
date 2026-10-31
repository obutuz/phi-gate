"""Detector and policy tests. All identifiers below are synthetic."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from phi_gate.config import Config  # noqa: E402
from phi_gate.detectors import dea_ok, luhn_ok, npi_ok  # noqa: E402
from phi_gate.scanner import scan_text  # noqa: E402

CFG = Config()


def verdict(text):
    return scan_text(text, CFG)


class BlocksDirectIdentifiers(unittest.TestCase):
    CASES = {
        "ssn": "Patient SSN: 123-45-6789",
        "ssn bare labelled": "ssn=123456789",
        "dob": "DOB: 04/12/1980",
        "dob json": '{"birthDate": "1980-04-12"}',
        "dob words": "date of birth: April 12, 1980",
        "mrn": "MRN: 00482913",
        "mbi": "MBI 1EG4-TE5-MK73",
        "member id": "Medicaid ID: AB1234567",
        "patient name": "Patient Name: Jane Q Doe",
        "patient name json": '{"patientName": "Jane Doe"}',
        "x12 835/837": "NM1*QC*1*DOE*JOHN****MI*W123456789~DMG*D8*19800412*M~",
        "hl7 pid": "MSH|^~\\&|A|B\nPID|1||12345^^^MRN||DOE^JOHN^Q||19800412|M",
        "fhir": '{"resourceType": "Patient", "name": [{"family": "Doe", "given": ["Jane"]}]}',
        "csv export": "patient_name,dob,dx\nJohn Doe,1980-04-12,F84.0\n",
        "card": "card 4539 1488 0343 6467",
        "account": "Account Number: 0012345678",
        "diagnosis with name": "Name: Jane Doe, Dx: F84.0",
        "service date with phone": "DOS: 03/04/2026 callback (412) 867-5309",
        # Keys as they appear in JSON, YAML and code
        "date_of_birth yaml": "date_of_birth: 1984-02-17",
        "date_of_birth json": '{"date_of_birth": "1984-02-17"}',
        "birth_date": 'birth_date = "1984-02-17"',
        "dateOfBirth": '{"dateOfBirth": "1984-02-17"}',
        "patient_dob": "patient_dob: 1984-02-17",
        "patientDob": "patientDob: 1984-02-17",
        "member_id": "member_id: W483920175",
        "memberId": '{"memberId": "W483920175"}',
        "subscriber_id": 'subscriber_id="W483920175"',
        "patient_id": '{"patient_id": "00482913"}',
        "medical_record_number": "medical_record_number: 00482913",
        "medicaid_id": "medicaid_id: AB1234567",
        "policy_number": 'policy_number = "W483920175"',
        "account_number": "account_number: 0012345678",
        "patient_ssn": "patient_ssn: 123456789",
        # Separators people actually type
        "ssn with spaces": "SSN: 123 45 6789",
        "ssn with dots": "ssn=123.45.6789",
        # Line endings: real HL7 separates segments with CR
        "hl7 cr": "MSH|^~\\&|A|B\rPID|1||12345^^^MRN||DOE^JOHN^Q||19800412|M\rPV1|1|O\r",
        "hl7 crlf": "MSH|^~\\&|A|B\r\nPID|1||12345^^^MRN||DOE^JOHN^Q||19800412|M\r\nPV1|1|O\r\n",
        "x12 pipe delimiter": "NM1|QC|1|DOE|JOHN||||MI|W123456789~",
        "x12 dmg pipe delimiter": "DMG|D8|19800412|M~",
        # Tables
        "two columns": "patient_name,dob\nMaria Lopez,1984-02-17\n",
        "two columns, id and surname": "mrn,last_name\n00482913,Lopez\n",
        "quoted commas": 'patient_name,address,member_id\n"Lopez, Maria","12 Elm St, Apt 4",W483920175\n',
        "cell spanning lines": 'patient_name,address,mrn\n"Maria Lopez","12 Elm St\nApt 4",00482913\n',
        "table with no digits": "patient_name,city,payer\nMaria Lopez,Pittsburgh,Aetna\n",
        "malformed only row in a wide table": "patient_name,dob,mrn,carc\nMaria Lopez,1984-02-17,00482913,CO-16,x,y\n",
        "trailing delimiter on every row": "patient_name,dob,mrn,\nMaria Lopez,1984-02-17,00482913,\n",
        "tab separated": "patient_name\tdob\tmrn\nMaria Lopez\t1984-02-17\t00482913\n",
    }

    def test_blocks(self):
        for label, text in self.CASES.items():
            with self.subTest(label):
                self.assertEqual(verdict(text).decision, "block", label)


class AllowsSyntheticAndOrdinaryCode(unittest.TestCase):
    CASES = {
        "never-issued ssn (synthea style)": "SSN 999-12-3456",
        "000 area ssn": "000-12-3456",
        "fictional phone": "Call 212-555-0123",
        "toll free": "Call 1-800-555-7788",
        "example email": "write to jane.doe@example.com",
        "stripe test card": "4242 4242 4242 4242",
        "org named as client": 'clientName: "Woodmere Financial"',
        "markdown schema table": "| mrn | dob |\n|---|---|\n| string | date |\n",
        "code with dates and versions": "const t = items.reduce((a, b) => a + b, 0); // 2024-10-06 v1.2.3",
        "variable named patientId": "const patientId = patient.id",
        "uuid": "id: 3f2b1c9e-8a7d-4e6f-9b0a-1c2d3e4f5a6b",
        "python signature": "def __setattr__(self, name, value):\n    self.x = 12\n",
        "tuple of names": "(name, value)\nx = 12\n",
        "for loop over names": "for type, name, param in items:\n    print(12)\n",
        "schema column type": "patient_id INT8 NOT NULL,\nmember_id UUID4,\n",
        "policy id is not insurance": 'policy_id = "arn123456"',
        "float digits": "x = 676.5203681218835 / z",
        "large float": "3002399751580331.0",
        "calendar row": "23 24 25 26 27 28 29 30",
        "prose with commas": "Patient, DOB and MRN are required\nfor 12 visits\n",
        "a list of column names in code": '    "patient_name", "dob", "member_id", "carc",\n    "ssn", 12,\n',
        "a call whose arguments name a column": '    "medicare_mbi", HIGH, DIRECT, "Medicare ID",\n    12,\n',
        "column names in a tuple": '("patient_name", "dob", "member_id", "ssn", "mrn"),\n    12,\n',
        "iso timestamp": "created_at: 2026-10-06T22:31:00Z",
        "sql schema": "CREATE TABLE patients (ssn TEXT, dob DATE, mrn TEXT);",
        "column names only csv": "patient_name,dob,mrn\n",
    }

    def test_not_blocked(self):
        for label, text in self.CASES.items():
            with self.subTest(label):
                self.assertNotEqual(verdict(text).decision, "block", label)


class RecordRule(unittest.TestCase):
    def test_contact_card_without_health_info_only_warns(self):
        v = verdict("Name: Jane Doe\nPhone: (412) 867-5309\nEmail: jane@acme-clinic.org")
        self.assertEqual(v.decision, "warn")

    def test_package_json_author_only_warns(self):
        v = verdict('"author": {"name": "Sindre Sorhus", "email": "sindresorhus@gmail.com"}')
        self.assertEqual(v.decision, "warn")

    def test_clinical_far_from_identifier_warns(self):
        text = "Name: Jane Doe\n" + ("x" * 1000) + "\nDx: F84.0"
        self.assertEqual(verdict(text).decision, "warn")

    def test_window_is_configurable(self):
        text = "Name: Jane Doe\n" + ("x" * 1000) + "\nDx: F84.0"
        self.assertEqual(scan_text(text, Config(record_window=2000)).decision, "block")


class Validators(unittest.TestCase):
    def test_luhn(self):
        self.assertTrue(luhn_ok("79927398713"))
        self.assertFalse(luhn_ok("79927398710"))

    def test_npi(self):
        self.assertTrue(npi_ok("1234567893"))  # CMS documentation example
        self.assertFalse(npi_ok("1234567890"))

    def test_dea(self):
        self.assertTrue(dea_ok("AB1234563"))
        self.assertFalse(dea_ok("AB1234567"))

    def test_npi_is_informational_only(self):
        v = verdict("Rendering provider NPI 1234567893")
        self.assertEqual(v.decision, "allow")
        self.assertIn("provider_npi", v.summary(include_low=True))


class FindingsNeverCarryValues(unittest.TestCase):
    def test_no_value_in_findings_or_summary(self):
        secret = "123-45-6789"
        v = verdict(f"SSN: {secret}")
        blob = repr(v.findings) + v.summary() + " ".join(v.reasons) + str([f.to_dict() for f in v.findings])
        self.assertNotIn(secret, blob)
        self.assertNotIn("6789", blob)

    def test_line_numbers(self):
        v = verdict("ok\nok\nSSN: 123-45-6789\n")
        self.assertEqual(v.findings[0].line, 3)
        self.assertEqual(v.findings[0].col, 6)


class ConfigOptions(unittest.TestCase):
    def test_disable_category(self):
        self.assertEqual(scan_text("SSN: 123-45-6789", Config(disable=["ssn"])).decision, "allow")

    def test_allow_values(self):
        cfg = Config(allow_values=[r"123-45-6789"])
        self.assertEqual(scan_text("SSN: 123-45-6789", cfg).decision, "allow")

    def test_bad_config_raises(self):
        from phi_gate.config import ConfigError

        with self.assertRaises(ConfigError):
            Config(mode="yolo")
        with self.assertRaises(ConfigError):
            Config(disable=["not_a_category"])


class Hints(unittest.TestCase):
    """Hints are an optimisation: they must never change what is found."""

    def test_same_findings_without_them(self):
        import dataclasses
        from unittest import mock

        from phi_gate import detectors

        bare = [dataclasses.replace(d, hints=()) for d in detectors.DETECTORS]
        texts = [*BlocksDirectIdentifiers.CASES.values(), *AllowsSyntheticAndOrdinaryCode.CASES.values()]
        for text in texts:
            hinted = detectors.run_detectors(text)
            with mock.patch.object(detectors, "DETECTORS", bare):
                self.assertEqual(hinted, detectors.run_detectors(text), text)


if __name__ == "__main__":
    unittest.main()
