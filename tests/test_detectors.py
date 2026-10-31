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


if __name__ == "__main__":
    unittest.main()
