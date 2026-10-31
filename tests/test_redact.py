import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from phi_gate.redact import redact, restore  # noqa: E402


class Redaction(unittest.TestCase):
    TEXT = "Patient Name: Jane Doe, DOB: 04/12/1980, SSN 123-45-6789. Jane Doe's SSN 123-45-6789 again."

    def test_typed_placeholders_and_consistency(self):
        out, mapping = redact(self.TEXT)
        self.assertNotIn("123-45-6789", out)
        self.assertNotIn("04/12/1980", out)
        self.assertIn("[SSN_1]", out)
        self.assertEqual(out.count("[SSN_1]"), 2)
        self.assertIn("DOB: [DOB_1]", out)
        self.assertEqual(mapping["[SSN_1]"], "123-45-6789")

    def test_round_trip(self):
        out, mapping = redact(self.TEXT)
        self.assertEqual(restore(out, mapping), self.TEXT)

    def test_table_keeps_shape_and_clinical_columns(self):
        csv = "patient_name,dob,member_id,dx,carc,amount\nMaria Lopez,1984-02-17,W483920175,F84.0,CO-197,412.50\nKevin Osei,1979-09-03,W582910446,F84.0,CO-16,98.00\n"
        out, mapping = redact(csv)
        lines = out.splitlines()
        self.assertEqual(lines[0], "patient_name,dob,member_id,dx,carc,amount")
        self.assertEqual(lines[1], "[PATIENT_NAME_1],[DOB_1],[MEMBER_ID_1],F84.0,CO-197,412.50")
        self.assertEqual(lines[2], "[PATIENT_NAME_2],[DOB_2],[MEMBER_ID_2],F84.0,CO-16,98.00")
        self.assertEqual(restore(out, mapping), csv)
        from phi_gate.config import Config
        from phi_gate.scanner import scan_text

        self.assertEqual(scan_text(out, Config()).decision, "allow")

    def test_x12_segment_fully_redacted(self):
        out, _ = redact("NM1*QC*1*LOPEZ*MARIA****MI*W483920175~DMG*D8*19840217*F~")
        self.assertNotIn("W483920175", out)
        self.assertNotIn("LOPEZ", out)

    def test_clean_text_unchanged(self):
        text = "def add(a, b):\n    return a + b\n"
        out, mapping = redact(text)
        self.assertEqual(out, text)
        self.assertEqual(mapping, {})

    def test_redacted_output_passes_scan(self):
        from phi_gate.config import Config
        from phi_gate.scanner import scan_text

        out, _ = redact(self.TEXT)
        self.assertEqual(scan_text(out, Config()).decision, "allow")


if __name__ == "__main__":
    unittest.main()
