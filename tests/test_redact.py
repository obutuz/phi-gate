import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from phi_gate.config import Config  # noqa: E402
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


class RedactionCannotLeak(unittest.TestCase):
    """Redaction is what a block tells an agent to use instead, so a value that
    survives it reaches the model with phi-gate's blessing."""

    HEADER = "patient_name,dob,member_id,carc,amount\n"

    def assertGone(self, text, *values):
        out, _ = redact(text, Config())
        for value in values:
            self.assertNotIn(value, out)
        return out

    def test_a_quoted_comma_does_not_shift_the_columns(self):
        row = '"Lopez, Maria",1984-02-17,W483920175,CO-197,412.50\n'
        out = self.assertGone(self.HEADER + row, "Lopez", "Maria", "1984-02-17", "W483920175")
        self.assertIn("CO-197,412.50", out)

    def test_quotes_survive_around_the_placeholder(self):
        out = self.assertGone(self.HEADER + '"Lopez, Maria",1984-02-17,W483920175,CO-197,412.50\n', "Maria")
        self.assertIn('"[PATIENT_NAME_1]"', out)

    def test_a_row_of_the_wrong_width_goes_entirely(self):
        row = "Maria Lopez,1984-02-17,W483920175,CO-197,412.50,extra,more\n"
        self.assertGone(self.HEADER + row, "Maria Lopez", "W483920175", "extra")

    def test_a_stray_quote_cannot_expose_the_rest_of_the_row(self):
        self.assertGone(self.HEADER + 'Maria "Mia" Lopez,1984-02-17,W483920175,CO-197,412.50\n', "W483920175")

    def test_a_cell_spanning_lines(self):
        text = 'patient_name,address,mrn\n"Maria Lopez","12 Elm St\nApt 4",00482913\n'
        self.assertGone(text, "Maria", "12 Elm St", "Apt 4", "00482913")

    def test_rows_after_a_malformed_row_are_still_redacted(self):
        text = self.HEADER + "a,b\nKevin Osei,1979-09-03,W582910446,CO-16,98.00\n"
        self.assertGone(text, "Kevin Osei", "W582910446")

    def test_identifying_columns_that_are_not_on_any_fixed_list(self):
        for column, value in (
            ("full_name", "Maria Lopez"), ("name", "Maria Lopez"), ("patient", "Maria Lopez"),
            ("city", "Pittsburgh"), ("address2", "Apt 4"), ("fax_number", "412-867-5309"),
            ("guarantor_name", "Kevin Osei"), ("emergency_contact_phone", "412-867-5309"),
            ("clinical_notes", "Lives with daughter Ana"),
        ):
            with self.subTest(column):
                self.assertGone(f"{column},dob,mrn,carc\n{value},1984-02-17,00482913,CO-16\n", value)

    def test_clinical_and_organisation_columns_stay(self):
        text = "patient_name,dob,payer_name,provider_name,diagnosis_code,amount\n"
        text += "Maria Lopez,1984-02-17,Aetna,Dr Shah Clinic,F84.0,412.50\n"
        out = self.assertGone(text, "Maria Lopez")
        for value in ("Aetna", "Dr Shah Clinic", "F84.0", "412.50"):
            self.assertIn(value, out)


if __name__ == "__main__":
    unittest.main()
