"""Property-based tests. These need Hypothesis (`pip install -e '.[dev]'`) and
are skipped without it, so `python3 -m unittest` stays standard-library only."""

import csv
import io
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

try:
    from hypothesis import HealthCheck, given, settings
    from hypothesis import strategies as st
except ImportError as exc:
    raise unittest.SkipTest("Hypothesis is not installed") from exc

from phi_gate import audit  # noqa: E402
from phi_gate.config import Config  # noqa: E402
from phi_gate.detectors import cell_spans  # noqa: E402
from phi_gate.redact import redact, restore  # noqa: E402
from phi_gate.scanner import added_lines_by_file, decode_bytes, scan_text  # noqa: E402

CFG = Config()
QUICK = settings(max_examples=60, deadline=None, suppress_health_check=[HealthCheck.too_slow])

# The awkward characters real exports contain, next to ordinary text.
cell_text = st.text(alphabet="abcXYZ ,;\"'-.", min_size=1, max_size=16).filter(lambda s: s.strip(" \"',;-."))
member_id = st.from_regex(r"W[0-9]{9}", fullmatch=True)


def write_csv(rows):
    out = io.StringIO()
    writer = csv.writer(out, lineterminator="\n")
    writer.writerow(["patient_name", "dob", "member_id", "carc", "amount"])
    writer.writerows(rows)
    return out.getvalue()


class Scanning(unittest.TestCase):
    @QUICK
    @given(st.text(max_size=400))
    def test_any_text_gets_a_decision(self, text):
        self.assertIn(scan_text(text, CFG).decision, ("allow", "warn", "block"))

    @QUICK
    @given(st.binary(max_size=400))
    def test_any_bytes_decode_or_are_called_binary(self, raw):
        self.assertIsInstance(decode_bytes(raw), (str, type(None)))


class CellSpans(unittest.TestCase):
    @QUICK
    @given(st.lists(cell_text, min_size=1, max_size=6))
    def test_agree_with_the_csv_module(self, cells):
        row = write_csv([]).replace(write_csv([]), "")  # an empty start, to read the next line clearly
        out = io.StringIO()
        csv.writer(out, lineterminator="").writerow(cells)
        row = out.getvalue()
        spans = cell_spans(row, ",")
        self.assertEqual(len(spans), len(cells))
        pieces = [row[a:b] for a, b in spans]
        self.assertEqual(next(csv.reader(pieces and [",".join(pieces)])), cells)


class Redaction(unittest.TestCase):
    @QUICK
    @given(st.lists(st.tuples(cell_text, member_id), min_size=1, max_size=6))
    def test_no_identifier_survives_however_the_cells_are_quoted(self, people):
        rows = [[name, "1984-02-17", member, "CO-197", "412.50"] for name, member in people]
        out, mapping = redact(write_csv(rows), CFG)
        for name, member in people:
            self.assertNotIn(member, out)
            self.assertNotIn(",".join(next(csv.reader([name]))) + ",1984", out)
        self.assertNotIn("1984-02-17", out)
        self.assertTrue(mapping)

    @QUICK
    @given(st.lists(st.tuples(cell_text, member_id), min_size=1, max_size=6))
    def test_a_redacted_table_passes_the_scanner(self, people):
        rows = [[name, "1984-02-17", member, "CO-197", "412.50"] for name, member in people]
        out, _ = redact(write_csv(rows), CFG)
        self.assertNotIn("tabular_phi", scan_text(out, CFG).summary())


# Synthetic identifiers: issued-range SSNs that are not on the dummy list,
# placeholder names, and record numbers of the shapes the detectors accept.
ssn = st.builds(
    lambda a, g, s: f"{a:03d}-{g:02d}-{s:04d}",
    st.integers(100, 665), st.integers(10, 98), st.integers(1000, 9998),
)
person = st.sampled_from(["Jane Doe", "John Smith", "JANE DOE", "SMITH, JOHN", "Maria Lopez", "Kevin Osei"])
birth = st.sampled_from(["1961-03-14", "03/14/1961", "14-Mar-1961", "March 14th, 1961", "19610314"])
record_no = st.from_regex(r"[A-Z]{1,3}[0-9]{6,9}", fullmatch=True)
separator = st.sampled_from([": ", " = ", "#: ", " ", '": "', "\t"])
field = st.one_of(
    st.tuples(st.sampled_from(["SSN", "ssn", "SS#", "Social Security Number"]), ssn),
    st.tuples(st.sampled_from(["DOB", "Date of Birth", "birthDate", "birthday"]), birth),
    st.tuples(st.sampled_from(["MRN", "MR#", "Pt ID", "patient_id", "Encounter #"]), record_no),
    st.tuples(st.sampled_from(["Member ID", "Mbr ID", "subscriber_id", "Medicaid ID", "Insured ID"]), record_no),
    st.tuples(st.sampled_from(["Patient Name", "patientName", "Member Name"]), person),
)

COLUMNS = {
    "patient_name": person, "PatientName": person, "First": st.just("Jane"), "Last": st.just("Doe"),
    "DOB": birth, "DateOfBirth": birth, "Member #": record_no, "Mbr_ID": record_no, "MRN": record_no,
    "Account #": record_no, "Policy #": record_no, "Medicaid #": record_no, "SSN": ssn,
    "Payer": st.sampled_from(["Aetna", "Gold Plan"]), "amount": st.sampled_from(["12.00", "412.50"]),
    "dx": st.sampled_from(["F84.0", "E11.9"]),
}


@st.composite
def tables(draw):
    names = draw(st.lists(st.sampled_from(sorted(COLUMNS)), min_size=3, max_size=6, unique=True))
    names = [*names, "MRN"] if not any(n in ("MRN", "SSN", "DOB", "DateOfBirth") for n in names) else names
    rows = draw(st.lists(st.tuples(*(COLUMNS[n] for n in names)), min_size=1, max_size=5))
    out = io.StringIO()
    writer = csv.writer(out, lineterminator="\n")
    writer.writerow(names)
    if draw(st.booleans()):
        out.write("\n")  # a blank line under the header
    for k, row in enumerate(rows):
        if k and draw(st.booleans()):
            out.write("\n")  # a blank line between rows
        writer.writerow(row)
    return out.getvalue()


def high_findings(text):
    return [f.category for f in scan_text(text, CFG).findings if f.severity == "high"]


class RedactionLeavesNothingToBlock(unittest.TestCase):
    """What redaction returns must pass the scanner that sent the agent to it."""

    @QUICK
    @given(st.lists(st.tuples(field, separator), min_size=1, max_size=6), st.sampled_from([", ", "\n", "; "]))
    def test_records(self, fields, joiner):
        text = joiner.join(f"{label}{sep}{value}" for (label, value), sep in fields)
        out, mapping = redact(text, CFG)
        self.assertEqual(high_findings(out), [], (text, out))
        self.assertEqual(restore(out, mapping), text)

    @QUICK
    @given(tables())
    def test_tables(self, text):
        self.assertIn("tabular_phi", {f.category for f in scan_text(text, CFG).findings})
        out, mapping = redact(text, CFG)
        self.assertEqual(high_findings(out), [], (text, out))
        self.assertEqual(restore(out, mapping), text)


class DiffParser(unittest.TestCase):
    @QUICK
    @given(st.lists(st.text(alphabet="+-@ ab/", max_size=12), min_size=1, max_size=8))
    def test_every_added_line_is_kept_whatever_it_says(self, added):
        body = "".join(f"+{line}\n" for line in added)
        diff = f"+++ b/f.txt\n@@ -0,0 +1,{len(added)} @@\n{body}"
        self.assertEqual([text for _, text in added_lines_by_file(diff)["f.txt"]], added)


class AuditChain(unittest.TestCase):
    @QUICK
    @given(st.integers(0, 4), st.sampled_from(["block", "warn", "audited"]))
    def test_changing_any_line_breaks_the_chain(self, target, replacement):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = Config(root=Path(tmp))
            for n in range(5):
                audit.record(cfg, event="PreToolUse", decision="flagged", tool=f"tool{n}")
            log = Path(tmp) / cfg.audit_log
            lines = log.read_text().splitlines()
            lines[target] = lines[target].replace('"flagged"', f'"{replacement}"')
            log.write_text("\n".join(lines) + "\n")
            self.assertFalse(audit.verify(cfg).intact)


if __name__ == "__main__":
    unittest.main()
