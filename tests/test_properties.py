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
from phi_gate.redact import redact  # noqa: E402
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
