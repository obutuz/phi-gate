"""A change is judged by what it adds, read with the file around it (issue #2).

Through the CLI and a real git repository: rows appended under a header that
was committed earlier, a diagnosis added beside a name already in the file,
files too large or too filtered to read whole, and the edits that must still
pass. All identifiers are synthetic."""

import subprocess
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from test_gates import CliCase  # noqa: E402

HEADER = "patient_name,visit_date\n"
ROWS = "Grace Wanjiru,2026-03-14\nPeter Otieno,2026-04-02\n"
ALLOW_TABLE = '[phi-gate]\nallow_paths = ["tests/fixtures/*", "visits.csv", "notes.md"]\n'
DEFAULT = '[phi-gate]\nallow_paths = ["tests/fixtures/*"]\n'


class Changes(CliCase):
    def setUp(self):
        super().setUp()
        subprocess.run(["rm", "-rf", str(self.dir / "data")], check=True)

    def commit(self, message="base", *paths):
        self.git("add", *(paths or ["-A"]))
        self.git("commit", "-qm", message)

    def commit_allowed(self, name, text):
        """A file with PHI that went in while its path was allowed, and the
        allowance taken away afterwards: the state an old table is in."""
        (self.dir / ".phi-gate.toml").write_text(ALLOW_TABLE)
        (self.dir / name).write_text(text)
        self.commit("allowed then")
        (self.dir / ".phi-gate.toml").write_text(DEFAULT)
        self.commit("not any more")

    def staged_scan(self):
        return self.cli("scan", "--staged")

    def assertStagedBlocked(self, name):
        result = self.staged_scan()
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn(name, result.stdout + result.stderr)

    def assertStagedAllowed(self):
        result = self.staged_scan()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    # -- the issue ---------------------------------------------------------

    def test_rows_under_a_header_committed_earlier(self):
        (self.dir / "visits.csv").write_text(HEADER)
        self.commit()
        (self.dir / "visits.csv").write_text(HEADER + ROWS)
        self.git("add", "visits.csv")
        self.assertStagedBlocked("visits.csv")

    def test_rows_added_between_old_rows(self):
        self.commit_allowed("visits.csv", HEADER + "Grace Wanjiru,2026-03-14\n\n# end\n")
        (self.dir / "visits.csv").write_text(HEADER + "Grace Wanjiru,2026-03-14\nPeter Otieno,2026-04-02\n\n# end\n")
        self.git("add", "visits.csv")
        self.assertStagedBlocked("visits.csv")

    def test_a_diagnosis_added_beside_a_name_already_there(self):
        for label in ("Patient Name", "Name"):
            with self.subTest(label=label):
                self.commit_allowed("notes.md", f"{label}: Grace Wanjiru\n\nSeen today.\n")
                (self.dir / "notes.md").write_text(f"{label}: Grace Wanjiru\n\nSeen today.\nDx: F84.0\n")
                self.git("add", "notes.md")
                self.assertStagedBlocked("notes.md")
                self.git("reset", "-q", "--hard")

    def test_a_diagnosis_far_from_any_name_only_warns(self):
        self.commit_allowed("notes.md", "Name: Grace Wanjiru\n" + "\n" * 3 + "x" * 900 + "\n")
        with (self.dir / "notes.md").open("a") as fh:
            fh.write("Dx: F84.0\n")
        self.git("add", "notes.md")
        self.assertStagedAllowed()

    # -- what must still pass ----------------------------------------------

    def test_an_edit_away_from_old_phi_passes(self):
        self.commit_allowed("visits.csv", HEADER + ROWS + "\n# notes\n")
        with (self.dir / "visits.csv").open("a") as fh:
            fh.write("# reviewed in March\n")
        self.git("add", "visits.csv")
        self.assertStagedAllowed()

    def test_a_header_alone_passes(self):
        (self.dir / "visits.csv").write_text(HEADER)
        self.git("add", "visits.csv")
        self.assertStagedAllowed()

    def test_code_beside_a_table_header_passes(self):
        (self.dir / "visits.csv").write_text(HEADER)
        self.commit()
        (self.dir / "src" / "app.py").write_text("def total(xs):\n    return sum(xs) + 1\n")
        self.git("add", "src/app.py")
        self.assertStagedAllowed()

    # -- when the whole file is not to hand --------------------------------

    def test_an_oversize_table_is_read_under_its_first_line(self):
        filler = "".join(f"9{i:08d},2026-01-01\n" for i in range(2000))
        (self.dir / ".phi-gate.toml").write_text(DEFAULT + "max_bytes = 4096\n")
        (self.dir / "visits.csv").write_text(HEADER + filler)
        self.commit()
        with (self.dir / "visits.csv").open("a") as fh:
            fh.write(ROWS)
        self.git("add", "visits.csv")
        self.assertStagedBlocked("visits.csv")

    def test_a_filtered_diff_is_read_under_the_first_line(self):
        # A textconv driver shows git a different text from the file's bytes,
        # so the file's own lines cannot place the change.
        (self.dir / ".gitattributes").write_text("*.csv diff=upper\n")
        self.git("config", "diff.upper.textconv", "tr a-z A-Z <")
        (self.dir / "visits.csv").write_text(HEADER)
        self.commit()
        (self.dir / "visits.csv").write_text(HEADER + ROWS)
        self.git("add", "visits.csv")
        self.assertStagedBlocked("visits.csv")

    def test_unstaged_rows_under_a_committed_header(self):
        (self.dir / "visits.csv").write_text(HEADER)
        self.commit()
        (self.dir / "visits.csv").write_text(HEADER + ROWS)
        result = self.cli("scan", "--diff")
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)

    def test_many_changed_files_in_one_commit(self):
        for n in range(40):
            (self.dir / f"t{n}.csv").write_text(HEADER)
        self.commit()
        for n in range(40):
            (self.dir / f"t{n}.csv").write_text(HEADER + (ROWS if n == 37 else "\n# nothing\n"))
        self.git("add", "-A")
        self.assertStagedBlocked("t37.csv")


if __name__ == "__main__":
    unittest.main()
