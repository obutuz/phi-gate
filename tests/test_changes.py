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


class ChangeCase(CliCase):
    """A repository whose only PHI is what each test puts there."""

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



class Changes(ChangeCase):
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


class WhatAChangeIntroduces(ChangeCase):
    """Findings the new file has that the old one did not: some appear on a
    line the change never touched."""

    def test_a_header_added_over_rows_already_committed(self):
        (self.dir / "visits.csv").write_text(ROWS)
        self.commit()
        (self.dir / "visits.csv").write_text(HEADER + ROWS)
        self.git("add", "visits.csv")
        self.assertStagedBlocked("visits.csv")

    def test_deleting_the_line_between_a_header_and_rows(self):
        (self.dir / "visits.csv").write_text(HEADER + "\n" + ROWS)
        self.commit()
        (self.dir / "visits.csv").write_text(HEADER + ROWS)
        self.git("add", "visits.csv")
        self.assertStagedBlocked("visits.csv")

    def test_evidence_that_completes_a_fhir_patient(self):
        (self.dir / "p.json").write_text('{\n  "resourceType": "Patient",\n  "id": "p1"\n}\n')
        self.commit()
        (self.dir / "p.json").write_text(
            '{\n  "resourceType": "Patient",\n  "id": "p1",\n  "name": [{"family": "Wanjiru"}]\n}\n'
        )
        self.git("add", "p.json")
        self.assertStagedBlocked("p.json")

    def test_a_name_added_beside_a_diagnosis_already_there(self):
        self.commit_allowed("notes.md", "Seen today.\nDx: F84.0\n")
        (self.dir / "notes.md").write_text("Name: Grace Wanjiru\nSeen today.\nDx: F84.0\n")
        self.git("add", "notes.md")
        self.assertStagedBlocked("notes.md")

    def test_a_row_copied_within_a_table(self):
        self.commit_allowed("visits.csv", HEADER + ROWS)
        (self.dir / "visits.csv").write_text(HEADER + ROWS + "Peter Otieno,2026-04-02\n")
        self.git("add", "visits.csv")
        self.assertStagedBlocked("visits.csv")

    def test_a_file_renamed_out_of_an_allowed_path(self):
        fixture = self.dir / "tests" / "fixtures" / "visits.csv"
        fixture.write_text(HEADER + ROWS)
        self.commit()
        self.git("mv", "tests/fixtures/visits.csv", "visits.csv")
        self.assertStagedBlocked("visits.csv")

    def test_the_first_commit(self):
        (self.dir / "visits.csv").write_text(HEADER + ROWS)
        self.git("add", "visits.csv")
        self.assertStagedBlocked("visits.csv")

    def test_reformatting_a_line_of_old_phi_passes(self):
        self.commit_allowed("notes.md", "SSN: 234-56-7891\n")
        (self.dir / "notes.md").write_text("SSN: 234-56-7891   \n")
        self.git("add", "notes.md")
        self.assertStagedAllowed()

    def test_moving_old_phi_within_a_file_passes(self):
        self.commit_allowed("notes.md", "intro\n\nSSN: 234-56-7891\n\noutro\n")
        (self.dir / "notes.md").write_text("SSN: 234-56-7891\n\nintro\n\noutro\n")
        self.git("add", "notes.md")
        self.assertStagedAllowed()


class HowGitIsRead(ChangeCase):
    """What git prints depends on its configuration and the file's bytes."""

    def test_a_carriage_return_inside_a_line_does_not_hide_the_next_file(self):
        (self.dir / "a.txt").write_text("start\n")
        self.commit()
        (self.dir / "a.txt").write_bytes(b"start\nfoo\rbar\nbaz\rqux\n")
        (self.dir / "b.md").write_text("SSN: 234-56-7891\n")
        self.git("add", "a.txt", "b.md")
        self.assertStagedBlocked("b.md")

    def test_mnemonic_prefixes(self):
        self.git("config", "diff.mnemonicPrefix", "true")
        (self.dir / "visits.csv").write_text(HEADER)
        self.commit()
        (self.dir / "visits.csv").write_text(HEADER + ROWS)
        self.git("add", "visits.csv")
        self.assertStagedBlocked("visits.csv")

    def test_no_prefixes(self):
        self.git("config", "diff.noprefix", "true")
        (self.dir / "visits.csv").write_text(HEADER)
        self.commit()
        (self.dir / "visits.csv").write_text(HEADER + ROWS)
        self.git("add", "visits.csv")
        self.assertStagedBlocked("visits.csv")

    def test_a_path_git_quotes(self):
        name = 'vis"its\tnov.csv'
        (self.dir / name).write_text(HEADER)
        self.commit()
        (self.dir / name).write_text(HEADER + ROWS)
        self.git("add", "-A")
        self.assertStagedBlocked("vis")

    def test_a_byte_order_mark(self):
        (self.dir / "visits.csv").write_bytes(b"\xef\xbb\xbf" + HEADER.encode())
        self.commit()
        (self.dir / "visits.csv").write_bytes(b"\xef\xbb\xbf" + (HEADER + ROWS).encode())
        self.git("add", "visits.csv")
        self.assertStagedBlocked("visits.csv")

    def test_crlf_line_endings(self):
        (self.dir / "visits.csv").write_bytes(HEADER.replace("\n", "\r\n").encode())
        self.commit()
        (self.dir / "visits.csv").write_bytes((HEADER + ROWS).replace("\n", "\r\n").encode())
        self.git("add", "visits.csv")
        self.assertStagedBlocked("visits.csv")

    def test_a_symlink_to_a_fifo_does_not_hang_commit_all(self):
        import os
        import time

        fifo = self.dir / "pipe"
        os.mkfifo(fifo)
        (self.dir / "link").symlink_to("notes.md")
        self.commit("base", "link")
        (self.dir / "link").unlink()
        (self.dir / "link").symlink_to(fifo)
        started = time.monotonic()
        result = self.cli("scan", "--diff")
        self.assertLess(time.monotonic() - started, 20)
        self.assertNotEqual(result.returncode, 2, result.stderr)

    def test_a_submodule_pointer_is_not_an_error(self):
        sub = self.dir / "sub"
        sub.mkdir()
        subprocess.run(["git", "init", "-q"], cwd=sub, check=True)
        subprocess.run(["git", "-c", "user.email=t@example.com", "-c", "user.name=t", "commit", "-q",
                        "--allow-empty", "-m", "s"], cwd=sub, check=True)
        self.git("add", "sub")
        result = self.staged_scan()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_many_large_files_over_the_read_budget(self):
        (self.dir / ".phi-gate.toml").write_text(DEFAULT + "max_bytes = 4096\n")
        filler = "".join(f"9{i:08d},2026-01-01\n" for i in range(150))  # about 3 KB
        for n in range(30):
            (self.dir / f"t{n:02d}.csv").write_text(HEADER + filler)
        self.commit()
        for n in range(30):
            with (self.dir / f"t{n:02d}.csv").open("a") as fh:
                fh.write(ROWS if n == 29 else "9999,2026-01-01\n")
        self.git("add", "-A")
        self.assertStagedBlocked("t29.csv")


class GitLfs(ChangeCase):
    """A file stored with git-lfs reaches git as a pointer; its content is
    in the object store, and that is what leaves with the push."""

    def pointer_for(self, data: bytes) -> tuple[str, bytes]:
        import hashlib

        oid = hashlib.sha256(data).hexdigest()
        pointer = f"version https://git-lfs.github.com/spec/v1\noid sha256:{oid}\nsize {len(data)}\n"
        return oid, pointer.encode()

    def store(self, oid: str, data: bytes):
        git_dir = Path(subprocess.run(["git", "rev-parse", "--git-common-dir"], cwd=self.dir, capture_output=True,
                                      text=True, check=True).stdout.strip())
        if not git_dir.is_absolute():
            git_dir = self.dir / git_dir
        target = git_dir / "lfs" / "objects" / oid[:2] / oid[2:4] / oid
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)

    def test_the_stored_object_is_scanned(self):
        data = (HEADER + ROWS).encode()
        oid, pointer = self.pointer_for(data)
        self.store(oid, data)
        (self.dir / "visits.csv").write_bytes(pointer)
        self.git("add", "visits.csv")
        self.assertStagedBlocked("visits.csv")

    def test_a_clean_object_passes(self):
        data = b"nothing,to,see\n1,2,3\n"
        oid, pointer = self.pointer_for(data)
        self.store(oid, data)
        (self.dir / "visits.csv").write_bytes(pointer)
        self.git("add", "visits.csv")
        self.assertStagedAllowed()

    def test_a_missing_object_follows_the_opaque_setting(self):
        _oid, pointer = self.pointer_for((HEADER + ROWS).encode())
        (self.dir / "visits.csv").write_bytes(pointer)
        self.git("add", "visits.csv")
        self.assertStagedAllowed()
        (self.dir / ".phi-gate.toml").write_text(DEFAULT + 'opaque = "block"\n')
        self.git("add", ".phi-gate.toml")
        self.assertStagedBlocked("visits.csv")


if __name__ == "__main__":
    unittest.main()
