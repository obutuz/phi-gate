"""The CLI and git gates against the formats real exports arrive in, through
real files and a real git repository. All identifiers are synthetic."""

import gzip
import json
import os
import sqlite3
import subprocess
import sys
import unittest
import zipfile
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from test_hooks import ROOT, HookTestCase  # noqa: E402

from phi_gate.config import Config  # noqa: E402
from phi_gate.scanner import added_lines_by_file, scan_file  # noqa: E402

EXPORT = "patient_name,dob,member_id,carc,amount\nMaria Lopez,1984-02-17,W483920175,CO-197,412.50\n"
PHI_VALUES = ("Maria Lopez", "1984-02-17", "W483920175")


def zip_of(path, text):
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("export.csv", text)


def sqlite_of(path):
    db = sqlite3.connect(path)
    db.execute("create table patients (patient_name, dob, member_id)")
    db.execute("insert into patients values ('Maria Lopez', '1984-02-17', 'W483920175')")
    db.commit()
    db.close()


class CliCase(HookTestCase):
    def cli(self, *args, stdin=None, text=True):
        env = {**self.env, "PYTHONPATH": str(ROOT / "src")}
        return subprocess.run(
            [sys.executable, "-m", "phi_gate", *args],
            cwd=self.dir, env=env, capture_output=True, input=stdin, text=text,
        )

    def git(self, *args):
        subprocess.run(["git", *args], cwd=self.dir, check=True, capture_output=True)


class RedactSeesWhatScanSees(CliCase):
    """`phi-gate redact` is what a block message tells an agent to run, so it
    must never pass through bytes the scanner would have decoded."""

    def assertRedacted(self, result):
        self.assertEqual(result.returncode, 0, result.stderr)
        plain = result.stdout.replace("\x00", "")
        for value in PHI_VALUES:
            self.assertNotIn(value, plain)
        self.assertIn("[MEMBER_ID_1]", plain)

    def test_utf16_file(self):
        (self.dir / "e.csv").write_bytes(EXPORT.encode("utf-16"))
        self.assertRedacted(self.cli("redact", "e.csv"))

    def test_gzip_file(self):
        (self.dir / "e.csv.gz").write_bytes(gzip.compress(EXPORT.encode()))
        self.assertRedacted(self.cli("redact", "e.csv.gz"))

    def test_zip_file(self):
        zip_of(self.dir / "e.zip", EXPORT)
        self.assertRedacted(self.cli("redact", "e.zip"))

    def test_sqlite_file(self):
        sqlite_of(self.dir / "e.sqlite")
        self.assertRedacted(self.cli("redact", "e.sqlite"))

    def test_utf16_on_stdin(self):
        result = self.cli("redact", stdin=EXPORT.encode("utf-16"), text=False)
        self.assertEqual(result.returncode, 0)
        self.assertNotIn(b"W483920175", result.stdout.replace(b"\x00", b""))

    def test_refuses_a_format_it_cannot_read(self):
        (self.dir / "scan.pdf").write_bytes(b"%PDF-1.7 Maria Lopez")
        result = self.cli("redact", "scan.pdf")
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")
        self.assertIn("cannot read", result.stderr)


class ExitCodes(CliCase):
    """A gate that exits 0 on a path it never saw reports a clean scan of nothing."""

    def assertCleanError(self, result, code=2):
        self.assertEqual(result.returncode, code, result.stderr)
        self.assertNotIn("Traceback", result.stderr)

    def test_scan_of_a_missing_path_is_an_error(self):
        result = self.cli("scan", "no-such-file.csv")
        self.assertCleanError(result)
        self.assertIn("no-such-file.csv", result.stderr)

    def test_redact_of_a_missing_file_is_an_error(self):
        self.assertCleanError(self.cli("redact", "no-such-file.csv"))

    def test_restore_with_a_missing_map_is_an_error(self):
        self.assertCleanError(self.cli("restore", "--map", "no-such-map.json", stdin="x"))

    def test_restore_with_a_corrupt_map_is_an_error(self):
        (self.dir / "map.json").write_text("{not json")
        self.assertCleanError(self.cli("restore", "--map", "map.json", stdin="x"))

    @unittest.skipIf(os.geteuid() == 0, "root can read anything")
    def test_a_file_it_cannot_read_blocks(self):
        locked = self.dir / "locked.csv"
        locked.write_text(EXPORT)
        locked.chmod(0)
        try:
            self.assertCleanError(self.cli("scan", "locked.csv"), code=1)
        finally:
            locked.chmod(0o600)


class FormatsGitCallsBinary(CliCase):
    """Git shows no added lines for these, which is why a scan of the diff
    alone waved them through."""

    def assertStagedBlocked(self, name):
        self.git("add", name)
        result = self.cli("scan", "--staged")
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn(name, result.stdout)

    def test_utf16_csv(self):
        (self.dir / "e.csv").write_bytes(EXPORT.encode("utf-16"))
        self.assertStagedBlocked("e.csv")

    def test_zip(self):
        zip_of(self.dir / "e.zip", EXPORT)
        self.assertStagedBlocked("e.zip")

    def test_gzip(self):
        (self.dir / "e.gz").write_bytes(gzip.compress(EXPORT.encode()))
        self.assertStagedBlocked("e.gz")

    def test_sqlite(self):
        sqlite_of(self.dir / "e.sqlite")
        self.assertStagedBlocked("e.sqlite")

    def test_scans_the_staged_copy_not_the_working_tree(self):
        target = self.dir / "e.zip"
        zip_of(target, EXPORT)
        self.git("add", "e.zip")
        zip_of(target, "nothing,to,see\n")
        self.assertEqual(self.cli("scan", "--staged").returncode, 1)

    def test_an_allowlisted_binary_passes(self):
        fixture = self.dir / "tests" / "fixtures" / "e.zip"
        zip_of(fixture, EXPORT)
        self.git("add", "tests/fixtures/e.zip", ".phi-gate.toml")
        self.assertEqual(self.cli("scan", "--staged").returncode, 0)

    def test_commit_dash_a_checks_modified_binaries(self):
        target = self.dir / "e.zip"
        zip_of(target, "nothing,to,see\n")
        self.git("add", "e.zip")
        self.git("commit", "-m", "base")
        zip_of(target, EXPORT)
        self.assertBlocked(self.pre("Bash", {"command": "git commit -am update"}))

    def test_an_image_still_passes(self):
        (self.dir / "logo.png").write_bytes(b"\x89PNG\r\n\x1a\n" + bytes(range(256)))
        self.git("add", "logo.png")
        self.assertEqual(self.cli("scan", "--staged").returncode, 0)


class DiffParsing(CliCase):
    def test_a_line_that_looks_like_a_file_header_hides_nothing(self):
        (self.dir / "notes.txt").write_text("++ /dev/null\nSSN: 123-45-6789\n")
        self.git("add", "notes.txt")
        self.assertEqual(self.cli("scan", "--staged").returncode, 1)

    def test_lines_stay_with_their_file(self):
        diff = (
            "+++ b/a.txt\n@@ -0,0 +1,2 @@\n+one\n+++ b/fake.txt\n"
            "+++ b/b.txt\n@@ -3 +3 @@\n-old\n+new\n"
        )
        self.assertEqual(
            added_lines_by_file(diff),
            {"a.txt": [(1, "one"), (2, "++ b/fake.txt")], "b.txt": [(3, "new")]},
        )

    def test_a_name_with_spaces(self):
        (self.dir / "my notes.txt").write_text("SSN: 123-45-6789\n")
        self.git("add", "my notes.txt")
        self.assertIn("my notes.txt", self.cli("scan", "--staged").stdout)


class FormatsItCannotRead(CliCase):
    def dicom(self):
        path = self.dir / "study.dcm"
        path.write_bytes(b"\0" * 128 + b"DICM" + b"\x10\x00\x10\x00PN\x08\x00DOE^JANE" + b"\0" * 300)
        return path

    def test_dicom_is_blocked(self):
        self.assertTrue(scan_file(self.dicom(), Config(root=self.dir)).blocking)

    def test_dicom_can_be_allowlisted(self):
        self.dicom()
        cfg = Config(root=self.dir, allow_paths=["study.dcm"])
        self.assertFalse(scan_file(self.dir / "study.dcm", cfg).blocking)

    def test_opaque_formats_pass_by_default(self):
        (self.dir / "scan.pdf").write_bytes(b"%PDF-1.7")
        self.assertFalse(scan_file(self.dir / "scan.pdf", Config(root=self.dir)).blocking)

    def test_opaque_formats_block_when_configured(self):
        (self.dir / "scan.pdf").write_bytes(b"%PDF-1.7")
        self.assertTrue(scan_file(self.dir / "scan.pdf", Config(root=self.dir, opaque="block")).blocking)


class ManagedPolicy(CliCase):
    """A floor set by a security team, which a repository cannot lower."""

    def setUp(self):
        super().setUp()
        self.policy = self.dir.parent / f"{self.dir.name}-policy.toml"
        self.addCleanup(self.policy.unlink, missing_ok=True)
        self.env["PHI_GATE_MANAGED_CONFIG"] = str(self.policy)

    def use(self, policy, repo='[phi-gate]\nallow_paths = ["tests/fixtures/*"]\n'):
        self.policy.write_text(policy)
        (self.dir / ".phi-gate.toml").write_text(repo)

    def test_a_repository_cannot_lower_the_mode(self):
        self.use('[phi-gate]\nmode = "block"\n', '[phi-gate]\nmode = "audit"\n')
        self.assertBlocked(self.pre("Read", {"file_path": str(self.dir / "data" / "patients.csv")}))

    def test_a_repository_can_raise_the_mode(self):
        self.use('[phi-gate]\nmode = "warn"\n', '[phi-gate]\nmode = "block"\n')
        self.assertBlocked(self.pre("Read", {"file_path": str(self.dir / "data" / "patients.csv")}))

    def test_a_repository_cannot_add_to_a_list_the_policy_sets(self):
        self.use('[phi-gate]\nallow_paths = []\n', '[phi-gate]\nallow_paths = ["data/*"]\n')
        self.assertBlocked(self.pre("Read", {"file_path": str(self.dir / "data" / "patients.csv")}))

    def test_a_list_the_policy_leaves_alone_stays_the_repositorys(self):
        self.use('[phi-gate]\nmode = "block"\n', '[phi-gate]\nallow_paths = ["data/*"]\n')
        self.assertAllowed(self.pre("Read", {"file_path": str(self.dir / "data" / "patients.csv")}))

    def test_a_repository_cannot_turn_the_override_back_on(self):
        self.use('[phi-gate]\nprompt_override_token = ""\n', '[phi-gate]\nprompt_override_token = "#ok"\n')
        self.assertBlocked(self.run_hook("UserPromptSubmit", {"prompt": "#ok SSN 123-45-6789"}))

    def test_limits_keep_the_stricter_value(self):
        self.use('[phi-gate]\nmax_bytes = 1000\n', '[phi-gate]\nmax_bytes = 2000\n')
        (self.dir / "big.txt").write_text("x" * 1500)
        self.assertBlocked(self.pre("Read", {"file_path": str(self.dir / "big.txt")}))

    def test_a_bad_policy_blocks(self):
        self.use("not toml [[[")
        self.assertBlocked(self.pre("Read", {"file_path": str(self.dir / "src" / "app.py")}))

    def test_a_policy_path_that_does_not_exist_blocks(self):
        self.assertBlocked(self.pre("Read", {"file_path": str(self.dir / "src" / "app.py")}))

    def test_status_names_the_policy(self):
        self.use('[phi-gate]\nmode = "block"\n')
        self.assertIn(str(self.policy), self.cli("status").stdout)


class AuditLog(CliCase):
    def log(self):
        return self.dir / ".phi-gate" / "audit.jsonl"

    def write_events(self, count=3):
        for _ in range(count):
            self.pre("Read", {"file_path": str(self.dir / "data" / "patients.csv")})

    def assertBroken(self, line):
        result = self.cli("audit", "verify")
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn(f"line {line}", result.stderr)

    def test_a_clean_log_verifies(self):
        self.write_events()
        result = self.cli("audit", "verify")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("3 event(s)", result.stdout)

    def test_no_log_verifies(self):
        self.assertEqual(self.cli("audit", "verify").returncode, 0)

    def test_an_edited_line_is_found(self):
        self.write_events()
        lines = self.log().read_text().splitlines()
        lines[1] = lines[1].replace('"block"', '"allow"')
        self.log().write_text("\n".join(lines) + "\n")
        self.assertBroken(2)

    def test_a_removed_line_is_found(self):
        self.write_events()
        lines = self.log().read_text().splitlines()
        del lines[1]
        self.log().write_text("\n".join(lines) + "\n")
        self.assertBroken(2)

    def test_reordered_lines_are_found(self):
        self.write_events()
        lines = self.log().read_text().splitlines()
        lines[0], lines[1] = lines[1], lines[0]
        self.log().write_text("\n".join(lines) + "\n")
        self.assertBroken(1)

    def test_a_line_that_is_not_an_event_is_found(self):
        self.write_events()
        with self.log().open("a") as fh:
            fh.write("garbage\n")
        self.assertBroken(4)

    def test_events_are_versioned_and_identified(self):
        self.write_events(2)
        first, second = map(json.loads, self.log().read_text().splitlines())
        self.assertEqual(first["v"], 1)
        self.assertNotEqual(first["id"], second["id"])
        self.assertEqual(second["prev"], first["hash"])

    def test_the_chain_carries_on_across_processes_and_never_holds_a_value(self):
        self.write_events(2)
        self.pre("Bash", {"command": "echo SSN 123-45-6789"})
        text = self.log().read_text()
        self.assertEqual(self.cli("audit", "verify").returncode, 0)
        self.assertNotIn("123-45-6789", text)

    def test_status_still_reads_the_log(self):
        self.write_events(1)
        self.assertIn("tabular_phi", self.cli("status").stdout)


class Packaging(unittest.TestCase):
    def test_every_manifest_states_the_same_version(self):
        import json as _json
        import tomllib

        from phi_gate import __version__

        project = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]
        plugin = _json.loads((ROOT / ".claude-plugin" / "plugin.json").read_text())
        marketplace = _json.loads((ROOT / ".claude-plugin" / "marketplace.json").read_text())
        self.assertEqual(
            {__version__, project["version"], plugin["version"], marketplace["plugins"][0]["version"]},
            {__version__},
        )


class ConfigEdgeCases(unittest.TestCase):
    def test_config_rejects_a_bad_opaque_value(self):
        from phi_gate.config import ConfigError

        with self.assertRaises(ConfigError):
            Config(opaque="maybe")

    def test_managed_paths_are_looked_up_when_no_env_is_set(self):
        from phi_gate import config

        with mock.patch.dict(os.environ, clear=True), mock.patch.object(config, "MANAGED_PATHS", ("/no/such/file",)):
            self.assertIsNone(config.find_managed())


if __name__ == "__main__":
    unittest.main()
