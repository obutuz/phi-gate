import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ENV = {**{k: v for k, v in os.environ.items() if not k.startswith("PHI_GATE_")}, "PYTHONPATH": str(ROOT / "src")}


def cli(*args, cwd, stdin=None):
    return subprocess.run([sys.executable, "-m", "phi_gate", *args], cwd=cwd, input=stdin,
                          capture_output=True, text=True, env=ENV, timeout=60)


class CliTests(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="phi-gate-cli-"))
        (self.dir / "clean.py").write_text("print('hello')\n")
        (self.dir / "notes.txt").write_text("follow up\nPatient Name: Jane Doe\nMRN: 00482913\n")

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def test_scan_exit_codes(self):
        self.assertEqual(cli("scan", "clean.py", cwd=self.dir).returncode, 0)
        res = cli("scan", ".", cwd=self.dir)
        self.assertEqual(res.returncode, 1)
        self.assertIn("notes.txt:2:", res.stdout)
        self.assertNotIn("Jane Doe", res.stdout + res.stderr)

    def test_scan_json(self):
        res = cli("scan", "--json", ".", cwd=self.dir)
        data = json.loads(res.stdout)
        self.assertEqual(data["decision"], "block")
        self.assertEqual(data["files"][0]["path"], "notes.txt")

    def test_redact_stdin(self):
        res = cli("redact", "-", cwd=self.dir, stdin="SSN 123-45-6789\n")
        self.assertIn("SSN [SSN_1]", res.stdout)
        self.assertNotIn("123-45-6789", res.stdout)

    def test_redact_map_and_restore(self):
        mp = self.dir / "map.json"
        red = cli("redact", "notes.txt", "--map", str(mp), cwd=self.dir)
        self.assertEqual(mp.stat().st_mode & 0o777, 0o600)
        back = cli("restore", "--map", str(mp), cwd=self.dir, stdin=red.stdout)
        self.assertEqual(back.stdout, (self.dir / "notes.txt").read_text())

    def test_git_pre_commit_hook(self):
        subprocess.run(["git", "init", "-q"], cwd=self.dir, check=True)
        subprocess.run(["git", "config", "user.email", "t@example.com"], cwd=self.dir, check=True)
        subprocess.run(["git", "config", "user.name", "t"], cwd=self.dir, check=True)
        self.assertEqual(cli("install-git-hook", cwd=self.dir).returncode, 0)
        subprocess.run(["git", "add", "clean.py"], cwd=self.dir, check=True)
        ok = subprocess.run(["git", "commit", "-qm", "clean"], cwd=self.dir, capture_output=True, text=True)
        self.assertEqual(ok.returncode, 0, ok.stderr)
        subprocess.run(["git", "add", "notes.txt"], cwd=self.dir, check=True)
        bad = subprocess.run(["git", "commit", "-qm", "notes"], cwd=self.dir, capture_output=True, text=True)
        self.assertNotEqual(bad.returncode, 0)
        self.assertIn("BLOCK", bad.stdout + bad.stderr)


if __name__ == "__main__":
    unittest.main()
