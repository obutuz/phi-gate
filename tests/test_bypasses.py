"""Regression tests for bypasses found in review. Each test is a concrete
attempt to get synthetic PHI past phi-gate, or a fail-open path."""

import json
import subprocess
import sys
import time
import unittest
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from phi_gate.config import Config, ConfigError  # noqa: E402
from phi_gate.scanner import scan_text  # noqa: E402
from test_hooks import PHI_CSV, RUN, SSN, HookTestCase  # noqa: E402


def git(cwd, *args):
    subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True)


class Timeouts(HookTestCase):
    """Claude Code lets an action through when a hook times out, so slow
    inputs must not exist."""

    def test_detectors_are_linear_on_adversarial_input(self):
        cfg = Config()
        for text in ("1." * 80_000, "Title Case Words " * 12_000, "a" * 200_000, "a@" * 50_000, "1 " * 100_000):
            start = time.time()
            scan_text(text, cfg)
            self.assertLess(time.time() - start, 3, text[:20])

    def test_long_bash_command_is_fast(self):
        start = time.time()
        self.assertAllowed(self.pre("Bash", {"command": "echo " + "a" * 40_000}))
        self.assertLess(time.time() - start, 10)

    def test_large_write_with_phi_still_blocks_quickly(self):
        start = time.time()
        res = self.pre("Write", {"file_path": str(self.dir / "src" / "x.py"), "content": f"ssn='{SSN}'\n" + "1." * 80_000})
        self.assertBlocked(res)
        self.assertLess(time.time() - start, 10)

    def test_internal_deadline_blocks(self):
        import io
        import os
        from unittest import mock

        from phi_gate import hooks

        def slow(*_a, **_k):
            time.sleep(5)
            return hooks.Outcome(0)

        payload = json.dumps({"cwd": str(self.dir), "prompt": "hello"})
        with mock.patch.dict(os.environ, {"PHI_GATE_DEADLINE": "1"}), mock.patch.object(hooks, "decide", slow), \
                mock.patch("sys.stdin", io.StringIO(payload)), mock.patch("sys.stderr", io.StringIO()) as err:
            start = time.time()
            code = hooks.main("UserPromptSubmit")
        self.assertEqual(code, 2)
        self.assertLess(time.time() - start, 3)
        self.assertIn("took too long", err.getvalue())


class Commits(HookTestCase):
    def test_commit_from_subdirectory(self):
        (self.dir / ".phi-gate.toml").write_text('[phi-gate]\nallow_paths = ["tests/*"]\n')
        git(self.dir, "add", "data/patients.csv")
        sub = self.dir / "tests"
        res = self.run_hook("PreToolUse", {"cwd": str(sub), "tool_name": "Bash", "tool_input": {"command": "git commit -m x"}})
        self.assertBlocked(res)

    def test_add_and_commit_in_one_command(self):
        for cmd in ("git add -A && git commit -m wip", "git add . && git commit -m wip", "git add data && git commit -m wip"):
            with self.subTest(cmd):
                self.assertBlocked(self.pre("Bash", {"command": cmd}))

    def test_commit_all_in_repo_without_commits(self):
        git(self.dir, "add", "src/app.py")
        res = self.pre("Bash", {"command": "git commit -am first"})
        self.assertNotIn("internal error", res.stderr)

    def test_bypass_spellings(self):
        for cmd in (
            'git commit -m"wip" -n',
            "git commit --no-veri -m wip",
            "/usr/bin/git commit --no-verify -m x",
            'bash -c "git commit --no-verify -m x"',
            "git -c core.hookspath=/dev/null commit -m x",
        ):
            with self.subTest(cmd):
                self.assertBlocked(self.pre("Bash", {"command": cmd}))


class BashReads(HookTestCase):
    def test_read_bypasses(self):
        for cmd in (
            "cd data && cat patients.csv",
            "cd data; head -3 patients.csv",
            'cat "$PWD/data/patients.csv"',
            "cat ${PWD}/data/patients.csv",
            "cat data/{patients,foo}.csv",
            "cat data/*; echo hi",
            "cat data/*|head",
            "head data/*.csv>out.txt",
            'grep -r "" data/',
            "find data -type f -exec cat {} +",
            "tar cf - data | tar xOf -",
            "phi-gate scan .\ncat data/patients.csv",
            "phi-gate redact data/patients.csv --map /dev/stdout",
            "sort < data/patients.csv",
        ):
            with self.subTest(cmd):
                self.assertBlocked(self.pre("Bash", {"command": cmd}))

    def test_remediation_and_metadata_commands_allowed(self):
        git(self.dir, "add", "data/patients.csv")
        for cmd in ("rm data/patients.csv", "git rm --cached data/patients.csv", "wc -l data/patients.csv",
                    "ls -la data", "mv data/patients.csv /tmp/elsewhere.csv", "ls ~nosuchuser/notes.txt"):
            with self.subTest(cmd):
                self.assertAllowed(self.pre("Bash", {"command": cmd}))


class FileFormats(HookTestCase):
    def read(self, name):
        return self.pre("Read", {"file_path": str(self.dir / name)})

    def test_utf16_csv(self):
        (self.dir / "u16.csv").write_bytes(PHI_CSV.encode("utf-16"))
        (self.dir / "u16le.csv").write_bytes(PHI_CSV.encode("utf-16-le"))
        self.assertBlocked(self.read("u16.csv"))
        self.assertBlocked(self.read("u16le.csv"))

    def test_csv_with_nul_byte(self):
        (self.dir / "nul.csv").write_bytes(PHI_CSV.encode() + b"\x00")
        self.assertBlocked(self.read("nul.csv"))

    def test_text_renamed_to_office_suffix(self):
        (self.dir / "export.xlsx").write_text(PHI_CSV)
        self.assertBlocked(self.read("export.xlsx"))
        self.assertBlocked(self.pre("Bash", {"command": "cat export.xlsx"}))

    def test_real_xlsx(self):
        ns = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
        shared = ["patient_name", "dob", "mrn", "John Doe", "1980-04-12", "00482913"]
        sst = f'<sst xmlns="{ns}">' + "".join(f"<si><t>{s}</t></si>" for s in shared) + "</sst>"
        rows = "".join(
            f'<row r="{r + 1}">' + "".join(f'<c t="s"><v>{r * 3 + c}</v></c>' for c in range(3)) + "</row>" for r in range(2)
        )
        sheet = f'<worksheet xmlns="{ns}"><sheetData>{rows}</sheetData></worksheet>'
        with zipfile.ZipFile(self.dir / "real.xlsx", "w") as zf:
            zf.writestr("xl/workbook.xml", f'<workbook xmlns="{ns}"/>')
            zf.writestr("xl/sharedStrings.xml", sst)
            zf.writestr("xl/worksheets/sheet1.xml", sheet)
        self.assertBlocked(self.read("real.xlsx"))

    def test_docx_text(self):
        body = "<w:p><w:r><w:t>Patient Name: Jane Doe</w:t></w:r></w:p><w:p><w:r><w:t>MRN: 00482913</w:t></w:r></w:p>"
        xml = f'<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body>{body}</w:body></w:document>'
        with zipfile.ZipFile(self.dir / "note.docx", "w") as zf:
            zf.writestr("word/document.xml", xml)
        self.assertBlocked(self.read("note.docx"))

    def test_read_directory_is_not_an_error(self):
        res = self.read("src")
        self.assertAllowed(res)

    def test_relative_read_path_uses_payload_cwd(self):
        sub = self.dir / "sub"
        sub.mkdir()
        (sub / "s.txt").write_text(f"SSN: {SSN}\n")
        res = self.run_hook("PreToolUse", {"cwd": str(sub), "tool_name": "Read", "tool_input": {"file_path": "s.txt"}})
        self.assertBlocked(res)

    def test_grep_tool_on_phi_file(self):
        self.assertBlocked(self.pre("Grep", {"pattern": ".", "path": str(self.dir / "data" / "patients.csv")}))

    def test_hex_strings_are_not_cards(self):
        import hashlib

        blob = "\n".join(hashlib.sha1(str(i).encode()).hexdigest() for i in range(20_000))
        self.assertNotEqual(scan_text(blob, Config()).decision, "block")


class ConfigIntegrity(HookTestCase):
    def test_tampering(self):
        for cmd in ("rm -rf .phi-gate", "printf '[phi-gate]\\nmode = \"audit\"\\n' > .phi-gate.t*",
                    "python3 -c \"open('.phi-gate.toml','w').write('')\"", "cp /tmp/x .phi-gate.toml",
                    "echo '' | tee .phi-gate.toml"):
            with self.subTest(cmd):
                self.assertBlocked(self.pre("Bash", {"command": cmd}))
        self.assertBlocked(self.pre("Write", {"file_path": str(self.dir / ".PHI-GATE.TOML"), "content": ""}))

    def test_read_only_access_allowed(self):
        for cmd in ("cat .phi-gate.toml 2>/dev/null", "ls .phi-gate/ && echo done", "phi-gate status"):
            with self.subTest(cmd):
                self.assertAllowed(self.pre("Bash", {"command": cmd}))

    def test_config_types(self):
        for bad in ({"protect_config": "false"}, {"record_window": True}, {"audit_log": 5}):
            with self.subTest(bad), self.assertRaises(ConfigError):
                Config(**bad)


class MalformedPayloads(HookTestCase):
    def test_missing_tool_name_blocks(self):
        self.assertBlocked(self.run_hook("PreToolUse", {"tool_input": {"file_path": "x"}}))

    def test_empty_stdin_blocks(self):
        res = subprocess.run(["bash", str(RUN), "PreToolUse"], input="", capture_output=True, text=True, cwd=self.dir, env=self.env)
        self.assertEqual(res.returncode, 2)

    def test_post_tool_events_logged_as_flagged(self):
        self.run_hook("PostToolUse", {"tool_name": "Bash", "tool_input": {"command": "x"}, "tool_response": {"stdout": PHI_CSV}})
        log = (self.dir / ".phi-gate" / "audit.jsonl").read_text()
        self.assertIn('"decision": "flagged"', log)
        self.assertEqual(json.loads(log.splitlines()[-1])["event"], "PostToolUse")


if __name__ == "__main__":
    unittest.main()


class SecondReview(HookTestCase):
    """Regressions from the second review pass."""

    def make_tree(self, n=250):
        src = self.dir / "src" / "big"
        src.mkdir(parents=True)
        for i in range(n):
            (src / f"m{i}.js").write_text(f"export const v{i} = {i}; // TODO\n")

    def test_dev_commands_on_medium_trees(self):
        self.make_tree()
        for cmd in ('grep -rn TODO src/', 'find . -name "*.js" | head',
                    "tar czf /tmp/phi-gate-src.tgz src", 'find . -name "*.py"'):
            with self.subTest(cmd):
                self.assertAllowed(self.pre("Bash", {"command": cmd}))
        # a recursive read of a tree that holds a PHI file is refused before it runs
        self.assertBlocked(self.pre("Bash", {"command": "grep -rn TODO ."}))
        (self.dir / "data" / "patients.csv").unlink()
        self.assertAllowed(self.pre("Bash", {"command": "grep -rn TODO ."}))

    def test_walk_is_lazy(self):
        nm = self.dir / "node_modules" / "pkg"
        nm.mkdir(parents=True)
        for i in range(5000):
            (nm / f"f{i}.js").write_text("x")
        start = time.time()
        self.assertAllowed(self.pre("Bash", {"command": "grep -rn TODO src"}))
        self.assertLess(time.time() - start, 5)

    def test_corrupt_office_file_fails_closed_without_breaking_other_commands(self):
        (self.dir / "data" / "bad.xlsx").write_bytes(b"PK\x03\x04" + b"garbage" * 50)
        with zipfile.ZipFile(self.dir / "data" / "bad2.xlsx", "w") as zf:
            zf.writestr("xl/workbook.xml", "<workbook")
            zf.writestr("xl/worksheets/sheet1.xml", "<not-closed")
        for name in ("bad.xlsx", "bad2.xlsx"):
            res = self.pre("Read", {"file_path": str(self.dir / "data" / name)})
            self.assertBlocked(res)
            self.assertNotIn("internal error", res.stderr)
        self.assertAllowed(self.pre("Bash", {"command": 'find . -name "*.py"'}))

    def test_heredocs_and_indirection(self):
        for cmd in (
            "python3 <<'PY'\nimport csv\nfor r in csv.reader(open('data/patients.csv')): print(r)\nPY",
            "python3 - <<'PY'\nprint(open('data/patients.csv').read())\nPY",
            "F=data/patients.csv; cat $F",
            "cat $(ls data/*.csv)",
            "cat `ls data/*.csv`",
            "ls data/*.csv | xargs head -5",
            "cp data/patients.csv /dev/stdout",
        ):
            with self.subTest(cmd):
                self.assertBlocked(self.pre("Bash", {"command": cmd}))

    def test_git_prints_staged_content(self):
        git(self.dir, "add", "data/patients.csv")
        for cmd in ("git show :data/patients.csv", "git cat-file -p :data/patients.csv", "git diff --cached"):
            with self.subTest(cmd):
                self.assertBlocked(self.pre("Bash", {"command": cmd}))
        self.assertAllowed(self.pre("Bash", {"command": "git status"}))

    def test_containers(self):
        import gzip
        import sqlite3

        with zipfile.ZipFile(self.dir / "data" / "arch.zip", "w") as zf:
            zf.writestr("export.csv", PHI_CSV)
        with gzip.open(self.dir / "data" / "export.csv.gz", "wt") as gz:
            gz.write(PHI_CSV)
        db = sqlite3.connect(self.dir / "data" / "p.db")
        db.execute("create table patients (patient_name text, dob text, mrn text)")
        db.execute("insert into patients values ('John Doe', '1980-04-12', '00482913')")
        db.commit()
        db.close()
        ods = ("<office:document-content><table:table><table:table-row><table:table-cell><text:p>mrn</text:p>"
               "</table:table-cell><table:table-cell><text:p>dob</text:p></table:table-cell></table:table-row>"
               "<table:table-row><table:table-cell><text:p>00482913</text:p></table:table-cell><table:table-cell>"
               "<text:p>1980-04-12</text:p></table:table-cell></table:table-row></table:table></office:document-content>")
        with zipfile.ZipFile(self.dir / "data" / "sheet.ods", "w") as zf:
            zf.writestr("mimetype", "application/vnd.oasis.opendocument.spreadsheet")
            zf.writestr("content.xml", ods)
        for name in ("arch.zip", "export.csv.gz", "p.db", "sheet.ods"):
            with self.subTest(name):
                self.assertBlocked(self.pre("Read", {"file_path": str(self.dir / "data" / name)}))
        self.assertBlocked(self.pre("Bash", {"command": 'sqlite3 data/p.db "select * from patients"'}))
        self.assertBlocked(self.pre("Bash", {"command": "zcat data/export.csv.gz"}))

    def test_grep_tool_on_directory(self):
        self.assertBlocked(self.pre("Grep", {"pattern": ".", "path": str(self.dir / "data")}))
        self.assertAllowed(self.pre("Grep", {"pattern": "TODO", "path": str(self.dir / "src")}))
        self.assertAllowed(self.pre("Grep", {"pattern": ".", "path": str(self.dir / "data"), "glob": "*.md"}))

    def test_audit_deletion(self):
        (self.dir / ".phi-gate").mkdir(exist_ok=True)
        for cmd in ("find .phi-gate -delete", "git clean -fdx"):
            with self.subTest(cmd):
                self.assertBlocked(self.pre("Bash", {"command": cmd}))


class PhiGateInPipelines(HookTestCase):
    """The safe path (redact, then work from the copy) must not be blocked."""

    def test_redact_to_file_then_read_copy(self):
        for cmd in (
            "phi-gate redact data/patients.csv > /tmp/phi-gate-redacted.csv",
            "mkdir -p /tmp/r && phi-gate redact data/patients.csv > /tmp/r/out.csv && wc -l /tmp/r/out.csv",
            "phi-gate redact data/patients.csv | python3 -c 'import sys; print(sum(1 for _ in sys.stdin))'",
            "phi-gate scan data/ && echo ok",
        ):
            with self.subTest(cmd):
                self.assertAllowed(self.pre("Bash", {"command": cmd}))

    def test_still_blocked(self):
        for cmd in (
            "phi-gate redact data/patients.csv --map /dev/stdout",
            "phi-gate redact data/patients.csv > /tmp/x.csv && cat data/patients.csv",
            "phi-gate scan . ; head data/patients.csv",
        ):
            with self.subTest(cmd):
                self.assertBlocked(self.pre("Bash", {"command": cmd}))

    def test_redacted_copy_is_readable(self):
        import os

        out = self.dir / "redacted.csv"
        env = {**os.environ, "PYTHONPATH": str(Path(RUN).resolve().parents[1] / "src")}
        res = subprocess.run([sys.executable, "-m", "phi_gate", "redact", "data/patients.csv"], cwd=self.dir,
                             capture_output=True, text=True, env=env)
        out.write_text(res.stdout)
        self.assertAllowed(self.pre("Read", {"file_path": str(out)}))
        self.assertAllowed(self.pre("Bash", {"command": f"cat {out}"}))
