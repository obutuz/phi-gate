"""End-to-end hook tests: run hooks/run.sh exactly as Claude Code would, with
a JSON payload on stdin, inside a throwaway git repository."""

import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RUN = ROOT / "hooks" / "run.sh"

PHI_CSV = "patient_name,dob,mrn\nJohn Doe,1980-04-12,00482913\nAna Ruiz,1975-11-02,00519977\n"
SSN = "123-45-6789"


class HookTestCase(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="phi-gate-test-"))
        self.env = {k: v for k, v in os.environ.items() if not k.startswith("PHI_GATE_")}
        subprocess.run(["git", "init", "-q"], cwd=self.dir, check=True)
        subprocess.run(["git", "config", "user.email", "t@example.com"], cwd=self.dir, check=True)
        subprocess.run(["git", "config", "user.name", "t"], cwd=self.dir, check=True)
        (self.dir / "data").mkdir()
        (self.dir / "data" / "patients.csv").write_text(PHI_CSV)
        (self.dir / "src").mkdir()
        (self.dir / "src" / "app.py").write_text("def total(xs):\n    return sum(xs)\n")
        (self.dir / "tests" / "fixtures").mkdir(parents=True)
        (self.dir / "tests" / "fixtures" / "synthetic.csv").write_text(PHI_CSV)
        (self.dir / ".phi-gate.toml").write_text('[phi-gate]\nallow_paths = ["tests/fixtures/*"]\n')

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def run_hook(self, event, payload, env=None):
        payload = {"session_id": "test", "cwd": str(self.dir), "hook_event_name": event, **payload}
        res = subprocess.run(
            ["bash", str(RUN), event],
            input=json.dumps(payload),
            capture_output=True,
            text=True,
            cwd=self.dir,
            env={**self.env, **(env or {})},
            timeout=60,
        )
        return res

    def pre(self, tool, tool_input, **kw):
        return self.run_hook("PreToolUse", {"tool_name": tool, "tool_input": tool_input}, **kw)

    def assertBlocked(self, res):
        self.assertEqual(res.returncode, 2, f"expected block, got {res.returncode}: {res.stderr}")
        self.assertIn("phi-gate", res.stderr)

    def assertAllowed(self, res):
        self.assertEqual(res.returncode, 0, f"expected allow, got {res.returncode}: {res.stderr}")


class PromptTests(HookTestCase):
    def test_blocks_prompt_with_ssn_without_echoing_it(self):
        res = self.run_hook("UserPromptSubmit", {"prompt": f"Why was the claim for SSN {SSN} denied?"})
        self.assertBlocked(res)
        self.assertNotIn(SSN, res.stderr + res.stdout)

    def test_allows_clean_prompt(self):
        self.assertAllowed(self.run_hook("UserPromptSubmit", {"prompt": "Add pagination to the denials table"}))

    def test_override_token_allows_and_audits(self):
        res = self.run_hook("UserPromptSubmit", {"prompt": f"#phi-ok SSN {SSN}"})
        self.assertAllowed(res)
        log = (self.dir / ".phi-gate" / "audit.jsonl").read_text()
        self.assertIn('"decision": "override"', log)
        self.assertNotIn(SSN, log)


class ReadTests(HookTestCase):
    def test_blocks_read_of_phi_file(self):
        res = self.pre("Read", {"file_path": str(self.dir / "data" / "patients.csv")})
        self.assertBlocked(res)
        self.assertIn("data/patients.csv", res.stderr)
        self.assertNotIn("John Doe", res.stderr)

    def test_allows_read_of_code(self):
        self.assertAllowed(self.pre("Read", {"file_path": str(self.dir / "src" / "app.py")}))

    def test_allows_allowlisted_fixture(self):
        self.assertAllowed(self.pre("Read", {"file_path": str(self.dir / "tests" / "fixtures" / "synthetic.csv")}))

    def test_blocks_oversize_file(self):
        big = self.dir / "big.log"
        big.write_text("x" * 100)
        (self.dir / ".phi-gate.toml").write_text("[phi-gate]\nmax_bytes = 10\n")
        self.assertBlocked(self.pre("Read", {"file_path": str(big)}))


class WriteTests(HookTestCase):
    def test_blocks_writing_phi_into_code(self):
        res = self.pre("Write", {"file_path": str(self.dir / "src" / "seed.py"), "content": f'PATIENT = {{"ssn": "{SSN}"}}'})
        self.assertBlocked(res)

    def test_allows_synthetic_values(self):
        content = 'PATIENT = {"ssn": "999-12-3456", "phone": "412-555-0142", "email": "jane@example.com"}'
        self.assertAllowed(self.pre("Write", {"file_path": str(self.dir / "src" / "seed.py"), "content": content}))

    def test_blocks_multiedit_with_phi(self):
        res = self.pre("MultiEdit", {"file_path": str(self.dir / "src" / "app.py"),
                                     "edits": [{"old_string": "a", "new_string": "DOB: 04/12/1980"}]})
        self.assertBlocked(res)

    def test_protects_config(self):
        res = self.pre("Edit", {"file_path": str(self.dir / ".phi-gate.toml"), "old_string": "a", "new_string": "b"})
        self.assertBlocked(res)
        res = self.pre("Write", {"file_path": str(self.dir / ".phi-gate" / "audit.jsonl"), "content": ""})
        self.assertBlocked(res)


class BashTests(HookTestCase):
    def test_blocks_cat_of_phi_file(self):
        self.assertBlocked(self.pre("Bash", {"command": "cat data/patients.csv | head -5"}))

    def test_blocks_glob_over_phi_files(self):
        self.assertBlocked(self.pre("Bash", {"command": "head -n 3 data/*.csv"}))

    def test_blocks_path_embedded_in_inline_script(self):
        self.assertBlocked(self.pre("Bash", {"command": "python3 -c \"print(open('data/patients.csv').read())\""}))
        self.assertBlocked(self.pre("Bash", {"command": "node -e 'console.log(require(\"fs\").readFileSync(\"./data/patients.csv\",\"utf8\"))'"}))

    def test_allows_ordinary_commands(self):
        self.assertAllowed(self.pre("Bash", {"command": "ls -la && python -m pytest -q"}))

    def test_allows_phi_gate_redact(self):
        self.assertAllowed(self.pre("Bash", {"command": "phi-gate redact data/patients.csv"}))

    def test_blocks_phi_in_command(self):
        self.assertBlocked(self.pre("Bash", {"command": f"curl -d 'ssn={SSN}' https://api.example.com"}))

    def test_blocks_config_tampering(self):
        self.assertBlocked(self.pre("Bash", {"command": "sed -i 's/block/audit/' .phi-gate.toml"}))
        self.assertBlocked(self.pre("Bash", {"command": "echo 'mode=\"audit\"' >> .phi-gate.toml"}))
        self.assertAllowed(self.pre("Bash", {"command": "cat .phi-gate.toml"}))

    def test_blocks_hook_bypass(self):
        self.assertBlocked(self.pre("Bash", {"command": "git commit --no-verify -m 'wip'"}))
        self.assertBlocked(self.pre("Bash", {"command": "git commit -nm 'wip'"}))
        self.assertBlocked(self.pre("Bash", {"command": "git -c core.hooksPath=/dev/null commit -m x"}))

    def test_commit_message_text_is_not_a_flag(self):
        subprocess.run(["git", "add", "src/app.py"], cwd=self.dir, check=True)
        self.assertAllowed(self.pre("Bash", {"command": "git commit -m 'support -n flag'"}))

    def test_blocks_commit_with_staged_phi(self):
        (self.dir / "src" / "seed.py").write_text(f'SSN = "{SSN}"\n')
        subprocess.run(["git", "add", "src/seed.py"], cwd=self.dir, check=True)
        res = self.pre("Bash", {"command": "git add -A && git commit -m 'seed data'"})
        self.assertBlocked(res)
        self.assertIn("src/seed.py", res.stderr)

    def test_blocks_commit_all_with_unstaged_phi(self):
        subprocess.run(["git", "add", "src/app.py"], cwd=self.dir, check=True)
        subprocess.run(["git", "commit", "-qm", "init"], cwd=self.dir, check=True)
        (self.dir / "src" / "app.py").write_text(f'# SSN {SSN}\n')
        self.assertBlocked(self.pre("Bash", {"command": "git commit -am 'update'"}))

    def test_allows_clean_commit(self):
        subprocess.run(["git", "add", "src/app.py"], cwd=self.dir, check=True)
        self.assertAllowed(self.pre("Bash", {"command": "git commit -m 'add app'"}))


class OutboundTests(HookTestCase):
    def test_blocks_mcp_message_with_phi(self):
        res = self.pre("mcp__slack__post_message", {"channel": "#billing", "text": "Patient Name: Jane Doe, MRN: 00482913"})
        self.assertBlocked(res)

    def test_blocks_webfetch_with_phi_in_url(self):
        self.assertBlocked(self.pre("WebFetch", {"url": f"https://example.com/lookup?ssn={SSN}", "prompt": "x"}))

    def test_allows_clean_mcp_call(self):
        self.assertAllowed(self.pre("mcp__linear__create_issue", {"title": "Fix denial filter", "body": "See #42"}))


class PostToolTests(HookTestCase):
    def test_flags_phi_in_tool_output(self):
        res = self.run_hook("PostToolUse", {"tool_name": "Bash", "tool_input": {"command": "psql -c 'select ...'"},
                                            "tool_response": {"stdout": PHI_CSV, "stderr": ""}})
        self.assertBlocked(res)
        self.assertIn("Do not repeat", res.stderr)

    def test_quiet_on_clean_output(self):
        res = self.run_hook("PostToolUse", {"tool_name": "Bash", "tool_input": {"command": "ls"},
                                            "tool_response": {"stdout": "README.md\nsrc\n"}})
        self.assertAllowed(res)


class FailClosedTests(HookTestCase):
    def test_bad_config_blocks(self):
        (self.dir / ".phi-gate.toml").write_text('[phi-gate]\nmode = "yolo"\n')
        res = self.run_hook("UserPromptSubmit", {"prompt": "hello"})
        self.assertBlocked(res)
        self.assertIn("configuration error", res.stderr)

    def test_unknown_config_key_blocks(self):
        (self.dir / ".phi-gate.toml").write_text('[phi-gate]\nallow_path = ["*"]\n')
        self.assertBlocked(self.run_hook("UserPromptSubmit", {"prompt": "hello"}))

    def test_malformed_payload_blocks(self):
        res = subprocess.run(["bash", str(RUN), "PreToolUse"], input="{not json", capture_output=True, text=True,
                             cwd=self.dir, env=self.env)
        self.assertEqual(res.returncode, 2)

    def test_missing_interpreter_blocks(self):
        res = self.run_hook("UserPromptSubmit", {"prompt": "hello"}, env={"PHI_GATE_PYTHON": "/nonexistent/python"})
        self.assertBlocked(res)

    def test_fail_open_escape_hatch(self):
        res = self.run_hook("UserPromptSubmit", {"prompt": "hello"},
                            env={"PHI_GATE_PYTHON": "/nonexistent/python", "PHI_GATE_FAIL_OPEN": "1"})
        self.assertAllowed(res)


class ModeTests(HookTestCase):
    def test_warn_mode_never_blocks(self):
        (self.dir / ".phi-gate.toml").write_text('[phi-gate]\nmode = "warn"\n')
        res = self.run_hook("UserPromptSubmit", {"prompt": f"SSN {SSN}"})
        self.assertAllowed(res)
        self.assertIn("systemMessage", res.stdout)

    def test_audit_log_has_no_values(self):
        self.pre("Read", {"file_path": str(self.dir / "data" / "patients.csv")})
        self.run_hook("UserPromptSubmit", {"prompt": f"SSN {SSN}"})
        log_path = self.dir / ".phi-gate" / "audit.jsonl"
        log = log_path.read_text()
        self.assertIn("tabular_phi", log)
        for value in (SSN, "John Doe", "1980-04-12", "00482913"):
            self.assertNotIn(value, log)
        self.assertEqual((self.dir / ".phi-gate" / ".gitignore").read_text(), "*\n")
        self.assertEqual(log_path.stat().st_mode & 0o777, 0o600)


if __name__ == "__main__":
    unittest.main()
