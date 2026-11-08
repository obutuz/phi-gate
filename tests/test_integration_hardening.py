"""Where the configuration, the shell analysis and the hooks meet: the secrets
phi-gate keys its audit log with cannot be read through any tool, a managed
policy switches the fail-open escape hatch off, and `git clean -x` cannot
delete what phi-gate depends on."""

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from test_hooks import HookTestCase  # noqa: E402

from phi_gate import config, hooks, shell  # noqa: E402

SALT = ".phi-gate/audit.jsonl.salt"


class AuditSecretsCannotBeRead(HookTestCase):
    def setUp(self):
        super().setUp()
        salt = self.dir / SALT
        salt.parent.mkdir(parents=True, exist_ok=True)
        salt.write_bytes(os.urandom(32))

    def test_read(self):
        self.assertBlocked(self.pre("Read", {"file_path": str(self.dir / SALT)}))

    def test_shell(self):
        for command in (f"cat {SALT}", f"base64 {SALT}", f"cp {SALT} /tmp/salt"):
            with self.subTest(command=command):
                self.assertBlocked(self.pre("Bash", {"command": command}))

    def test_grep(self):
        self.assertBlocked(self.pre("Grep", {"pattern": ".", "path": str(self.dir / SALT)}))

    def test_another_tool_naming_it(self):
        self.assertBlocked(self.pre("mcp__files__read", {"path": str(self.dir / SALT)}))

    def test_the_audit_log_itself_stays_readable(self):
        (self.dir / ".phi-gate/audit.jsonl").write_text("")
        self.assertAllowed(self.pre("Read", {"file_path": str(self.dir / ".phi-gate/audit.jsonl")}))


class FailOpenUnderAManagedPolicy(unittest.TestCase):
    def setUp(self):
        self.policy = Path(tempfile.mkdtemp(prefix="phi-gate-sys-")) / "policy.toml"
        patch = mock.patch.object(config, "MANAGED_PATHS", (str(self.policy),))
        patch.start()
        self.addCleanup(patch.stop)
        env = mock.patch.dict(os.environ, {"PHI_GATE_FAIL_OPEN": "1"})
        env.start()
        self.addCleanup(env.stop)

    def test_without_a_policy_the_escape_hatch_works(self):
        self.assertTrue(hooks._fail_open())

    def test_a_policy_switches_it_off(self):
        self.policy.write_text('[phi-gate]\nmode = "block"\n')
        self.assertFalse(hooks._fail_open())

    def test_unless_the_policy_permits_overrides(self):
        self.policy.write_text('[phi-gate]\nallow_env_overrides = true\n')
        self.assertTrue(hooks._fail_open())

    def test_an_unreadable_policy_permits_nothing(self):
        self.policy.write_text("not toml [")
        self.assertFalse(hooks._fail_open())


class GitCleanIgnored(unittest.TestCase):
    def test_counts_every_protected_entry_as_a_write(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            a = shell.analyze("git clean -fdx", root)
            written = {p.name for p in a.writes}
            for name in (".phi-gate", ".phi-gate.toml", ".claude", ".mcp.json", ".pre-commit-config.yaml"):
                self.assertIn(name, written)


class GitCleanThroughTheHook(HookTestCase):
    def test_is_refused(self):
        self.assertBlocked(self.pre("Bash", {"command": "git clean -fdX"}))


if __name__ == "__main__":
    unittest.main()
