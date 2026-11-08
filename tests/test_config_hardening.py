"""Configuration, CLI, audit and hook-wrapper hardening: each test reproduces
a way to switch phi-gate off or make it leak, and checks that it no longer
works. All identifiers are synthetic."""

import io
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from test_hooks import PHI_CSV, ROOT, SSN, HookTestCase  # noqa: E402

from phi_gate import audit, cli, config  # noqa: E402
from phi_gate.config import Config, ConfigError, is_protected, load, load_for_payload  # noqa: E402

NO_SYSTEM_POLICY = ("/nonexistent/phi-gate/policy.toml",)


def write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    return path


class TempDirCase(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="phi-gate-cfg-")).resolve()
        self.addCleanup(shutil.rmtree, self.dir, True)
        (self.dir / ".git").mkdir()
        clean = {k: v for k, v in os.environ.items() if not k.startswith("PHI_GATE_") and k != "CLAUDE_PROJECT_DIR"}
        patcher = mock.patch.dict(os.environ, clean, clear=True)
        patcher.start()
        self.addCleanup(patcher.stop)
        managed = mock.patch.object(config, "MANAGED_PATHS", NO_SYSTEM_POLICY)
        managed.start()
        self.addCleanup(managed.stop)

    def outside(self, name: str) -> Path:
        other = Path(tempfile.mkdtemp(prefix="phi-gate-out-")).resolve()
        self.addCleanup(shutil.rmtree, other, True)
        return other / name


# ----------------------------------------------------------------------
# 1. Protected paths
# ----------------------------------------------------------------------


class ProtectedPaths(TempDirCase):
    def test_files_that_can_switch_phi_gate_off_are_protected(self):
        cfg = Config(root=self.dir, audit_log="logs/decisions.log")
        for rel in (
            ".claude/settings.json", ".claude/settings.local.json", ".claude/agents/helper.md",
            ".CLAUDE/Settings.JSON", ".mcp.json", ".git/hooks/pre-commit", ".git/config", ".git",
            ".pre-commit-config.yaml", "sub/deeper/.phi-gate.toml", "logs/decisions.log",
            "logs/decisions.log.salt", "pkg/.claude/settings.json",
        ):
            with self.subTest(rel):
                self.assertTrue(is_protected(self.dir / rel, cfg))
                self.assertTrue(is_protected(rel, cfg))

    def test_ordinary_files_are_not_protected(self):
        cfg = Config(root=self.dir)
        for rel in ("src/app.py", ".github/workflows/ci.yml", ".git/HEAD", "claude/settings.json", "README.md"):
            with self.subTest(rel):
                self.assertFalse(is_protected(self.dir / rel, cfg))

    def test_claude_code_worktrees_are_judged_as_checkouts(self):
        cfg = Config(root=self.dir)
        wt = self.dir / ".claude" / "worktrees" / "agent-1"
        self.assertFalse(is_protected(wt / "src" / "app.py", cfg))
        for path in (wt, wt / ".git", wt / ".claude" / "settings.json", wt / ".phi-gate.toml", wt / ".mcp.json"):
            with self.subTest(str(path)):
                self.assertTrue(is_protected(path, cfg))

    def test_user_level_claude_settings_are_protected(self):
        cfg = Config(root=self.dir)
        self.assertTrue(is_protected(Path.home() / ".claude" / "settings.json", cfg))
        self.assertTrue(is_protected(Path.home() / ".claude.json", cfg))

    def test_a_symlink_to_a_protected_file_is_protected(self):
        write(self.dir / ".claude" / "settings.json", "{}")
        (self.dir / "innocent.json").symlink_to(self.dir / ".claude" / "settings.json")
        self.assertTrue(is_protected(self.dir / "innocent.json", Config(root=self.dir)))

    def test_audit_key_file_is_protected_and_secret(self):
        key = self.outside("audit.key")
        cfg = Config(root=self.dir, audit_key_file=str(key))
        self.assertTrue(is_protected(key, cfg))
        self.assertTrue(config.is_secret(key, cfg))
        self.assertTrue(config.is_secret(self.dir / ".phi-gate" / "audit.jsonl.salt", cfg))
        self.assertFalse(config.is_secret(self.dir / ".phi-gate" / "audit.jsonl", cfg))


class ProtectedPathsThroughHooks(HookTestCase):
    def test_agent_cannot_write_claude_settings(self):
        settings = {"env": {"PHI_GATE_PYTHON": "true", "PHI_GATE_FAIL_OPEN": "1"}}
        for rel in (".claude/settings.json", ".claude/settings.local.json", ".mcp.json", ".git/hooks/pre-commit",
                    ".pre-commit-config.yaml", "sub/.phi-gate.toml"):
            with self.subTest(rel):
                self.assertBlocked(self.pre("Write", {"file_path": str(self.dir / rel), "content": json.dumps(settings)}))

    def test_agent_cannot_write_claude_settings_from_the_shell(self):
        self.assertBlocked(self.pre("Bash", {"command": "echo '{}' > .claude/settings.json"}))
        self.assertBlocked(self.pre("Bash", {"command": "echo x >> .git/config"}))


# ----------------------------------------------------------------------
# 2. The hook wrapper: sentinel, timeout, managed policy
# ----------------------------------------------------------------------


class WrapperCase(HookTestCase):
    def plugin(self, limit=None, policy=None):
        """A copy of the plugin whose run.sh uses a shorter limit or another
        system policy path."""
        root = Path(tempfile.mkdtemp(prefix="phi-gate-plugin-"))
        self.addCleanup(shutil.rmtree, root, True)
        (root / "hooks").mkdir()
        (root / "src").symlink_to(ROOT / "src")
        text = (ROOT / "hooks" / "run.sh").read_text()
        if limit is not None:
            text = text.replace("LIMIT=25", f"LIMIT={limit}")
        if policy is not None:
            text = text.replace('"/etc/phi-gate/policy.toml"', f'"{policy}"')
        (root / "hooks" / "run.sh").write_text(text)
        return root / "hooks" / "run.sh"

    def run_with(self, script, payload, env=None, path=None):
        payload = {"session_id": "t", "cwd": str(self.dir), **payload}
        full_env = {**self.env, **(env or {})}
        if path is not None:
            full_env["PATH"] = path
        return subprocess.run([shutil.which("bash") or "/bin/bash", str(script), payload.get("hook_event_name", "UserPromptSubmit")],
                              input=json.dumps(payload), capture_output=True, text=True, cwd=self.dir,
                              env=full_env, timeout=60)

    def fake_python(self, body):
        bindir = Path(tempfile.mkdtemp(prefix="phi-gate-bin-"))
        self.addCleanup(shutil.rmtree, bindir, True)
        exe = bindir / "fakepy"
        exe.write_text("#!/bin/sh\n" + body + "\n")
        exe.chmod(0o755)
        return exe

    def bare_path(self, *extra):
        """A PATH holding only what run.sh needs, without timeout(1)."""
        bindir = Path(tempfile.mkdtemp(prefix="phi-gate-path-"))
        self.addCleanup(shutil.rmtree, bindir, True)
        for tool in ("dirname", "grep", "sleep", "python3", "git", *extra):
            found = shutil.which(tool)
            if found:
                (bindir / tool).symlink_to(found)
        return str(bindir)


class Sentinel(WrapperCase):
    def test_an_interpreter_that_exits_zero_does_not_allow(self):
        for fake in ("true", "/bin/true"):
            with self.subTest(fake):
                self.assertBlocked(self.run_hook("UserPromptSubmit", {"prompt": f"SSN {SSN}"},
                                                 env={"PHI_GATE_PYTHON": fake}))

    def test_a_program_printing_json_and_exiting_zero_does_not_allow(self):
        fake = self.fake_python('echo "{}"; exit 0')
        self.assertBlocked(self.run_hook("UserPromptSubmit", {"prompt": "hello"}, env={"PHI_GATE_PYTHON": str(fake)}))

    def test_real_checker_still_allows_and_passes_stdout_through(self):
        (self.dir / ".phi-gate.toml").write_text('[phi-gate]\nmode = "warn"\n')
        res = self.run_hook("UserPromptSubmit", {"prompt": f"SSN {SSN}"})
        self.assertAllowed(res)
        self.assertEqual(set(json.loads(res.stdout)), {"systemMessage"})
        self.assertNotIn(cli.ALLOW_TOKEN, res.stdout + res.stderr)

    def test_hook_entry_writes_the_token_only_on_allow(self):
        read_end, write_end = os.pipe()
        try:
            with mock.patch.object(cli, "ALLOW_FD", write_end), mock.patch.object(cli.hooks, "main", return_value=2):
                self.assertEqual(cli.hook_entry("PreToolUse"), 2)
            with mock.patch.object(cli, "ALLOW_FD", write_end), mock.patch.object(cli.hooks, "main", return_value=7):
                self.assertEqual(cli.hook_entry("PreToolUse"), 2)
            with mock.patch.object(cli, "ALLOW_FD", write_end), mock.patch.object(cli.hooks, "main", return_value=0):
                self.assertEqual(cli.hook_entry("PreToolUse"), 0)
            os.close(write_end)
            write_end = -1
            self.assertEqual(os.read(read_end, 100).decode(), cli.ALLOW_TOKEN)
        finally:
            os.close(read_end)
            if write_end >= 0:
                os.close(write_end)

    def test_hook_entry_blocks_when_the_token_cannot_be_written(self):
        with mock.patch.object(cli, "ALLOW_FD", 987), mock.patch.object(cli.hooks, "main", return_value=0), \
                mock.patch("sys.stderr", io.StringIO()):
            self.assertEqual(cli.hook_entry("PreToolUse"), 2)


class Deadline(WrapperCase):
    def test_a_hung_checker_blocks(self):
        hang = self.fake_python("sleep 30")
        start = time.time()
        res = self.run_with(self.plugin(limit=2), {"prompt": "hello"}, env={"PHI_GATE_PYTHON": str(hang)})
        self.assertBlocked(res)
        self.assertIn("did not finish", res.stderr)
        self.assertLess(time.time() - start, 20)

    def test_a_hung_checker_blocks_without_timeout_installed(self):
        hang = self.fake_python("sleep 30")
        path = self.bare_path()
        self.assertIsNone(shutil.which("timeout", path=path))
        start = time.time()
        res = self.run_with(self.plugin(limit=2), {"prompt": "hello"}, env={"PHI_GATE_PYTHON": str(hang)}, path=path)
        self.assertBlocked(res)
        self.assertLess(time.time() - start, 20)

    def test_the_fallback_still_allows_a_clean_prompt(self):
        res = self.run_with(self.plugin(limit=20), {"prompt": "hello"}, path=self.bare_path())
        self.assertAllowed(res)
        res = self.run_with(self.plugin(limit=20), {"prompt": f"SSN {SSN}"}, path=self.bare_path())
        self.assertBlocked(res)


class WrapperPolicy(WrapperCase):
    def setUp(self):
        super().setUp()
        self.policy = Path(tempfile.mkdtemp(prefix="phi-gate-sys-")) / "policy.toml"
        self.addCleanup(shutil.rmtree, self.policy.parent, True)

    def test_overrides_are_ignored_under_a_managed_policy(self):
        self.policy.write_text('[phi-gate]\nmode = "block"\n')
        script = self.plugin(policy=self.policy)
        res = self.run_with(script, {"prompt": "hello"},
                            env={"PHI_GATE_PYTHON": "/nonexistent/python", "PHI_GATE_FAIL_OPEN": "1"})
        self.assertAllowed(res)  # the override was dropped: the real python3 ran and allowed
        res = self.run_with(script, {"prompt": f"SSN {SSN}"}, env={"PHI_GATE_PYTHON": "true", "PHI_GATE_FAIL_OPEN": "1"})
        self.assertBlocked(res)

    def test_a_policy_can_permit_overrides(self):
        self.policy.write_text('[phi-gate]\nallow_env_overrides = true\n')
        res = self.run_with(self.plugin(policy=self.policy), {"prompt": "hello"},
                            env={"PHI_GATE_PYTHON": "/nonexistent/python", "PHI_GATE_FAIL_OPEN": "1"})
        self.assertAllowed(res)
        self.assertIn("PHI_GATE_FAIL_OPEN=1", res.stderr)

    def test_without_a_policy_fail_open_is_honoured_for_a_broken_checker_only(self):
        res = self.run_with(self.plugin(), {"prompt": "hello"},
                            env={"PHI_GATE_PYTHON": "/nonexistent/python", "PHI_GATE_FAIL_OPEN": "1"})
        self.assertAllowed(res)


# ----------------------------------------------------------------------
# 3, 4. Managed policy floor and layering
# ----------------------------------------------------------------------


class ManagedFloor(TempDirCase):
    LOOSE = (
        '[phi-gate]\nmode = "audit"\nopaque = "allow"\noversize = "scan_head"\nallow_paths = ["*", "**"]\n'
        'disable = ["ssn"]\nallow_values = ["re:.*", "234-56-7891"]\nprotect_config = false\n'
        'scan_tool_output = false\naudit_log = ""\nprompt_override_token = "#yes"\nmax_bytes = 99999999\n'
        'record_window = 1\naudit_targets = "path"\n'
    )

    def policy(self, text):
        path = self.outside("policy.toml")
        path.write_text(text)
        os.environ["PHI_GATE_MANAGED_CONFIG"] = str(path)
        return path

    def test_a_repository_cannot_loosen_any_key_the_policy_leaves_unset(self):
        self.policy('[phi-gate]\nmode = "block"\nopaque = "block"\nmax_bytes = 1000\nrecord_window = 500\n')
        write(self.dir / ".phi-gate.toml", self.LOOSE)
        cfg = load(self.dir)
        self.assertEqual(cfg.mode, "block")
        self.assertEqual(cfg.opaque, "block")
        self.assertEqual(cfg.oversize, "block")
        self.assertEqual(cfg.allow_paths, [])
        self.assertEqual(cfg.disable, [])
        self.assertEqual(cfg.allow_values, [])
        self.assertTrue(cfg.protect_config)
        self.assertTrue(cfg.scan_tool_output)
        self.assertEqual(cfg.audit_log, ".phi-gate/audit.jsonl")
        self.assertEqual(cfg.prompt_override_token, "#phi-ok")
        self.assertEqual(cfg.max_bytes, 1000)
        self.assertEqual(cfg.record_window, 500)
        self.assertEqual(cfg.audit_targets, "hash")
        self.assertFalse(cfg.is_allowed_path(self.dir / "data.csv"))

    def test_a_repository_can_tighten(self):
        self.policy('[phi-gate]\nmode = "audit"\nmax_bytes = 5000\n')
        write(self.dir / ".phi-gate.toml", '[phi-gate]\nmode = "block"\nmax_bytes = 10\nrecord_window = 900\n'
              'prompt_override_token = ""\nwarn_in_hooks = true\naudit_targets = "category"\n')
        cfg = load(self.dir)
        self.assertEqual((cfg.mode, cfg.max_bytes, cfg.record_window), ("block", 10, 900))
        self.assertEqual((cfg.prompt_override_token, cfg.warn_in_hooks, cfg.audit_targets), ("", True, "category"))

    def test_policy_opt_in_lets_repositories_add_list_entries(self):
        self.policy('[phi-gate]\nallow_repo_allowlists = true\nallow_paths = ["vendor/**"]\n')
        write(self.dir / ".phi-gate.toml", '[phi-gate]\nallow_paths = ["tests/fixtures/*"]\ndisable = ["ssn"]\n'
              'allow_values = ["1EG4-TE5-MK73"]\nallow_repo_allowlists = false\n')
        cfg = load(self.dir)
        self.assertEqual(cfg.allow_paths, ["vendor/**", "tests/fixtures/*"])
        self.assertEqual(cfg.disable, ["ssn"])
        self.assertTrue(cfg.is_allowed_path(self.dir / "tests" / "fixtures" / "a.csv"))
        self.assertFalse(cfg.is_allowed_path(self.outside("tests") / "fixtures" / "a.csv"))

    def test_policy_only_keys_are_refused_without_a_policy(self):
        write(self.dir / ".phi-gate.toml", '[phi-gate]\nallow_env_overrides = true\n')
        with self.assertRaises(ConfigError):
            load(self.dir)

    def test_both_files_are_validated_before_merging(self):
        self.policy('[phi-gate]\nmode = "block"\n')
        write(self.dir / ".phi-gate.toml", '[phi-gate]\nmode = "off"\n')
        with self.assertRaisesRegex(ConfigError, "mode must be one of"):
            load(self.dir)
        self.policy('[phi-gate]\nmode = "never"\n')
        write(self.dir / ".phi-gate.toml", '[phi-gate]\nmode = "block"\n')
        with self.assertRaisesRegex(ConfigError, "mode must be one of"):
            load(self.dir)


class SystemPolicyLayers(TempDirCase):
    def setUp(self):
        super().setUp()
        self.system = self.outside("policy.toml")
        patcher = mock.patch.object(config, "MANAGED_PATHS", (str(self.system),))
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_the_environment_cannot_replace_the_system_policy(self):
        self.system.write_text('[phi-gate]\nmode = "block"\n')
        empty = self.outside("empty.toml")
        empty.write_text("")
        os.environ["PHI_GATE_MANAGED_CONFIG"] = str(empty)
        write(self.dir / ".phi-gate.toml", '[phi-gate]\nmode = "audit"\n')
        cfg = load(self.dir)
        self.assertEqual(cfg.mode, "block")
        self.assertEqual(cfg.managed, self.system)

    def test_the_environment_can_add_a_stricter_layer_only(self):
        self.system.write_text('[phi-gate]\nmode = "warn"\nopaque = "block"\n')
        extra = self.outside("extra.toml")
        extra.write_text('[phi-gate]\nmode = "block"\nopaque = "allow"\nallow_repo_allowlists = true\n')
        os.environ["PHI_GATE_MANAGED_CONFIG"] = str(extra)
        write(self.dir / ".phi-gate.toml", '[phi-gate]\nallow_paths = ["**"]\n')
        cfg = load(self.dir)
        self.assertEqual((cfg.mode, cfg.opaque, cfg.allow_paths), ("block", "block", []))

    def test_phi_gate_config_is_ignored_under_a_system_policy(self):
        self.system.write_text('[phi-gate]\nmode = "block"\n')
        loose = write(self.outside("loose.toml"), '[phi-gate]\nscan_tool_output = false\n')
        os.environ["PHI_GATE_CONFIG"] = str(loose)
        self.assertIsNone(load(self.dir).source)
        self.assertFalse(config.env_overrides_permitted())
        self.system.write_text('[phi-gate]\nallow_env_overrides = true\n')
        self.assertTrue(config.env_overrides_permitted())
        self.assertEqual(load(self.dir).source, loose)

    def test_a_policy_path_that_is_a_directory_is_an_error(self):
        self.system.mkdir()
        with self.assertRaises(ConfigError):
            load(self.dir)
        self.assertFalse(config.env_overrides_permitted())


# ----------------------------------------------------------------------
# 5. Project root and nested configuration
# ----------------------------------------------------------------------


class ProjectRoot(TempDirCase):
    def test_a_nested_config_cannot_loosen(self):
        write(self.dir / ".phi-gate.toml", '[phi-gate]\nmode = "block"\nallow_paths = ["tests/fixtures/*"]\n')
        sub = self.dir / "sub"
        write(sub / ".phi-gate.toml", '[phi-gate]\nmode = "audit"\nallow_paths = ["**"]\nscan_tool_output = false\n')
        cfg = load(sub)
        self.assertEqual(cfg.root, self.dir)
        self.assertEqual(cfg.source, self.dir / ".phi-gate.toml")
        self.assertEqual((cfg.mode, cfg.allow_paths, cfg.scan_tool_output), ("block", ["tests/fixtures/*"], True))

    def test_a_nested_config_can_tighten(self):
        write(self.dir / ".phi-gate.toml", '[phi-gate]\nmode = "warn"\n')
        write(self.dir / "a" / ".phi-gate.toml", '[phi-gate]\nopaque = "block"\n')
        write(self.dir / "a" / "b" / ".phi-gate.toml", '[phi-gate]\nmode = "block"\n')
        cfg = load(self.dir / "a" / "b")
        self.assertEqual((cfg.mode, cfg.opaque), ("block", "block"))
        self.assertEqual(len(cfg.layers), 2)

    def test_a_nested_config_without_a_root_config_cannot_loosen_the_defaults(self):
        write(self.dir / "sub" / ".phi-gate.toml", '[phi-gate]\nmode = "audit"\n')
        self.assertEqual(load(self.dir / "sub").mode, "block")

    def test_claude_project_dir_is_the_root(self):
        project = self.dir / "project"
        write(project / ".phi-gate.toml", '[phi-gate]\nopaque = "block"\n')
        write(project / "inner" / ".git" / "HEAD", "")
        os.environ["CLAUDE_PROJECT_DIR"] = str(project)
        cfg = load_for_payload({"cwd": str(project / "inner")})
        self.assertEqual(cfg.root, project)
        self.assertEqual(cfg.opaque, "block")

    def test_claude_project_dir_is_ignored_for_a_cwd_outside_it(self):
        os.environ["CLAUDE_PROJECT_DIR"] = str(self.outside("elsewhere").parent)
        self.assertEqual(load(self.dir / "src").root, self.dir)


# ----------------------------------------------------------------------
# 6. Validation and exit codes
# ----------------------------------------------------------------------


class Validation(TempDirCase):
    def assertConfigError(self, text):
        write(self.dir / ".phi-gate.toml", text)
        with self.assertRaises(ConfigError):
            load(self.dir)

    def test_section_must_be_a_table(self):
        self.assertConfigError("phi-gate = 1\n")
        self.assertConfigError('phi-gate = "block"\n')

    def test_keys_outside_the_section_are_errors(self):
        self.assertConfigError('mode = "audit"\n[phi-gate]\nmode = "block"\n')
        self.assertConfigError('[phi-gate]\nmode = "block"\n[other]\nx = 1\n')

    def test_list_values_must_be_strings(self):
        self.assertConfigError('[phi-gate]\nallow_paths = [1]\n')
        self.assertConfigError('[phi-gate]\nallow_values = "x"\n')


class ExitCodes(TempDirCase):
    def test_an_unexpected_exception_exits_2_without_its_message(self):
        os.chdir(self.dir)
        self.addCleanup(os.chdir, ROOT)
        with mock.patch.object(cli, "cmd_explain", side_effect=TypeError("Jane Doe 234-56-7891")), \
                mock.patch("sys.stderr", io.StringIO()) as err:
            self.assertEqual(cli.main(["explain"]), 2)
        self.assertEqual(err.getvalue().count("\n"), 1)
        self.assertIn("TypeError", err.getvalue())
        self.assertNotIn("Jane", err.getvalue())

    def test_a_bad_section_exits_2(self):
        write(self.dir / ".phi-gate.toml", "phi-gate = 1\n")
        res = subprocess.run([sys.executable, "-m", "phi_gate", "status"], cwd=self.dir, capture_output=True,
                             text=True, env={**os.environ, "PYTHONPATH": str(ROOT / "src")})
        self.assertEqual(res.returncode, 2, res.stderr)
        self.assertNotIn("Traceback", res.stderr)

    def test_restore_requires_a_string_map(self):
        os.chdir(self.dir)
        self.addCleanup(os.chdir, ROOT)
        for bad in ("[1, 2]", '{"[SSN_1]": 5}', "{not json"):
            with self.subTest(bad):
                mp = write(self.outside("bad.map.json"), bad)
                with mock.patch("sys.stdin", io.StringIO("x")), mock.patch("sys.stderr", io.StringIO()):
                    self.assertEqual(cli.main(["restore", "--map", str(mp), "-"]), 2)


# ----------------------------------------------------------------------
# 7. allow_paths matching
# ----------------------------------------------------------------------


class AllowPaths(TempDirCase):
    def test_paths_outside_the_root_never_match(self):
        cfg = Config(root=self.dir, allow_paths=["*.csv", "**"])
        self.assertFalse(cfg.is_allowed_path(self.outside("patients.csv")))
        self.assertFalse(cfg.is_allowed_path(self.dir / ".." / "patients.csv"))
        self.assertTrue(cfg.is_allowed_path(self.dir / "patients.csv"))

    def test_a_star_stays_within_one_folder(self):
        cfg = Config(root=self.dir, allow_paths=["tests/*"])
        self.assertTrue(cfg.is_allowed_path(self.dir / "tests" / "a.csv"))
        self.assertFalse(cfg.is_allowed_path(self.dir / "tests" / "a" / "b" / "real.csv"))
        self.assertTrue(Config(root=self.dir, allow_paths=["tests/**"]).is_allowed_path(self.dir / "tests/a/b/x.csv"))
        self.assertTrue(Config(root=self.dir, allow_paths=["tests/"]).is_allowed_path(self.dir / "tests/a/b/x.csv"))

    def test_documented_examples_keep_working(self):
        cfg = Config(root=self.dir, allow_paths=["tests/fixtures/*", "seed/synthetic/*", "*.synthetic.*", "study.dcm"])
        for rel in ("tests/fixtures/a.csv", "seed/synthetic/b.json", "deep/er/x.synthetic.csv", "study.dcm"):
            with self.subTest(rel):
                self.assertTrue(cfg.is_allowed_path(self.dir / rel))
        self.assertFalse(cfg.is_allowed_path(self.dir / "tests/fixtures/sub/a.csv"))

    def test_a_leading_slash_anchors_and_bare_names_match_at_any_depth(self):
        self.assertTrue(Config(root=self.dir, allow_paths=["visits.csv"]).is_allowed_path(self.dir / "a/visits.csv"))
        anchored = Config(root=self.dir, allow_paths=["/visits.csv"])
        self.assertTrue(anchored.is_allowed_path(self.dir / "visits.csv"))
        self.assertFalse(anchored.is_allowed_path(self.dir / "a/visits.csv"))

    def test_patterns_that_leave_the_root_are_errors(self):
        for bad in ("../*.csv", "a/../../b", "", "a\\b"):
            with self.subTest(bad), self.assertRaises(ConfigError):
                Config(root=self.dir, allow_paths=[bad])


# ----------------------------------------------------------------------
# 8. allow_values
# ----------------------------------------------------------------------


class AllowValues(unittest.TestCase):
    def test_values_are_literal_by_default(self):
        cfg = Config(allow_values=["(a+)+$", "1EG4-TE5-MK73", ".*"])
        start = time.time()
        self.assertFalse(cfg.is_allowed_value("a" * 28 + "!"))
        self.assertLess(time.time() - start, 0.5)
        self.assertTrue(cfg.is_allowed_value("1EG4-TE5-MK73"))
        self.assertFalse(cfg.is_allowed_value("234-56-7891"))

    def test_regex_values_refuse_catastrophic_patterns(self):
        for bad in (r"(a+)+$", r"(\d{3})+", r"(a|aa)*", r"(x)\1", "a" * 201, r"(?:(?:a)*)*"):
            with self.subTest(bad), self.assertRaises(ConfigError):
                Config(allow_values=["re:" + bad])

    def test_safe_regex_values_work(self):
        cfg = Config(allow_values=[r"re:900-\d\d-\d{4}", r"re:555-01\d\d"])
        self.assertTrue(cfg.is_allowed_value("900-12-3456"))
        self.assertFalse(cfg.is_allowed_value("234-56-7891"))

    def test_invalid_regex_is_an_error(self):
        with self.assertRaises(ConfigError):
            Config(allow_values=["re:(unclosed"])


# ----------------------------------------------------------------------
# 9. Redaction map
# ----------------------------------------------------------------------


class RedactionMap(HookTestCase):
    def cli(self, *args, stdin=f"SSN {SSN}\n"):
        return subprocess.run([sys.executable, "-m", "phi_gate", *args], cwd=self.dir, input=stdin,
                              capture_output=True, text=True, env={**self.env, "PYTHONPATH": str(ROOT / "src")})

    def test_a_symlinked_map_is_refused(self):
        victim = Path(tempfile.mkdtemp()) / "victim.txt"
        self.addCleanup(shutil.rmtree, victim.parent, True)
        victim.write_text("keep")
        link = Path(tempfile.mkdtemp()) / "out.map.json"
        self.addCleanup(shutil.rmtree, link.parent, True)
        link.symlink_to(victim)
        res = self.cli("redact", "-", "--map", str(link))
        self.assertEqual(res.returncode, 2)
        self.assertEqual(victim.read_text(), "keep")
        self.assertNotIn("[SSN_1]", res.stdout)

    def test_an_existing_map_becomes_private(self):
        out = Path(tempfile.mkdtemp()) / "out.map.json"
        self.addCleanup(shutil.rmtree, out.parent, True)
        out.write_text("old")
        out.chmod(0o644)
        res = self.cli("redact", "-", "--map", str(out))
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertEqual(stat.S_IMODE(out.stat().st_mode), 0o600)
        self.assertEqual(json.loads(out.read_text()), {"[SSN_1]": SSN})

    def test_a_hard_linked_map_is_refused(self):
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, True)
        (tmp / "a").write_text("keep")
        os.link(tmp / "a", tmp / "b.map.json")
        self.assertEqual(self.cli("redact", "-", "--map", str(tmp / "b.map.json")).returncode, 2)
        self.assertEqual((tmp / "a").read_text(), "keep")

    def test_a_map_git_would_commit_is_refused(self):
        res = self.cli("redact", "-", "--map", "phi.map.json")
        self.assertEqual(res.returncode, 2)
        self.assertFalse((self.dir / "phi.map.json").exists())
        (self.dir / ".gitignore").write_text("*.map.json\n")
        res = self.cli("redact", "-", "--map", "phi.map.json")
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertEqual(stat.S_IMODE((self.dir / "phi.map.json").stat().st_mode), 0o600)


# ----------------------------------------------------------------------
# 10. Audit log
# ----------------------------------------------------------------------


class AuditFailures(TempDirCase):
    def test_a_write_failure_warns_in_block_mode(self):
        write(self.dir / "blocker", "a file where the log directory should be")
        cfg = Config(root=self.dir, audit_log="blocker/audit.jsonl")
        with mock.patch("sys.stderr", io.StringIO()) as err:
            audit.record(cfg, event="PreToolUse", decision="block", tool="Read")
        self.assertIn("could not write the audit log", err.getvalue())

    def test_a_write_failure_raises_in_audit_mode_and_for_overrides(self):
        write(self.dir / "blocker", "x")
        with self.assertRaises(audit.AuditWriteError):
            audit.record(Config(root=self.dir, mode="audit", audit_log="blocker/a.jsonl"), event="E", decision="audited")
        with self.assertRaises(audit.AuditWriteError):
            audit.record(Config(root=self.dir, audit_log="blocker/a.jsonl"), event="E", decision="override")


class AuditWriteFailureBlocks(HookTestCase):
    def test_audit_mode_blocks_when_the_log_cannot_be_written(self):
        (self.dir / "blocker").write_text("x")
        (self.dir / ".phi-gate.toml").write_text('[phi-gate]\nmode = "audit"\naudit_log = "blocker/a.jsonl"\n')
        self.assertBlocked(self.pre("Read", {"file_path": str(self.dir / "data" / "patients.csv")}))
        self.assertAllowed(self.pre("Read", {"file_path": str(self.dir / "src" / "app.py")}))


class AuditKeyed(TempDirCase):
    def keyed(self, **kw):
        key = self.outside("audit.key")
        key.write_bytes(os.urandom(32).hex().encode())
        return Config(root=self.dir, audit_key_file=str(key), **kw)

    def log(self, cfg):
        return audit._log_path(cfg)

    def test_keyed_chain_verifies_and_resists_recomputation(self):
        cfg = self.keyed()
        for n in range(3):
            audit.record(cfg, event="PreToolUse", decision="block", tool=f"t{n}")
        report = audit.verify(cfg)
        self.assertTrue(report.intact)
        self.assertEqual(report.keyed, 3)
        lines = [json.loads(x) for x in self.log(cfg).read_text().splitlines()]
        self.assertTrue(all(e["mac"] == audit.MAC for e in lines))
        # Rewrite the log as an unkeyed chain, the way someone without the key would.
        prev = audit.GENESIS
        forged = []
        for e in lines:
            e = {k: v for k, v in e.items() if k not in ("mac", "kid", "hash")}
            e["decision"] = "allow"
            e["prev"] = prev
            e["hash"] = audit._digest(e)
            prev = e["hash"]
            forged.append(json.dumps(e, sort_keys=True))
        forged_text = "\n".join(forged) + "\n"
        self.log(cfg).write_text(forged_text)
        self.assertTrue(audit.verify(Config(root=self.dir)).intact)  # an unkeyed chain cannot tell
        # Keyed forgery with a guessed key fails.
        self.log(cfg).write_text("")
        bad = Config(root=self.dir, audit_key_file=str(self.outside("other.key")))
        Path(bad.audit_key_file).write_bytes(b"0" * 32)
        audit.record(bad, event="PreToolUse", decision="allow")
        self.assertFalse(audit.verify(cfg).intact)

    def test_keyed_events_need_the_key(self):
        cfg = self.keyed()
        audit.record(cfg, event="PreToolUse", decision="block")
        self.assertFalse(audit.verify(Config(root=self.dir)).intact)

    def test_an_unkeyed_event_after_keyed_ones_breaks_the_chain(self):
        cfg = self.keyed()
        audit.record(cfg, event="PreToolUse", decision="block")
        audit.record(Config(root=self.dir), event="PreToolUse", decision="block")
        report = audit.verify(cfg)
        self.assertEqual(report.broken_line, 2)

    def test_a_legacy_unkeyed_prefix_still_verifies(self):
        audit.record(Config(root=self.dir), event="PreToolUse", decision="block")
        cfg = self.keyed()
        audit.record(cfg, event="PreToolUse", decision="block")
        report = audit.verify(cfg)
        self.assertTrue(report.intact)
        self.assertEqual((report.legacy, report.keyed), (1, 1))

    def test_a_short_or_missing_key_is_a_config_error(self):
        short = self.outside("short.key")
        short.write_bytes(b"abc")
        with self.assertRaises(ConfigError):
            audit.verify(Config(root=self.dir, audit_key_file=str(short)))

    def test_repository_key_file_must_lie_outside_the_project(self):
        write(self.dir / ".phi-gate.toml", f'[phi-gate]\naudit_key_file = "{self.dir / "k.key"}"\n')
        with self.assertRaises(ConfigError):
            load(self.dir)
        outside = self.outside("k.key")
        write(self.dir / ".phi-gate.toml", f'[phi-gate]\naudit_key_file = "{outside}"\n')
        self.assertEqual(load(self.dir).audit_key_file, str(outside))


class AuditTargets(TempDirCase):
    NAME = "JaneDoe_labs.csv"

    def record(self, cfg):
        audit.record(cfg, event="PreToolUse", decision="block", tool="Read", target=f"data/{self.NAME}",
                     note=f"Read of data/{self.NAME}")
        return audit._log_path(cfg).read_text()

    def test_file_names_are_hashed_by_default(self):
        cfg = Config(root=self.dir)
        log = self.record(cfg)
        self.assertNotIn("JaneDoe", log)
        target = json.loads(log)["target"]
        self.assertRegex(target, r"^data/#[0-9a-f]{16}\.csv$")
        self.assertEqual(json.loads(self.record(cfg).splitlines()[-1])["target"], target)
        self.assertEqual(stat.S_IMODE((self.dir / ".phi-gate" / "audit.jsonl.salt").stat().st_mode), 0o600)

    def test_category_and_path_modes(self):
        self.assertEqual(json.loads(self.record(Config(root=self.dir, audit_targets="category")))["target"],
                         "data/[csv]")
        (self.dir / ".phi-gate" / "audit.jsonl").unlink()
        self.assertIn(self.NAME, self.record(Config(root=self.dir, audit_targets="path")))

    def test_keyed_hash_uses_the_audit_key(self):
        key = self.outside("k.key")
        key.write_bytes(b"k" * 32)
        target = json.loads(self.record(Config(root=self.dir, audit_key_file=str(key))))["target"]
        self.assertEqual(target, audit.describe_target(Config(root=self.dir, audit_key_file=str(key)),
                                                       f"data/{self.NAME}", b"k" * 32))
        self.assertFalse((self.dir / ".phi-gate" / "audit.jsonl.salt").exists())


class AuditTargetsThroughHooks(HookTestCase):
    def test_a_name_that_is_phi_does_not_reach_the_log(self):
        (self.dir / "data" / "JaneDoe_labs.csv").write_text(PHI_CSV)
        self.assertBlocked(self.pre("Read", {"file_path": str(self.dir / "data" / "JaneDoe_labs.csv")}))
        log = (self.dir / ".phi-gate" / "audit.jsonl").read_text()
        self.assertNotIn("JaneDoe", log)
        self.assertIn("tabular_phi", log)


# ----------------------------------------------------------------------
# 11. Git hook
# ----------------------------------------------------------------------


class GitHookInterpreter(HookTestCase):
    def test_the_hook_ignores_a_phi_gate_on_path(self):
        env = {**self.env, "PYTHONPATH": str(ROOT / "src")}
        res = subprocess.run([sys.executable, "-m", "phi_gate", "install-git-hook"], cwd=self.dir, env=env,
                             capture_output=True, text=True)
        self.assertEqual(res.returncode, 0, res.stderr)
        hook = (self.dir / ".git" / "hooks" / "pre-commit").read_text()
        self.assertIn(str(Path(sys.executable).absolute()), hook)
        self.assertNotIn("command -v phi-gate", hook)
        fake = Path(tempfile.mkdtemp(prefix="phi-gate-fakebin-"))
        self.addCleanup(shutil.rmtree, fake, True)
        (fake / "phi-gate").write_text("#!/bin/sh\nexit 0\n")
        (fake / "phi-gate").chmod(0o755)
        subprocess.run(["git", "add", "data/patients.csv"], cwd=self.dir, check=True)
        bad = subprocess.run(["git", "commit", "-qm", "x"], cwd=self.dir, capture_output=True, text=True,
                             env={**self.env, "PATH": f"{fake}:{self.env.get('PATH', '')}"})
        self.assertNotEqual(bad.returncode, 0)

    def test_a_missing_recorded_interpreter_blocks_the_commit(self):
        hooks_dir = self.dir / ".git" / "hooks"
        hooks_dir.mkdir(exist_ok=True)
        (hooks_dir / "pre-commit").write_text(cli.HOOK_TEMPLATE.format(python="/nonexistent/python3", src="/nonexistent"))
        (hooks_dir / "pre-commit").chmod(0o755)
        subprocess.run(["git", "add", "src/app.py"], cwd=self.dir, check=True)
        res = subprocess.run(["git", "commit", "-qm", "x"], cwd=self.dir, capture_output=True, text=True, env=self.env)
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("install-git-hook", res.stderr)


if __name__ == "__main__":
    unittest.main()
