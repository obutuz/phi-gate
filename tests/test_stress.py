"""Load: hooks fire concurrently in real sessions, and input can be hostile."""

import subprocess
import sys
import tempfile
import time
import unittest
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from test_hooks import ROOT, HookTestCase  # noqa: E402

from phi_gate import audit  # noqa: E402
from phi_gate.config import Config  # noqa: E402
from phi_gate.scanner import scan_text  # noqa: E402


def append_events(args):
    root, count = args
    cfg = Config(root=Path(root))
    for n in range(count):
        audit.record(cfg, event="PreToolUse", decision="block", tool=f"tool{n}")


class ConcurrentAudit(unittest.TestCase):
    def test_writers_racing_cannot_fork_the_chain(self):
        with tempfile.TemporaryDirectory() as tmp:
            with ProcessPoolExecutor(max_workers=8) as pool:
                list(pool.map(append_events, [(tmp, 25)] * 8))
            report = audit.verify(Config(root=Path(tmp)))
            self.assertTrue(report.intact, report.problem)
            self.assertEqual(report.events, 200)


class ConcurrentHooks(HookTestCase):
    def test_hook_processes_racing_keep_the_chain_intact(self):
        payload = f'{{"cwd": "{self.dir}", "tool_name": "Bash", "tool_input": {{"command": "echo SSN 123-45-6789"}}}}'
        env = {k: v for k, v in self.env.items()}
        running = [
            subprocess.Popen(
                ["bash", str(ROOT / "hooks" / "run.sh"), "PreToolUse"],
                stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, cwd=self.dir, env=env,
            )
            for _ in range(16)
        ]
        for proc in running:
            proc.stdin.write(payload.encode())
            proc.stdin.close()
        self.assertEqual({proc.wait() for proc in running}, {2})
        report = audit.verify(Config(root=self.dir))
        self.assertTrue(report.intact, report.problem)
        self.assertEqual(report.events, 16)


class HostileInput(unittest.TestCase):
    """A check that runs out of time blocks, which is safe, but a repository of
    awkward files should not block for that reason."""

    def assertFast(self, text, limit=3):
        start = time.perf_counter()
        scan_text(text, Config())
        self.assertLess(time.perf_counter() - start, limit, text[:30])

    def test_repeated_header_lines(self):
        self.assertFast("dob,mrn,ssn\n" * 40_000)

    def test_repeated_name_columns(self):
        self.assertFast("first_name,last_name,dob\n" * 20_000)

    def test_a_table_with_a_stray_quote_on_every_row(self):
        self.assertFast("patient_name,dob,mrn\n" + 'a"b,1984-02-17,1\n' * 20_000)

    def test_one_enormous_line(self):
        self.assertFast("patient_name," * 40_000)


if __name__ == "__main__":
    unittest.main()
