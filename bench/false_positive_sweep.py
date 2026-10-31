"""Measure how often phi-gate would block ordinary source code.

    python3 bench/false_positive_sweep.py /usr/lib/python3.13 ./node_modules

Every BLOCK in clean code is a false positive. Prints counts, timing and the
blocked files with their reasons (never their contents).
"""

import collections
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from phi_gate.config import Config  # noqa: E402
from phi_gate.scanner import scan_file  # noqa: E402

EXTS = {".py", ".js", ".ts", ".tsx", ".jsx", ".mjs", ".cjs", ".json", ".md", ".svelte",
        ".css", ".html", ".yml", ".yaml", ".toml", ".txt", ".csv"}


def main(roots: list[str]) -> int:
    cfg = Config(root=Path("/"))
    start = time.time()
    files = size = 0
    decisions: collections.Counter = collections.Counter()
    blocked = []
    for root in roots:
        for p in Path(root).rglob("*"):
            if p.suffix not in EXTS or not p.is_file():
                continue
            res = scan_file(p, cfg)
            files += 1
            size += p.stat().st_size
            decisions[res.verdict.decision] += 1
            if res.blocking:
                blocked.append((str(p), "; ".join(res.verdict.reasons)))
    secs = time.time() - start
    print(f"files: {files}  size: {size / 1e6:.1f} MB  time: {secs:.1f}s  ({1000 * secs / max(files, 1):.1f} ms/file)")
    print(f"decisions: {dict(decisions)}")
    for path, why in blocked:
        print(f"BLOCK {path}: {why}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:] or ["."]))
