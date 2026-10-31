"""phi-gate command line.

    phi-gate scan [PATHS...] [--staged | --diff] [--json] [--all]
    phi-gate redact [FILE|-] [--map MAP.json] [--all]
    phi-gate restore --map MAP.json [FILE|-]
    phi-gate status
    phi-gate explain
    phi-gate install-git-hook [--force]
    phi-gate hook <EventName>          (used by Claude Code)

Exit codes for `scan`: 0 clean or warnings only, 1 blocking findings, 2 error.
"""

from __future__ import annotations

import argparse
import json
import os
import stat
import sys
from pathlib import Path

from . import __version__, audit, hooks
from .config import CONFIG_NAME, ConfigError, load
from .detectors import DETECTORS, LOW
from .redact import redact, restore
from .scanner import FileResult, iter_files, scan_file, scan_git_diff, worst

SEV_LABEL = {"high": "HIGH", "medium": "MED ", "low": "LOW "}


def _print_result(r: FileResult, show_low: bool) -> None:
    if r.skipped:
        return
    if r.note == "oversize" and r.blocking:
        print(f"{r.path}: BLOCK {'; '.join(r.verdict.reasons)}")
        return
    shown = [f for f in r.verdict.findings if show_low or f.severity != LOW]
    if not shown and r.verdict.decision == "allow":
        return
    print(f"{r.path}: {r.verdict.decision.upper()}" + (f"  ({'; '.join(r.verdict.reasons)})" if r.verdict.reasons else ""))
    for f in shown:
        print(f"  {r.path}:{f.line}:{f.col}  {SEV_LABEL[f.severity]}  {f.category}")
    if r.note:
        print(f"  note: {r.note}")


def cmd_scan(args) -> int:
    cfg = load(Path.cwd())
    if args.staged or args.diff:
        results = scan_git_diff(cfg, Path.cwd(), staged=args.staged)
    else:
        results = [scan_file(p, cfg) for p in iter_files(args.paths or ["."], cfg)]
    if args.json:
        payload = {
            "decision": worst(results),
            "files": [
                {
                    "path": r.path,
                    "decision": r.verdict.decision,
                    "reasons": r.verdict.reasons,
                    "note": r.note,
                    "findings": [f.to_dict() for f in r.verdict.findings if args.all or f.severity != LOW],
                }
                for r in results
                if not r.skipped and (r.verdict.findings or r.verdict.decision != "allow")
            ],
        }
        print(json.dumps(payload, indent=2))
    else:
        for r in results:
            _print_result(r, args.all)
        scanned = sum(1 for r in results if not r.skipped)
        overall = worst(results)
        print(f"phi-gate: {scanned} file(s) scanned, result: {overall.upper()}", file=sys.stderr)
    return 1 if worst(results) == "block" else 0


def _read_input(path: str | None) -> str:
    if not path or path == "-":
        return sys.stdin.read()
    return Path(path).read_text(encoding="utf-8", errors="replace")


def cmd_redact(args) -> int:
    cfg = load(Path.cwd())
    text = _read_input(args.file)
    out, mapping = redact(text, cfg, include_low=args.all)
    sys.stdout.write(out)
    if args.map:
        fd = os.open(args.map, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(mapping, fh, indent=2)
        print(
            f"\nphi-gate: wrote {len(mapping)} placeholder(s) to {args.map}. That file contains the original "
            "values: keep it local and never commit it.",
            file=sys.stderr,
        )
    else:
        print(f"\nphi-gate: replaced {len(mapping)} distinct value(s).", file=sys.stderr)
    return 0


def cmd_restore(args) -> int:
    mapping = json.loads(Path(args.map).read_text(encoding="utf-8"))
    sys.stdout.write(restore(_read_input(args.file), mapping))
    return 0


def cmd_status(args) -> int:
    cfg = load(Path.cwd())
    print(f"phi-gate {__version__}")
    print(f"config:        {cfg.source or 'defaults (no ' + CONFIG_NAME + ' found)'}")
    print(f"mode:          {cfg.mode}")
    print(f"allow_paths:   {cfg.allow_paths or '[]'}")
    print(f"disabled:      {cfg.disable or '[]'}")
    print(f"max_bytes:     {cfg.max_bytes} (oversize: {cfg.oversize})")
    print(f"audit_log:     {cfg.audit_log or 'disabled'}")
    events = audit.tail(cfg, args.n)
    print(f"\nlast {len(events)} audit event(s):")
    for e in events:
        cats = ", ".join(f"{k} x{v}" for k, v in e.get("categories", {}).items())
        where = e.get("target") or e.get("tool") or ""
        print(f"  {e.get('ts')}  {e.get('decision', ''):8} {e.get('event', ''):17} {where}  {cats}")
    return 0


def cmd_explain(args) -> int:
    print("phi-gate detectors (category, severity, description):\n")
    for d in DETECTORS:
        print(f"  {d.name:15} {d.severity:6} {d.description}")
    print(
        "\nDecision rules: any HIGH finding blocks. A clinical fact (diagnosis code, date of "
        "service) within record_window characters of a name, phone, email or address blocks. "
        "Other MEDIUM findings warn. LOW findings are informational."
    )
    return 0


HOOK_TEMPLATE = """#!/bin/sh
# Installed by phi-gate. Blocks commits whose staged changes contain likely PHI.
# Prefers a phi-gate on PATH (pipx install), else the copy that installed it.
if command -v phi-gate >/dev/null 2>&1; then
  exec phi-gate scan --staged
fi
exec "{python}" -I -c 'import sys; sys.path.insert(0, sys.argv[1]); from phi_gate.cli import main; sys.exit(main(["scan", "--staged"]))' "{src}"
"""


def cmd_install_git_hook(args) -> int:
    import subprocess

    try:
        git_dir = subprocess.run(
            ["git", "rev-parse", "--git-path", "hooks"], capture_output=True, text=True, check=True
        ).stdout.strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("phi-gate: not inside a git repository", file=sys.stderr)
        return 2
    hook = Path(git_dir) / "pre-commit"
    if hook.exists() and not args.force:
        print(f"phi-gate: {hook} already exists; re-run with --force to replace it", file=sys.stderr)
        return 2
    hook.parent.mkdir(parents=True, exist_ok=True)
    src = Path(__file__).resolve().parent.parent
    hook.write_text(HOOK_TEMPLATE.format(python=sys.executable, src=src), encoding="utf-8")
    hook.chmod(hook.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    print(f"phi-gate: installed {hook}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="phi-gate", description="Fail-closed PHI guardrails for AI coding agents.")
    p.add_argument("--version", action="version", version=f"phi-gate {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="scan files, directories or git changes")
    s.add_argument("paths", nargs="*")
    g = s.add_mutually_exclusive_group()
    g.add_argument("--staged", action="store_true", help="scan lines added in staged changes")
    g.add_argument("--diff", action="store_true", help="scan lines added in unstaged changes")
    s.add_argument("--json", action="store_true")
    s.add_argument("--all", action="store_true", help="include LOW (informational) findings")
    s.set_defaults(func=cmd_scan)

    r = sub.add_parser("redact", help="print a copy with typed placeholders")
    r.add_argument("file", nargs="?")
    r.add_argument("--map", help="write placeholder->value JSON (contains PHI)")
    r.add_argument("--all", action="store_true", help="also redact LOW findings")
    r.set_defaults(func=cmd_redact)

    rs = sub.add_parser("restore", help="put original values back using a map")
    rs.add_argument("file", nargs="?")
    rs.add_argument("--map", required=True)
    rs.set_defaults(func=cmd_restore)

    st = sub.add_parser("status", help="show config and recent audit events")
    st.add_argument("-n", type=int, default=15)
    st.set_defaults(func=cmd_status)

    ex = sub.add_parser("explain", help="list detectors and decision rules")
    ex.set_defaults(func=cmd_explain)

    gh = sub.add_parser("install-git-hook", help="install a pre-commit hook in this repository")
    gh.add_argument("--force", action="store_true")
    gh.set_defaults(func=cmd_install_git_hook)

    h = sub.add_parser("hook", help="Claude Code hook entry point (reads JSON on stdin)")
    h.add_argument("event")
    h.set_defaults(func=lambda a: hooks.main(a.event))
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except ConfigError as exc:
        print(f"phi-gate configuration error: {exc}", file=sys.stderr)
        return 2
    except RuntimeError as exc:
        print(f"phi-gate: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
