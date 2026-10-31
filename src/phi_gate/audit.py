"""Append-only audit log.

Each event records what was decided, where, and which categories triggered
it. It never records matched values, hashes of values, or surrounding text:
a 9-digit SSN space is small enough that a hash is as good as the value, and
an audit trail must not become a second copy of the PHI it is protecting.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path

from .config import Config
from .policy import Verdict


def record(
    cfg: Config,
    *,
    event: str,
    decision: str,
    verdict: Verdict | None = None,
    tool: str | None = None,
    target: str | None = None,
    session_id: str | None = None,
    note: str | None = None,
) -> None:
    if not cfg.audit_log:
        return
    path = Path(cfg.audit_log)
    if not path.is_absolute():
        path = cfg.root / path
    entry = {
        "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "event": event,
        "decision": decision,
        "tool": tool,
        "target": target,
        "categories": dict(verdict.counts()) if verdict else {},
        "reasons": verdict.reasons if verdict else [],
        "session": session_id,
        "note": note,
    }
    entry = {k: v for k, v in entry.items() if v not in (None, [], {})}
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        ignore = path.parent / ".gitignore"
        if path.parent.name == ".phi-gate" and not ignore.exists():
            ignore.write_text("*\n", encoding="utf-8")
        fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        with os.fdopen(fd, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, sort_keys=True) + "\n")
    except OSError:
        # The audit trail is secondary to the decision itself; never let a
        # read-only filesystem turn a block into an allow or vice versa.
        pass


def tail(cfg: Config, n: int = 20) -> list[dict]:
    path = Path(cfg.audit_log)
    if not path.is_absolute():
        path = cfg.root / path
    if not cfg.audit_log or not path.is_file():
        return []
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()[-n:]
    out = []
    for ln in lines:
        try:
            out.append(json.loads(ln))
        except json.JSONDecodeError:
            continue
    return out
