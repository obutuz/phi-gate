"""Append-only, tamper-evident audit log.

Each event records what was decided, where, and which categories triggered
it. It never records matched values, hashes of values, or surrounding text:
a 9-digit SSN space is small enough that a hash is as good as the value, and
an audit trail must not become a second copy of the PHI it is protecting.

Events form a hash chain: each carries the hash of the one before it, so
editing, removing or reordering a line breaks every hash after it, and
`phi-gate audit verify` finds where. A chain cannot show that its newest lines
were cut off, so a deployment that needs that guarantee ships events somewhere
the developer cannot write as they are made.
"""

from __future__ import annotations

import hashlib
import json
import os
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from .config import Config
from .policy import Verdict

try:
    import fcntl
except ModuleNotFoundError:  # pragma: no cover - Windows
    fcntl = None  # type: ignore[assignment]

SCHEMA_VERSION = 1
GENESIS = "0" * 64
TAIL_BLOCK = 4096


def _log_path(cfg: Config) -> Path:
    path = Path(cfg.audit_log)
    return path if path.is_absolute() else cfg.root / path


def _digest(entry: dict) -> str:
    body = {k: v for k, v in entry.items() if k != "hash"}
    return hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _last_hash(fd: int) -> str:
    """The hash on the file's last line, read from the end so that writing an
    event does not get slower as the log grows."""
    size = os.fstat(fd).st_size
    if size == 0:
        return GENESIS
    tail = b""
    position = size
    while position > 0 and tail.count(b"\n") < 2:
        position = max(position - TAIL_BLOCK, 0)
        tail = os.pread(fd, min(TAIL_BLOCK, size - position), position) + tail
    try:
        return json.loads(tail.strip().rsplit(b"\n", 1)[-1]).get("hash", GENESIS)
    except (ValueError, AttributeError):
        return GENESIS  # a damaged line: verification reports it


def _append(path: Path, entry: dict) -> None:
    fd = os.open(path, os.O_RDWR | os.O_APPEND | os.O_CREAT, 0o600)
    try:
        # Reading the last hash and writing the next line must be one step, or
        # two hooks firing together would fork the chain.
        if fcntl is not None:
            fcntl.flock(fd, fcntl.LOCK_EX)
        entry["prev"] = _last_hash(fd)
        entry["hash"] = _digest(entry)
        os.write(fd, (json.dumps(entry, sort_keys=True) + "\n").encode())
    finally:
        os.close(fd)


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
    path = _log_path(cfg)
    entry = {
        "v": SCHEMA_VERSION,
        "id": uuid.uuid4().hex,
        "ts": datetime.now(UTC).isoformat(timespec="seconds"),
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
        _append(path, entry)
    except OSError:
        # The audit trail is secondary to the decision itself; never let a
        # read-only filesystem turn a block into an allow or vice versa.
        pass


def tail(cfg: Config, n: int = 20) -> list[dict]:
    if not cfg.audit_log:
        return []
    path = _log_path(cfg)
    if not path.is_file():
        return []
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()[-n:]
    out = []
    for ln in lines:
        try:
            out.append(json.loads(ln))
        except json.JSONDecodeError:
            continue
    return out


@dataclass
class ChainReport:
    events: int
    broken_line: int | None = None
    problem: str = ""

    @property
    def intact(self) -> bool:
        return self.broken_line is None


def verify(cfg: Config) -> ChainReport:
    """Walk the chain and report the first line that does not hold."""
    if not cfg.audit_log or not _log_path(cfg).is_file():
        return ChainReport(0)
    previous = GENESIS
    events = 0
    with _log_path(cfg).open(encoding="utf-8", errors="replace") as fh:
        for number, line in enumerate(fh, 1):
            try:
                entry = json.loads(line)
                claimed = entry["hash"]
                linked = entry["prev"]
            except (ValueError, KeyError, TypeError):
                return ChainReport(events, number, "not a chained audit event")
            if linked != previous:
                return ChainReport(events, number, "does not follow the event before it")
            if _digest(entry) != claimed:
                return ChainReport(events, number, "content does not match its hash")
            previous = claimed
            events += 1
    return ChainReport(events)
