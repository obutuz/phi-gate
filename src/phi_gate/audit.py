"""Append-only, tamper-evident audit log.

Each event records what was decided, where, and which categories triggered
it. It never records matched values, hashes of values, or surrounding text:
a 9-digit SSN space is small enough that a hash is as good as the value, and
an audit trail must not become a second copy of the PHI it is protecting.

A file name can itself be PHI (`JaneDoe_labs.csv`), so the final component
of a target path is recorded according to `audit_targets`:

* `hash` (default): a keyed hash of the name plus its extension, such as
  `data/#3f2a9c1d0b7e4a65.csv`. The key is the audit key when one is
  configured, else a random salt kept beside the log (`<log>.salt`, mode
  0600). The same file gives the same hash, so repeated events can be
  correlated without revealing the name.
* `category`: the extension only, such as `data/[csv]`.
* `path`: the path as given. Use only where file names are known not to
  carry identifiers.

Events form a hash chain: each carries the hash of the one before it, so
editing, removing or reordering a line breaks every hash after it, and
`phi-gate audit verify` finds where. Without a key the chain is only
tamper-evident against accidental damage, since anyone who can write the log
can recompute it. With `audit_key_file` set (in the managed policy, or in a
repository configuration as a path outside the project) each link is an
HMAC-SHA256 under that key, marked `"mac": "hmac-sha256"` with a key
identifier `"kid"`. Unkeyed events written before the key was introduced
still verify as a legacy prefix; an unkeyed event after a keyed one breaks
the chain. A chain cannot show that its newest lines were cut off, so a
deployment that needs that guarantee ships events somewhere the developer
cannot write as they are made.

A failure to write an event is reported on stderr. In `audit` mode the log
is the only control, so a failure raises AuditWriteError and the hook blocks
the action; a prompt override that cannot be logged is refused the same way.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import sys
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath

from .config import Config, ConfigError
from .policy import Verdict

try:
    import fcntl
except ModuleNotFoundError:  # pragma: no cover - Windows
    fcntl = None  # type: ignore[assignment]

SCHEMA_VERSION = 1
GENESIS = "0" * 64
TAIL_BLOCK = 4096
MAC = "hmac-sha256"
MIN_KEY_BYTES = 16
MAX_EXTENSION = 8


class AuditWriteError(Exception):
    """An event that must be recorded could not be written."""


def _log_path(cfg: Config) -> Path:
    path = Path(cfg.audit_log)
    return path if path.is_absolute() else cfg.root / path


def _salt_path(cfg: Config) -> Path:
    log = _log_path(cfg)
    return log.with_name(log.name + ".salt")


def audit_key(cfg: Config) -> bytes | None:
    """The configured audit key, or None. A configured key that cannot be
    read, or is shorter than MIN_KEY_BYTES, is a configuration error."""
    if not cfg.audit_key_file:
        return None
    path = Path(cfg.audit_key_file).expanduser()
    try:
        key = path.read_bytes().strip()
    except OSError as exc:
        raise ConfigError(f"cannot read audit_key_file {path}: {exc.strerror or exc}") from exc
    if len(key) < MIN_KEY_BYTES:
        raise ConfigError(f"audit_key_file {path} holds fewer than {MIN_KEY_BYTES} bytes")
    return key


def key_id(key: bytes) -> str:
    return hashlib.sha256(b"phi-gate audit key id\0" + key).hexdigest()[:16]


def _canonical(entry: dict) -> bytes:
    body = {k: v for k, v in entry.items() if k != "hash"}
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode()


def _digest(entry: dict, key: bytes | None = None) -> str:
    if key is None:
        return hashlib.sha256(_canonical(entry)).hexdigest()
    return hmac.new(key, _canonical(entry), hashlib.sha256).hexdigest()


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


def _append(path: Path, entry: dict, key: bytes | None) -> None:
    flags = os.O_RDWR | os.O_APPEND | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    fd = os.open(path, flags, 0o600)
    try:
        # Reading the last hash and writing the next line must be one step, or
        # two hooks firing together would fork the chain.
        if fcntl is not None:
            fcntl.flock(fd, fcntl.LOCK_EX)
        if key is not None:
            entry["mac"] = MAC
            entry["kid"] = key_id(key)
        entry["prev"] = _last_hash(fd)
        entry["hash"] = _digest(entry, key)
        os.write(fd, (json.dumps(entry, sort_keys=True) + "\n").encode())
    finally:
        os.close(fd)


def _salt(cfg: Config) -> bytes:
    """A random per-log salt for hashed targets, created on first use."""
    path = _salt_path(cfg)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(path, flags)
    except FileNotFoundError:
        value = secrets.token_hex(32).encode()
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        except FileExistsError:
            return _salt(cfg)
        try:
            os.write(fd, value)
        finally:
            os.close(fd)
        return value
    try:
        value = os.read(fd, 4096).strip()
    finally:
        os.close(fd)
    if len(value) < MIN_KEY_BYTES:
        raise OSError(f"audit salt {path} is too short")
    return value


def _extension(name: str) -> str:
    suffix = PurePosixPath(name).suffix
    return suffix if 1 < len(suffix) <= MAX_EXTENSION and suffix[1:].isalnum() else ""


def describe_target(cfg: Config, target: str, key: bytes | None = None) -> str:
    """The form of `target` written to the log, per `audit_targets`."""
    if cfg.audit_targets == "path" or not target:
        return target
    head, sep, name = target.rstrip("/").rpartition("/")
    prefix = head + sep
    ext = _extension(name)
    if cfg.audit_targets == "category":
        return f"{prefix}[{ext[1:].lower() if ext else 'file'}]"
    try:
        secret = key if key is not None else _salt(cfg)
    except OSError:
        return f"{prefix}[{ext[1:].lower() if ext else 'file'}]"
    digest = hmac.new(secret, b"target\0" + name.encode("utf-8", "surrogatepass"), hashlib.sha256).hexdigest()
    return f"{prefix}#{digest[:16]}{ext}"


def _scrub(text: str, name: str, replacement: str) -> str:
    return text.replace(name, replacement) if name and name in text else text


def _warn(message: str) -> None:
    try:
        print(f"phi-gate warning: {message}", file=sys.stderr)
    except (OSError, ValueError):
        pass


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
    """Append one event. Raises AuditWriteError when it cannot be written
    and the decision depends on the log: in `audit` mode, and for a prompt
    override. Otherwise a failure is reported on stderr."""
    if not cfg.audit_log:
        return
    must_record = cfg.mode == "audit" or decision == "override"
    try:
        key = audit_key(cfg)
        path = _log_path(cfg)
        path.parent.mkdir(parents=True, exist_ok=True)
        ignore = path.parent / ".gitignore"
        if path.parent.name == ".phi-gate" and not ignore.exists():
            ignore.write_text("*\n", encoding="utf-8")
        reasons = list(verdict.reasons) if verdict else []
        if target:
            shown = describe_target(cfg, target, key)
            name = target.rstrip("/").rpartition("/")[2]
            shown_name = shown.rpartition("/")[2]
            if shown != target and len(name) > 2:
                note = _scrub(note, name, shown_name) if note else note
                reasons = [_scrub(r, name, shown_name) for r in reasons]
            target = shown
        entry = {
            "v": SCHEMA_VERSION,
            "id": uuid.uuid4().hex,
            "ts": datetime.now(UTC).isoformat(timespec="seconds"),
            "event": event,
            "decision": decision,
            "tool": tool,
            "target": target,
            "categories": dict(verdict.counts()) if verdict else {},
            "reasons": reasons,
            "session": session_id,
            "note": note,
        }
        entry = {k: v for k, v in entry.items() if v not in (None, [], {})}
        _append(path, entry, key)
    except (OSError, ConfigError) as exc:
        detail = exc.strerror if isinstance(exc, OSError) and exc.strerror else str(exc)
        message = f"could not write the audit log {cfg.audit_log}: {detail}"
        if must_record:
            raise AuditWriteError(message) from exc
        _warn(message)


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
    keyed: int = 0
    legacy: int = 0

    @property
    def intact(self) -> bool:
        return self.broken_line is None


def verify(cfg: Config) -> ChainReport:
    """Walk the chain and report the first line that does not hold. Keyed
    events are checked with the configured audit key; a keyed event without
    that key, or under a different key, does not verify."""
    key = audit_key(cfg)
    if not cfg.audit_log or not _log_path(cfg).is_file():
        return ChainReport(0)
    kid = key_id(key) if key is not None else None
    previous = GENESIS
    events = keyed = legacy = 0
    with _log_path(cfg).open(encoding="utf-8", errors="replace") as fh:
        for number, line in enumerate(fh, 1):
            try:
                entry = json.loads(line)
                claimed = entry["hash"]
                linked = entry["prev"]
                mac = entry.get("mac")
            except (ValueError, KeyError, TypeError, AttributeError):
                return ChainReport(events, number, "not a chained audit event", keyed, legacy)
            if linked != previous:
                return ChainReport(events, number, "does not follow the event before it", keyed, legacy)
            if mac is None:
                if keyed:
                    return ChainReport(events, number, "unkeyed event after keyed events", keyed, legacy)
                if _digest(entry) != claimed:
                    return ChainReport(events, number, "content does not match its hash", keyed, legacy)
                legacy += 1
            elif mac == MAC:
                if key is None:
                    return ChainReport(events, number, "keyed event, but no audit_key_file is configured",
                                       keyed, legacy)
                if entry.get("kid") != kid:
                    return ChainReport(events, number, "keyed under a different audit key", keyed, legacy)
                if not hmac.compare_digest(_digest(entry, key), str(claimed)):
                    return ChainReport(events, number, "content does not match its keyed hash", keyed, legacy)
                keyed += 1
            else:
                return ChainReport(events, number, f"unknown integrity scheme {mac!r}", keyed, legacy)
            previous = claimed
            events += 1
    return ChainReport(events, keyed=keyed, legacy=legacy)
