"""Configuration loading.

phi-gate reads `.phi-gate.toml` from the project (searching upward from the
working directory). The file is meant to be edited by humans only: the Claude
Code hooks refuse agent edits to it, so an agent cannot loosen its own
guardrails.

Unknown keys and bad values raise ConfigError. The hooks turn that into a
block (fail-closed), because a silently ignored typo in an allowlist or mode
setting is worse than a loud error.

A security team can also install a managed policy at a path developers and
agents cannot write to. It is a floor: a repository can tighten it but never
loosen it. See `_apply_floor`.
"""

from __future__ import annotations

import fnmatch
import os
import re
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python < 3.11
    tomllib = None  # type: ignore[assignment]

from .detectors import CATEGORIES

CONFIG_NAME = ".phi-gate.toml"
STATE_DIR = ".phi-gate"

MODES = ("block", "warn", "audit")
OVERSIZE = ("block", "scan_head")
OPAQUE = ("allow", "block")
MANAGED_PATHS = ("/etc/phi-gate/policy.toml", "/Library/Application Support/phi-gate/policy.toml")


class ConfigError(Exception):
    pass


@dataclass
class Config:
    root: Path = field(default_factory=Path.cwd)
    source: Path | None = None
    mode: str = "block"
    record_window: int = 400
    max_bytes: int = 5_000_000
    oversize: str = "block"
    opaque: str = "allow"
    allow_paths: list[str] = field(default_factory=list)
    disable: list[str] = field(default_factory=list)
    allow_values: list[str] = field(default_factory=list)
    audit_log: str = ".phi-gate/audit.jsonl"
    protect_config: bool = True
    prompt_override_token: str = "#phi-ok"
    scan_tool_output: bool = True
    warn_in_hooks: bool = False
    managed: Path | None = None

    _allow_value_rx: list[re.Pattern] = field(default_factory=list, repr=False, init=False)

    def __post_init__(self) -> None:
        self.validate()

    def validate(self) -> None:
        for name in ("mode", "oversize", "opaque", "audit_log", "prompt_override_token"):
            if not isinstance(getattr(self, name), str):
                raise ConfigError(f"{name} must be a string")
        for name in ("record_window", "max_bytes"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int):
                raise ConfigError(f"{name} must be an integer")
        for name in ("protect_config", "scan_tool_output", "warn_in_hooks"):
            if not isinstance(getattr(self, name), bool):
                raise ConfigError(f"{name} must be true or false")
        if self.mode not in MODES:
            raise ConfigError(f"mode must be one of {MODES}, got {self.mode!r}")
        if self.oversize not in OVERSIZE:
            raise ConfigError(f"oversize must be one of {OVERSIZE}, got {self.oversize!r}")
        if self.opaque not in OPAQUE:
            raise ConfigError(f"opaque must be one of {OPAQUE}, got {self.opaque!r}")
        if self.record_window < 0:
            raise ConfigError("record_window must be a non-negative integer")
        if self.max_bytes <= 0:
            raise ConfigError("max_bytes must be a positive integer")
        unknown = sorted(set(self.disable) - set(CATEGORIES))
        if unknown:
            raise ConfigError(f"disable lists unknown categories {unknown}; known: {CATEGORIES}")
        try:
            self._allow_value_rx = [re.compile(p) for p in self.allow_values]
        except re.error as exc:
            raise ConfigError(f"allow_values contains an invalid regex: {exc}") from exc

    # ------------------------------------------------------------------
    def is_allowed_value(self, value: str) -> bool:
        return any(rx.fullmatch(value) for rx in self._allow_value_rx)

    def relpath(self, path: str | os.PathLike) -> str:
        p = Path(path)
        if not p.is_absolute():
            p = self.root / p
        try:
            rel = p.resolve().relative_to(self.root.resolve())
        except ValueError:
            return p.resolve().as_posix()
        return PurePosixPath(rel).as_posix()

    def is_allowed_path(self, path: str | os.PathLike) -> bool:
        rel = self.relpath(path)
        return any(fnmatch.fnmatchcase(rel, pat) for pat in self.allow_paths)

    def is_protected_path(self, path: str | os.PathLike) -> bool:
        if not self.protect_config:
            return False
        # Case-insensitive: on macOS and Windows .PHI-GATE.TOML is the same file.
        parts = [part.lower() for part in PurePosixPath(self.relpath(path)).parts]
        return bool(parts) and (parts[-1] == CONFIG_NAME or STATE_DIR in parts)


KEYS = {
    "mode", "record_window", "max_bytes", "oversize", "opaque", "allow_paths", "disable",
    "allow_values", "audit_log", "protect_config", "prompt_override_token",
    "scan_tool_output", "warn_in_hooks",
}


def find_config(start: Path) -> Path | None:
    env = os.environ.get("PHI_GATE_CONFIG")
    if env:
        p = Path(env)
        if not p.is_file():
            raise ConfigError(f"PHI_GATE_CONFIG points to a missing file: {env}")
        return p
    cur = start.resolve()
    for d in (cur, *cur.parents):
        candidate = d / CONFIG_NAME
        if candidate.is_file():
            return candidate
    return None


def _read_settings(path: Path) -> dict:
    if tomllib is None:
        raise ConfigError("phi-gate needs Python 3.11+ to read .phi-gate.toml")
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise ConfigError(f"cannot parse {path}: {exc}") from exc
    section = data.get("phi-gate", data)
    unknown = sorted(set(section) - KEYS - {"phi-gate"})
    if unknown:
        raise ConfigError(f"{path}: unknown keys {unknown}")
    settings = {k: v for k, v in section.items() if k in KEYS}
    for key in ("allow_paths", "disable", "allow_values"):
        if key in settings and not (
            isinstance(settings[key], list) and all(isinstance(x, str) for x in settings[key])
        ):
            raise ConfigError(f"{path}: {key} must be a list of strings")
    return settings


def find_managed() -> Path | None:
    env = os.environ.get("PHI_GATE_MANAGED_CONFIG")
    if env:
        p = Path(env)
        if not p.is_file():
            raise ConfigError(f"PHI_GATE_MANAGED_CONFIG points to a missing file: {env}")
        return p
    return next((p for p in map(Path, MANAGED_PATHS) if p.is_file()), None)


def _stricter(order: tuple[str, ...], managed: str, local: str) -> str:
    return managed if order.index(managed) < order.index(local) else local


def _apply_floor(local: dict, floor: dict) -> dict:
    """Merge a repository's settings over a managed policy. Where they differ
    the stricter value wins. Exceptions are the policy's to grant, so if it
    sets a list, the repository's list for that key is ignored rather than
    added to it."""
    merged = {**local, **floor}
    if "mode" in floor and "mode" in local:
        merged["mode"] = _stricter(MODES, floor["mode"], local["mode"])
    if "oversize" in floor and "oversize" in local:
        merged["oversize"] = _stricter(OVERSIZE, floor["oversize"], local["oversize"])
    if "opaque" in floor and "opaque" in local:
        merged["opaque"] = _stricter(("block", "allow"), floor["opaque"], local["opaque"])
    if "max_bytes" in floor and "max_bytes" in local:
        merged["max_bytes"] = min(floor["max_bytes"], local["max_bytes"])
    if "record_window" in floor and "record_window" in local:
        merged["record_window"] = max(floor["record_window"], local["record_window"])
    for key in ("protect_config", "scan_tool_output"):
        if floor.get(key) is True:
            merged[key] = True
    return merged


def load(start: str | os.PathLike | None = None) -> Config:
    start_path = Path(start) if start else Path.cwd()
    path = find_config(start_path)
    managed = find_managed()
    settings = _read_settings(path) if path else {}
    if managed:
        settings = _apply_floor(settings, _read_settings(managed))
    root = path.parent.resolve() if path else start_path.resolve()
    return Config(root=root, source=path, managed=managed, **settings)
