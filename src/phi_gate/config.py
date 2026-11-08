"""Configuration loading.

phi-gate reads `.phi-gate.toml` for the project that a hook payload or a
command runs in. The project root is `CLAUDE_PROJECT_DIR` when the working
directory lies inside it, else the nearest enclosing git working tree, else
the working directory. The nearest `.phi-gate.toml` at or above that root is
the project configuration. A `.phi-gate.toml` in a subdirectory between the
root and the working directory can only make the policy stricter; see
`_merge`.

The file is meant to be edited by humans only: the Claude Code hooks refuse
agent edits to it and to every other file that can switch phi-gate off (see
`is_protected`), so an agent cannot loosen its own guardrails.

Unknown keys and bad values raise ConfigError. The hooks turn that into a
block (fail-closed), because a silently ignored typo in an allowlist or mode
setting is worse than a loud error.

A security team can also install a managed policy at a path developers and
agents cannot write to. It is a floor: a repository can tighten it but never
loosen it. Exceptions (`allow_paths`, `allow_values`, `disable`), the audit
log location and the prompt override token come from the policy alone unless
it sets `allow_repo_allowlists = true`. When a managed policy is installed,
the `PHI_GATE_CONFIG` and `PHI_GATE_FAIL_OPEN` environment overrides are
ignored unless it sets `allow_env_overrides = true`, and
`PHI_GATE_MANAGED_CONFIG` can only add a stricter layer.
"""

from __future__ import annotations

import fnmatch
import importlib
import os
import re
from dataclasses import dataclass, field, fields
from pathlib import Path, PurePosixPath
from typing import Any

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python < 3.11
    tomllib = None  # type: ignore[assignment]

from .detectors import CATEGORIES

CONFIG_NAME = ".phi-gate.toml"
STATE_DIR = ".phi-gate"

MODES = ("block", "warn", "audit")
OVERSIZE = ("block", "scan_head")
OPAQUE = ("block", "allow")
AUDIT_TARGETS = ("category", "hash", "path")
MANAGED_PATHS = ("/etc/phi-gate/policy.toml", "/Library/Application Support/phi-gate/policy.toml")

REGEX_PREFIX = "re:"
MAX_VALUE_REGEX = 200

# File names that can switch phi-gate or the agent's hooks off, at any depth.
PROTECTED_NAMES = frozenset({
    CONFIG_NAME, ".mcp.json", ".claude.json", ".pre-commit-config.yaml", ".pre-commit-config.yml",
})
# Directories whose whole contents are protected, at any depth.
PROTECTED_DIRS = frozenset({STATE_DIR, ".claude"})
GIT_CONFIG_NAMES = frozenset({"config", "config.worktree"})

# Keys only a managed policy may set.
POLICY_ONLY = frozenset({"allow_repo_allowlists", "allow_env_overrides"})


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
    audit_key_file: str = ""
    audit_targets: str = "hash"
    protect_config: bool = True
    prompt_override_token: str = "#phi-ok"
    scan_tool_output: bool = True
    warn_in_hooks: bool = False
    allow_repo_allowlists: bool = False
    allow_env_overrides: bool = False
    managed: Path | None = None
    managed_layers: list[Path] = field(default_factory=list)
    layers: list[Path] = field(default_factory=list)

    _allow_literals: frozenset[str] = field(default_factory=frozenset, repr=False, init=False)
    _allow_value_rx: list[re.Pattern] = field(default_factory=list, repr=False, init=False)
    _allow_globs: list[tuple[str, ...]] = field(default_factory=list, repr=False, init=False)

    def __post_init__(self) -> None:
        self.validate()

    def validate(self) -> None:
        for name in ("mode", "oversize", "opaque", "audit_log", "audit_key_file", "audit_targets",
                     "prompt_override_token"):
            if not isinstance(getattr(self, name), str):
                raise ConfigError(f"{name} must be a string")
        for name in ("record_window", "max_bytes"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int):
                raise ConfigError(f"{name} must be an integer")
        for name in ("protect_config", "scan_tool_output", "warn_in_hooks", "allow_repo_allowlists",
                     "allow_env_overrides"):
            if not isinstance(getattr(self, name), bool):
                raise ConfigError(f"{name} must be true or false")
        for name in ("allow_paths", "disable", "allow_values"):
            value = getattr(self, name)
            if not (isinstance(value, list) and all(isinstance(x, str) for x in value)):
                raise ConfigError(f"{name} must be a list of strings")
        if self.mode not in MODES:
            raise ConfigError(f"mode must be one of {MODES}, got {self.mode!r}")
        if self.oversize not in OVERSIZE:
            raise ConfigError(f"oversize must be one of {OVERSIZE}, got {self.oversize!r}")
        if self.opaque not in OPAQUE:
            raise ConfigError(f"opaque must be one of {OPAQUE}, got {self.opaque!r}")
        if self.audit_targets not in AUDIT_TARGETS:
            raise ConfigError(f"audit_targets must be one of {AUDIT_TARGETS}, got {self.audit_targets!r}")
        if self.record_window < 0:
            raise ConfigError("record_window must be a non-negative integer")
        if self.max_bytes <= 0:
            raise ConfigError("max_bytes must be a positive integer")
        unknown = sorted(set(self.disable) - set(CATEGORIES))
        if unknown:
            raise ConfigError(f"disable lists unknown categories {unknown}; known: {CATEGORIES}")
        literals, patterns = set(), []
        for value in self.allow_values:
            if value.startswith(REGEX_PREFIX):
                patterns.append(compile_value_regex(value[len(REGEX_PREFIX):]))
            else:
                literals.add(value)
        self._allow_literals = frozenset(literals)
        self._allow_value_rx = patterns
        self._allow_globs = [compile_path_glob(p) for p in self.allow_paths]

    # ------------------------------------------------------------------
    def is_allowed_value(self, value: str) -> bool:
        return value in self._allow_literals or any(rx.fullmatch(value) for rx in self._allow_value_rx)

    def _absolute(self, path: str | os.PathLike) -> Path:
        p = Path(path).expanduser()
        return p if p.is_absolute() else self.root / p

    def inside_parts(self, path: str | os.PathLike) -> tuple[str, ...] | None:
        """The path's segments relative to the project root after resolving
        symbolic links, or None when it lies outside the root."""
        try:
            rel = self._absolute(path).resolve().relative_to(self.root.resolve())
        except (ValueError, OSError, RuntimeError):
            return None
        return PurePosixPath(rel).parts

    def relpath(self, path: str | os.PathLike) -> str:
        p = self._absolute(path)
        try:
            rel = p.resolve().relative_to(self.root.resolve())
        except ValueError:
            return p.resolve().as_posix()
        return PurePosixPath(rel).as_posix()

    def is_allowed_path(self, path: str | os.PathLike) -> bool:
        """Whether an `allow_paths` glob covers the path. Paths outside the
        project root are never allowlisted."""
        parts = self.inside_parts(path)
        if not parts:
            return False
        return any(_glob_match(segments, parts) for segments in self._allow_globs)

    def audit_log_path(self) -> Path | None:
        if not self.audit_log:
            return None
        return self._absolute(self.audit_log)

    def is_protected_path(self, path: str | os.PathLike) -> bool:
        """Whether writing the path could change or switch off phi-gate: its
        configuration and state, Claude Code settings and MCP configuration,
        git hooks and git configuration, pre-commit configuration, and the
        audit log and audit key. Matching ignores case, because on macOS and
        Windows `.PHI-GATE.TOML` is the same file."""
        if not self.protect_config:
            return False
        literal = self._absolute(path)
        try:
            resolved = literal.resolve()
        except (OSError, RuntimeError):
            return True
        for candidate in (literal, resolved):
            if _protected_parts(self._parts_for(candidate)):
                return True
        special = {_fold(s) for path in self._special_paths() for s in (path, path.resolve())}
        return _fold(literal) in special or _fold(resolved) in special

    def _special_paths(self) -> list[Path]:
        """The audit log, the salt that keys hashed audit targets, and the
        audit key file."""
        out = []
        log = self.audit_log_path()
        if log is not None:
            out += [log, log.with_name(log.name + ".salt")]
        if self.audit_key_file:
            out.append(Path(self.audit_key_file).expanduser())
        return out

    def is_secret_path(self, path: str | os.PathLike) -> bool:
        """Whether reading the path would hand the agent a secret phi-gate
        relies on: the audit key, or the salt that keys hashed audit targets."""
        try:
            resolved = self._absolute(path).resolve()
        except (OSError, RuntimeError):
            return True
        log = self.audit_log_path()
        secrets = [p for p in self._special_paths() if log is None or p != log]
        return _fold(resolved) in {_fold(s) for path in secrets for s in (path, path.resolve())}

    def _parts_for(self, p: Path) -> tuple[str, ...]:
        """Segments relative to the project root when inside it (in either
        its literal or its resolved spelling), else the absolute segments."""
        for base in (self.root, self.root.resolve()):
            try:
                return PurePosixPath(p.relative_to(base)).parts
            except ValueError:
                continue
        return PurePosixPath(p).parts


def _fold(path: Path) -> str:
    return os.path.normcase(str(path)).lower()


def _protected_parts(parts: tuple[str, ...]) -> bool:
    lowered = [part.lower() for part in parts if part not in ("/", "")]
    if not lowered:
        return False
    for i in range(len(lowered) - 3):
        if lowered[i] == ".claude" and lowered[i + 1] == "worktrees":
            # A Claude Code worktree is a checkout of the project: its files
            # are judged as the project's own, so only its protected files
            # (and the worktrees folder itself) are refused.
            return _protected_parts(tuple(lowered[:i])) or _protected_parts(tuple(lowered[i + 3:]))
    if lowered[-1] in PROTECTED_NAMES:
        return True
    if PROTECTED_DIRS.intersection(lowered):
        return True
    for i, part in enumerate(lowered):
        if part == ".git":
            rest = lowered[i + 1:]
            if not rest or "hooks" in rest or rest[-1] in GIT_CONFIG_NAMES:
                return True
    return False


def is_protected(path: str | os.PathLike, cfg: Config) -> bool:
    """Whether an agent must be refused a write to `path`. The single check
    the hooks and the shell analysis use for every write target."""
    return cfg.is_protected_path(path)


def is_secret(path: str | os.PathLike, cfg: Config) -> bool:
    """Whether an agent must be refused a read of `path`."""
    return cfg.is_secret_path(path)


# ----------------------------------------------------------------------
# allow_paths globs
# ----------------------------------------------------------------------


def compile_path_glob(pattern: str) -> tuple[str, ...]:
    """An `allow_paths` entry as path segments, read the way `.gitignore`
    reads a pattern: `*`, `?` and `[...]` stay within one segment, `**`
    spans any number of segments, a pattern with no `/` except a trailing one
    matches at any depth, a leading `/` anchors to the project root, and a
    trailing `/` covers everything below a directory."""
    text = pattern.strip()
    if not text:
        raise ConfigError("allow_paths contains an empty pattern")
    if "\\" in text:
        raise ConfigError(f"allow_paths pattern {pattern!r} contains a backslash; use / between folders")
    text = text.removeprefix("./")
    anchored = text.startswith("/")
    directory = text.endswith("/")
    core = text.strip("/")
    if not core:
        raise ConfigError(f"allow_paths pattern {pattern!r} names no path")
    segments: list[str] = []
    for seg in core.split("/"):
        if seg in ("", "."):
            continue
        if seg == "..":
            raise ConfigError(f"allow_paths pattern {pattern!r} leaves the project root")
        if "**" in seg and seg != "**":
            seg = re.sub(r"\*{2,}", "*", seg)
        if seg == "**" and segments[-1:] == ["**"]:
            continue
        segments.append(seg)
    if not anchored and "/" not in core:
        segments.insert(0, "**")
    if directory and segments[-1:] != ["**"]:
        segments.append("**")
    return tuple(segments)


def _glob_match(segments: tuple[str, ...], parts: tuple[str, ...]) -> bool:
    """Anchored match of glob segments against path segments. A dynamic
    programme over (glob segment, path segment), so the cost is their
    product however many `**` the glob holds."""
    m = len(parts)
    reach = [True] + [False] * m
    for seg in segments:
        nxt = [False] * (m + 1)
        if seg == "**":
            seen = False
            for j in range(m + 1):
                seen = seen or reach[j]
                nxt[j] = seen
        else:
            for j in range(m):
                if reach[j] and fnmatch.fnmatchcase(parts[j], seg):
                    nxt[j + 1] = True
        reach = nxt
    return reach[m]


# ----------------------------------------------------------------------
# allow_values regular expressions
# ----------------------------------------------------------------------

_REPEATS = {"MAX_REPEAT", "MIN_REPEAT", "POSSESSIVE_REPEAT"}
_REFUSED = {"GROUPREF", "GROUPREF_EXISTS", "GROUPREF_IGNORE", "GROUPREF_LOC_IGNORE", "GROUPREF_UNI_IGNORE"}


def _regex_parser() -> Any:
    return importlib.import_module("re._parser")


def _check_regex_tree(items: Any, repeated: bool) -> None:
    for op, av in items:
        name = str(op)
        if name in _REFUSED:
            raise ConfigError("allow_values regex uses a backreference")
        if name in _REPEATS:
            low, high, sub = av
            if repeated:
                raise ConfigError("allow_values regex nests one quantifier inside another")
            _check_regex_tree(sub, repeated or high != 1)
        elif name == "BRANCH":
            if repeated:
                raise ConfigError("allow_values regex repeats an alternation")
            for branch in av[1]:
                _check_regex_tree(branch, repeated)
        elif name == "SUBPATTERN":
            _check_regex_tree(av[-1], repeated)
        elif name in ("ASSERT", "ASSERT_NOT"):
            _check_regex_tree(av[1], repeated)
        elif name == "ATOMIC_GROUP":
            _check_regex_tree(av, repeated)


def compile_value_regex(pattern: str) -> re.Pattern:
    """Compile an `allow_values` entry written as `re:<pattern>`. The
    pattern is matched against every detected value, and a repository writes
    it, so constructs that can backtrack exponentially are refused: a
    quantifier inside another quantifier, a repeated alternation, and
    backreferences. Patterns are limited to MAX_VALUE_REGEX characters."""
    if len(pattern) > MAX_VALUE_REGEX:
        raise ConfigError(f"allow_values regex is longer than {MAX_VALUE_REGEX} characters")
    try:
        tree = _regex_parser().parse(pattern)
        compiled = re.compile(pattern)
    except re.error as exc:
        raise ConfigError(f"allow_values contains an invalid regex: {exc}") from exc
    _check_regex_tree(tree, False)
    return compiled


# ----------------------------------------------------------------------
# Reading and merging
# ----------------------------------------------------------------------

KEYS = {
    "mode", "record_window", "max_bytes", "oversize", "opaque", "allow_paths", "disable",
    "allow_values", "audit_log", "audit_key_file", "audit_targets", "protect_config",
    "prompt_override_token", "scan_tool_output", "warn_in_hooks", "allow_repo_allowlists",
    "allow_env_overrides",
}
DEFAULTS: dict[str, Any] = {
    f.name: (f.default_factory() if callable(f.default_factory) else f.default)  # type: ignore[misc]
    for f in fields(Config)
    if f.name in KEYS
}
LIST_KEYS = ("allow_paths", "allow_values", "disable")


def _read_settings(path: Path) -> dict:
    if tomllib is None:
        raise ConfigError("phi-gate needs Python 3.11+ to read .phi-gate.toml")
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise ConfigError(f"cannot parse {path}: {exc}") from exc
    if "phi-gate" in data:
        section = data["phi-gate"]
        if not isinstance(section, dict):
            raise ConfigError(f"{path}: phi-gate must be a table ([phi-gate])")
        outside = sorted(set(data) - {"phi-gate"})
        if outside:
            raise ConfigError(f"{path}: keys outside the [phi-gate] table {outside}")
    else:
        section = data
    unknown = sorted(set(section) - KEYS)
    if unknown:
        raise ConfigError(f"{path}: unknown keys {unknown}")
    settings = dict(section)
    try:
        Config(**settings)
    except TypeError as exc:  # pragma: no cover - guarded by the key check
        raise ConfigError(f"{path}: {exc}") from exc
    except ConfigError as exc:
        raise ConfigError(f"{path}: {exc}") from exc
    return settings


def _stricter(order: tuple[str, ...], a: str, b: str) -> str:
    return a if order.index(a) < order.index(b) else b


def _merge(base: dict, layer: dict, *, lists_from_layer: bool = False) -> dict:
    """Combine `layer` over `base` so that the result is never looser than
    `base`. `base` holds every key (defaults filled in). Enumerations and
    numeric limits take the stricter value, booleans the safer one. Lists,
    the audit log, the audit key and policy-only keys stay as `base` has
    them, except that with `lists_from_layer` the layer's lists are added. A
    layer may switch the prompt override off but never choose a token."""
    merged = dict(base)
    for key, value in layer.items():
        if key == "mode":
            merged[key] = _stricter(MODES, base[key], value)
        elif key == "oversize":
            merged[key] = _stricter(OVERSIZE, base[key], value)
        elif key == "opaque":
            merged[key] = _stricter(OPAQUE, base[key], value)
        elif key == "audit_targets":
            merged[key] = _stricter(AUDIT_TARGETS, base[key], value)
        elif key == "max_bytes":
            merged[key] = min(base[key], value)
        elif key == "record_window":
            merged[key] = max(base[key], value)
        elif key in ("protect_config", "scan_tool_output", "warn_in_hooks"):
            merged[key] = base[key] or value
        elif key == "prompt_override_token":
            if value == "":
                merged[key] = ""
        elif key in LIST_KEYS and lists_from_layer:
            merged[key] = list(dict.fromkeys([*base[key], *value]))
    return merged


def system_policy() -> Path | None:
    """The managed policy installed at a system path, if any. A path that
    exists but is not a regular file is an error, not an absence."""
    for candidate in map(Path, MANAGED_PATHS):
        if candidate.exists():
            if not candidate.is_file():
                raise ConfigError(f"managed policy {candidate} is not a regular file")
            return candidate
    return None


def env_overrides_permitted() -> bool:
    """Whether PHI_GATE_FAIL_OPEN, PHI_GATE_PYTHON, PHI_GATE_CONFIG and
    PHI_GATE_MANAGED_CONFIG may take effect: always without a system managed
    policy, and with one only if it sets `allow_env_overrides = true`. An
    unreadable policy permits nothing."""
    try:
        policy = system_policy()
        if policy is None:
            return True
        return _read_settings(policy).get("allow_env_overrides") is True
    except ConfigError:
        return False


def find_managed() -> list[Path]:
    """Managed policy layers, strongest first. The system policy, when
    installed, always applies; PHI_GATE_MANAGED_CONFIG then adds a layer that
    can only tighten it. Without a system policy the variable names the
    policy."""
    layers: list[Path] = []
    policy = system_policy()
    if policy is not None:
        layers.append(policy)
    env = os.environ.get("PHI_GATE_MANAGED_CONFIG")
    if env:
        p = Path(env)
        if not p.is_file():
            raise ConfigError(f"PHI_GATE_MANAGED_CONFIG points to a missing file: {env}")
        if not layers or p.resolve() != layers[0].resolve():
            layers.append(p)
    return layers


def project_root(start: str | os.PathLike) -> Path:
    """CLAUDE_PROJECT_DIR when `start` lies inside it, else the nearest
    directory at or above `start` holding a `.git` entry, else `start`."""
    cur = Path(start).expanduser().resolve()
    env = os.environ.get("CLAUDE_PROJECT_DIR")
    if env:
        project = Path(env).expanduser().resolve()
        if project.is_dir() and (cur == project or project in cur.parents):
            return project
    for d in (cur, *cur.parents):
        if (d / ".git").exists():
            return d
    return cur


def find_config(start: Path) -> Path | None:
    """The project configuration: PHI_GATE_CONFIG when permitted, else the
    nearest `.phi-gate.toml` at or above the project root."""
    env = os.environ.get("PHI_GATE_CONFIG")
    if env and env_overrides_permitted():
        p = Path(env)
        if not p.is_file():
            raise ConfigError(f"PHI_GATE_CONFIG points to a missing file: {env}")
        return p
    root = project_root(start)
    for d in (root, *root.parents):
        candidate = d / CONFIG_NAME
        if candidate.is_file():
            return candidate
    return None


def nested_configs(root: Path, start: Path) -> list[Path]:
    """`.phi-gate.toml` files in directories below the project root down to
    `start`, outermost first."""
    cur = start.expanduser().resolve()
    if cur == root or root not in cur.parents:
        return []
    chain = [d for d in (cur, *cur.parents) if root in d.parents]
    return [d / CONFIG_NAME for d in reversed(chain) if (d / CONFIG_NAME).is_file()]


def load(start: str | os.PathLike | None = None) -> Config:
    start_path = Path(start) if start else Path.cwd()
    root = project_root(start_path)
    path = find_config(start_path)
    managed = find_managed()
    repo = _read_settings(path) if path else {}
    nested = nested_configs(root, start_path)
    nested_settings = [_read_settings(p) for p in nested]

    if managed:
        policies = [_read_settings(p) for p in managed]
        effective = {**DEFAULTS, **policies[0]}
        for extra in policies[1:]:
            effective = _merge(effective, extra)
        settings = _merge(effective, repo, lists_from_layer=effective["allow_repo_allowlists"])
    else:
        policy_only = sorted(POLICY_ONLY & set(repo))
        if policy_only:
            raise ConfigError(f"{path}: {policy_only} may only be set in a managed policy")
        settings = {**DEFAULTS, **repo}
        key_file = settings["audit_key_file"]
        if key_file:
            key_path = Path(key_file).expanduser()
            if not key_path.is_absolute():
                raise ConfigError(f"{path}: audit_key_file must be an absolute path")
            resolved = key_path.resolve()
            if resolved == root.resolve() or root.resolve() in resolved.parents:
                raise ConfigError(f"{path}: audit_key_file must lie outside the project")
    for extra in nested_settings:
        settings = _merge(settings, extra)
    return Config(
        root=root, source=path, managed=managed[0] if managed else None,
        managed_layers=managed, layers=nested, **settings,
    )


def load_for_payload(payload: dict) -> Config:
    """The configuration for a hook payload, from its `cwd` (or the
    process's working directory when the payload carries none)."""
    cwd = payload.get("cwd")
    return load(cwd if isinstance(cwd, str) and cwd else None)
