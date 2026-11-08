# Changelog

## Unreleased

This release closes the two issues reported by Matt Abate and a set of further
routes found in a review of the whole tool. Several configuration rules change;
read **Upgrading** before updating.

### Upgrading

- `allow_paths` patterns are now gitignore-style and relative to the project
  root: `*` stays within one folder, so `tests/fixtures/*` no longer covers
  subfolders. Use `tests/fixtures/**`. A pattern without a slash matches at any
  depth, a leading `/` anchors it to the root, and paths outside the project
  never match.
- `allow_values` entries are now matched exactly. Give a regular expression
  the prefix `re:`; it may be at most 200 characters and may not nest
  quantifiers, repeat an alternation or use a backreference.
- Under a managed policy a project can no longer set `allow_paths`,
  `allow_values`, `disable`, `audit_log` or `audit_key_file`, even where the
  policy leaves them unset. A policy can let projects add allowlist entries
  with `allow_repo_allowlists = true`.
- The configuration is read from the project root. A `.phi-gate.toml` in a
  subfolder can only make the rules stricter.
- The audit log records file names as keyed hashes by default (`audit_targets`).
- A redaction map inside a git repository must be a path git ignores (outside
  git, its name must end in `.map.json`).
- The git hook installed by `install-git-hook` records the interpreter it was
  installed with; reinstall it with `--force` after moving phi-gate.

### Fixed

- Grep pre-check: a brace glob such as `*.{csv,txt}` was split into patterns
  that matched no file, so nothing was scanned before the search ran (#1). The
  glob is now read the way ripgrep reads it, and one that cannot be followed
  scans every file instead of none.
- Commit check: rows appended to a table whose header was committed earlier
  passed, because only the added lines were scanned (#2). Each changed file is
  now scanned whole, from the staged content or the working tree, and the
  change is judged by the findings it introduces compared with the previous
  version. Reformatting or moving PHI that was already committed is not
  reported again; a clinical fact added near an identity already in the file
  is.
- An agent could switch phi-gate off by writing Claude Code settings, which can
  set environment variables or disable plugins. Writes to `.claude/`,
  `~/.claude.json`, `.mcp.json`, `.git/config`, `.git/hooks/`,
  `.pre-commit-config.yaml`, any `.phi-gate.toml` and any file named
  `phi-gate` are now refused.
- The hook wrapper treated any program that exited 0 as an allow. It now
  requires a token the checker writes after deciding to allow, and stops the
  checker at 25 seconds.
- A managed policy could be loosened through keys it did not set, or replaced
  through `PHI_GATE_MANAGED_CONFIG`. Under an installed policy the `PHI_GATE_*`
  variables are ignored unless the policy sets `allow_env_overrides = true`.
- Shell routes now checked before the command runs: directories too large to
  scan sent off the machine, `grep -r` and `rg` with no path, commits through
  aliases and plumbing, reads of git history, copies, `pushd`, `export`,
  ANSI-C quoting, command substitution and computed paths in inline scripts.
- Every tool is now checked, including sub-agent prompts, `BashOutput`, MCP
  resources and `@file` mentions in prompts. An unknown or mismatched hook
  event blocks.
- Detection: a label separator could take seconds on crafted input and is now
  linear. XML elements, FHIR XML, `SSN#:` labels, invisible and look-alike
  characters, camelCase and bracketed table headers, lowercase and spaced MBIs,
  undotted ICD-10 codes, and further label spellings are recognised.
- Redaction left unrecognised identifier columns and rows after a blank line
  in clear text, and a literal placeholder in the input could be restored to a
  real value. Both are fixed.
- Configuration errors such as a non-table `[phi-gate]` exited with 1 or a
  traceback instead of 2; every unexpected error now exits 2.

### Added

- Optional `audit_key_file`, which makes the audit chain an HMAC-SHA256.
- `audit_targets` (`hash`, `category` or `path`).
- Well-known dummy SSNs (`123-45-6789`, `078-05-1120`, repeated digits) are
  treated as synthetic.
- Documentation: [configuration reference](docs/CONFIGURATION.md) and
  [data handling](docs/DATA-HANDLING.md).
- Releases are tested before they are built, built with hash-pinned tools, and
  published with `SHA256SUMS` and build provenance.

## 0.1.0 (2026-11-01)

First release.

- Claude Code hooks for prompts, file reads, writes and edits, shell commands,
  git commits, outbound web and MCP calls, and tool output.
- Fail-closed wrapper: crashes, missing interpreter, malformed payloads and
  config errors all block.
- Detectors for SSN, Medicare MBI, MRN, member IDs, DOB, account and card
  numbers, labelled names, X12 835/837 patient segments, HL7 PID, FHIR Patient
  and patient tables; contextual phone, email, address, diagnosis and service
  dates; informational NPI, DEA and IP.
- Reads inside xlsx, docx, pptx, OpenDocument, zip, gzip and SQLite files, and
  UTF-16/32 text, in the file scanner, the redactor and the commit gate.
  Unparseable containers are blocked. DICOM files are blocked, and
  `opaque = "block"` extends that to every format phi-gate cannot read.
- Bash analysis that follows cd, variables, globs, braces, redirections,
  heredocs, command substitution, xargs, bash -c and recursive readers.
- Internal deadline so a slow check blocks instead of timing out open.
- Typed, reversible redaction (`phi-gate redact` / `restore`). Tables keep their
  shape: identifier columns become placeholders, clinical and financial columns
  stay, and a redacted copy is itself allowed through the hooks.
- Colored CLI output on terminals (`NO_COLOR` / `FORCE_COLOR` respected).
- Hash-chained audit log holding categories and locations only, checked by
  `phi-gate audit verify`.
- Managed policy: a floor set by a security team that a repository cannot lower.
- `hipaa-aware-dev` skill and `/phi-gate:scan`, `/phi-gate:redact`,
  `/phi-gate:status` commands.
- CLI, git pre-commit installer and pre-commit framework hook. Exit 0 from
  `scan` always means every path it was given was scanned.
