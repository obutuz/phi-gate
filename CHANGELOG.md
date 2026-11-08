# Changelog

## Unreleased

Fixes for two ways PHI could pass a check. Both were reported by Matt Abate.

- Grep pre-check: a brace glob such as `*.{csv,txt}` was split into patterns
  that matched no file, so nothing was scanned before the search ran (#1). The
  glob is now read the way ripgrep reads it: commas between globs but not
  inside braces, nested braces, `**` across directories, and a glob with a
  slash matched under the search root. A glob it cannot follow (a negation, an
  escape, unbalanced braces, over 256 alternatives) now scans every file
  instead of none.
- Commit check: rows appended to a table whose header was committed earlier
  passed, because only the added lines were scanned and the header was not
  among them (#2). A changed text file is now scanned whole, from the staged
  content (or the working tree for `git commit -a`), and judged by the findings
  that touch an added line. A finding is matched by its whole span, because a
  table's finding starts at its first data row, which may be an old one. A file
  over `max_bytes`, or one shown through a diff filter, is read as its added
  lines under its first line.
- Commit check: a clinical fact added within `record_window` of an identifier
  already in the file now blocks as a record. PHI already in a file is still
  not reported again for an unrelated edit.

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
