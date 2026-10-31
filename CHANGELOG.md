# Changelog

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
