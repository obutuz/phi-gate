<!-- Copy this section into AGENTS.md, .cursor/rules, or your agent's
     instructions file in a repository that may contain patient data. -->

## Patient data (PHI)

This repository may contain protected health information. Before reading,
printing, or copying any data file (CSV, JSON, EDI/835/837, HL7, logs, exports),
run `phi-gate scan <path>` first.

- If the result is BLOCK, do not open the file by any means. Use
  `phi-gate redact <path>` and work from the placeholder copy, or write a script
  that prints only aggregates and ask the user to run it.
- Never put real identifiers in code, tests, fixtures, seed data, commit
  messages, issue trackers, chat tools or URLs. Use synthetic values: SSNs
  starting with 9, phone numbers 555-0100 to 555-0199, example.com emails.
- Never edit `.phi-gate.toml`, and never commit with `--no-verify`.
- Run `phi-gate scan --staged` before every commit.
