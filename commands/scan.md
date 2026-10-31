---
disable-model-invocation: true
description: Scan files, a folder, or staged git changes for likely PHI (reports locations and categories, never values)
argument-hint: "[path ...] | --staged"
allowed-tools: Bash(phi-gate scan:*)
---

Run `phi-gate scan $ARGUMENTS` with the Bash tool. If no arguments were given, run `phi-gate scan .` instead.

Then report back to the user:

1. The overall result (BLOCK, WARN or ALLOW) and how many files were scanned.
2. For each BLOCK file: the path, the categories found, and the line numbers. Do not open those files or quote their contents; phi-gate deliberately prints locations only.
3. A short recommendation per file: delete it from the repo, move it outside the repo, replace it with synthetic data (see the hipaa-aware-dev skill), or, if the user confirms it is already synthetic, add it to `allow_paths` in `.phi-gate.toml` themselves.

Keep WARN findings brief: they are possible identifiers without health context (for example an email address) and usually need no action.
