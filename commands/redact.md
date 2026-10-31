---
disable-model-invocation: true
description: Print a copy of a file with typed placeholders instead of identifiers
argument-hint: "<file>"
allowed-tools: Bash(phi-gate redact:*)
---

Run `phi-gate redact $ARGUMENTS` with the Bash tool and work only from its output. Placeholders such as `[SSN_1]` or `[PERSON_NAME_2]` are consistent within the file, so you can still reason about which rows belong together.

Do not run it with `--map`: the map file contains the original values. If the user needs the original values restored in a result, tell them to run `phi-gate redact <file> --map map.json` and `phi-gate restore --map map.json` themselves.
