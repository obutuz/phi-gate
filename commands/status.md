---
description: Show phi-gate configuration and recent block events
allowed-tools: Bash(phi-gate status:*)
---

Run `phi-gate status` with the Bash tool and summarise for the user in a few lines: the active mode, the allowlisted paths, and what the recent audit events show (what was blocked, from which tool, and how often). If the same path keeps getting blocked, suggest whether it should be cleaned up or, if it is synthetic, allowlisted by the user in `.phi-gate.toml`.
