# Security policy

## Reporting a bypass

A way to get PHI past phi-gate (a read, write, command or outbound call that
should have been blocked) is a security bug. Please report it privately through
GitHub's "Report a vulnerability" button on this repository rather than in a
public issue.

Describe the pattern and the tool call. **Never include real patient data**:
reproduce with synthetic values (SSNs starting with 9 will not trigger the SSN
detector, so use a format-valid fake such as 123-45-6789).

## Scope

In scope: bypasses of the hooks, fail-open behaviour, values leaking into
messages or the audit log, config tampering by the agent.

Out of scope: identifiers phi-gate does not claim to detect (see the
Limitations section of the README), and a user deliberately disabling the
plugin.
