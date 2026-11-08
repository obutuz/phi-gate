# Security policy

## Reporting a vulnerability

A way to get PHI past phi-gate (a read, write, command, commit or outbound call
that should have been blocked), a way to make it fail open, or a way for an
agent to change its rules is a security vulnerability. Report it privately
through GitHub's **Report a vulnerability** button on this repository
(Security, then Advisories). Do not open a public issue.

Include the tool call or command, the file layout needed to reproduce it, and
the phi-gate version (`phi-gate --version`).

**Never include real patient data.** Reproduce with synthetic values: an SSN
such as 234-56-7891 is format-valid and triggers the detector, while SSNs
starting with 9, 000 or 666 are never issued and are ignored by design.

## What to expect

| Step | Target |
|---|---|
| Acknowledgement | Within 3 business days |
| Initial assessment and severity | Within 7 days |
| Fix for a confirmed bypass | Within 30 days, sooner for high severity |
| Public advisory | When the fix is released, with credit if you would like it |

Every confirmed bypass gets a regression test that fails without the fix. We
will keep you informed throughout, and ask that you do not disclose the issue
until a fix is available or 90 days have passed, whichever comes first.

## Supported versions

Security fixes are released for the latest minor version. Pin the plugin and
the CLI to a release tag, and watch this repository's releases and security
advisories for updates.

## Scope

In scope:

- bypasses of any hook, the CLI, or the git pre-commit hook;
- fail-open behaviour: any path where an error, a time-out or a substituted
  program lets an action through;
- matched values, or text from which they can be recovered, appearing in
  messages, terminal output or the audit log;
- an agent changing phi-gate's configuration, its managed policy, its audit
  log or key, or the agent settings that load it;
- patterns or configuration that make a check run long enough to time out.

Out of scope:

- identifiers phi-gate does not claim to detect (see Limitations in the
  README and the [threat model](docs/THREAT-MODEL.md));
- a person with control of the machine deliberately disabling or uninstalling
  the plugin;
- programs the agent runs that open files themselves, beyond what the threat
  model describes.

## Verifying a release

Each release on GitHub carries the built packages, a `SHA256SUMS` file and a
signed build provenance attestation. Verify a download with:

```bash
gh attestation verify phi_gate-<version>-py3-none-any.whl --repo obutuz/phi-gate
```
