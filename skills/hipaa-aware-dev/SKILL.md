---
name: hipaa-aware-dev
description: Use when building or changing software that stores, displays, logs, exports or transmits patient or member data (healthcare billing, ABA therapy, home care, nursing homes, claims, eligibility, EHR/EMR integrations, healthcare internal tools and dashboards), or when phi-gate blocks an action. Covers minimum-necessary data access, PHI-free logging and error reporting, audit trails, synthetic test data, vendor and AI-provider boundaries, and session security for Next.js, React, Svelte and Python apps.
---

# HIPAA-aware development

You are working on software that may handle protected health information (PHI):
individually identifiable health information held by a covered entity or its
business associate. Treat every patient, member, client or resident record as PHI
unless the user says it is synthetic.

This skill describes engineering practice. It is not legal advice and does not make
software "HIPAA compliant": compliance belongs to the organisation (risk analysis,
policies, BAAs, training). Say "HIPAA-aware" in code comments, docs and PRs, never
"HIPAA compliant".

## When phi-gate blocks you

phi-gate is a guardrail, not an obstacle to route around.

1. Do not retry the same data through another tool (cat, grep, python, a new file).
   That is the exact behaviour it exists to stop, and it will block that too.
2. Tell the user what was blocked and why, using the categories in the message
   (for example "tabular_phi in data/export.csv"). Never quote the values.
3. Offer a safe path:
   - `phi-gate redact <file>` prints a placeholder copy you may read.
   - Write a script that processes the file and prints only aggregates
     (counts, denial-reason totals), then ask the user to run it.
   - Generate synthetic data with the same shape (see below).
4. If the user says the data is synthetic, ask them to add the path to
   `allow_paths` in `.phi-gate.toml`. You cannot edit that file; that is by design.

## Build rules

Apply these by default. Mention them in PR descriptions when you apply them.

### 1. Minimum necessary
- Select only the columns a screen or job needs. No `SELECT *` on patient tables,
  no `include: { patient: true }` that drags every field into a list view.
- API responses for list views return display fields and an opaque ID, not SSN,
  DOB, member ID or full address. Detail views fetch more on demand.
- Mask by default in the UI: `***-**-6789`, DOB as age or year, member ID last 4.
  Reveal-on-click is an audited action.
- Role-based access at the query layer (row-level security or a scoped repository),
  not only by hiding buttons.

### 2. Logs, errors and analytics never contain PHI
- Log record IDs and event names, never names, DOBs, notes or request bodies.
- Scrub error reporters before they send (Sentry `beforeSend`, `sendDefaultPii: false`).
- Product analytics (PostHog, GA, Mixpanel, Hotjar) must not capture PHI-bearing
  pages: disable session replay and autocapture there, mask inputs.
- See `references/patterns.md` for ready-made redacting loggers (Python, pino,
  Next.js) and a Sentry scrubber.

### 3. Audit trail
- Record who viewed, created, changed, exported or deleted which record and when:
  `actor_id, action, resource_type, resource_id, timestamp, ip, outcome`.
- Store identifiers, not content. An audit log full of PHI is a second breach surface.
- Append-only (no UPDATE/DELETE grants for the app role), retained per policy.

### 4. Synthetic data only, outside production
- Never copy production rows into dev, staging, tests, fixtures, seed files, demos,
  screenshots, Storybook stories or prompts.
- Use values that cannot belong to a real person:
  - SSNs starting with 9 (never issued), for example `999-12-3456`
  - phone numbers `555-0100` to `555-0199`
  - emails at `example.com`, `example.org`, `.test`
  - processor test cards (`4242 4242 4242 4242`)
  - names from a generator (Synthea for full synthetic patients, Faker otherwise)
- phi-gate treats these values as synthetic, so hand-written fixtures that use them pass.
  Generated records (Synthea CSVs, FHIR bundles) still look like patient records, so keep
  them in a folder the user has listed in `allow_paths`.

### 5. Vendor boundaries
- PHI may only go to a vendor that has signed a BAA with the organisation and
  only for the covered purpose. This includes LLM APIs, email/SMS providers, error
  trackers, log platforms, analytics, file storage and no-code tools.
- When an integration would send PHI to a new vendor, stop and flag it to the user
  before writing the code. Ask whether a BAA is in place.
- Prefer sending IDs and letting the vendor call back into an authenticated API,
  over sending PHI in webhook payloads, URLs, email bodies or SMS text.

### 6. Transport, storage and sessions
- TLS everywhere; HSTS on web apps; no PHI in URLs or query strings (they end up
  in logs, browser history and Referer headers). Use POST bodies or path IDs.
- Encrypt at rest (managed DB encryption plus field-level encryption for SSN/MBI).
- Automatic logoff for idle sessions on PHI screens; short-lived tokens; no PHI in
  JWT claims or localStorage.
- Exports (CSV, PDF) are audited actions with access checks, watermarking where
  useful, and expiring download links.

### 7. Webhooks and integrations
- Verify signatures (HMAC with constant-time compare), check timestamps to stop
  replays, make handlers idempotent, respond fast and process async.
- Validate and minimise payloads at the edge; drop fields you do not need before
  they reach queues and logs.

## Reference

- `references/patterns.md`: copy-paste code for redacting loggers, Sentry scrubbing,
  masked display helpers, audit table schema, Next.js and FastAPI middleware.
- `references/safe-harbor.md`: the 18 HIPAA Safe Harbor identifiers and which ones
  phi-gate detects.
