# HIPAA-aware code patterns

Copy-paste starting points. Adapt field names to the project's schema.

## Logging

Log IDs and event names. Redaction is a safety net, not the plan.

### Python (standard logging)

```python
import logging
import re

_PATTERNS = [
    (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "[SSN]"),
    (re.compile(r"\b[\w.%+-]+@[\w-]+(?:\.[\w-]+)+\b"), "[EMAIL]"),
    (re.compile(r"\(?\b\d{3}\)?[.\- ]\d{3}[.\-]\d{4}\b"), "[PHONE]"),
    (re.compile(r"(?i)\b(dob|mrn|member[_ ]?id)\b\s*[:=]\s*\S+"), r"\1=[REDACTED]"),
]


class RedactPHI(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        msg = record.getMessage()
        for rx, repl in _PATTERNS:
            msg = rx.sub(repl, msg)
        record.msg, record.args = msg, None
        return True


handler = logging.StreamHandler()
handler.addFilter(RedactPHI())
logging.basicConfig(level=logging.INFO, handlers=[handler])

log = logging.getLogger("claims")
log.info("claim %s denied, reason=%s", claim.id, claim.carc_code)  # IDs, not people
```

### Node / Next.js (pino)

```ts
import pino from "pino";

export const logger = pino({
  redact: {
    paths: [
      "*.ssn", "*.dob", "*.dateOfBirth", "*.mrn", "*.memberId", "*.firstName", "*.lastName",
      "*.address", "*.phone", "*.email", "req.headers.authorization", "req.headers.cookie",
      "req.body", "res.body",
    ],
    censor: "[REDACTED]",
  },
});

logger.info({ claimId: claim.id, carc: claim.carcCode }, "claim denied");
```

## Error reporting (Sentry, Next.js)

```ts
import * as Sentry from "@sentry/nextjs";

Sentry.init({
  dsn: process.env.NEXT_PUBLIC_SENTRY_DSN,
  sendDefaultPii: false,
  beforeSend(event) {
    if (event.request) {
      delete event.request.data;
      delete event.request.cookies;
      delete event.request.query_string;
    }
    if (event.user) event.user = { id: event.user.id };
    return event;
  },
  beforeBreadcrumb(crumb) {
    // console and fetch breadcrumbs often carry payloads
    if (crumb.category === "console" || crumb.category === "fetch") delete crumb.data;
    return crumb;
  },
});
```

Disable session replay on routes that render PHI, or configure it to mask all
text and inputs.

## Masked display helpers (TypeScript)

```ts
export const maskSSN = (ssn: string) => `***-**-${ssn.slice(-4)}`;
export const maskId = (id: string, keep = 4) => `${"*".repeat(Math.max(0, id.length - keep))}${id.slice(-keep)}`;

export function ageFromDob(dob: string, today = new Date()): number {
  const d = new Date(dob);
  let age = today.getFullYear() - d.getFullYear();
  const m = today.getMonth() - d.getMonth();
  if (m < 0 || (m === 0 && today.getDate() < d.getDate())) age--;
  return age;
}
```

Show age or birth year in lists. Reveal full values only on an explicit, audited
action.

## Audit trail (PostgreSQL)

```sql
CREATE TABLE audit_events (
  id            bigserial PRIMARY KEY,
  occurred_at   timestamptz NOT NULL DEFAULT now(),
  actor_id      text        NOT NULL,
  action        text        NOT NULL,  -- view | create | update | delete | export | reveal
  resource_type text        NOT NULL,  -- patient | claim | note | report
  resource_id   text        NOT NULL,
  outcome       text        NOT NULL,  -- success | denied | error
  ip            inet,
  user_agent    text
);
CREATE INDEX ON audit_events (resource_type, resource_id, occurred_at DESC);
CREATE INDEX ON audit_events (actor_id, occurred_at DESC);

-- the application role can append but never rewrite history
REVOKE UPDATE, DELETE, TRUNCATE ON audit_events FROM app_role;
GRANT INSERT, SELECT ON audit_events TO app_role;
```

No names, values or diffs in the audit row: the resource ID is enough to look
the record up under access control.

## Next.js route handler with access check and audit

```ts
// app/api/patients/[id]/route.ts
import { NextResponse } from "next/server";
import { requireUser, can } from "@/lib/auth";
import { db } from "@/lib/db";
import { audit } from "@/lib/audit";

export async function GET(_req: Request, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const user = await requireUser();
  if (!can(user, "patient:read", id)) {
    await audit({ actorId: user.id, action: "view", resourceType: "patient", resourceId: id, outcome: "denied" });
    return NextResponse.json({ error: "forbidden" }, { status: 403 });
  }
  const patient = await db.patient.findUnique({
    where: { id },
    select: { id: true, displayName: true, birthYear: true, payerName: true }, // minimum necessary
  });
  await audit({ actorId: user.id, action: "view", resourceType: "patient", resourceId: id, outcome: "success" });
  return NextResponse.json(patient, { headers: { "Cache-Control": "no-store" } });
}
```

## FastAPI dependency with audit

```python
from fastapi import Depends, FastAPI, HTTPException, Request

app = FastAPI()


def audited(action: str, resource_type: str):
    async def dep(request: Request, user=Depends(current_user)):
        resource_id = request.path_params.get("id", "-")
        allowed = can(user, f"{resource_type}:{action}", resource_id)
        await write_audit(user.id, action, resource_type, resource_id, "success" if allowed else "denied")
        if not allowed:
            raise HTTPException(status_code=403)
        return user

    return dep


@app.get("/claims/{id}")
async def get_claim(id: str, user=Depends(audited("view", "claim"))):
    return await claims.summary(id)  # returns codes and amounts, not demographics
```

## Webhook verification

```ts
import { createHmac, timingSafeEqual } from "node:crypto";

export function verifySignature(rawBody: string, header: string | null, secret: string, toleranceSec = 300) {
  if (!header) return false;
  const [tsPart, sigPart] = header.split(",");           // e.g. "t=1700000000,v1=abcd..."
  const ts = Number(tsPart?.split("=")[1]);
  const sig = sigPart?.split("=")[1] ?? "";
  if (!ts || Math.abs(Date.now() / 1000 - ts) > toleranceSec) return false;  // replay window
  const expected = createHmac("sha256", secret).update(`${ts}.${rawBody}`).digest("hex");
  const a = Buffer.from(sig, "hex");
  const b = Buffer.from(expected, "hex");
  return a.length === b.length && timingSafeEqual(a, b);
}
```

```python
import hashlib
import hmac
import time


def verify_signature(raw_body: bytes, header: str, secret: bytes, tolerance: int = 300) -> bool:
    try:
        parts = dict(p.split("=", 1) for p in header.split(","))
        ts, sig = int(parts["t"]), parts["v1"]
    except (KeyError, ValueError):
        return False
    if abs(time.time() - ts) > tolerance:
        return False
    expected = hmac.new(secret, f"{ts}.".encode() + raw_body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, sig)
```

Header formats differ by provider; follow each provider's documented scheme.
Verify against the raw request body, before JSON parsing.
