# Security Controls

This document lists the security controls SentinelX implements (in **hardened** mode) and
where each lives. The matching **vulnerable** mode deliberately removes or weakens the
control so the difference can be demonstrated.

## Authentication (`backend/src/routes/auth.ts`, `security/crypto.ts`)

- **Password hashing:** scrypt (salted, memory-hard). Format `scrypt$N$r$p$salt$hash`.
  Verification uses `crypto.timingSafeEqual` to avoid a timing side channel.
- **No plaintext passwords** anywhere — enforced by test.
- **Generic failure message** for every login failure (unknown user, wrong password,
  inactive) to prevent username enumeration; the no-user path still spends hashing time
  to avoid a timing oracle.
- **Account lockout** after 5 consecutive failures (15-minute window).
- **Rate limiting** on login (5/min/identity).
- **Password strength** policy and live assessment (length-weighted, common-password list).
- **Re-authentication** required to change password; **all other sessions revoked** on change.

## Sessions & cookies (`security/session.ts`)

- Opaque 256-bit random identifiers from a CSPRNG (`crypto.randomBytes`).
- Server-side session store → **logout truly invalidates** (marked revoked, auditable).
- Cookie attributes in hardened mode: **HttpOnly**, **SameSite=Strict**, **Secure**
  (in production), and an **absolute expiry**. (Vulnerable mode drops all four and issues a
  predictable sequential id.)
- Note: over loopback HTTP the browser ignores `Secure`/HSTS; the UI says so explicitly.

## Authorization (`security/rbac.ts`, `middleware/auth.ts`)

- Three roles with ranks; capabilities derived from roles loaded **from the database**,
  never from a client-supplied claim.
- **Object-level authorization** (`authorizeDocumentAccess`) on every document access —
  ownership, explicit grant, or an audited administrative override. The object identifier
  from the URL is never treated as entitlement. This is the IDOR control.
- Role guards on privileged routes (the `api_authz` control).

## Input handling (`security/validation.ts`, `security/sanitize.ts`)

- **Positive validation** with Zod on every mutating endpoint (allow-list shapes).
- **Context-aware output encoding** — HTML text, attribute, URL and JS-string encoders —
  which is the actual XSS fix. An allow-list rich-text sanitiser is provided for fields
  that may carry limited markup.
- **Parameterised queries** everywhere in real code (`db.prepared`). The only unparameterised
  path is the SQLi lab's vulnerable mode, which exists to be exploited.
- Attack-pattern signatures power **detection** (the live event console and request flagger),
  explicitly *not* prevention — detection is the smoke alarm, parameterisation/encoding are
  the controls.

## Cryptography (`security/crypto.ts`)

- **AES-256-GCM** authenticated encryption for sensitive columns (phone numbers, recovery
  notes, confidential/restricted document bodies). Random 96-bit IV per encryption; tampering
  is detected and fails closed.
- Clear separation taught in the Cryptography Center: **hashing** (one-way, verification) vs
  **encryption** (reversible, keyed, confidential) vs **encoding** (base64 — not security).
- **No hardcoded keys.** All secrets come from environment config; the frontend never receives
  a key. In production the server refuses to start without them.

## HTTP security headers (`security/headers.ts`)

Hardened mode sets CSP, HSTS, X-Content-Type-Options, Referrer-Policy, Permissions-Policy and
X-Frame-Options on every response, and removes `X-Powered-By`/`Server`. Vulnerable mode sends
none of these and adds misleading banners. The Headers Inspector reads values back off a
**live response**, so it never fakes them.

## CSRF (`security/csrf.ts`)

Signed double-submit token (readable cookie + HMAC bound to the session, echoed in a header),
plus an Origin check as defence in depth. Pre-authentication endpoints (login/register) are
exempt because CSRF targets an existing session; this is documented in THREAT_MODEL.md.

## Rate limiting (`security/ratelimit.ts`)

Fixed-window limiter on authentication and security operations. In-memory (single process) —
noted as a limitation for multi-instance deployments.

## Error handling (`middleware/errorHandler.ts`)

Hardened mode returns a generic message plus a correlation id; stack traces, SQL text, paths
and driver errors go to the server log only. A redaction pass (`core/errors.ts`) strips
credentials from everything logged, audited or captured by the request inspector. Vulnerable
mode deliberately leaks the stack and SQL, as the error-disclosure lab.

## Logging & accountability (`security/audit.ts`, `security/events.ts`)

Every security-relevant action is written to `audit_logs` with actor, action, outcome,
severity and request context (filterable/searchable), and significant events are pushed to
the live SSE console. Both pass through redaction first.

## Secure defaults & fail-securely

A fresh install is fully hardened. Unknown modes default to `secure`. Missing production
secrets stop startup. Decryption failures throw rather than returning raw bytes. Authorization
defaults to deny.

## Reporting a (real) issue

This is a deliberately vulnerable educational platform, so most "vulnerabilities" are intended.
If you find an *unintended* flaw in the control implementations, note it against the relevant
file in `backend/src/security/` — the controls, not the labs, are what should hold.
