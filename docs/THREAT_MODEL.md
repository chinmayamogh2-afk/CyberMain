# Threat Model — SecureVault / SentinelX

A lightweight threat model in the spirit of OWASP. SentinelX is an educational platform,
so this model describes the *application being assessed* (SecureVault) as if it were real,
which is what makes the demonstration meaningful.

## Assets

| Asset | Why it matters |
|---|---|
| User credentials | Account takeover; reused elsewhere |
| Session identifiers | Impersonation without credentials |
| Confidential documents (finance, payroll) | Business confidentiality |
| Encryption key (`DATA_ENCRYPTION_KEY`) | Decrypts all data at rest |
| Signing secrets (session, CSRF) | Forge sessions / CSRF tokens |
| Audit log integrity | Accountability / incident evidence |
| Administrative functions | Full control of the platform |

## Threat actors

- **Unauthenticated attacker** — reaches public endpoints (login, register, reflected inputs).
- **Authenticated low-privilege user** (e.g. Bob) — the IDOR / broken-access-control actor.
- **Cross-site attacker** — lures a victim to a malicious page (CSRF, reflected XSS).
- **Malicious content author** — stores a payload others will view (stored XSS, file upload).
- **Insider / curious analyst** — has elevated read access; audit logging holds them accountable.

## Entry points

- Web UI (`http://localhost:5173`) → API (`/api/*`)
- Auth API (`/api/auth/*`), app API (`/api/vault/*`), security API (`/api/security/*`),
  admin API (`/api/admin/*`), lab probe endpoints (`/api/lab/*`)
- File upload, URL fetch (SSRF lab), file read (traversal lab) — all sandboxed locally

## Trust boundaries

```
     Internet / other origins          ┊  = trust boundary
                 │                      ┊
   ┌─────────────▼─────────────┐        ┊
   │  Browser (untrusted input)│        ┊
   └─────────────┬─────────────┘        ┊
 ════════════════╪════════════════════  ┊  (1) network → server
   ┌─────────────▼─────────────┐
   │  Express API              │  authN, authZ, validation, CSRF, headers
   └──────┬───────────┬────────┘
 ═════════╪═══════════╪═════════════════   (2) app → data store / filesystem
   ┌──────▼─────┐ ┌───▼───────────┐
   │  SQLite    │ │ File storage  │
   └────────────┘ └───────────────┘
 ═══════════════════════════════════════   (3) app → external (SSRF-controlled)
            (simulated; never leaves host)
```

- **(1)** Everything from the browser is untrusted. Controls: validation, output encoding,
  authN/authZ, CSRF, security headers, rate limiting.
- **(2)** Data access is parameterised; object access is authorized per-object; file paths are
  normalised and confined; uploads are validated.
- **(3)** Outbound fetch is allow-listed and private ranges are blocked; in this platform the
  targets are simulated locally so nothing actually leaves the host.

## Attack vectors → controls (STRIDE-ish)

| Threat | Vector | Primary control |
|---|---|---|
| Spoofing | Credential guessing, session theft | scrypt + lockout + rate limit; HttpOnly/SameSite cookies; random session ids |
| Tampering | SQL injection, parameter manipulation | parameterised queries; server-derived authz |
| Repudiation | Deny performing an action | audit logging with actor + context |
| Information disclosure | IDOR, verbose errors, data exposure, missing headers | object-level authz; safe errors; field allow-lists; CSP/headers; encryption at rest |
| Denial of service | Unbounded auth attempts, large uploads | rate limiting; upload size caps |
| Elevation of privilege | Broken access control on privileged routes | role guards from DB; administrative override audited |
| Cross-site | CSRF, reflected/stored XSS | CSRF tokens + Origin check; context output encoding + CSP |
| SSRF | Server fetches attacker URL | scheme/host allow-list; private-range block (simulated) |

## Potential impact (if controls were absent — i.e. vulnerable mode)

- **SQLi:** authentication bypass and full table extraction → account/data compromise.
- **IDOR / broken access control:** any user reads others' confidential documents.
- **Stored XSS:** session theft and action-on-behalf for every viewer.
- **CSRF:** attacker-forced state changes (email/password), leading to takeover.
- **Sensitive data exposure / missing headers:** offline hash cracking, downgrade, fingerprinting.

## Residual risks / accepted limitations

- Login-CSRF is possible because login is CSRF-exempt (low impact; documented).
- Rate limiting is per-process; a clustered deployment needs shared state.
- `Secure`/HSTS are inert over loopback HTTP.
- The platform is intentionally vulnerable in parts and must stay on localhost.

See the interactive version on the **Attack Surface** page.
