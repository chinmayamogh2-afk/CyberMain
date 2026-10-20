# SentinelX — Web Application Security & Secure Development Platform

SentinelX is a controlled, local environment for demonstrating the full lifecycle
of web-application vulnerabilities against a realistic application:

> **Attack → Detect → Explain → Remediate → Retest → Verify**

Every vulnerability class can be toggled between a **Vulnerable** and a **Hardened**
implementation. The weakness is genuinely present in vulnerable mode and genuinely
mitigated in hardened mode — the platform's scanner probes its own endpoints over
real HTTP, so findings and the security score are *derived from actual state*, never
hardcoded. Fix SQL injection and the score really rises; reintroduce it and it falls.

> ⚠️ **Educational platform for local demonstration only.** It intentionally hosts
> vulnerable endpoints and binds to loopback. Do not expose it to a network. It makes
> no claim of being "secure", "unhackable" or "enterprise-grade".

---

## The application: SecureVault

A believable enterprise document-collaboration app — users register, log in, manage
profiles, create and share classified documents, send messages, and access an API.
Three roles (**User**, **Security Analyst**, **Administrator**) with real role-based
access control. This is the realistic surface the labs and scanner operate against.

## What you can demonstrate

| Capability | Where |
|---|---|
| Login, RBAC, sessions, secure cookies | Sign-in, Sessions, Users |
| SQL Injection (real, extracts data) | Security Lab → SQL Injection |
| Reflected & Stored XSS | Security Lab → XSS |
| CSRF (forged vs tokened request) | Security Lab → CSRF |
| IDOR (Bob reads Alice's document) | Security Lab → IDOR |
| Broken auth, session & cookie weakness | Security Lab |
| Security headers (read from live responses) | Security Headers |
| File upload, path traversal, SSRF, parameter injection | Security Lab |
| Sensitive data exposure | Security Lab |
| Password hashing & encryption | Cryptography Center |
| Internal security scanner | Security Scan |
| One-click attack with terminal output | Attack Simulator |
| HTTP request/response inspector | Request Inspector |
| Vulnerability detail + risk rationale | Vulnerabilities |
| Remediation + verified retest | Remediation Center |
| Dynamic security score | Dashboard |
| Professional security report (export) | Reports |
| Audit logs (filter/search) | Audit Logs |
| Attack-surface map | Attack Surface |
| Guided presentation walkthrough | Demo Mode |

See **[docs/ACCEPTANCE.md](docs/ACCEPTANCE.md)** for the full acceptance checklist.

---

## Architecture

```
frontend/   React + TypeScript + Vite + Tailwind + Recharts   (presentation)
backend/    Node + TypeScript + Express                        (API + security)
  ├─ security/   headers, csrf, rate-limit, session, rbac, crypto, modes, audit
  ├─ labs/       one real runner per vulnerability class
  ├─ engine/     scanner, risk, score, findings, remediation, report
  ├─ routes/     auth, vault (app), lab, security, admin, crypto
  └─ db/         SQLite schema + seed (real, injectable SQL)
database/   SQLite file (default) — zero setup
docker/     see docker-compose.yml
docs/       ARCHITECTURE, SECURITY, THREAT_MODEL, API, TESTING, BURP_ZAP, ACCEPTANCE
tests/      Vitest security control + integration tests
```

The core mechanism is the **security mode registry** (`backend/src/security/modes.ts`):
one toggle per vulnerability class. Every relevant code path branches on it at request
time, so the same feature behaves differently in each mode and the difference is real.

Full detail: **[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)**.

## Technology stack

- **Frontend:** React 18, TypeScript, Vite, Tailwind CSS, Recharts
- **Backend:** Node 20+, TypeScript, Express 4
- **Database:** SQLite via `better-sqlite3` (default); PostgreSQL service available via Docker
- **Auth:** server-side sessions, scrypt password hashing, AES-256-GCM at rest
- **Testing:** Vitest
- **Containers:** Docker + Docker Compose

SQLite is the default so the demo runs with **zero configuration** and never fails on a
missing database — and because real string-built SQL makes the injection lab genuine.

---

## Running locally

### Prerequisites
- Node.js 20+ and npm
- (optional) Docker Desktop for the containerised stack

### 1. Backend

```bash
cd backend
cp .env.example .env            # then set the three secrets (see below)
npm install
npm run db:seed                 # migrate + seed demo data (idempotent)
npm run dev                     # API on http://127.0.0.1:4000
```

Generate the three required secrets and paste them into `.env`:

```bash
echo "SESSION_SECRET=$(openssl rand -hex 32)"
echo "CSRF_SECRET=$(openssl rand -hex 32)"
echo "DATA_ENCRYPTION_KEY=$(openssl rand -hex 32)"
```

In development, if these are omitted the server generates ephemeral ones and warns;
in production it refuses to start without them (it fails securely rather than inventing
a signing key).

### 2. Frontend

```bash
cd frontend
npm install
npm run dev                     # UI on http://localhost:5173 (proxies /api → :4000)
```

Open **http://localhost:5173** and sign in with a demo account.

### Demo accounts

| Username | Password | Role |
|---|---|---|
| `admin` | `Admin#2024!Vault` | Administrator |
| `analyst` | `Analyst#2024!Vault` | Security Analyst |
| `alice` | `Alice#2024!Vault` | User (owns the finance documents) |
| `bob` | `Bob#2024!Vault` | User (used to demonstrate IDOR against Alice) |

> These are deliberately simple so they can be typed during a presentation, and exist
> only when `ENABLE_DEMO_SEED=true`.

### Reset to a clean baseline before a demo

```bash
./scripts/reset-demo.sh         # all controls hardened, history cleared, data re-seeded
```

---

## Running with Docker

```bash
./scripts/gen-secrets.sh > .env.docker      # fresh secrets
docker compose up --build                    # UI → http://localhost:8080
docker compose --profile pg up --build       # also start the Postgres service
```

The stack binds only to `127.0.0.1`. See **[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)**
for the container layout.

---

## Security modes (Vulnerable vs Hardened)

Each vulnerability class has an independent toggle, flipped from **Security Lab**,
**Attack Simulator**, **Security Headers**, or the admin **mode API**. A fresh install
is fully hardened. Flipping a class to vulnerable genuinely weakens that one code path;
the scanner, findings and score all react.

The typical demonstration (also scripted in **Demo Mode**):

1. Run SQL Injection in **Hardened** mode → blocked.
2. Flip it to **Vulnerable** → run again → injection succeeds, 5 rows extracted.
3. Run a full **security scan** → a Critical finding appears; the score drops.
4. Open the finding → root cause, evidence, risk rationale.
5. **Apply mitigation** → the control flips to secure; **retest** re-runs the identical
   check and confirms it is blocked; the score recovers.
6. **Generate the report.**

---

## Testing

```bash
cd backend
npm test            # Vitest: crypto, every vulnerability control, HTTP integration, lifecycle
```

See **[docs/TESTING.md](docs/TESTING.md)** and **[docs/BURP_ZAP.md](docs/BURP_ZAP.md)**
for manual testing and interception with Burp Suite / OWASP ZAP.

---

## Documentation

- **[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)** — components, data flow, the mode mechanism
- **[docs/SECURITY.md](docs/SECURITY.md)** — controls implemented and how
- **[docs/THREAT_MODEL.md](docs/THREAT_MODEL.md)** — assets, actors, trust boundaries, diagram
- **[docs/API.md](docs/API.md)** — endpoint reference
- **[docs/TESTING.md](docs/TESTING.md)** — automated + manual testing
- **[docs/BURP_ZAP.md](docs/BURP_ZAP.md)** — intercepting with Burp Suite / ZAP
- **[docs/ACCEPTANCE.md](docs/ACCEPTANCE.md)** — acceptance-criteria checklist

## Known limitations

- SQLite is the implemented driver; a Postgres service is provided for demonstration but
  the data layer targets SQLite (see ARCHITECTURE.md).
- Rate limiting is in-memory (single process); a multi-instance deployment would need
  shared state.
- HSTS and the `Secure` cookie flag have no effect over loopback HTTP; the UI states this
  rather than implying TLS.
- Some classes (parameter injection, SSRF, sensitive-data-exposure) run as controlled
  demonstrations — clearly labelled — because a live exploit would be unsafe or unreliable
  to automate. These never touch anything outside this application.

## License / use

Built as a Web Application Security course project. For local, educational use only.
