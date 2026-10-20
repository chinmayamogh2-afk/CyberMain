# Architecture

## Overview

SentinelX is a two-tier application with a clear separation between presentation,
API/business logic, security controls, and data — plus a dedicated security-assessment
layer (scanner, risk engine, scoring, remediation, reporting).

```
┌──────────────────────────────────────────────────────────────────────┐
│  Browser (React SPA)                                                   │
│  Dashboard · Security Lab · Attack Simulator · Scanner · Vulns ·       │
│  Remediation · Request Inspector · Headers · Crypto · Reports · …      │
└───────────────┬───────────────────────────────── SSE event stream ◄───┘
                │ /api (fetch, credentials: include, CSRF header)
┌───────────────▼────────────────────────────────────────────────────────┐
│  Express API                                                             │
│                                                                          │
│  Middleware (order matters):                                             │
│   cookieParser → json → securityHeaders → cors → attachAuth →            │
│   recorder → csrfProtection → routes → notFound → errorHandler           │
│                                                                          │
│  Routes:  /auth  /vault(app)  /lab  /security  /admin  /crypto           │
│                                                                          │
│  Security controls:  headers · csrf · ratelimit · session · rbac ·       │
│                      crypto · sanitize · validation · audit · events     │
│                                                                          │
│  Mode registry  ◄── the core mechanism: one toggle per vuln class        │
│                                                                          │
│  Labs (1 runner / class)   Engine (scanner · risk · score ·              │
│                            findings · remediation · report)              │
└───────────────┬──────────────────────────────────────────────────────────┘
                │ better-sqlite3 (synchronous, real SQL)
┌───────────────▼──────────────────────────────────────────────────────────┐
│  SQLite  — users, roles, sessions, documents, permissions, messages,       │
│  security_modes, audit_logs, security_events, http_transactions, scans,    │
│  findings, security_tests, score_snapshots, reports, lab_accounts          │
└────────────────────────────────────────────────────────────────────────────┘
```

## The security mode registry — the core mechanism

`backend/src/security/modes.ts` holds one mode (`vulnerable` | `secure`) per
vulnerability class. It is the single idea the whole platform turns on.

- Application code consults `getMode(key)` / `isSecure(key)` **at request time** and
  takes a genuinely different code path.
- The state is cached in memory for fast reads and persisted to the `security_modes`
  table so choices survive a restart mid-demonstration.
- Flipping a toggle changes real behaviour → which changes what the scanner finds →
  which changes the findings table → which changes the security score.

Because the scanner issues **real HTTP requests to the app's own endpoints** and parses
the genuine responses, the chain "Apply Mitigation → Retest → score moves" is honest,
not animated.

## Why these technology choices

- **SQLite / better-sqlite3** — zero-config (the demo never fails on a missing DB),
  synchronous (simple control flow), and it executes raw SQL strings, which is what makes
  the SQL-injection lab a *real* injection rather than a mock. A `db.raw()` / `db.prepared()`
  split keeps the vulnerable and secure query paths visibly distinct.
- **Server-side sessions** (not stateless JWT) — so logout can truly invalidate a session,
  which the Session lab demonstrates.
- **scrypt** for passwords (memory-hard, in Node core) and **AES-256-GCM** for data at rest
  (authenticated encryption). No invented crypto; keys come only from the environment.
- **Vite + React + Tailwind + Recharts** — fast local dev, a cohesive SOC-style UI, real
  interactive charts.

## Request lifecycle (the pipeline the Attack Surface page visualises)

```
Request → Security Headers → Authentication → CSRF → Authorization →
Input Validation → Business Logic → Database → Safe Response
```

Each stage is a real middleware or check. The `recorder` middleware captures each
request/response pair (with secrets redacted) for the HTTP inspector, and flags any
exchange carrying attack-shaped input as a *detection* signal (not a control).

## Data model

Normalised relational schema (`backend/src/db/schema.sql`): identity (`users`, `roles`,
`user_roles`), sessions and `login_attempts`, the SecureVault domain (`documents`,
`document_permissions`, `messages`), the mode registry, observability (`audit_logs`,
`security_events`, `http_transactions`), and the assessment domain (`scans`, `findings`,
`security_tests`, `score_snapshots`, `reports`). Foreign keys and indexes are used
throughout; nothing is flattened into a single table.

## Containers

`docker-compose.yml` builds:

- **backend** — multi-stage Node image; compiles TypeScript, recompiles `better-sqlite3`
  for the runtime, seeds on first boot, runs as non-root, data on a named volume.
- **frontend** — Vite build served by nginx, which also proxies `/api` to the backend
  (with SSE buffering disabled).
- **postgres** *(optional, `--profile pg`)* — a server database for demonstration.

Everything publishes to `127.0.0.1` only.

## PostgreSQL status

The data-access layer (`backend/src/db/index.ts`) targets SQLite. A Postgres service is
provided in Compose for demonstrating a server-backed database, and `DB_DRIVER=postgres`
is validated in config, but the query layer is not yet ported to `pg`. The abstraction
point for that work is the `db` object: its `prepared` / `raw` / `run` methods are the
only surface the rest of the backend uses, so a Postgres adapter would implement that
same interface. This is stated plainly rather than overclaimed.
