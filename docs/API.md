# API Reference

Base URL: `http://127.0.0.1:4000/api` (or `http://localhost:5173/api` via the dev proxy).

All responses are JSON. Mutating requests require the session cookie and an
`X-CSRF-Token` header (value from the login / `me` response), except the pre-auth
endpoints noted below. Errors follow:

```json
{ "error": { "code": "forbidden", "message": "…", "incidentId": "…" } }
```

## Auth — `/api/auth`

| Method | Path | Auth | Notes |
|---|---|---|---|
| POST | `/register` | — | Creates a user (lowest role). CSRF-exempt. |
| POST | `/login` | — | Returns `user`, `csrfToken`, `session`. CSRF-exempt. Rate-limited 5/min. |
| POST | `/logout` | cookie | Invalidates the session server-side. CSRF-exempt. |
| GET | `/me` | — | Current user (or `null`) + fresh `csrfToken`. |
| POST | `/password` | ✔ | Change password (re-auth required; revokes other sessions). |
| POST | `/password/assess` | — | Password-strength assessment (not stored). |
| GET | `/sessions` | ✔ | Own sessions. |
| DELETE | `/sessions/:id` | ✔ | Revoke an own session (object-level check). |

## SecureVault app — `/api/vault`  *(all require auth)*

| Method | Path | Notes |
|---|---|---|
| GET | `/documents` | Documents readable by the caller. |
| POST | `/documents` | Create (confidential/restricted are encrypted at rest). |
| GET | `/documents/:id` | Object-level authorized read. |
| PATCH | `/documents/:id` | Authorized write. |
| DELETE | `/documents/:id` | Owner-only (soft delete). |
| POST | `/documents/:id/share` | Owner grants read/write to a user. |
| GET | `/documents/:id/permissions` | List grants. |
| GET/POST | `/messages` | List / send messages (output-encoded). |
| PATCH | `/profile` | Update own profile (phone encrypted). |
| GET | `/activity` | Caller's own audit trail. |

## Security assessment — `/api/security`

| Method | Path | Role | Notes |
|---|---|---|---|
| GET | `/modes` | — | Vuln-class catalogue + current modes. |
| PUT | `/modes/:key` | admin | Set one class vulnerable/secure; returns new score. |
| PUT | `/modes` | admin | Set all classes. |
| GET | `/score` | — | Live security score + history. |
| POST | `/scan` | analyst | Run a full assessment (real HTTP probes). |
| GET | `/scans` | analyst | Scan history. |
| GET | `/checks` | — | Check catalogue. |
| GET | `/findings` | — | Findings (filter `status`, `severity`, `active`). |
| GET | `/findings/:id` | — | Full finding + catalogue entry. |
| PUT | `/findings/:id/status` | analyst | Triage a finding. |
| POST | `/findings/:id/remediate` | analyst | Apply mitigation + retest; returns score delta. |
| POST | `/findings/:id/retest` | analyst | Retest only. |
| POST | `/reports` | analyst | Generate a report. |
| GET | `/reports` / `/reports/:id` | analyst | List / fetch (append `?format=markdown` to export). |
| GET | `/tests` | — | Security-test history. |
| GET | `/events/recent` | — | Recent events (JSON). |
| GET | `/events/stream` | — | **SSE** live event stream. |

## Labs — `/api/lab`

- `POST /run/{sqli,xss,csrf,idor,auth,session,headers,upload,traversal,ssrf,cmdi,exposure}`
  → returns a full `LabOutcome` (trace, exchange, evidence, explanation, verdict). Accepts an
  optional `mode` to force vulnerable/secure for that run.
- `GET /sqli/payloads`, `GET /xss/payloads` → example payload menus.
- Bare probe endpoints (behave per live mode; interceptable with Burp/ZAP):
  `POST /sqli/login`, `GET /xss/search`, `GET /headers/probe`, `GET /exposure/profile`,
  `GET /idor/document/:id`.

## Admin console — `/api/admin`  *(analyst unless noted)*

| Method | Path | Notes |
|---|---|---|
| GET | `/audit` | Filter/search audit logs. |
| GET | `/requests` | Captured HTTP transactions (inspector). |
| GET | `/sessions` | All sessions. |
| DELETE | `/sessions/:id` | Revoke (admin). |
| GET | `/headers/inspect` | Reads headers off a live response. |
| GET | `/users` | List users + RBAC state. |
| PUT | `/users/:id/roles` | Set roles (admin). |
| PUT | `/users/:id/active` | Enable/disable (admin). |
| GET | `/roles` | Role definitions + capabilities. |

## Cryptography — `/api/crypto`

| Method | Path | Notes |
|---|---|---|
| GET | `/operations` | Explanations of each crypto family. |
| POST | `/demonstrate` | Hash/encrypt/encode one sample (in-memory, not stored). |
| POST | `/verify-demo` | Hash + verify demonstration. |

## Misc

- `GET /api/health` — liveness.
- `GET /api/config` — public, non-secret config for the frontend.
