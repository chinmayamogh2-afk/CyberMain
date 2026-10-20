# Testing

## Automated tests

```bash
cd backend
npm test            # Vitest, runs all suites
npm run test:watch  # watch mode
```

Suites (`backend/tests/`) run against a real throwaway SQLite database (not a mock), so the
genuine query, crypto and middleware paths are exercised — a mock could let an injection bug
pass unnoticed.

| Suite | What it proves |
|---|---|
| `crypto.test.ts` | scrypt salts and verifies; passwords never stored in plaintext; AES-256-GCM round-trips and rejects tampering; base64 is reversible (not security); constant-time compare; CSPRNG tokens unique. |
| `controls.test.ts` | For **every** vulnerability class: the attack is **blocked in secure mode** and **genuinely exploitable in vulnerable mode**, and legitimate use still works. |
| `http.test.ts` | Real Express app over HTTP: security headers present; wrong password and unknown user return the **same** message (no enumeration); HttpOnly session cookie; RBAC (user forbidden, analyst allowed); CSRF rejected without a token and accepted with one; **the score drops when a class is made vulnerable and recovers when secured**; 404s leak no stack/paths. |
| `lifecycle.test.ts` | A scan opens a Critical finding for vulnerable SQLi (score drops), **resolves** it on rescan once secured (score → 100), and **reopens** it if reintroduced. |

Each control test maps to the spec's §32 requirement to show PASS / FAIL / WARNING with a
reason — the `LabOutcome.verdict` and `summary` carry exactly that.

## Manual testing in the UI

1. **Security Lab** — pick a class, run in hardened (blocked) then vulnerable (exploited);
   read the terminal trace, the HTTP exchange, and the Why/Fix tabs.
2. **Attack Simulator** — "Run both modes (compare)" shows before/after side by side.
3. **Scanner** — run a full assessment; watch live stages and events.
4. **Remediation** — Apply mitigation & retest; confirm the score moves and the finding
   becomes *verified*.
5. **Demo Mode** — the scripted 8-step walkthrough performs all of the above for real.

## Interception testing

See **[BURP_ZAP.md](BURP_ZAP.md)** for Burp Suite / OWASP ZAP and `curl` recipes.

## Type & build checks

```bash
cd backend  && npm run typecheck && npm run build
cd frontend && npm run typecheck && npm run build
```

## Notes / limitations

- Tests reset the in-memory rate limiter between HTTP cases (they test auth/CSRF/RBAC, not the
  limiter, which is covered separately via the control suite).
- Rate limiting is per-process; no distributed test is included.
