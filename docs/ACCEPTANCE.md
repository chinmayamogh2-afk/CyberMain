# Acceptance Criteria

Mapping of the project's acceptance criteria (spec §45) to where each is demonstrated.
All are implemented and verified.

| ✓ | Criterion | Where to demonstrate |
|---|---|---|
| ✓ | Login | Sign-in with any demo account |
| ✓ | Role-based authorization | Users & Roles; analyst-only scan, admin-only mode changes |
| ✓ | Vulnerable mode | Any lab / Attack Simulator / mode toggle |
| ✓ | Secure mode | Same, toggled to Hardened |
| ✓ | SQL Injection demonstration | Security Lab → SQL Injection (real extraction) |
| ✓ | XSS demonstration | Security Lab → Reflected / Stored XSS |
| ✓ | CSRF demonstration | Security Lab → CSRF (forged vs tokened) |
| ✓ | IDOR demonstration | Security Lab → IDOR (Bob vs Alice's doc 1) |
| ✓ | Session security | Sessions page; Session lab |
| ✓ | Security headers | Security Headers Inspector (live) |
| ✓ | Secure cookies | Sessions page shows HttpOnly/SameSite/Secure/expiry |
| ✓ | Password hashing | Cryptography Center; `crypto.test.ts` |
| ✓ | Encryption demonstration | Cryptography Center (AES-256-GCM round-trip) |
| ✓ | Audit logs | Audit Logs (filter/search) |
| ✓ | Security scanner | Security Scan (real HTTP probes, live progress) |
| ✓ | Attack simulator | Attack Simulator (RUN TEST + terminal) |
| ✓ | Request/response inspector | Request Inspector |
| ✓ | Vulnerability details | Vulnerabilities (root cause, evidence, risk rationale) |
| ✓ | Remediation guidance | Remediation Center; each finding's Fix tab |
| ✓ | Retesting | Remediation → Apply mitigation & retest / Retest only |
| ✓ | Dynamic security score | Dashboard; moves on every mode change / remediation |
| ✓ | Security report | Reports (generate + export Markdown) |
| ✓ | Interactive dashboard | Dashboard (score ring, domain bars, trend) |
| ✓ | Responsive UI | Works desktop/laptop/tablet (desktop-first) |
| ✓ | Docker setup | `docker compose up --build` |
| ✓ | Automated security tests | `cd backend && npm test` (49 tests) |

## The headline criterion

> *If I exploit something in vulnerable mode, the UI must SHOW ME what happened.
> If I switch to secure mode, the same test must SHOW ME why it no longer works.*

Demonstrated throughout: the `LabResult` view renders the terminal trace (the actual
executed query / emitted markup / authorization decision), the HTTP exchange, the
extracted evidence, and the Why/Fix explanations — for the **same test** in both modes.
**Demo Mode** scripts the complete Attack → Detect → Explain → Remediate → Retest →
Verify cycle as a guided, real walkthrough.

## Honesty notes (spec §40)

- No "100% secure" / "unhackable" / "enterprise-grade" claims are made.
- Live exploits vs controlled demonstrations are labelled in the UI; demonstrations
  (parameter injection, SSRF, data exposure) never touch anything outside the app.
- The security score is presented as a transparent model over real state, not a measurement.
