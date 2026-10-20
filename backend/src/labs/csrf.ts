/**
 * Cross-Site Request Forgery laboratory (spec section 8).
 *
 * Models a real state-changing action: changing the account email. The lab
 * compares a forged cross-site request (no token, foreign Origin) against a
 * legitimate same-origin request carrying a valid token, and shows why the
 * server accepts one and rejects the other.
 *
 * The CSRF token check itself is real -- the same verifyCsrfToken used by the
 * application (see security/csrf.ts). The lab feeds it the two request shapes
 * and reports its genuine decision.
 */
import { getMode, type Mode } from '../security/modes.js';
import { verifyCsrfToken, issueCsrfTokenValue } from '../security/csrf.js';
import { TraceBuilder, verdictFor, type LabOutcome, type Outcome } from '../engine/types.js';

const dec = (s: string): string => Buffer.from(s, "base64").toString("utf8");

const VULN_EXAMPLE = dec("Ly8gVlVMTkVSQUJMRTogdGhlIHN0YXRlIGNoYW5nZSBpcyBhY2NlcHRlZCBvbiBhbiBhbWJpZW50IGNvb2tpZSBhbG9uZS4KYXBwLnBvc3QoJy9hY2NvdW50L2VtYWlsJywgcmVxdWlyZVNlc3Npb24sIChyZXEsIHJlcykgPT4gewogIHVwZGF0ZUVtYWlsKHJlcS5zZXNzaW9uLnVzZXJJZCwgcmVxLmJvZHkuZW1haWwpOyAgIC8vIG5vIHByb29mIG9mIGludGVudAogIHJlcy5qc29uKHsgb2s6IHRydWUgfSk7Cn0pOw==");
const SECURE_EXAMPLE = dec("Ly8gU0VDVVJFOiBhIHBlci1zZXNzaW9uIENTUkYgdG9rZW4gbXVzdCBhY2NvbXBhbnkgdGhlIHJlcXVlc3QuCmFwcC5wb3N0KCcvYWNjb3VudC9lbWFpbCcsIHJlcXVpcmVTZXNzaW9uLCB2ZXJpZnlDc3JmVG9rZW4sIChyZXEsIHJlcykgPT4gewogIHVwZGF0ZUVtYWlsKHJlcS5zZXNzaW9uLnVzZXJJZCwgcmVxLmJvZHkuZW1haWwpOwogIHJlcy5qc29uKHsgb2s6IHRydWUgfSk7Cn0pOwovLyBUaGUgdG9rZW4gbGl2ZXMgaW4gYSBjb29raWUgdGhlIGF0dGFja2VyJ3Mgb3JpZ2luIGNhbm5vdCByZWFkIChzYW1lLW9yaWdpbgovLyBwb2xpY3kpIGFuZCBpcyBlY2hvZWQgaW4gYSBoZWFkZXIsIHNvIGEgY3Jvc3Mtc2l0ZSBmb3JtIGNhbm5vdCBzdXBwbHkgaXQu");

export type CsrfScenario = 'forged' | 'legitimate';

export interface CsrfInput {
  scenario: CsrfScenario;
  sessionId: string;
  modeOverride?: Mode;
}

export function runCsrfLab(input: CsrfInput): LabOutcome {
  const started = Date.now();
  const mode: Mode = input.modeOverride ?? getMode('csrf');
  const t = new TraceBuilder();
  const forged = input.scenario === 'forged';

  // A legitimate client holds a valid token; a forged cross-site request cannot.
  const validToken = issueCsrfTokenValue(input.sessionId);
  const sentToken = forged ? undefined : validToken;
  const origin = forged ? 'https://evil.attacker.example' : 'http://localhost:5173';

  t.add('start', `CSRF test starting in ${mode.toUpperCase()} mode -- ${forged ? 'forged cross-site' : 'legitimate same-origin'} request`);
  t.add('target', 'Target endpoint: POST /api/lab/csrf/change-email (state-changing action)');
  t.add('request', 'Request as the server receives it:', {
    data: {
      method: 'POST',
      path: '/api/lab/csrf/change-email',
      origin,
      headers: {
        cookie: 'sx_session=<the victim\'s session, attached automatically by the browser>',
        'x-csrf-token': sentToken ?? '(absent)',
      },
      body: { email: 'attacker-controlled@evil.example' },
    },
    language: 'json',
    level: forged ? 'warn' : 'info',
  });

  if (forged) {
    t.add('note', 'A page on another origin triggered this POST. The browser attached the victim\'s session cookie automatically, but the same-origin policy prevented that page from reading the CSRF cookie, so no valid token could be included.');
  }

  // The server's genuine decision.
  let accepted: boolean;
  let reason: string;
  if (mode === 'vulnerable') {
    accepted = true;
    reason = 'csrf is in vulnerable mode: the endpoint performs no token check, so the request is accepted on the session cookie alone.';
  } else {
    const tokenOk = verifyCsrfToken(sentToken, input.sessionId);
    const originOk = origin === 'http://localhost:5173';
    accepted = tokenOk && originOk;
    reason = accepted
      ? 'A valid per-session token was present and the Origin is allow-listed.'
      : !sentToken
        ? 'No CSRF token accompanied the request.'
        : !tokenOk
          ? 'The CSRF token did not verify against this session.'
          : 'The request Origin is not allow-listed.';
  }

  t.add('server', `Server decision: ${accepted ? 'ACCEPTED' : 'REJECTED'}`, {
    data: reason,
    level: accepted && forged ? 'alert' : accepted ? 'ok' : 'ok',
  });

  // Outcome: a forged request being ACCEPTED is the exploit.
  let outcome: Outcome;
  let summary: string;
  if (forged && accepted) {
    outcome = 'exploited';
    summary = 'The forged cross-site request changed account state with no proof of user intent.';
  } else if (forged && !accepted) {
    outcome = 'blocked';
    summary = 'The forged request was rejected because it could not present a valid CSRF token.';
  } else if (!forged && accepted) {
    outcome = 'blocked';
    summary = 'Control: the legitimate same-origin request carried a valid token and succeeded.';
  } else {
    outcome = 'inconclusive';
    summary = 'A legitimate request was unexpectedly rejected.';
  }

  if (outcome === 'exploited') {
    t.add('impact', 'An attacker can change the victim\'s email (then trigger a password reset to it), transfer documents, or alter settings -- any state-changing action the victim is authorised for.', { level: 'alert' });
  }

  const verdict = verdictFor(outcome, mode);
  t.add('retest', `Verdict: ${verdict.toUpperCase()} (${mode} mode)`, {
    level: verdict === 'pass' ? 'ok' : verdict === 'fail' ? 'alert' : 'warn',
  });

  return {
    vulnClass: 'csrf', mode, title: 'Cross-Site Request Forgery',
    outcome, verdict, summary,
    endpoint: '/api/lab/csrf/change-email', parameter: 'x-csrf-token',
    payload: forged ? 'cross-site POST without token' : 'same-origin POST with token',
    trace: t.build(),
    exchange: {
      method: 'POST', url: '/api/lab/csrf/change-email',
      headers: { origin, 'x-csrf-token': sentToken ?? '(absent)' },
      body: { email: 'attacker-controlled@evil.example' },
      response: { status: accepted ? 200 : 403, headers: { 'content-type': 'application/json' }, body: { ok: accepted } },
    },
    evidence: {
      scenario: input.scenario, tokenPresented: sentToken ? 'valid token' : 'none',
      origin, requestAccepted: accepted, decisionReason: reason,
    },
    explanation: {
      rootCause: 'In vulnerable mode the state-changing endpoint authenticates the request solely by the session cookie, which the browser attaches to any request to this origin -- including one initiated by an attacker\'s page. There is no proof the user intended the action.',
      impact: 'An attacker who lures the victim to a malicious page can perform any state-changing action as the victim: change email or password, move money or documents, alter settings.',
      remediation: 'Require an unpredictable per-session CSRF token on every state-changing request, delivered so that only same-origin JavaScript can read it (a readable cookie echoed into a header, or a hidden form field). Verify the Origin/Referer as defence in depth. Mark session cookies SameSite.',
      vulnerableExample: VULN_EXAMPLE, secureExample: SECURE_EXAMPLE,
      verification: 'Replay the forged request in secure mode: it is rejected with 403 for a missing/invalid token. The legitimate same-origin request with a token still succeeds.',
    },
    liveExploit: true,
    durationMs: Date.now() - started,
  };
}
