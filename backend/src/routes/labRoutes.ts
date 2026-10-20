/**
 * Laboratory HTTP routes (spec section 5).
 *
 * Two kinds of endpoint live here:
 *
 *   1. `/run/*` endpoints invoke a lab runner and return a full LabOutcome for
 *      the Security Lab UI to render (trace, evidence, explanation, verdict).
 *
 *   2. The bare vulnerable endpoints (e.g. POST /sqli/login) behave exactly as a
 *      vulnerable or hardened app would, with no explanatory wrapper. These are
 *      what the scanner probes over real HTTP, and what a student can intercept
 *      with Burp Suite or ZAP (spec section 14). Their behaviour depends on the
 *      live mode registry.
 *
 * Everything is confined to this local application (spec section 41).
 */
import { Router } from 'express';
import { asyncRoute } from '../middleware/errorHandler.js';
import { badRequest } from '../core/errors.js';
import { getMode, isVulnClass, type Mode } from '../security/modes.js';
import { recordSecurityTest } from '../engine/testStore.js';
import { emitSecurityEvent } from '../security/events.js';
import { runSqliLab, SQLI_PAYLOADS, resetLabAccounts, labAccountCount } from '../labs/sqli.js';
import { runXssLab, XSS_PAYLOADS } from '../labs/xss.js';
import { runCsrfLab } from '../labs/csrf.js';
import { runIdorLab } from '../labs/idor.js';
import {
  runAuthLab, runSessionLab, runHeadersLab, runUploadLab,
  runTraversalLab, runSsrfLab, runCmdiLab, runExposureLab,
} from '../labs/misc.js';
import type { LabOutcome } from '../engine/types.js';

export const labRouter = Router();

function modeOverrideFrom(body: Record<string, unknown>): Mode | undefined {
  const m = body.mode;
  return m === 'vulnerable' || m === 'secure' ? m : undefined;
}

/**
 * Persists a lab run as a security_test row and emits the lifecycle events that
 * feed the live console, then returns the outcome. Centralised so every lab run
 * is recorded identically.
 */
function finishRun(outcome: LabOutcome, kind: 'simulation' | 'retest', userId?: number): LabOutcome {
  emitSecurityEvent('info', 'simulator', `${outcome.title} test executed in ${outcome.mode} mode`, {
    vulnClass: outcome.vulnClass, outcome: outcome.outcome, verdict: outcome.verdict,
  });
  if (outcome.outcome === 'exploited') {
    emitSecurityEvent('alert', 'simulator', `${outcome.title}: vulnerability confirmed`, {
      vulnClass: outcome.vulnClass, endpoint: outcome.endpoint,
    });
  }
  recordSecurityTest({
    testId: `lab:${outcome.vulnClass}`, vulnClass: outcome.vulnClass, kind,
    modeAtRun: outcome.mode, outcome: outcome.outcome, verdict: outcome.verdict,
    explanation: outcome.summary, trace: outcome.trace, executedBy: userId,
  });
  return outcome;
}

// ── Catalogue + payload menus ───────────────────────────────────────────────

labRouter.get('/sqli/payloads', (_req, res) => res.json({ payloads: SQLI_PAYLOADS }));
labRouter.get('/xss/payloads', (_req, res) => res.json({ payloads: XSS_PAYLOADS }));

labRouter.get('/sqli/status', (_req, res) =>
  res.json({ mode: getMode('sqli'), labAccounts: labAccountCount() }));

labRouter.post('/sqli/reset', asyncRoute(async (_req, res) => {
  resetLabAccounts();
  res.json({ ok: true, labAccounts: labAccountCount() });
}));

// ── Run endpoints (return full LabOutcome) ──────────────────────────────────

labRouter.post('/run/sqli', asyncRoute(async (req, res) => {
  const b = req.body as Record<string, unknown>;
  const username = typeof b.username === 'string' ? b.username : '';
  const password = typeof b.password === 'string' ? b.password : '';
  if (!username) throw badRequest('A username value is required.');
  res.json(finishRun(runSqliLab({ username, password, modeOverride: modeOverrideFrom(b) }), 'simulation', req.auth?.userId));
}));

labRouter.post('/run/xss', asyncRoute(async (req, res) => {
  const b = req.body as Record<string, unknown>;
  const input = typeof b.input === 'string' ? b.input : '';
  const variant = b.variant === 'stored' ? 'stored' : 'reflected';
  if (!input) throw badRequest('An input value is required.');
  res.json(finishRun(runXssLab({ input, variant, modeOverride: modeOverrideFrom(b) }), 'simulation', req.auth?.userId));
}));

labRouter.post('/run/csrf', asyncRoute(async (req, res) => {
  const b = req.body as Record<string, unknown>;
  const scenario = b.scenario === 'legitimate' ? 'legitimate' : 'forged';
  const sessionId = req.auth?.sessionId ?? 'demo-session';
  res.json(finishRun(runCsrfLab({ scenario, sessionId, modeOverride: modeOverrideFrom(b) }), 'simulation', req.auth?.userId));
}));

labRouter.post('/run/idor', asyncRoute(async (req, res) => {
  const b = req.body as Record<string, unknown>;
  const documentId = Number(b.documentId);
  // Defaults chosen so the lab works even for an anonymous demo: Bob reading
  // Alice's private document 1 is the canonical IDOR case.
  const actingUserId = Number(b.actingUserId) || req.auth?.userId || 4;
  if (!Number.isFinite(documentId)) throw badRequest('A numeric documentId is required.');
  res.json(finishRun(runIdorLab({ actingUserId, documentId, modeOverride: modeOverrideFrom(b) }), 'simulation', req.auth?.userId));
}));

labRouter.post('/run/auth', asyncRoute(async (req, res) => {
  const b = req.body as Record<string, unknown>;
  res.json(finishRun(runAuthLab({
    username: typeof b.username === 'string' ? b.username : 'demo',
    password: typeof b.password === 'string' ? b.password : 'demo-password',
    modeOverride: modeOverrideFrom(b),
  }), 'simulation', req.auth?.userId));
}));

labRouter.post('/run/session', asyncRoute(async (req, res) => {
  res.json(finishRun(runSessionLab({ modeOverride: modeOverrideFrom(req.body as Record<string, unknown>) }), 'simulation', req.auth?.userId));
}));

labRouter.post('/run/headers', asyncRoute(async (req, res) => {
  res.json(finishRun(runHeadersLab({ modeOverride: modeOverrideFrom(req.body as Record<string, unknown>) }), 'simulation', req.auth?.userId));
}));

labRouter.post('/run/upload', asyncRoute(async (req, res) => {
  const b = req.body as Record<string, unknown>;
  res.json(finishRun(runUploadLab({
    filename: typeof b.filename === 'string' ? b.filename : 'document.txt',
    declaredType: typeof b.declaredType === 'string' ? b.declaredType : 'text/plain',
    sizeBytes: Number(b.sizeBytes) || 1024,
    modeOverride: modeOverrideFrom(b),
  }), 'simulation', req.auth?.userId));
}));

labRouter.post('/run/traversal', asyncRoute(async (req, res) => {
  const b = req.body as Record<string, unknown>;
  res.json(finishRun(runTraversalLab({
    requestedPath: typeof b.requestedPath === 'string' ? b.requestedPath : 'welcome.txt',
    modeOverride: modeOverrideFrom(b),
  }), 'simulation', req.auth?.userId));
}));

labRouter.post('/run/ssrf', asyncRoute(async (req, res) => {
  const b = req.body as Record<string, unknown>;
  res.json(finishRun(runSsrfLab({
    url: typeof b.url === 'string' ? b.url : 'https://status.securevault.local/health',
    modeOverride: modeOverrideFrom(b),
  }), 'simulation', req.auth?.userId));
}));

labRouter.post('/run/cmdi', asyncRoute(async (req, res) => {
  const b = req.body as Record<string, unknown>;
  res.json(finishRun(runCmdiLab({
    format: typeof b.format === 'string' ? b.format : 'pdf',
    modeOverride: modeOverrideFrom(b),
  }), 'simulation', req.auth?.userId));
}));

labRouter.post('/run/exposure', asyncRoute(async (req, res) => {
  const b = req.body as Record<string, unknown>;
  res.json(finishRun(runExposureLab({
    targetUserId: Number(b.targetUserId) || 3,
    modeOverride: modeOverrideFrom(b),
  }), 'simulation', req.auth?.userId));
}));

// ── Bare probe endpoints (what the scanner / Burp / ZAP hit) ────────────────
// These return realistic responses with NO explanatory wrapper, and behave
// according to the live mode registry.

labRouter.post('/sqli/login', asyncRoute(async (req, res) => {
  const b = req.body as Record<string, unknown>;
  const r = runSqliLab({
    username: typeof b.username === 'string' ? b.username : '',
    password: typeof b.password === 'string' ? b.password : '',
  });
  const authed = r.outcome === 'exploited' || (r.evidence as Record<string, unknown>).rowsReturned;
  res.status(r.outcome === 'exploited' ? 200 : (r.evidence as { rowsReturned: number }).rowsReturned > 0 ? 200 : 401)
    .json({ authenticated: !!authed, rows: (r.evidence as { rows: unknown[] }).rows, mode: r.mode });
}));

labRouter.get('/xss/search', asyncRoute(async (req, res) => {
  const q = typeof req.query.q === 'string' ? req.query.q : '';
  const r = runXssLab({ input: q, variant: 'reflected' });
  // Returns an HTML fragment so the reflection is directly observable.
  res.type('html').send((r.exchange?.response?.body as string) ?? '');
}));

labRouter.get('/headers/probe', (_req, res) => {
  // The security headers (or their absence) are applied by middleware upstream
  // according to the mode. We just confirm the endpoint exists.
  res.json({ mode: getMode('headers'), note: 'Inspect the response headers of THIS response.' });
});

labRouter.get('/exposure/profile', asyncRoute(async (req, res) => {
  const r = runExposureLab({ targetUserId: Number(req.query.userId) || 3 });
  res.json((r.exchange?.response?.body as unknown) ?? (r.evidence as Record<string, unknown>));
}));

labRouter.get('/idor/document/:id', asyncRoute(async (req, res) => {
  const documentId = Number(req.params.id);
  const actingUserId = req.auth?.userId ?? 4;
  const r = runIdorLab({ actingUserId, documentId });
  const served = (r.evidence as { contentServed: boolean }).contentServed;
  res.status(served ? 200 : 403).json(r.exchange?.response?.body ?? {});
}));
