/**
 * Security assessment API (spec sections 13, 17, 18, 19, 20, 21, 22).
 *
 * These routes expose the engines: scanner, score, findings, remediation,
 * reports, the live event stream and the mode registry. Read endpoints require
 * the analyst role; mutating the mode registry requires admin (spec section 24).
 */
import { Router } from 'express';
import { asyncRoute } from '../middleware/errorHandler.js';
import { requireAuth, requireRole, authOf } from '../middleware/auth.js';
import { badRequest, notFound } from '../core/errors.js';
import { rateLimit, LIMITS } from '../security/ratelimit.js';
import { audit } from '../security/audit.js';
import {
  getAllModes, setMode, setAllModes, describeAllClasses, isVulnClass,
  VULN_CATALOGUE, type Mode,
} from '../security/modes.js';
import { subscribe, recentEvents, storedEvents } from '../security/events.js';
import { computeScore, snapshotScore, scoreHistory } from '../engine/score.js';
import { runScan, listScans, describeChecks } from '../engine/scanner.js';
import { listFindings, getFinding, setFindingStatus } from '../engine/findings.js';
import { applyAndRetest, retestOnly } from '../engine/remediation.js';
import { generateReport, getReport, listReports, reportToMarkdown } from '../engine/report.js';
import { recentTests } from '../engine/testStore.js';

export const securityRouter = Router();

// ── Mode registry ───────────────────────────────────────────────────────────

securityRouter.get('/modes', asyncRoute(async (_req, res) => {
  res.json({ classes: describeAllClasses(), modes: getAllModes() });
}));

securityRouter.put('/modes/:key', requireAuth, requireRole('admin'), asyncRoute(async (req, res) => {
  const key = req.params.key!;
  const mode = (req.body as { mode?: unknown }).mode;
  if (!isVulnClass(key)) throw notFound(`Unknown vulnerability class '${key}'.`);
  if (mode !== 'vulnerable' && mode !== 'secure') throw badRequest("mode must be 'vulnerable' or 'secure'.");
  const change = setMode(key, mode as Mode, req.auth?.userId);
  audit({ action: 'mode.change', category: 'admin', outcome: 'success', severity: mode === 'vulnerable' ? 'high' : 'medium',
    req, targetType: 'mode', targetId: key, detail: { from: change.from, to: change.to } });
  const score = snapshotScore(`mode ${key} -> ${mode}`);
  res.json({ change, score });
}));

securityRouter.put('/modes', requireAuth, requireRole('admin'), asyncRoute(async (req, res) => {
  const mode = (req.body as { mode?: unknown }).mode;
  if (mode !== 'vulnerable' && mode !== 'secure') throw badRequest("mode must be 'vulnerable' or 'secure'.");
  const changes = setAllModes(mode as Mode, req.auth?.userId);
  audit({ action: 'mode.change.all', category: 'admin', outcome: 'success', severity: mode === 'vulnerable' ? 'high' : 'medium',
    req, detail: { to: mode, count: changes.length } });
  const score = snapshotScore(`all modes -> ${mode}`);
  res.json({ changes, score });
}));

// ── Security score ────────────────────────────────────────────────────────

securityRouter.get('/score', asyncRoute(async (_req, res) => {
  res.json({ score: computeScore(), history: scoreHistory(30) });
}));

// ── Scanner ─────────────────────────────────────────────────────────────────

securityRouter.post('/scan', requireAuth, requireRole('analyst'),
  rateLimit(LIMITS.securityOps),
  asyncRoute(async (req, res) => {
    const result = await runScan({ initiatedBy: req.auth?.userId });
    snapshotScore('post-scan');
    audit({ action: 'security.scan', category: 'security', outcome: 'success', severity: 'low', req,
      detail: { scanId: result.scanId, findings: result.findings.length } });
    res.json(result);
  }));

securityRouter.get('/scans', requireAuth, requireRole('analyst'), asyncRoute(async (_req, res) => {
  res.json({ scans: listScans() });
}));

securityRouter.get('/checks', asyncRoute(async (_req, res) => {
  res.json({ checks: describeChecks() });
}));

// ── Findings ──────────────────────────────────────────────────────────────

securityRouter.get('/findings', asyncRoute(async (req, res) => {
  const status = req.query.status as string | undefined;
  const severity = req.query.severity as string | undefined;
  res.json({ findings: listFindings({
    status: status as never, severity: severity as never,
    activeOnly: req.query.active === 'true',
  }) });
}));

securityRouter.get('/findings/:id', asyncRoute(async (req, res) => {
  const finding = getFinding(Number(req.params.id));
  if (!finding) throw notFound('Finding not found.');
  res.json({ finding, catalogue: VULN_CATALOGUE[finding.vulnClass as keyof typeof VULN_CATALOGUE] });
}));

securityRouter.put('/findings/:id/status', requireAuth, requireRole('analyst'), asyncRoute(async (req, res) => {
  const status = (req.body as { status?: unknown }).status;
  const notes = (req.body as { notes?: unknown }).notes;
  const valid = ['open', 'remediated', 'verified', 'accepted', 'false_positive'];
  if (typeof status !== 'string' || !valid.includes(status)) throw badRequest('Invalid status.');
  const finding = setFindingStatus(Number(req.params.id), status as never, typeof notes === 'string' ? notes : undefined);
  if (!finding) throw notFound('Finding not found.');
  audit({ action: 'finding.status.change', category: 'security', outcome: 'success', req,
    targetType: 'finding', targetId: req.params.id, detail: { status } });
  res.json({ finding });
}));

// ── Remediation + retest ────────────────────────────────────────────────────

securityRouter.post('/findings/:id/remediate', requireAuth, requireRole('analyst'),
  rateLimit(LIMITS.securityOps),
  asyncRoute(async (req, res) => {
    const result = applyAndRetest(Number(req.params.id), req.auth?.userId);
    if (!result) throw notFound('Finding not found.');
    res.json(result);
  }));

securityRouter.post('/findings/:id/retest', requireAuth, requireRole('analyst'),
  rateLimit(LIMITS.securityOps),
  asyncRoute(async (req, res) => {
    const result = retestOnly(Number(req.params.id), req.auth?.userId);
    if (!result) throw notFound('Finding not found.');
    res.json(result);
  }));

// ── Reports ─────────────────────────────────────────────────────────────────

securityRouter.post('/reports', requireAuth, requireRole('analyst'), asyncRoute(async (req, res) => {
  const title = (req.body as { title?: unknown }).title;
  const report = generateReport({ title: typeof title === 'string' ? title : undefined, generatedBy: req.auth?.userId });
  audit({ action: 'report.generate', category: 'security', outcome: 'success', req, targetType: 'report', targetId: report.id });
  res.json({ report });
}));

securityRouter.get('/reports', requireAuth, requireRole('analyst'), asyncRoute(async (_req, res) => {
  res.json({ reports: listReports() });
}));

securityRouter.get('/reports/:id', requireAuth, requireRole('analyst'), asyncRoute(async (req, res) => {
  const report = getReport(Number(req.params.id));
  if (!report) throw notFound('Report not found.');
  const format = req.query.format;
  if (format === 'markdown') {
    res.type('text/markdown').send(reportToMarkdown(report));
    return;
  }
  res.json({ report });
}));

// ── Security tests history (§32 results feed) ───────────────────────────────

securityRouter.get('/tests', asyncRoute(async (req, res) => {
  const vulnClass = req.query.vulnClass as string | undefined;
  res.json({ tests: recentTests(80, vulnClass) });
}));

// ── Live event stream (§17) via Server-Sent Events ──────────────────────────

securityRouter.get('/events/recent', asyncRoute(async (_req, res) => {
  res.json({ events: storedEvents(100) });
}));

securityRouter.get('/events/stream', (req, res) => {
  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache, no-transform',
    Connection: 'keep-alive',
    'X-Accel-Buffering': 'no',
  });
  res.write(': connected\n\n');

  // Replay recent backlog so a freshly-opened console is not empty.
  for (const event of recentEvents(20).reverse()) {
    res.write(`event: security\ndata: ${JSON.stringify(event)}\n\n`);
  }

  const unsubscribe = subscribe((event) => {
    res.write(`event: security\ndata: ${JSON.stringify(event)}\n\n`);
  });

  // Heartbeat keeps the connection alive through proxies.
  const heartbeat = setInterval(() => res.write(': ping\n\n'), 20_000);

  req.on('close', () => {
    clearInterval(heartbeat);
    unsubscribe();
    res.end();
  });
});
