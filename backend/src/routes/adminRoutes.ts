/**
 * Admin / Security Analyst console routes (spec sections 23, 24, 15, 12).
 *
 * Audit log search, session administration, the HTTP request inspector feed,
 * the security-headers inspector, and user management. All require at least the
 * analyst role; user management requires admin.
 */
import { Router } from 'express';
import { db } from '../db/index.js';
import { asyncRoute } from '../middleware/errorHandler.js';
import { requireAuth, requireRole } from '../middleware/auth.js';
import { notFound, badRequest } from '../core/errors.js';
import { audit, queryAuditLogs, type AuditCategory, type AuditOutcome, type AuditSeverity } from '../security/audit.js';
import { queryTransactions } from '../middleware/recorder.js';
import { listAllSessions, revokeSession } from '../security/session.js';
import { HEADER_SPECS, LEAKY_HEADERS } from '../security/headers.js';
import { getMode } from '../security/modes.js';
import { config } from '../config/env.js';
import { loadUserRoles, highestRole, ROLES, capabilitiesFor } from '../security/rbac.js';

export const adminRouter = Router();
adminRouter.use(requireAuth);

// ── Audit logs (§23) ──────────────────────────────────────────────────────

adminRouter.get('/audit', requireRole('analyst'), asyncRoute(async (req, res) => {
  const result = queryAuditLogs({
    search: req.query.search as string | undefined,
    category: req.query.category as AuditCategory | undefined,
    outcome: req.query.outcome as AuditOutcome | undefined,
    severity: req.query.severity as AuditSeverity | undefined,
    limit: req.query.limit ? Number(req.query.limit) : 100,
    offset: req.query.offset ? Number(req.query.offset) : 0,
  });
  res.json(result);
}));

// ── HTTP request inspector (§15) ────────────────────────────────────────────

adminRouter.get('/requests', requireRole('analyst'), asyncRoute(async (req, res) => {
  const result = queryTransactions({
    limit: req.query.limit ? Number(req.query.limit) : 60,
    method: req.query.method as string | undefined,
    pathContains: req.query.path as string | undefined,
    flaggedOnly: req.query.flagged === 'true',
    origin: req.query.origin as string | undefined,
  });
  res.json(result);
}));

adminRouter.get('/requests/:id', requireRole('analyst'), asyncRoute(async (req, res) => {
  const result = queryTransactions({ limit: 1 });
  const one = queryTransactions({ limit: 200 }).rows.find((r) => r.id === Number(req.params.id));
  if (!one) throw notFound('Transaction not found.');
  res.json({ transaction: one });
}));

// ── Sessions (§24) ────────────────────────────────────────────────────────

adminRouter.get('/sessions', requireRole('analyst'), asyncRoute(async (_req, res) => {
  const sessions = listAllSessions(100).map((s) => {
    const user = db.preparedOne<{ username: string }>('SELECT username FROM users WHERE id = ?', [s.userId]);
    return {
      id: `${s.id.slice(0, 10)}…`, username: user?.username ?? 'unknown',
      createdAt: s.createdAt, lastSeenAt: s.lastSeenAt, expiresAt: s.expiresAt,
      ipAddress: s.ipAddress, revokedAt: s.revokedAt, issuedMode: s.issuedMode,
      active: !s.revokedAt && new Date(s.expiresAt).getTime() > Date.now(),
      fullId: s.id,
    };
  });
  res.json({ sessions });
}));

adminRouter.delete('/sessions/:id', requireRole('admin'), asyncRoute(async (req, res) => {
  revokeSession(req.params.id!, 'revoked by administrator');
  audit({ action: 'session.admin.revoke', category: 'admin', outcome: 'success', severity: 'medium', req,
    targetType: 'session', targetId: req.params.id!.slice(0, 12) });
  res.json({ ok: true });
}));

// ── Security headers inspector (§12) ────────────────────────────────────────
// Reads headers back off a REAL response from this server, so values are not
// faked -- they are whatever the mode registry actually caused to be sent.

adminRouter.get('/headers/inspect', requireRole('analyst'), asyncRoute(async (_req, res) => {
  const probeUrl = `${config.selfBaseUrl}/api/lab/headers/probe`;
  let received: Record<string, string> = {};
  let error: string | null = null;
  try {
    const response = await fetch(probeUrl, { headers: { 'x-sentinelx-origin': 'scanner' } });
    received = Object.fromEntries([...response.headers.entries()].map(([k, v]) => [k.toLowerCase(), v]));
  } catch (e) {
    error = e instanceof Error ? e.message : String(e);
  }

  const analysis = HEADER_SPECS.map((spec) => {
    const current = received[spec.name];
    const present = typeof current === 'string' && current.length > 0;
    return {
      header: spec.name,
      status: present ? 'secure' : spec.required ? 'missing' : 'optional-missing',
      icon: present ? 'ok' : spec.required ? 'missing' : 'warn',
      purpose: spec.purpose, risk: spec.risk,
      current: current ?? null, recommended: spec.recommended, required: spec.required,
    };
  });

  const leakyPresent = Object.keys(LEAKY_HEADERS).filter((h) => received[h.toLowerCase()] !== undefined)
    .map((h) => ({ header: h, value: received[h.toLowerCase()]!, risk: 'Leaks server/stack identity, aiding targeted attacks.' }));

  res.json({
    mode: getMode('headers'),
    probeUrl,
    error,
    headers: analysis,
    leakingHeaders: leakyPresent,
    note: 'These values are read from a live HTTP response, not stored. Flip the headers mode to see them change.',
  });
}));

// ── Users (§24) ─────────────────────────────────────────────────────────────

adminRouter.get('/users', requireRole('analyst'), asyncRoute(async (_req, res) => {
  const rows = db.prepared<{ id: number; username: string; email: string; full_name: string; is_active: number; last_login_at: string | null; failed_login_count: number; locked_until: string | null; created_at: string }>(
    'SELECT id, username, email, full_name, is_active, last_login_at, failed_login_count, locked_until, created_at FROM users ORDER BY id');
  const users = rows.map((u) => {
    const roles = loadUserRoles(u.id);
    return { id: u.id, username: u.username, email: u.email, fullName: u.full_name,
      roles, primaryRole: highestRole(roles), roleLabel: ROLES[highestRole(roles)].label,
      active: u.is_active === 1, lastLoginAt: u.last_login_at,
      failedLoginCount: u.failed_login_count,
      locked: !!u.locked_until && new Date(u.locked_until).getTime() > Date.now(),
      createdAt: u.created_at };
  });
  res.json({ users });
}));

adminRouter.put('/users/:id/roles', requireRole('admin'), asyncRoute(async (req, res) => {
  const id = Number(req.params.id);
  const roles = (req.body as { roles?: unknown }).roles;
  if (!Array.isArray(roles) || roles.some((r) => !['user', 'analyst', 'admin'].includes(r as string)))
    throw badRequest('roles must be an array of user|analyst|admin.');
  const user = db.preparedOne<{ id: number }>('SELECT id FROM users WHERE id = ?', [id]);
  if (!user) throw notFound('User not found.');
  db.transaction(() => {
    db.run('DELETE FROM user_roles WHERE user_id = ?', [id]);
    for (const roleName of roles as string[]) {
      const role = db.preparedOne<{ id: number }>('SELECT id FROM roles WHERE name = ?', [roleName]);
      if (role) db.run('INSERT OR IGNORE INTO user_roles (user_id, role_id) VALUES (?, ?)', [id, role.id]);
    }
  });
  audit({ action: 'user.roles.change', category: 'admin', outcome: 'success', severity: 'high', req,
    targetType: 'user', targetId: id, detail: { roles } });
  res.json({ ok: true, roles });
}));

adminRouter.put('/users/:id/active', requireRole('admin'), asyncRoute(async (req, res) => {
  const id = Number(req.params.id);
  const active = (req.body as { active?: unknown }).active;
  if (typeof active !== 'boolean') throw badRequest('active must be a boolean.');
  db.run('UPDATE users SET is_active = ?, locked_until = NULL, failed_login_count = 0 WHERE id = ?', [active ? 1 : 0, id]);
  audit({ action: active ? 'user.activate' : 'user.deactivate', category: 'admin', outcome: 'success', severity: 'high', req,
    targetType: 'user', targetId: id });
  res.json({ ok: true });
}));

adminRouter.get('/roles', requireRole('analyst'), asyncRoute(async (_req, res) => {
  res.json({ roles: Object.values(ROLES).map((r) => ({ ...r, capabilities: capabilitiesFor([r.name]) })) });
}));
