/**
 * SecureVault application routes (spec section 4).
 *
 * The real document-collaboration features. Every object access goes through the
 * authorization decision in security/rbac.ts, every mutation is audited, and
 * confidential document bodies are encrypted at rest. These are the application's
 * own routes and are always secure -- the IDOR/exposure LABS demonstrate the
 * insecure variants separately.
 */
import { Router } from 'express';
import { db } from '../db/index.js';
import { asyncRoute } from '../middleware/errorHandler.js';
import { requireAuth, authOf } from '../middleware/auth.js';
import { badRequest, forbidden, notFound } from '../core/errors.js';
import { audit } from '../security/audit.js';
import { encrypt, tryDecrypt } from '../security/crypto.js';
import { encodeHtml } from '../security/sanitize.js';
import { authorizeDocumentAccess, readableDocumentIds, hasRole } from '../security/rbac.js';
import { documentCreateSchema, documentUpdateSchema, shareSchema, messageSchema, profileUpdateSchema } from '../security/validation.js';

export const appRouter = Router();
appRouter.use(requireAuth);

const CONFIDENTIAL = new Set(['confidential', 'restricted']);

interface DocRow {
  id: number; owner_id: number; title: string; body: string;
  body_encrypted: string | null; classification: string;
  created_at: string; updated_at: string;
}

function presentDocument(row: DocRow, includeBody: boolean) {
  const body = row.body_encrypted ? tryDecrypt(row.body_encrypted) : row.body;
  const owner = db.preparedOne<{ username: string; full_name: string }>(
    'SELECT username, full_name FROM users WHERE id = ?', [row.owner_id]);
  return {
    id: row.id, title: row.title, classification: row.classification,
    ownerId: row.owner_id, ownerName: owner?.full_name ?? 'unknown',
    encryptedAtRest: !!row.body_encrypted,
    createdAt: row.created_at, updatedAt: row.updated_at,
    ...(includeBody ? { body: body ?? '' } : {}),
  };
}

// ── Documents ───────────────────────────────────────────────────────────────

appRouter.get('/documents', asyncRoute(async (req, res) => {
  const auth = authOf(req);
  const ids = readableDocumentIds(auth.userId, auth.roles);
  if (ids.length === 0) { res.json({ documents: [] }); return; }
  const rows = db.prepared<DocRow>(
    `SELECT * FROM documents WHERE id IN (${ids.map(() => '?').join(',')}) AND deleted_at IS NULL ORDER BY updated_at DESC`,
    ids);
  res.json({ documents: rows.map((r) => presentDocument(r, false)) });
}));

appRouter.post('/documents', asyncRoute(async (req, res) => {
  const auth = authOf(req);
  const input = documentCreateSchema.parse(req.body);
  const encryptBody = CONFIDENTIAL.has(input.classification);
  const result = db.run(
    `INSERT INTO documents (owner_id, title, body, body_encrypted, classification, size_bytes)
     VALUES (?, ?, ?, ?, ?, ?)`,
    [auth.userId, input.title, encryptBody ? '' : input.body,
     encryptBody ? encrypt(input.body) : null, input.classification, Buffer.byteLength(input.body)]);
  const id = Number(result.lastInsertRowid);
  db.run('INSERT INTO document_permissions (document_id, user_id, capability, granted_by) VALUES (?, ?, ?, ?)',
    [id, auth.userId, 'owner', auth.userId]);
  audit({ action: 'document.create', category: 'data', outcome: 'success', req, targetType: 'document', targetId: id,
    detail: { classification: input.classification, encrypted: encryptBody } });
  res.status(201).json({ document: presentDocument(db.preparedOne<DocRow>('SELECT * FROM documents WHERE id = ?', [id])!, true) });
}));

appRouter.get('/documents/:id', asyncRoute(async (req, res) => {
  const auth = authOf(req);
  const id = Number(req.params.id);
  const decision = authorizeDocumentAccess(id, auth.userId, auth.roles, 'read');
  if (!decision.allowed) {
    audit({ action: 'document.read.denied', category: 'access', outcome: 'blocked', severity: 'medium', req,
      targetType: 'document', targetId: id, detail: { reason: decision.rule } });
    throw forbidden(decision.reason);
  }
  const row = db.preparedOne<DocRow>('SELECT * FROM documents WHERE id = ? AND deleted_at IS NULL', [id]);
  if (!row) throw notFound('Document not found.');
  audit({ action: 'document.read', category: 'data', outcome: 'success', req, targetType: 'document', targetId: id,
    detail: { rule: decision.rule } });
  res.json({ document: presentDocument(row, true), authorization: decision });
}));

appRouter.patch('/documents/:id', asyncRoute(async (req, res) => {
  const auth = authOf(req);
  const id = Number(req.params.id);
  const decision = authorizeDocumentAccess(id, auth.userId, auth.roles, 'write');
  if (!decision.allowed) throw forbidden(decision.reason);
  const input = documentUpdateSchema.parse(req.body);
  const row = db.preparedOne<DocRow>('SELECT * FROM documents WHERE id = ?', [id]);
  if (!row) throw notFound('Document not found.');
  const classification = input.classification ?? row.classification;
  const newBody = input.body ?? (row.body_encrypted ? tryDecrypt(row.body_encrypted) ?? '' : row.body);
  const encryptBody = CONFIDENTIAL.has(classification);
  db.run(`UPDATE documents SET title = ?, body = ?, body_encrypted = ?, classification = ?, updated_at = datetime('now') WHERE id = ?`,
    [input.title ?? row.title, encryptBody ? '' : newBody, encryptBody ? encrypt(newBody) : null, classification, id]);
  audit({ action: 'document.update', category: 'data', outcome: 'success', req, targetType: 'document', targetId: id });
  res.json({ document: presentDocument(db.preparedOne<DocRow>('SELECT * FROM documents WHERE id = ?', [id])!, true) });
}));

appRouter.delete('/documents/:id', asyncRoute(async (req, res) => {
  const auth = authOf(req);
  const id = Number(req.params.id);
  const decision = authorizeDocumentAccess(id, auth.userId, auth.roles, 'owner');
  if (!decision.allowed) throw forbidden(decision.reason);
  // Soft delete, so the audit trail and any references survive.
  db.run("UPDATE documents SET deleted_at = datetime('now') WHERE id = ?", [id]);
  audit({ action: 'document.delete', category: 'data', outcome: 'success', severity: 'medium', req, targetType: 'document', targetId: id });
  res.json({ ok: true });
}));

appRouter.post('/documents/:id/share', asyncRoute(async (req, res) => {
  const auth = authOf(req);
  const id = Number(req.params.id);
  const decision = authorizeDocumentAccess(id, auth.userId, auth.roles, 'owner');
  if (!decision.allowed) throw forbidden('Only the owner can share a document.');
  const input = shareSchema.parse(req.body);
  const grantee = db.preparedOne<{ id: number }>('SELECT id FROM users WHERE username = ?', [input.username]);
  if (!grantee) throw notFound('No such user.');
  db.run('INSERT OR REPLACE INTO document_permissions (document_id, user_id, capability, granted_by) VALUES (?, ?, ?, ?)',
    [id, grantee.id, input.capability, auth.userId]);
  audit({ action: 'document.share', category: 'data', outcome: 'success', severity: 'medium', req, targetType: 'document', targetId: id,
    detail: { grantee: input.username, capability: input.capability } });
  res.json({ ok: true });
}));

appRouter.get('/documents/:id/permissions', asyncRoute(async (req, res) => {
  const auth = authOf(req);
  const id = Number(req.params.id);
  const decision = authorizeDocumentAccess(id, auth.userId, auth.roles, 'read');
  if (!decision.allowed) throw forbidden(decision.reason);
  const rows = db.prepared<{ username: string; full_name: string; capability: string; granted_at: string }>(
    `SELECT u.username, u.full_name, p.capability, p.granted_at
       FROM document_permissions p JOIN users u ON u.id = p.user_id
      WHERE p.document_id = ? ORDER BY p.capability DESC`, [id]);
  res.json({ permissions: rows });
}));

// ── Messages ──────────────────────────────────────────────────────────────

appRouter.get('/messages', asyncRoute(async (req, res) => {
  const auth = authOf(req);
  const rows = db.prepared<{ id: number; sender: string; recipient: string; subject: string; body: string; created_at: string; read_at: string | null }>(
    `SELECT m.id, s.username AS sender, r.username AS recipient, m.subject, m.body, m.created_at, m.read_at
       FROM messages m JOIN users s ON s.id = m.sender_id LEFT JOIN users r ON r.id = m.recipient_id
      WHERE m.recipient_id = ? OR m.sender_id = ? ORDER BY m.id DESC LIMIT 100`, [auth.userId, auth.userId]);
  // Output-encode the body for safe display; the stored-XSS LAB shows the unsafe path.
  res.json({ messages: rows.map((m) => ({ ...m, body: encodeHtml(m.body), bodyRaw: m.body })) });
}));

appRouter.post('/messages', asyncRoute(async (req, res) => {
  const auth = authOf(req);
  const input = messageSchema.parse(req.body);
  const recipient = db.preparedOne<{ id: number }>('SELECT id FROM users WHERE username = ?', [input.recipientUsername]);
  if (!recipient) throw notFound('No such recipient.');
  const result = db.run('INSERT INTO messages (sender_id, recipient_id, subject, body) VALUES (?, ?, ?, ?)',
    [auth.userId, recipient.id, input.subject, input.body]);
  audit({ action: 'message.send', category: 'data', outcome: 'success', req, targetType: 'message', targetId: Number(result.lastInsertRowid) });
  res.status(201).json({ ok: true, id: Number(result.lastInsertRowid) });
}));

// ── Profile ─────────────────────────────────────────────────────────────────

appRouter.patch('/profile', asyncRoute(async (req, res) => {
  const auth = authOf(req);
  const input = profileUpdateSchema.parse(req.body);
  const sets: string[] = []; const params: unknown[] = [];
  if (input.fullName !== undefined) { sets.push('full_name = ?'); params.push(input.fullName); }
  if (input.bio !== undefined) { sets.push('bio = ?'); params.push(input.bio); }
  if (input.avatarColour !== undefined) { sets.push('avatar_colour = ?'); params.push(input.avatarColour); }
  if (input.phone !== undefined) { sets.push('phone_encrypted = ?'); params.push(encrypt(input.phone)); }
  if (sets.length === 0) throw badRequest('No profile fields to update.');
  sets.push("updated_at = datetime('now')");
  db.run(`UPDATE users SET ${sets.join(', ')} WHERE id = ?`, [...params, auth.userId]);
  audit({ action: 'profile.update', category: 'data', outcome: 'success', req, detail: { fields: Object.keys(input) } });
  res.json({ ok: true });
}));

// ── Activity (own audit trail) ──────────────────────────────────────────────

appRouter.get('/activity', asyncRoute(async (req, res) => {
  const auth = authOf(req);
  const rows = db.prepared<{ occurred_at: string; action: string; outcome: string; request_path: string | null }>(
    'SELECT occurred_at, action, outcome, request_path FROM audit_logs WHERE actor_user_id = ? ORDER BY id DESC LIMIT 50', [auth.userId]);
  res.json({ activity: rows });
}));
