/**
 * Session management (§10).
 *
 * Server-side sessions: the cookie carries an opaque random identifier and
 * nothing else. All state lives in the `sessions` table, so logout can truly
 * invalidate a session — which a self-contained JWT cannot do without extra
 * machinery.
 *
 * The `session` mode toggle changes real, observable properties of the cookie
 * and of the identifier itself, which is what the Session lab inspects.
 */
import type { Request, Response } from 'express';
import { config } from '../config/env.js';
import { db } from '../db/index.js';
import { randomToken, predictableToken } from './crypto.js';
import { getMode, isSecure } from './modes.js';

export const SESSION_COOKIE = 'sx_session';

export interface SessionRecord {
  id: string;
  userId: number;
  createdAt: string;
  lastSeenAt: string;
  expiresAt: string;
  ipAddress: string | null;
  userAgent: string | null;
  revokedAt: string | null;
  issuedMode: string;
}

/** Monotonic counter backing the deliberately predictable lab identifier. */
let weakCounter = 1000;

export interface CookieAttributes {
  httpOnly: boolean;
  secure: boolean;
  sameSite: 'strict' | 'lax' | 'none';
  maxAgeMs: number | null;
  path: string;
}

/**
 * The cookie attributes for the current mode.
 *
 * Secure mode:
 *   httpOnly  — script cannot read the cookie, so an XSS cannot steal the session
 *   sameSite  — the browser withholds it on cross-site requests, blunting CSRF
 *   secure    — only sent over TLS (enabled in production; see note below)
 *   maxAge    — the session expires rather than living forever
 *
 * Vulnerable mode drops all four, which is directly observable in DevTools and
 * is what makes the session lab a real demonstration.
 */
export function cookieAttributesForMode(): CookieAttributes {
  if (isSecure('session')) {
    return {
      httpOnly: true,
      // Loopback HTTP would drop a Secure cookie, so this follows NODE_ENV.
      // The Headers Inspector states this caveat rather than claiming TLS.
      secure: config.isProd,
      sameSite: 'strict',
      maxAgeMs: config.session.ttlMinutes * 60 * 1000,
      path: '/',
    };
  }
  return {
    httpOnly: false,
    secure: false,
    sameSite: 'none',
    maxAgeMs: null, // a non-expiring session cookie
    path: '/',
  };
}

export function createSession(
  userId: number,
  req: Request,
  res: Response,
): { record: SessionRecord; attributes: CookieAttributes } {
  const mode = getMode('session');

  // Vulnerable mode issues a sequential, guessable identifier: an attacker who
  // sees SESS-001042 can simply try SESS-001041 and ride someone else's session.
  const id = mode === 'secure' ? randomToken(32) : predictableToken(++weakCounter);

  const ttlMs = config.session.ttlMinutes * 60 * 1000;
  const expiresAt = new Date(Date.now() + (mode === 'secure' ? ttlMs : 365 * 24 * 3600 * 1000));

  db.run(
    `INSERT INTO sessions (id, user_id, expires_at, ip_address, user_agent, issued_mode)
     VALUES (?, ?, ?, ?, ?, ?)`,
    [
      id,
      userId,
      expiresAt.toISOString(),
      req.ip ?? null,
      req.get('user-agent') ?? null,
      mode,
    ],
  );

  const attributes = cookieAttributesForMode();
  res.cookie(SESSION_COOKIE, id, {
    httpOnly: attributes.httpOnly,
    secure: attributes.secure,
    sameSite: attributes.sameSite,
    path: attributes.path,
    ...(attributes.maxAgeMs !== null ? { maxAge: attributes.maxAgeMs } : {}),
  });

  const record = loadSession(id)!;
  return { record, attributes };
}

function rowToRecord(row: {
  id: string;
  user_id: number;
  created_at: string;
  last_seen_at: string;
  expires_at: string;
  ip_address: string | null;
  user_agent: string | null;
  revoked_at: string | null;
  issued_mode: string;
}): SessionRecord {
  return {
    id: row.id,
    userId: row.user_id,
    createdAt: row.created_at,
    lastSeenAt: row.last_seen_at,
    expiresAt: row.expires_at,
    ipAddress: row.ip_address,
    userAgent: row.user_agent,
    revokedAt: row.revoked_at,
    issuedMode: row.issued_mode,
  };
}

export function loadSession(id: string): SessionRecord | null {
  const row = db.preparedOne<Parameters<typeof rowToRecord>[0]>(
    'SELECT * FROM sessions WHERE id = ?',
    [id],
  );
  return row ? rowToRecord(row) : null;
}

export type SessionValidity =
  | { valid: true; session: SessionRecord }
  | { valid: false; reason: 'absent' | 'unknown' | 'revoked' | 'expired' };

/**
 * Validates a session identifier.
 *
 * Expiry is enforced here on the server. A client-side-only expiry would be
 * meaningless: the attacker controls the client.
 */
export function validateSession(id: string | undefined): SessionValidity {
  if (!id) return { valid: false, reason: 'absent' };
  const session = loadSession(id);
  if (!session) return { valid: false, reason: 'unknown' };
  if (session.revokedAt) return { valid: false, reason: 'revoked' };
  if (new Date(session.expiresAt).getTime() <= Date.now()) {
    return { valid: false, reason: 'expired' };
  }
  return { valid: true, session };
}

export function touchSession(id: string): void {
  db.run("UPDATE sessions SET last_seen_at = datetime('now') WHERE id = ?", [id]);
}

/**
 * Invalidates a session server-side.
 *
 * We mark it revoked rather than deleting the row, so the audit trail retains
 * evidence that the session existed and when it ended.
 */
export function revokeSession(id: string, reason: string): void {
  db.run(
    "UPDATE sessions SET revoked_at = datetime('now'), revoked_reason = ? WHERE id = ? AND revoked_at IS NULL",
    [reason, id],
  );
}

/** Revokes every session for a user — used after a password change. */
export function revokeAllUserSessions(userId: number, reason: string, exceptId?: string): number {
  const result = db.run(
    `UPDATE sessions
        SET revoked_at = datetime('now'), revoked_reason = ?
      WHERE user_id = ? AND revoked_at IS NULL AND id != ?`,
    [reason, userId, exceptId ?? ''],
  );
  return result.changes;
}

export function clearSessionCookie(res: Response): void {
  res.clearCookie(SESSION_COOKIE, { path: '/' });
}

export function listUserSessions(userId: number): SessionRecord[] {
  const rows = db.prepared<Parameters<typeof rowToRecord>[0]>(
    'SELECT * FROM sessions WHERE user_id = ? ORDER BY created_at DESC LIMIT 50',
    [userId],
  );
  return rows.map(rowToRecord);
}

export function listAllSessions(limit = 100): SessionRecord[] {
  const rows = db.prepared<Parameters<typeof rowToRecord>[0]>(
    'SELECT * FROM sessions ORDER BY created_at DESC LIMIT ?',
    [limit],
  );
  return rows.map(rowToRecord);
}

/** Removes expired rows. Called on boot so the table does not grow forever. */
export function pruneExpiredSessions(): number {
  const result = db.run("DELETE FROM sessions WHERE expires_at < datetime('now', '-7 days')");
  return result.changes;
}
