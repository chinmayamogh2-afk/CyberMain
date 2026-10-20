/**
 * Authentication routes (§10).
 *
 * This is the real authentication path used by the SecureVault application: it
 * is always secure. The deliberately weak variants live in routes/lab/auth.ts so
 * that a professor can see them side by side without the application's own login
 * ever being the vulnerable one.
 */
import { Router } from 'express';
import { db } from '../db/index.js';
import {
  hashPassword,
  verifyPassword,
  encrypt,
  tryDecrypt,
  passwordHashAlgorithm,
} from '../security/crypto.js';
import {
  createSession,
  revokeSession,
  revokeAllUserSessions,
  clearSessionCookie,
  listUserSessions,
  cookieAttributesForMode,
} from '../security/session.js';
import { issueCsrfToken } from '../security/csrf.js';
import { loadUserRoles, capabilitiesFor, highestRole, ROLES } from '../security/rbac.js';
import { audit } from '../security/audit.js';
import { emitSecurityEvent } from '../security/events.js';
import { rateLimit, LIMITS, consume } from '../security/ratelimit.js';
import { requireAuth, authOf } from '../middleware/auth.js';
import { asyncRoute } from '../middleware/errorHandler.js';
import { AppError, conflict, unauthenticated, badRequest } from '../core/errors.js';
import {
  registerSchema,
  loginSchema,
  changePasswordSchema,
  assessPassword,
} from '../security/validation.js';

export const authRouter = Router();

/** Lockout policy (§10). */
const MAX_FAILED_ATTEMPTS = 5;
const LOCKOUT_MINUTES = 15;

interface UserRow {
  id: number;
  username: string;
  email: string;
  password_hash: string;
  full_name: string;
  bio: string;
  avatar_colour: string;
  phone_encrypted: string | null;
  is_active: number;
  failed_login_count: number;
  locked_until: string | null;
  password_changed_at: string;
  last_login_at: string | null;
  created_at: string;
}

/**
 * The public shape of a user.
 *
 * Built by explicit allow-list, never by deleting fields from the database row.
 * A deny-list would leak any column added later — which is exactly the mistake
 * the sensitive-data-exposure lab demonstrates.
 */
function publicUser(row: UserRow) {
  const roles = loadUserRoles(row.id);
  return {
    id: row.id,
    username: row.username,
    email: row.email,
    fullName: row.full_name,
    bio: row.bio,
    avatarColour: row.avatar_colour,
    phone: tryDecrypt(row.phone_encrypted),
    roles,
    primaryRole: highestRole(roles),
    roleLabel: ROLES[highestRole(roles)].label,
    capabilities: capabilitiesFor(roles),
    passwordChangedAt: row.password_changed_at,
    lastLoginAt: row.last_login_at,
    createdAt: row.created_at,
  };
}

function findUserByUsername(username: string): UserRow | undefined {
  // Parameterised. The username is attacker-controlled on every login attempt,
  // so this query is the single most important one in the application to bind.
  return db.preparedOne<UserRow>('SELECT * FROM users WHERE username = ?', [username]);
}

function recordAttempt(
  username: string,
  userId: number | null,
  succeeded: boolean,
  req: { ip?: string; get(h: string): string | undefined },
  failureKind?: string,
): void {
  db.run(
    `INSERT INTO login_attempts (username, user_id, succeeded, ip_address, user_agent, failure_kind)
     VALUES (?, ?, ?, ?, ?, ?)`,
    [username, userId, succeeded ? 1 : 0, req.ip ?? null, req.get('user-agent') ?? null, failureKind ?? null],
  );
}

function lockoutState(row: UserRow): { locked: boolean; until: Date | null; minutesLeft: number } {
  if (!row.locked_until) return { locked: false, until: null, minutesLeft: 0 };
  const until = new Date(row.locked_until);
  const locked = until.getTime() > Date.now();
  return {
    locked,
    until,
    minutesLeft: locked ? Math.ceil((until.getTime() - Date.now()) / 60_000) : 0,
  };
}

// ── POST /api/auth/register ─────────────────────────────────────────────────

authRouter.post(
  '/register',
  rateLimit({ windowMs: 60_000, max: 5, bucket: 'register' }),
  asyncRoute(async (req, res) => {
    const input = registerSchema.parse(req.body);

    const existing = db.preparedOne<{ id: number }>(
      'SELECT id FROM users WHERE username = ? OR email = ?',
      [input.username, input.email],
    );
    if (existing) {
      audit({
        action: 'auth.register.rejected',
        category: 'auth',
        outcome: 'failure',
        severity: 'low',
        req,
        detail: { reason: 'username or email already registered' },
      });
      // Deliberately does not say WHICH one is taken. Saying so would let an
      // attacker enumerate registered email addresses.
      throw conflict('That username or email address is not available.');
    }

    const result = db.run(
      `INSERT INTO users (username, email, password_hash, full_name)
       VALUES (?, ?, ?, ?)`,
      [input.username, input.email, hashPassword(input.password), input.fullName],
    );
    const userId = Number(result.lastInsertRowid);

    const userRole = db.preparedOne<{ id: number }>('SELECT id FROM roles WHERE name = ?', ['user']);
    if (userRole) {
      // Least privilege: a new account gets the lowest role, never an inherited
      // or requested one.
      db.run('INSERT INTO user_roles (user_id, role_id) VALUES (?, ?)', [userId, userRole.id]);
    }

    audit({
      action: 'auth.register',
      category: 'auth',
      outcome: 'success',
      actorUserId: userId,
      actorLabel: input.username,
      req,
      targetType: 'user',
      targetId: userId,
      detail: { username: input.username },
    });

    const row = db.preparedOne<UserRow>('SELECT * FROM users WHERE id = ?', [userId])!;
    res.status(201).json({ user: publicUser(row) });
  }),
);

// ── POST /api/auth/login ────────────────────────────────────────────────────

authRouter.post(
  '/login',
  rateLimit(LIMITS.login),
  asyncRoute(async (req, res) => {
    const input = loginSchema.parse(req.body);
    const row = findUserByUsername(input.username);

    /**
     * A single generic failure message for every reason.
     *
     * "No such user" versus "wrong password" is a username-enumeration oracle:
     * an attacker learns which accounts exist and then focuses password guessing
     * on them. The lab shows the distinguishable version for contrast.
     */
    const genericFailure = () =>
      new AppError('unauthenticated', 'Invalid username or password.');

    if (!row) {
      recordAttempt(input.username, null, false, req, 'no_user');
      audit({
        action: 'auth.login.failed',
        category: 'auth',
        outcome: 'failure',
        severity: 'low',
        actorLabel: input.username,
        req,
        detail: { reason: 'no such user', note: 'Response is identical to a wrong password.' },
      });
      // Spend comparable time to the hash-verification path. Returning
      // immediately here would make "user does not exist" measurably faster and
      // reintroduce enumeration through a timing side channel.
      verifyPassword(input.password, hashPassword('timing-equalisation-placeholder'));
      throw genericFailure();
    }

    const lock = lockoutState(row);
    if (lock.locked) {
      recordAttempt(input.username, row.id, false, req, 'locked');
      audit({
        action: 'auth.login.blocked',
        category: 'auth',
        outcome: 'blocked',
        severity: 'medium',
        actorUserId: row.id,
        actorLabel: row.username,
        req,
        detail: { reason: 'account locked', minutesRemaining: lock.minutesLeft },
      });
      throw new AppError(
        'rate_limited',
        `This account is temporarily locked after repeated failed sign-ins. Try again in ${lock.minutesLeft} minute(s).`,
      );
    }

    if (row.is_active !== 1) {
      recordAttempt(input.username, row.id, false, req, 'inactive');
      throw genericFailure();
    }

    if (!verifyPassword(input.password, row.password_hash)) {
      const failures = row.failed_login_count + 1;
      const shouldLock = failures >= MAX_FAILED_ATTEMPTS;

      db.run(
        `UPDATE users SET failed_login_count = ?, locked_until = ? WHERE id = ?`,
        [
          failures,
          shouldLock
            ? new Date(Date.now() + LOCKOUT_MINUTES * 60_000).toISOString()
            : row.locked_until,
          row.id,
        ],
      );

      recordAttempt(input.username, row.id, false, req, 'bad_password');
      audit({
        action: 'auth.login.failed',
        category: 'auth',
        outcome: 'failure',
        severity: shouldLock ? 'high' : 'low',
        actorUserId: row.id,
        actorLabel: row.username,
        req,
        detail: {
          reason: 'incorrect password',
          consecutiveFailures: failures,
          lockApplied: shouldLock,
        },
      });

      if (shouldLock) {
        emitSecurityEvent('alert', 'auth', `Account '${row.username}' locked after ${failures} failed sign-ins`, {
          username: row.username,
          lockoutMinutes: LOCKOUT_MINUTES,
        });
      }
      throw genericFailure();
    }

    // Success. Reset the failure counter and clear any stale lock.
    db.run(
      `UPDATE users
          SET failed_login_count = 0, locked_until = NULL, last_login_at = datetime('now')
        WHERE id = ?`,
      [row.id],
    );

    const { record, attributes } = createSession(row.id, req, res);
    const csrfToken = issueCsrfToken(res, record.id);

    audit({
      action: 'auth.login',
      category: 'auth',
      outcome: 'success',
      actorUserId: row.id,
      actorLabel: row.username,
      req,
      detail: { sessionIssuedMode: record.issuedMode },
    });
    emitSecurityEvent('info', 'auth', `Authentication succeeded for '${row.username}'`, {
      username: row.username,
      role: highestRole(loadUserRoles(row.id)),
    });

    const fresh = db.preparedOne<UserRow>('SELECT * FROM users WHERE id = ?', [row.id])!;
    res.json({
      user: publicUser(fresh),
      csrfToken,
      session: {
        id: record.id,
        expiresAt: record.expiresAt,
        issuedMode: record.issuedMode,
        cookieAttributes: attributes,
      },
      passwordHashAlgorithm: passwordHashAlgorithm(row.password_hash),
    });
  }),
);

// ── POST /api/auth/logout ───────────────────────────────────────────────────

authRouter.post(
  '/logout',
  asyncRoute(async (req, res) => {
    if (req.auth) {
      // Server-side invalidation. Clearing the cookie alone would leave the
      // session usable by anyone who had already captured the identifier.
      revokeSession(req.auth.sessionId, 'user logout');
      audit({
        action: 'auth.logout',
        category: 'auth',
        outcome: 'success',
        req,
        detail: { sessionId: req.auth.sessionId },
      });
    }
    clearSessionCookie(res);
    res.json({ ok: true });
  }),
);

// ── GET /api/auth/me ────────────────────────────────────────────────────────

authRouter.get(
  '/me',
  asyncRoute(async (req, res) => {
    if (!req.auth) {
      res.status(200).json({ user: null, reason: req.authFailure ?? 'absent' });
      return;
    }
    const row = db.preparedOne<UserRow>('SELECT * FROM users WHERE id = ?', [req.auth.userId]);
    if (!row) throw unauthenticated();

    const csrfToken = issueCsrfToken(res, req.auth.sessionId);
    res.json({
      user: publicUser(row),
      csrfToken,
      session: {
        id: req.auth.sessionId,
        expiresAt: req.auth.session.expiresAt,
        issuedMode: req.auth.session.issuedMode,
        cookieAttributes: cookieAttributesForMode(),
      },
    });
  }),
);

// ── POST /api/auth/password ─────────────────────────────────────────────────

authRouter.post(
  '/password',
  requireAuth,
  asyncRoute(async (req, res) => {
    const auth = authOf(req);
    const input = changePasswordSchema.parse(req.body);

    const row = db.preparedOne<UserRow>('SELECT * FROM users WHERE id = ?', [auth.userId]);
    if (!row) throw unauthenticated();

    // Re-authentication before a sensitive change. Without it, an XSS or a
    // CSRF that reaches this endpoint could take over the account outright.
    if (!verifyPassword(input.currentPassword, row.password_hash)) {
      consume(req, { windowMs: 60_000, max: 5, bucket: 'password-change' });
      audit({
        action: 'auth.password.change.failed',
        category: 'auth',
        outcome: 'failure',
        severity: 'medium',
        req,
        detail: { reason: 'current password did not verify' },
      });
      throw badRequest('Your current password is not correct.');
    }

    if (input.newPassword === input.currentPassword) {
      throw badRequest('The new password must be different from the current one.');
    }

    db.run(
      `UPDATE users
          SET password_hash = ?, password_changed_at = datetime('now'), updated_at = datetime('now')
        WHERE id = ?`,
      [hashPassword(input.newPassword), auth.userId],
    );

    // Every other session is invalidated: if the password change was prompted by
    // a suspected compromise, leaving the attacker's session alive defeats it.
    const revoked = revokeAllUserSessions(auth.userId, 'password changed', auth.sessionId);

    audit({
      action: 'auth.password.change',
      category: 'auth',
      outcome: 'success',
      severity: 'medium',
      req,
      detail: { otherSessionsRevoked: revoked },
    });
    emitSecurityEvent('notice', 'auth', `Password changed for '${auth.username}'`, {
      otherSessionsRevoked: revoked,
    });

    res.json({ ok: true, otherSessionsRevoked: revoked });
  }),
);

// ── POST /api/auth/password/assess ──────────────────────────────────────────

authRouter.post(
  '/password/assess',
  asyncRoute(async (req, res) => {
    const body = req.body as { password?: unknown };
    const password = typeof body.password === 'string' ? body.password : '';
    // Note: never logged, never stored, never audited.
    res.json({ assessment: assessPassword(password) });
  }),
);

// ── Session management ──────────────────────────────────────────────────────

authRouter.get(
  '/sessions',
  requireAuth,
  asyncRoute(async (req, res) => {
    const auth = authOf(req);
    const sessions = listUserSessions(auth.userId).map((s) => ({
      id: `${s.id.slice(0, 8)}…`,
      fullId: s.id === auth.sessionId ? s.id : undefined,
      current: s.id === auth.sessionId,
      createdAt: s.createdAt,
      lastSeenAt: s.lastSeenAt,
      expiresAt: s.expiresAt,
      ipAddress: s.ipAddress,
      userAgent: s.userAgent,
      revokedAt: s.revokedAt,
      issuedMode: s.issuedMode,
      active: !s.revokedAt && new Date(s.expiresAt).getTime() > Date.now(),
    }));
    res.json({ sessions, cookieAttributes: cookieAttributesForMode() });
  }),
);

authRouter.delete(
  '/sessions/:id',
  requireAuth,
  asyncRoute(async (req, res) => {
    const auth = authOf(req);
    const targetId = req.params.id!;

    // Object-level authorisation: a user may only revoke their OWN sessions.
    // Without this check the endpoint would be an IDOR allowing anyone to log
    // anyone else out.
    const owned = listUserSessions(auth.userId).some((s) => s.id === targetId);
    if (!owned) {
      audit({
        action: 'session.revoke.denied',
        category: 'access',
        outcome: 'blocked',
        severity: 'medium',
        req,
        detail: { attemptedSessionId: targetId.slice(0, 12) },
      });
      throw new AppError('forbidden', 'That session does not belong to your account.');
    }

    revokeSession(targetId, 'revoked by user');
    audit({
      action: 'session.revoke',
      category: 'auth',
      outcome: 'success',
      req,
      targetType: 'session',
      targetId: targetId.slice(0, 12),
    });
    res.json({ ok: true });
  }),
);
