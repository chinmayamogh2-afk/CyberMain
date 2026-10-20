/**
 * Authentication and authorisation middleware.
 *
 * `attachAuth` resolves the session cookie into a trusted identity on every
 * request. The resulting `req.auth` is derived entirely from server-side state:
 * the cookie contributes only an opaque lookup key, and roles come from the
 * database. No field of `req.auth` is ever read from a client-supplied header or
 * body, which is what prevents privilege escalation by parameter manipulation.
 */
import type { Request, RequestHandler } from 'express';
import {
  SESSION_COOKIE,
  touchSession,
  validateSession,
  clearSessionCookie,
  type SessionRecord,
} from '../security/session.js';
import { loadUserRoles, hasRole, hasCapability, type RoleName } from '../security/rbac.js';
import { db } from '../db/index.js';
import { forbidden, unauthenticated } from '../core/errors.js';
import { audit } from '../security/audit.js';
import { isSecure } from '../security/modes.js';

export interface AuthContext {
  userId: number;
  username: string;
  email: string;
  fullName: string;
  roles: RoleName[];
  sessionId: string;
  session: SessionRecord;
}

declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace
  namespace Express {
    interface Request {
      auth?: AuthContext;
      /** Why authentication did not resolve, for the session lab to display. */
      authFailure?: 'absent' | 'unknown' | 'revoked' | 'expired' | 'inactive_user';
    }
  }
}

export const attachAuth: RequestHandler = (req, res, next) => {
  const cookies = req.cookies as Record<string, string> | undefined;
  const sessionId = cookies?.[SESSION_COOKIE];
  const validity = validateSession(sessionId);

  if (!validity.valid) {
    req.authFailure = validity.reason;
    // A stale cookie is cleared so the browser stops sending it. Doing this on
    // 'expired' and 'revoked' — rather than leaving it — is what makes logout
    // and timeout observable in DevTools during the session lab.
    if (validity.reason === 'expired' || validity.reason === 'revoked') {
      clearSessionCookie(res);
    }
    return next();
  }

  const user = db.preparedOne<{
    id: number;
    username: string;
    email: string;
    full_name: string;
    is_active: number;
  }>('SELECT id, username, email, full_name, is_active FROM users WHERE id = ?', [
    validity.session.userId,
  ]);

  if (!user || user.is_active !== 1) {
    req.authFailure = 'inactive_user';
    return next();
  }

  req.auth = {
    userId: user.id,
    username: user.username,
    email: user.email,
    fullName: user.full_name,
    roles: loadUserRoles(user.id),
    sessionId: validity.session.id,
    session: validity.session,
  };

  // Sliding activity timestamp. Deliberately does not extend `expires_at`:
  // an absolute session lifetime caps the damage from a stolen cookie.
  touchSession(validity.session.id);
  return next();
};

/** Requires an authenticated session. */
export const requireAuth: RequestHandler = (req, _res, next) => {
  if (!req.auth) {
    const detail =
      req.authFailure === 'expired'
        ? 'Your session has expired. Please sign in again.'
        : req.authFailure === 'revoked'
          ? 'This session was signed out. Please sign in again.'
          : 'Authentication required.';
    return next(unauthenticated(detail));
  }
  return next();
};

/**
 * Requires a minimum role.
 *
 * The `api_authz` toggle governs this guard. In vulnerable mode the check is
 * skipped and the request proceeds — a genuine broken-access-control
 * demonstration, recorded in the audit log so the bypass is evidenced rather
 * than silent.
 */
export function requireRole(required: RoleName): RequestHandler {
  return (req, _res, next) => {
    if (!req.auth) return next(unauthenticated());

    if (hasRole(req.auth.roles, required)) return next();

    if (!isSecure('api_authz')) {
      audit({
        action: 'security.authz.bypassed',
        category: 'security',
        outcome: 'detected',
        severity: 'critical',
        req,
        detail: {
          requiredRole: required,
          actualRoles: req.auth.roles,
          note: 'api_authz is in vulnerable mode: the role check was skipped and access allowed.',
        },
      });
      return next();
    }

    audit({
      action: 'security.authz.denied',
      category: 'access',
      outcome: 'blocked',
      severity: 'medium',
      req,
      detail: { requiredRole: required, actualRoles: req.auth.roles },
    });
    return next(
      forbidden(`This action requires the ${required} role.`),
    );
  };
}

export function requireCapability(capability: string): RequestHandler {
  return (req, _res, next) => {
    if (!req.auth) return next(unauthenticated());
    if (hasCapability(req.auth.roles, capability)) return next();

    audit({
      action: 'security.authz.denied',
      category: 'access',
      outcome: 'blocked',
      severity: 'medium',
      req,
      detail: { requiredCapability: capability, actualRoles: req.auth.roles },
    });
    return next(forbidden('You do not have permission to perform this action.'));
  };
}

/** Narrowing helper for handlers that run behind `requireAuth`. */
export function authOf(req: Request): AuthContext {
  if (!req.auth) throw unauthenticated();
  return req.auth;
}
