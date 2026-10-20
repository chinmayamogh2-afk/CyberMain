/**
 * CSRF protection (§8).
 *
 * Strategy: a signed double-submit token. The server issues a random value in a
 * readable cookie plus an HMAC of that value bound to the session; the client
 * echoes the pair back in a header. An attacker's page can cause the browser to
 * send cookies, but — thanks to the same-origin policy — cannot *read* the
 * cookie to populate the header, and cannot forge the HMAC without the secret.
 *
 * We additionally verify the Origin header. Together these are belt and braces:
 * defence in depth, since either alone has known edge cases.
 */
import type { RequestHandler, Request, Response } from 'express';
import { config } from '../config/env.js';
import { hmac, randomToken, safeEqual } from './crypto.js';
import { isSecure } from './modes.js';
import { AppError } from '../core/errors.js';
import { audit } from './audit.js';

export const CSRF_COOKIE = 'sx_csrf';
export const CSRF_HEADER = 'x-csrf-token';

/** Methods that cannot change state and therefore need no token. */
const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

/**
 * Endpoints exempt from CSRF enforcement.
 *
 * CSRF is an attack against an *existing* authenticated session: it abuses the
 * browser's willingness to attach cookies the victim already holds. These
 * endpoints run before any such session exists, so there is nothing to forge
 * against — and requiring a token on them would make it impossible to sign in
 * at all (no session, therefore no token to bind).
 *
 * The residual risk is login-CSRF, where an attacker forces a victim to log in
 * as the attacker. It is low impact here and is recorded as a known limitation
 * in docs/THREAT_MODEL.md rather than quietly ignored.
 *
 * Keeping these exempt is also what lets curl, Burp Suite and ZAP drive the
 * login flow directly, which §14 requires.
 */
const CSRF_EXEMPT_PATHS = new Set([
  '/api/auth/login',
  '/api/auth/register',
  '/api/auth/logout',
  '/api/auth/password/assess',
]);

/**
 * Produces a CSRF token value bound to a session, without touching a response.
 * Format: <random>.<hmac(random + sessionId)>. Exposed separately so labs and
 * tests can mint a legitimate token to compare against a forged request.
 */
export function issueCsrfTokenValue(sessionId: string): string {
  const nonce = randomToken(24);
  const signature = hmac(`${nonce}:${sessionId}`, config.secrets.csrf);
  return `${nonce}.${signature}`;
}

/** Token format: <random>.<hmac(random + sessionId)> */
export function issueCsrfToken(res: Response, sessionId: string): string {
  const token = issueCsrfTokenValue(sessionId);
  res.cookie(CSRF_COOKIE, token, {
    // Readable by JavaScript on purpose: the SPA must echo it into a header.
    // This is safe because the value is useless without also being same-origin.
    httpOnly: false,
    sameSite: 'strict',
    secure: config.isProd,
    path: '/',
    maxAge: config.session.ttlMinutes * 60 * 1000,
  });
  return token;
}

export function verifyCsrfToken(token: string | undefined, sessionId: string): boolean {
  if (!token) return false;
  const [nonce, signature] = token.split('.');
  if (!nonce || !signature) return false;
  const expected = hmac(`${nonce}:${sessionId}`, config.secrets.csrf);
  return safeEqual(signature, expected);
}

function originAllowed(req: Request): boolean {
  const origin = req.get('origin');
  // Non-browser clients (curl, Burp, the scanner) send no Origin. We cannot
  // reject those outright or the platform could not test itself, so the token
  // check remains the authoritative control and this is a supplementary signal.
  if (!origin) return true;
  return origin === config.frontendOrigin || origin === config.selfBaseUrl;
}

/**
 * Enforces CSRF protection on state-changing requests.
 *
 * In vulnerable mode this middleware steps aside entirely, so a cross-site
 * forged POST genuinely succeeds — which is what the CSRF lab demonstrates.
 */
export const csrfProtection: RequestHandler = (req, res, next) => {
  if (SAFE_METHODS.has(req.method)) return next();

  if (CSRF_EXEMPT_PATHS.has(req.path)) return next();

  // Lab routes manage their own CSRF posture so each lab can be toggled
  // independently of the application-wide control.
  if (req.path.startsWith('/api/lab/')) return next();

  if (!isSecure('csrf')) return next();

  const session = (req as Request & { auth?: { sessionId?: string } }).auth;
  const sessionId = session?.sessionId ?? 'anonymous';
  const headerToken = req.get(CSRF_HEADER) ?? undefined;
  const cookieToken = (req.cookies as Record<string, string> | undefined)?.[CSRF_COOKIE];

  const tokenValid = verifyCsrfToken(headerToken, sessionId);
  const doubleSubmitMatches =
    !!headerToken && !!cookieToken && safeEqual(headerToken, cookieToken);

  if (!tokenValid || !doubleSubmitMatches || !originAllowed(req)) {
    audit({
      action: 'security.csrf.rejected',
      category: 'security',
      outcome: 'blocked',
      severity: 'medium',
      req,
      detail: {
        reason: !headerToken
          ? 'no CSRF token header present'
          : !tokenValid
            ? 'token signature did not verify'
            : !doubleSubmitMatches
              ? 'header token did not match cookie token'
              : 'request Origin not allow-listed',
        origin: req.get('origin') ?? null,
      },
    });
    return next(
      new AppError('csrf_failed', 'This request could not be verified. Please reload and try again.'),
    );
  }
  return next();
};
