/**
 * Rate limiting and account throttling (§10, §29).
 *
 * A fixed-window counter keyed by client address plus route. In-memory, which is
 * correct for a single-process demo platform; a multi-instance deployment would
 * need shared state, and TESTING.md records that as a known limitation rather
 * than pretending otherwise.
 */
import type { RequestHandler, Request } from 'express';
import { AppError } from '../core/errors.js';
import { isSecure, type VulnClass } from './modes.js';
import { audit } from './audit.js';

interface Window {
  count: number;
  resetAt: number;
  firstSeenAt: number;
}

const windows = new Map<string, Window>();

/** Periodic sweep so the map cannot grow without bound. */
const sweeper = setInterval(() => {
  const now = Date.now();
  for (const [key, win] of windows) {
    if (win.resetAt <= now) windows.delete(key);
  }
}, 60_000);
// Do not hold the process open solely for the sweeper.
sweeper.unref?.();

export interface RateLimitOptions {
  /** Window length in milliseconds. */
  windowMs: number;
  /** Requests permitted per window. */
  max: number;
  /** Identifier used in the bucket key. */
  bucket: string;
  /**
   * When set, the limiter only applies while this class is in secure mode, so
   * the rate-limit lab can genuinely remove the control.
   */
  governedBy?: VulnClass;
  /** Additional key component, e.g. the submitted username. */
  keyBy?: (req: Request) => string;
}

export interface RateLimitState {
  limited: boolean;
  remaining: number;
  retryAfterSeconds: number;
  count: number;
  max: number;
}

function clientKey(req: Request): string {
  return req.ip ?? req.socket.remoteAddress ?? 'unknown';
}

/** Records a hit and reports the resulting state without throwing. */
export function consume(req: Request, options: RateLimitOptions): RateLimitState {
  const extra = options.keyBy ? options.keyBy(req) : '';
  const key = `${options.bucket}:${clientKey(req)}:${extra}`;
  const now = Date.now();
  let win = windows.get(key);

  if (!win || win.resetAt <= now) {
    win = { count: 0, resetAt: now + options.windowMs, firstSeenAt: now };
    windows.set(key, win);
  }
  win.count += 1;

  const limited = win.count > options.max;
  return {
    limited,
    remaining: Math.max(options.max - win.count, 0),
    retryAfterSeconds: Math.max(Math.ceil((win.resetAt - now) / 1000), 0),
    count: win.count,
    max: options.max,
  };
}

/** Reports current state without incrementing. */
export function peek(req: Request, options: RateLimitOptions): RateLimitState {
  const extra = options.keyBy ? options.keyBy(req) : '';
  const key = `${options.bucket}:${clientKey(req)}:${extra}`;
  const win = windows.get(key);
  const now = Date.now();
  if (!win || win.resetAt <= now) {
    return { limited: false, remaining: options.max, retryAfterSeconds: 0, count: 0, max: options.max };
  }
  return {
    limited: win.count > options.max,
    remaining: Math.max(options.max - win.count, 0),
    retryAfterSeconds: Math.max(Math.ceil((win.resetAt - now) / 1000), 0),
    count: win.count,
    max: options.max,
  };
}

export function resetLimiter(bucket?: string): void {
  if (!bucket) {
    windows.clear();
    return;
  }
  for (const key of windows.keys()) {
    if (key.startsWith(`${bucket}:`)) windows.delete(key);
  }
}

export function rateLimit(options: RateLimitOptions): RequestHandler {
  return (req, res, next) => {
    if (options.governedBy && !isSecure(options.governedBy)) {
      // Control deliberately disabled for the lab. Still count the request so
      // the lab can show how many attempts an attacker got through unimpeded.
      const state = consume(req, options);
      res.setHeader('x-ratelimit-enforced', 'false');
      res.setHeader('x-ratelimit-observed-count', String(state.count));
      return next();
    }

    const state = consume(req, options);
    res.setHeader('x-ratelimit-limit', String(options.max));
    res.setHeader('x-ratelimit-remaining', String(state.remaining));
    res.setHeader('x-ratelimit-enforced', 'true');

    if (state.limited) {
      res.setHeader('retry-after', String(state.retryAfterSeconds));
      audit({
        action: 'security.ratelimit.throttled',
        category: 'security',
        outcome: 'blocked',
        severity: 'medium',
        req,
        detail: { bucket: options.bucket, attempts: state.count, max: options.max },
      });
      return next(
        new AppError(
          'rate_limited',
          `Too many requests. Please wait ${state.retryAfterSeconds} seconds and try again.`,
        ),
      );
    }
    return next();
  };
}

/** Shared limiter configurations. */
export const LIMITS = {
  login: { windowMs: 60_000, max: 5, bucket: 'login', governedBy: 'rate_limit' as VulnClass },
  labLogin: { windowMs: 60_000, max: 5, bucket: 'lab-login', governedBy: 'rate_limit' as VulnClass },
  // The scanner and simulator legitimately burst, so their ceiling is higher,
  // but it is not unlimited: a runaway loop should not be able to wedge the box.
  securityOps: { windowMs: 60_000, max: 120, bucket: 'security-ops' },
  api: { windowMs: 60_000, max: 600, bucket: 'api' },
} satisfies Record<string, RateLimitOptions>;
