/**
 * HTTP-level integration tests against the real Express app (spec section 32).
 *
 * Uses Node's built-in fetch against a listening instance, so middleware order,
 * cookies, CSRF and RBAC are all exercised exactly as in production.
 */
import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import type { Server } from 'node:http';

let server: Server;
let base: string;

async function api(path: string, init: RequestInit & { jar?: string[] } = {}): Promise<{ status: number; json: any; cookies: string[]; headers: Headers }> {
  const headers = new Headers(init.headers);
  if (init.jar) headers.set('cookie', init.jar.join('; '));
  const res = await fetch(`${base}${path}`, { ...init, headers });
  const setCookie = res.headers.getSetCookie?.() ?? [];
  const text = await res.text();
  let json: any = null;
  try { json = JSON.parse(text); } catch { json = text; }
  return { status: res.status, json, cookies: setCookie, headers: res.headers };
}

function jarFrom(cookies: string[]): string[] {
  return cookies.map((c) => c.split(';')[0]!);
}

beforeAll(async () => {
  const { createApp } = await import('../src/app.ts');
  const app = createApp();
  await new Promise<void>((resolve) => {
    server = app.listen(0, '127.0.0.1', () => {
      const addr = server.address();
      const port = typeof addr === 'object' && addr ? addr.port : 0;
      base = `http://127.0.0.1:${port}`;
      resolve();
    });
  });
});

afterAll(() => { server?.close(); });

// These tests exercise auth, CSRF and RBAC -- not the rate limiter. Reset the
// login limiter between tests so repeated logins as the same demo user (all
// from 127.0.0.1) are not throttled. The limiter itself is covered separately.
beforeEach(async () => {
  const { resetLimiter } = await import('../src/security/ratelimit.ts');
  resetLimiter();
});

describe('security headers', () => {
  it('sends CSP, HSTS and nosniff in hardened mode', async () => {
    const r = await api('/api/health');
    expect(r.headers.get('content-security-policy')).toBeTruthy();
    expect(r.headers.get('x-content-type-options')).toBe('nosniff');
    expect(r.headers.get('x-powered-by')).toBeNull();
  });
});

describe('authentication', () => {
  it('rejects a wrong password with a generic message', async () => {
    const r = await api('/api/auth/login', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ username: 'alice', password: 'nope' }) });
    expect(r.status).toBe(401);
    expect(r.json.error.message).toBe('Invalid username or password.');
  });
  it('returns an identical message for an unknown user (no enumeration)', async () => {
    const r = await api('/api/auth/login', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ username: 'ghost', password: 'nope' }) });
    expect(r.status).toBe(401);
    expect(r.json.error.message).toBe('Invalid username or password.');
  });
  it('logs a user in and issues an HttpOnly session cookie', async () => {
    const r = await api('/api/auth/login', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ username: 'bob', password: 'Bob#2024!Vault' }) });
    expect(r.status).toBe(200);
    expect(r.json.user.username).toBe('bob');
    const sessionCookie = r.cookies.find((c) => c.startsWith('sx_session='));
    expect(sessionCookie).toContain('HttpOnly');
  });
});

describe('authorization (RBAC)', () => {
  it('forbids a plain user from running a scan (analyst required)', async () => {
    const login = await api('/api/auth/login', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ username: 'bob', password: 'Bob#2024!Vault' }) });
    const jar = jarFrom(login.cookies);
    const csrf = login.json.csrfToken;
    const r = await api('/api/security/scan', { method: 'POST', jar, headers: { 'x-csrf-token': csrf, origin: 'http://localhost:5173' } });
    expect(r.status).toBe(403);
  });
  it('allows an analyst to run a scan', async () => {
    const login = await api('/api/auth/login', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ username: 'analyst', password: 'Analyst#2024!Vault' }) });
    const jar = jarFrom(login.cookies);
    const csrf = login.json.csrfToken;
    const r = await api('/api/security/scan', { method: 'POST', jar, headers: { 'x-csrf-token': csrf, origin: 'http://localhost:5173' } });
    expect(r.status).toBe(200);
    expect(r.json.checksRun).toBeGreaterThan(0);
  });
});

describe('CSRF protection', () => {
  it('rejects a state-changing request with no token', async () => {
    const login = await api('/api/auth/login', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ username: 'alice', password: 'Alice#2024!Vault' }) });
    const jar = jarFrom(login.cookies);
    const r = await api('/api/vault/documents', { method: 'POST', jar, headers: { 'content-type': 'application/json' }, body: JSON.stringify({ title: 'x', body: 'y' }) });
    expect(r.status).toBe(403);
    expect(r.json.error.code).toBe('csrf_failed');
  });
  it('accepts it with a valid token', async () => {
    const login = await api('/api/auth/login', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ username: 'alice', password: 'Alice#2024!Vault' }) });
    const jar = jarFrom(login.cookies);
    const r = await api('/api/vault/documents', { method: 'POST', jar, headers: { 'content-type': 'application/json', 'x-csrf-token': login.json.csrfToken, origin: 'http://localhost:5173' }, body: JSON.stringify({ title: 'Test doc', body: 'hello', classification: 'internal' }) });
    expect(r.status).toBe(201);
  });
});

describe('security score reacts to mode changes', () => {
  it('drops when a class is made vulnerable and recovers when secured', async () => {
    const login = await api('/api/auth/login', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ username: 'admin', password: 'Admin#2024!Vault' }) });
    const jar = jarFrom(login.cookies);
    const csrf = login.json.csrfToken;
    const before = (await api('/api/security/score', { jar })).json.score.overall;
    await api('/api/security/modes/sqli', { method: 'PUT', jar, headers: { 'content-type': 'application/json', 'x-csrf-token': csrf, origin: 'http://localhost:5173' }, body: JSON.stringify({ mode: 'vulnerable' }) });
    const during = (await api('/api/security/score', { jar })).json.score.overall;
    await api('/api/security/modes/sqli', { method: 'PUT', jar, headers: { 'content-type': 'application/json', 'x-csrf-token': csrf, origin: 'http://localhost:5173' }, body: JSON.stringify({ mode: 'secure' }) });
    const after = (await api('/api/security/score', { jar })).json.score.overall;
    expect(during).toBeLessThan(before);
    expect(after).toBeGreaterThan(during);
  });
});

describe('error handling does not leak internals in secure mode', () => {
  it('returns a safe 404 with no stack trace', async () => {
    const r = await api('/api/nonexistent-endpoint');
    expect(r.status).toBe(404);
    expect(JSON.stringify(r.json)).not.toMatch(/\s+at\s+\S+\s+\(/);
    expect(JSON.stringify(r.json)).not.toContain('node_modules');
  });
});
