/**
 * Security mode registry — the core mechanism of SentinelX.
 *
 * Each vulnerability class has one toggle: `vulnerable` or `secure`. Application
 * code consults the toggle at request time and takes a genuinely different code
 * path. Nothing about the toggle is cosmetic:
 *
 *   * In `vulnerable` mode the weakness is really present and really exploitable
 *     against this application's own endpoints.
 *   * In `secure` mode the documented control is really applied.
 *
 * Because the scanner probes live endpoints over HTTP, flipping a toggle changes
 * what the scanner finds, which changes the findings table, which changes the
 * security score. That chain is what makes "Apply Mitigation → Retest → score
 * moves" an honest demonstration rather than an animation.
 */
import { db } from '../db/index.js';

export type Mode = 'vulnerable' | 'secure';

export const VULN_CLASSES = [
  'sqli',
  'xss_reflected',
  'xss_stored',
  'csrf',
  'idor',
  'auth',
  'session',
  'headers',
  'upload',
  'path_traversal',
  'ssrf',
  'cmdi',
  'data_exposure',
  'rate_limit',
  'api_authz',
  'error_handling',
] as const;

export type VulnClass = (typeof VULN_CLASSES)[number];

/** Which security score domain a vulnerability class contributes to (§20). */
export type ScoreDomain =
  | 'authentication'
  | 'authorization'
  | 'input_security'
  | 'session_security'
  | 'headers'
  | 'data_protection'
  | 'logging';

export interface VulnClassMeta {
  key: VulnClass;
  title: string;
  /** One-line statement of the weakness, used in list views. */
  summary: string;
  owaspCategory: string;
  cwe: string;
  domain: ScoreDomain;
  /** Severity this class carries when present. Feeds the risk engine. */
  baseSeverity: 'critical' | 'high' | 'medium' | 'low';
  /**
   * True when the vulnerable path is exercised by a real exploit against our own
   * endpoint. False when a live exploit would be unsafe or unreliable to
   * automate, in which case the lab runs a controlled demonstration and the UI
   * labels it as such (§2, §40).
   */
  liveExploit: boolean;
  /** Endpoint the scanner and simulator target for this class. */
  probeEndpoint: string;
}

export const VULN_CATALOGUE: Record<VulnClass, VulnClassMeta> = {
  sqli: {
    key: 'sqli',
    title: 'SQL Injection',
    summary:
      'User input is concatenated into a SQL statement, letting an attacker change the query the database parses.',
    owaspCategory: 'A03:2021 – Injection',
    cwe: 'CWE-89',
    domain: 'input_security',
    baseSeverity: 'critical',
    liveExploit: true,
    probeEndpoint: '/api/lab/sqli/login',
  },
  xss_reflected: {
    key: 'xss_reflected',
    title: 'Reflected Cross-Site Scripting',
    summary:
      'Request input is echoed into the response without output encoding, so markup in the input becomes markup in the page.',
    owaspCategory: 'A03:2021 – Injection',
    cwe: 'CWE-79',
    domain: 'input_security',
    baseSeverity: 'medium',
    liveExploit: true,
    probeEndpoint: '/api/lab/xss/search',
  },
  xss_stored: {
    key: 'xss_stored',
    title: 'Stored Cross-Site Scripting',
    summary:
      'Attacker-supplied markup is persisted and later served to other users, executing in their session context.',
    owaspCategory: 'A03:2021 – Injection',
    cwe: 'CWE-79',
    domain: 'input_security',
    baseSeverity: 'high',
    liveExploit: true,
    probeEndpoint: '/api/lab/xss/comments',
  },
  csrf: {
    key: 'csrf',
    title: 'Cross-Site Request Forgery',
    summary:
      'A state-changing endpoint accepts a request authenticated only by an ambient cookie, with no proof of user intent.',
    owaspCategory: 'A01:2021 – Broken Access Control',
    cwe: 'CWE-352',
    domain: 'session_security',
    baseSeverity: 'high',
    liveExploit: true,
    probeEndpoint: '/api/lab/csrf/change-email',
  },
  idor: {
    key: 'idor',
    title: 'Insecure Direct Object Reference',
    summary:
      'An object is fetched by the identifier in the request without checking that the caller is authorised for that object.',
    owaspCategory: 'A01:2021 – Broken Access Control',
    cwe: 'CWE-639',
    domain: 'authorization',
    baseSeverity: 'high',
    liveExploit: true,
    probeEndpoint: '/api/lab/idor/document',
  },
  auth: {
    key: 'auth',
    title: 'Broken Authentication',
    summary:
      'Credentials are stored or verified weakly — fast unsalted digests, no lockout, username enumeration via differing errors.',
    owaspCategory: 'A07:2021 – Identification and Authentication Failures',
    cwe: 'CWE-287',
    domain: 'authentication',
    baseSeverity: 'critical',
    liveExploit: true,
    probeEndpoint: '/api/lab/auth/login',
  },
  session: {
    key: 'session',
    title: 'Session and Cookie Weakness',
    summary:
      'Session identifiers are predictable, or the cookie lacks HttpOnly / Secure / SameSite and never expires.',
    owaspCategory: 'A07:2021 – Identification and Authentication Failures',
    cwe: 'CWE-614',
    domain: 'session_security',
    baseSeverity: 'high',
    liveExploit: true,
    probeEndpoint: '/api/lab/session/issue',
  },
  headers: {
    key: 'headers',
    title: 'Missing Security Headers',
    summary:
      'Responses omit CSP, HSTS, X-Content-Type-Options, Referrer-Policy and Permissions-Policy, removing defence in depth.',
    owaspCategory: 'A05:2021 – Security Misconfiguration',
    cwe: 'CWE-693',
    domain: 'headers',
    baseSeverity: 'medium',
    liveExploit: true,
    probeEndpoint: '/api/lab/headers/probe',
  },
  upload: {
    key: 'upload',
    title: 'Unrestricted File Upload',
    summary:
      'Uploads are accepted without validating type, size or filename, and are stored under the name the client chose.',
    owaspCategory: 'A04:2021 – Insecure Design',
    cwe: 'CWE-434',
    domain: 'input_security',
    baseSeverity: 'high',
    liveExploit: true,
    probeEndpoint: '/api/lab/upload/file',
  },
  path_traversal: {
    key: 'path_traversal',
    title: 'Path Traversal',
    summary:
      'A filename from the request is joined onto a base directory without normalisation, so ../ escapes the intended folder.',
    owaspCategory: 'A01:2021 – Broken Access Control',
    cwe: 'CWE-22',
    domain: 'input_security',
    baseSeverity: 'high',
    liveExploit: true,
    probeEndpoint: '/api/lab/traversal/read',
  },
  ssrf: {
    key: 'ssrf',
    title: 'Server-Side Request Forgery',
    summary:
      'The server fetches a URL supplied by the user, which can be redirected at internal-only addresses.',
    owaspCategory: 'A10:2021 – Server-Side Request Forgery',
    cwe: 'CWE-918',
    domain: 'input_security',
    baseSeverity: 'high',
    // The vulnerable path is real but is confined to loopback targets we host
    // ourselves; it will not reach out to the internet (§41).
    liveExploit: true,
    probeEndpoint: '/api/lab/ssrf/fetch',
  },
  cmdi: {
    key: 'cmdi',
    title: 'Argument and Parameter Injection',
    summary:
      'User input is interpolated into a command-style string, letting an attacker append their own arguments.',
    owaspCategory: 'A03:2021 – Injection',
    cwe: 'CWE-88',
    domain: 'input_security',
    baseSeverity: 'high',
    // Deliberately a parser-level demonstration: we never spawn a shell, so
    // nothing can escape the process. The UI labels this a demonstration.
    liveExploit: false,
    probeEndpoint: '/api/lab/cmdi/report',
  },
  data_exposure: {
    key: 'data_exposure',
    title: 'Sensitive Data Exposure',
    summary:
      'API responses include password hashes, tokens and internal fields that the caller has no need to see.',
    owaspCategory: 'A02:2021 – Cryptographic Failures',
    cwe: 'CWE-200',
    domain: 'data_protection',
    baseSeverity: 'high',
    liveExploit: true,
    probeEndpoint: '/api/lab/exposure/profile',
  },
  rate_limit: {
    key: 'rate_limit',
    title: 'Missing Rate Limiting',
    summary:
      'An authentication endpoint accepts unlimited attempts, making online password guessing practical.',
    owaspCategory: 'A07:2021 – Identification and Authentication Failures',
    cwe: 'CWE-307',
    domain: 'authentication',
    baseSeverity: 'medium',
    liveExploit: true,
    probeEndpoint: '/api/lab/ratelimit/attempt',
  },
  api_authz: {
    key: 'api_authz',
    title: 'Insecure Direct API Access',
    summary:
      'A privileged API route performs no role check, so any authenticated user — or none at all — can call it.',
    owaspCategory: 'A01:2021 – Broken Access Control',
    cwe: 'CWE-285',
    domain: 'authorization',
    baseSeverity: 'critical',
    liveExploit: true,
    probeEndpoint: '/api/lab/api-authz/users',
  },
  error_handling: {
    key: 'error_handling',
    title: 'Verbose Error Disclosure',
    summary:
      'Unhandled errors return stack traces, SQL text and internal paths to the client instead of a safe message.',
    owaspCategory: 'A05:2021 – Security Misconfiguration',
    cwe: 'CWE-209',
    domain: 'logging',
    baseSeverity: 'medium',
    liveExploit: true,
    probeEndpoint: '/api/lab/errors/trigger',
  },
};

// ── Runtime state ───────────────────────────────────────────────────────────

/**
 * In-memory cache of the registry. Reads happen on nearly every request, so we
 * keep them out of SQLite; the database remains the durable record so mode
 * choices survive a restart mid-demonstration.
 */
const cache = new Map<VulnClass, Mode>();
let loaded = false;

export function loadModes(): void {
  const rows = db.prepared<{ key: string; mode: string }>('SELECT key, mode FROM security_modes');
  const seen = new Set<string>();
  for (const row of rows) {
    if ((VULN_CLASSES as readonly string[]).includes(row.key)) {
      cache.set(row.key as VulnClass, row.mode === 'vulnerable' ? 'vulnerable' : 'secure');
      seen.add(row.key);
    }
  }
  // Any class added to the catalogue since the last migration defaults to
  // secure: a new control should be on until someone deliberately weakens it.
  for (const key of VULN_CLASSES) {
    if (!seen.has(key)) {
      db.run('INSERT OR IGNORE INTO security_modes (key, mode) VALUES (?, ?)', [key, 'secure']);
      cache.set(key, 'secure');
    }
  }
  loaded = true;
}

function ensureLoaded(): void {
  if (!loaded) loadModes();
}

/** Current mode for a class. Defaults to secure (fail securely / secure defaults). */
export function getMode(key: VulnClass): Mode {
  ensureLoaded();
  return cache.get(key) ?? 'secure';
}

export function isVulnerable(key: VulnClass): boolean {
  return getMode(key) === 'vulnerable';
}

export function isSecure(key: VulnClass): boolean {
  return getMode(key) === 'secure';
}

export interface ModeChange {
  key: VulnClass;
  from: Mode;
  to: Mode;
  changedAt: string;
}

export function setMode(key: VulnClass, mode: Mode, changedByUserId?: number): ModeChange {
  ensureLoaded();
  const from = getMode(key);
  const changedAt = new Date().toISOString();
  db.run(
    `UPDATE security_modes
        SET mode = ?, changed_at = datetime('now'), changed_by = ?,
            change_count = change_count + 1
      WHERE key = ?`,
    [mode, changedByUserId ?? null, key],
  );
  cache.set(key, mode);
  return { key, from, to: mode, changedAt };
}

export function getAllModes(): Record<VulnClass, Mode> {
  ensureLoaded();
  const out = {} as Record<VulnClass, Mode>;
  for (const key of VULN_CLASSES) out[key] = getMode(key);
  return out;
}

/** Sets every class at once. Powers the global Vulnerable/Hardened switch (§4). */
export function setAllModes(mode: Mode, changedByUserId?: number): ModeChange[] {
  return VULN_CLASSES.map((key) => setMode(key, mode, changedByUserId));
}

export function modeSnapshotJson(): string {
  return JSON.stringify(getAllModes());
}

/** Catalogue entries joined with live mode, for the UI. */
export function describeAllClasses() {
  ensureLoaded();
  return VULN_CLASSES.map((key) => ({
    ...VULN_CATALOGUE[key],
    mode: getMode(key),
  }));
}

export function isVulnClass(value: string): value is VulnClass {
  return (VULN_CLASSES as readonly string[]).includes(value);
}
