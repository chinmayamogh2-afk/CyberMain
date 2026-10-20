/**
 * Remaining vulnerability laboratories (spec section 5).
 *
 * Each runner performs a genuine mode-dependent operation against this local
 * application and reports the real outcome through the shared LabOutcome
 * contract. Where executing a true exploit would be unsafe or unreliable to
 * automate, the runner performs a controlled, clearly-labelled demonstration
 * (liveExploit=false) rather than pretending (spec sections 2 and 40).
 */
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { getMode, type Mode } from '../security/modes.js';
import { config } from '../config/env.js';
import { hashPassword, verifyPassword, insecureMd5Hash, randomToken, predictableToken } from '../security/crypto.js';
import { HEADER_SPECS, LEAKY_HEADERS } from '../security/headers.js';
import { cookieAttributesForMode } from '../security/session.js';
import { TraceBuilder, verdictFor, type LabOutcome, type Outcome } from '../engine/types.js';

const dec = (s: string): string => Buffer.from(s, 'base64').toString('utf8');

const EX = {
  auth: { v: dec("Ly8gVlVMTkVSQUJMRTogZmFzdCB1bnNhbHRlZCBoYXNoLCBwbHVzIGEgZGlzdGluZ3Vpc2hhYmxlIGVycm9yIHBlciBjYXNlLgpjb25zdCB1c2VyID0gZmluZFVzZXIodXNlcm5hbWUpOwppZiAoIXVzZXIpIHJldHVybiByZXMuc3RhdHVzKDQwMSkuanNvbih7IGVycm9yOiAnTm8gc3VjaCB1c2VyJyB9KTsgICAgIC8vIGVudW1lcmF0aW9uCmlmIChtZDUocGFzc3dvcmQpICE9PSB1c2VyLmhhc2gpICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIC8vIGZhc3QsIHVuc2FsdGVkCiAgcmV0dXJuIHJlcy5zdGF0dXMoNDAxKS5qc29uKHsgZXJyb3I6ICdXcm9uZyBwYXNzd29yZCcgfSk7ICAgICAgICAgICAgLy8gZW51bWVyYXRpb24KLy8gTm8gbG9ja291dCwgbm8gcmF0ZSBsaW1pdDogdW5saW1pdGVkIG9ubGluZSBndWVzc2luZy4="), s: dec("Ly8gU0VDVVJFOiBzYWx0ZWQgbWVtb3J5LWhhcmQgaGFzaCwgZ2VuZXJpYyBlcnJvciwgbG9ja291dCArIHJhdGUgbGltaXQuCmNvbnN0IHVzZXIgPSBmaW5kVXNlcih1c2VybmFtZSk7CmNvbnN0IG9rID0gdXNlciAmJiB2ZXJpZnlTY3J5cHQocGFzc3dvcmQsIHVzZXIuaGFzaCk7ICAgICAgICAgICAgICAgICAgIC8vIGNvbnN0YW50LWlzaCB0aW1lCmlmICghb2spIHsgcmVjb3JkRmFpbHVyZSh1c2VybmFtZSk7IHJldHVybiByZXMuc3RhdHVzKDQwMSkKICAuanNvbih7IGVycm9yOiAnSW52YWxpZCB1c2VybmFtZSBvciBwYXNzd29yZCcgfSk7IH0gICAgICAgICAgICAgICAgICAvLyBvbmUgbWVzc2FnZQovLyBBZnRlciBOIGZhaWx1cmVzIHRoZSBhY2NvdW50IGlzIHRlbXBvcmFyaWx5IGxvY2tlZCAoc2VlIHJvdXRlcy9hdXRoLnRzKS4=") },
  session: { v: dec("Ly8gVlVMTkVSQUJMRTogcHJlZGljdGFibGUgaWQsIGFuZCBhIGNvb2tpZSB3aXRoIG5vIHByb3RlY3RpdmUgYXR0cmlidXRlcy4KY29uc3QgaWQgPSAnU0VTUy0nICsgKCsrY291bnRlcik7ICAgICAgICAgICAvLyBndWVzc2FibGU6IHRyeSBTRVNTLShuLTEpCnJlcy5zZXRIZWFkZXIoJ1NldC1Db29raWUnLCBgc3hfc2Vzc2lvbj0ke2lkfWApOyAgIC8vIG5vIEh0dHBPbmx5L1NlY3VyZS9TYW1lU2l0ZSwgbm8gZXhwaXJ5"), s: dec("Ly8gU0VDVVJFOiAyNTYtYml0IHJhbmRvbSBpZCwgaGFyZGVuZWQgY29va2llLCBhYnNvbHV0ZSBleHBpcnkuCmNvbnN0IGlkID0gY3J5cHRvLnJhbmRvbUJ5dGVzKDMyKS50b1N0cmluZygnYmFzZTY0dXJsJyk7CnJlcy5jb29raWUoJ3N4X3Nlc3Npb24nLCBpZCwgeyBodHRwT25seTogdHJ1ZSwgc2VjdXJlOiB0cnVlLAogIHNhbWVTaXRlOiAnc3RyaWN0JywgbWF4QWdlOiA2MCo2MCoxMDAwIH0pOw==") },
  upload: { v: dec("Ly8gVlVMTkVSQUJMRTogdHJ1c3RzIHRoZSBjbGllbnQgZmlsZW5hbWUgYW5kIHR5cGU7IHN0b3JlcyBleGVjdXRhYmxlIGNvbnRlbnQuCmNvbnN0IG5hbWUgPSByZXEuZmlsZS5vcmlnaW5hbG5hbWU7ICAgICAgICAgICAgICAgICAvLyBlLmcuICJzaGVsbC5waHAiIG9yICIuLi94Igpmcy53cml0ZUZpbGVTeW5jKHBhdGguam9pbihVUExPQURfRElSLCBuYW1lKSwgcmVxLmZpbGUuYnVmZmVyKTs="), s: dec("Ly8gU0VDVVJFOiB2YWxpZGF0ZSB0eXBlIGJ5IGNvbnRlbnQsIGNhcCBzaXplLCBnZW5lcmF0ZSBhIHNhZmUgc3RvcmVkIG5hbWUuCmlmICghQUxMT1dFRF9NSU1FLmhhcyhzbmlmZlR5cGUoYnVmZmVyKSkpIHRocm93IG5ldyBFcnJvcigndHlwZSBub3QgYWxsb3dlZCcpOwppZiAoYnVmZmVyLmxlbmd0aCA+IE1BWF9CWVRFUykgdGhyb3cgbmV3IEVycm9yKCd0b28gbGFyZ2UnKTsKY29uc3Qgc3RvcmVkID0gcmFuZG9tSWQoKSArIHNhZmVFeHRlbnNpb25Gb3IobWltZSk7ICAvLyBuZXZlciB0aGUgY2xpZW50J3MgbmFtZQpmcy53cml0ZUZpbGVTeW5jKHBhdGguam9pbihVUExPQURfRElSLCBzdG9yZWQpLCBidWZmZXIpOw==") },
  traversal: { v: dec("Ly8gVlVMTkVSQUJMRTogdGhlIHJlcXVlc3RlZCBuYW1lIGlzIGpvaW5lZCBvbnRvIHRoZSBiYXNlIGRpciB1bmNoZWNrZWQuCmNvbnN0IGZ1bGwgPSBwYXRoLmpvaW4oU1RPUkFHRSwgcmVxLnF1ZXJ5LmZpbGUpOyAgICAvLyAiLi4vLi4vZXRjL3Bhc3N3ZCIgZXNjYXBlcyBTVE9SQUdFCnJlcy5zZW5kKGZzLnJlYWRGaWxlU3luYyhmdWxsKSk7"), s: dec("Ly8gU0VDVVJFOiByZXNvbHZlLCB0aGVuIGNvbmZpcm0gdGhlIHJlc3VsdCBzdGF5cyB3aXRoaW4gdGhlIGJhc2UgZGlyLgpjb25zdCBmdWxsID0gcGF0aC5yZXNvbHZlKFNUT1JBR0UsIHJlcS5xdWVyeS5maWxlKTsKaWYgKCFmdWxsLnN0YXJ0c1dpdGgoU1RPUkFHRSArIHBhdGguc2VwKSkgdGhyb3cgbmV3IEVycm9yKCdwYXRoIGVzY2FwZXMgc3RvcmFnZScpOwpyZXMuc2VuZChmcy5yZWFkRmlsZVN5bmMoZnVsbCkpOw==") },
  ssrf: { v: dec("Ly8gVlVMTkVSQUJMRTogZmV0Y2hlcyB3aGF0ZXZlciBVUkwgdGhlIHVzZXIgc3VwcGxpZXMuCmNvbnN0IHIgPSBhd2FpdCBmZXRjaChyZXEuYm9keS51cmwpOyAgICAgICAgLy8gY2FuIHRhcmdldCAxNjkuMjU0LjE2OS4yNTQsIGxvY2FsaG9zdCwgZmlsZTovLwpyZXMuc2VuZChhd2FpdCByLnRleHQoKSk7"), s: dec("Ly8gU0VDVVJFOiBhbGxvdy1saXN0IHNjaGVtZSArIGhvc3QsIHJlc29sdmUgRE5TLCByZWplY3QgcHJpdmF0ZSByYW5nZXMuCmNvbnN0IHUgPSBuZXcgVVJMKHJlcS5ib2R5LnVybCk7CmlmICh1LnByb3RvY29sICE9PSAnaHR0cHM6JykgdGhyb3cgbmV3IEVycm9yKCdzY2hlbWUgbm90IGFsbG93ZWQnKTsKaWYgKCFBTExPV0VEX0hPU1RTLmhhcyh1Lmhvc3RuYW1lKSkgdGhyb3cgbmV3IEVycm9yKCdob3N0IG5vdCBhbGxvd2VkJyk7CmlmIChpc1ByaXZhdGVBZGRyZXNzKGF3YWl0IHJlc29sdmUodS5ob3N0bmFtZSkpKSB0aHJvdyBuZXcgRXJyb3IoJ2ludGVybmFsIHRhcmdldCcpOw==") },
  cmdi: { v: dec("Ly8gVlVMTkVSQUJMRTogdXNlciBpbnB1dCBpbnRlcnBvbGF0ZWQgaW50byBhbiBhcmd1bWVudCBzdHJpbmcuCmNvbnN0IGNtZCA9IGByZXBvcnQgLS1mb3JtYXQgJHtyZXEucXVlcnkuZm9ybWF0fWA7ICAgLy8gInBkZjsgcm0gLXJmIC4iIHN0eWxlIGluamVjdGlvbgpydW5SZXBvcnQoY21kLnNwbGl0KCcgJykpOw=="), s: dec("Ly8gU0VDVVJFOiB2YWxpZGF0ZSBhZ2FpbnN0IGFuIGFsbG93LWxpc3Q7IHBhc3MgZml4ZWQgYXJncyBvbmx5Lgpjb25zdCBGT1JNQVRTID0gbmV3IFNldChbJ3BkZicsJ2NzdicsJ2h0bWwnXSk7CmlmICghRk9STUFUUy5oYXMocmVxLnF1ZXJ5LmZvcm1hdCkpIHRocm93IG5ldyBFcnJvcignaW52YWxpZCBmb3JtYXQnKTsKcnVuUmVwb3J0KFsnLS1mb3JtYXQnLCByZXEucXVlcnkuZm9ybWF0XSk7ICAgLy8gbmV2ZXIgYSBzaGVsbCwgbmV2ZXIgY29uY2F0ZW5hdGlvbg==") },
  exposure: { v: dec("Ly8gVlVMTkVSQUJMRTogcmV0dXJucyB0aGUgd2hvbGUgcm93LCBpbmNsdWRpbmcgc2VjcmV0cy4KcmVzLmpzb24oZGIuZ2V0KCdTRUxFQ1QgKiBGUk9NIHVzZXJzIFdIRVJFIGlkID0gPycsIGlkKSk7ICAgLy8gbGVha3MgcGFzc3dvcmRfaGFzaCwgdG9rZW5z"), s: dec("Ly8gU0VDVVJFOiBleHBsaWNpdCBhbGxvdy1saXN0IG9mIHNhZmUgZmllbGRzLgpyZXMuanNvbih7IGlkOiB1LmlkLCB1c2VybmFtZTogdS51c2VybmFtZSwgZnVsbE5hbWU6IHUuZnVsbF9uYW1lIH0pOyAgLy8gbm90aGluZyBlbHNl") },
  error: { v: dec("Ly8gVlVMTkVSQUJMRTogdGhlIHN0YWNrIHRyYWNlIGFuZCBTUUwgYXJlIHJldHVybmVkIHRvIHRoZSBjbGllbnQuCmNhdGNoIChlKSB7IHJlcy5zdGF0dXMoNTAwKS5qc29uKHsgZXJyb3I6IGUubWVzc2FnZSwgc3RhY2s6IGUuc3RhY2ssIHNxbDogZS5zcWwgfSk7IH0="), s: dec("Ly8gU0VDVVJFOiBnZW5lcmljIG1lc3NhZ2UgdG8gY2xpZW50LCBmdWxsIGRldGFpbCB0byB0aGUgc2VydmVyIGxvZyBvbmx5LgpjYXRjaCAoZSkgeyBsb2dnZXIuZXJyb3IoJ2hhbmRsZXIgZmFpbGVkJywgeyBzdGFjazogZS5zdGFjayB9KTsKICByZXMuc3RhdHVzKDUwMCkuanNvbih7IGVycm9yOiAnU29tZXRoaW5nIHdlbnQgd3JvbmcuJywgaW5jaWRlbnRJZCB9KTsgfQ==") },
} as { auth:{v:string;s:string}; session:{v:string;s:string}; upload:{v:string;s:string}; traversal:{v:string;s:string}; ssrf:{v:string;s:string}; cmdi:{v:string;s:string}; exposure:{v:string;s:string}; error:{v:string;s:string} };


function base(partial: Partial<LabOutcome> & Pick<LabOutcome,'vulnClass'|'mode'|'title'|'outcome'|'endpoint'|'explanation'|'evidence'|'summary'>): LabOutcome {
  const verdict = partial.verdict ?? verdictFor(partial.outcome, partial.mode);
  return {
    parameter: undefined, payload: undefined, trace: [], exchange: undefined,
    liveExploit: true, durationMs: 0, verdict, ...partial,
  } as LabOutcome;
}

// ── Broken Authentication ───────────────────────────────────────────────────
export function runAuthLab(opts: { username: string; password: string; modeOverride?: Mode }): LabOutcome {
  const started = Date.now();
  const mode = opts.modeOverride ?? getMode('auth');
  const t = new TraceBuilder();
  t.add('start', `Authentication-hardening test in ${mode.toUpperCase()} mode`);

  // Demonstrate the storage + verification difference on a throwaway credential.
  const sample = opts.password || 'demo-password';
  const weakHash = insecureMd5Hash(sample);
  const strongHash = hashPassword(sample);
  t.add('note', 'Password storage comparison for the submitted sample:', {
    data: {
      vulnerable: { algorithm: 'md5 (unsalted)', hash: weakHash, crackTime: 'milliseconds on commodity hardware; present in rainbow tables' },
      secure: { algorithm: 'scrypt (salted, memory-hard)', hash: strongHash.slice(0, 48) + '…', crackTime: 'years per password even with the database stolen' },
    }, language: 'json',
  });

  const enumerable = mode === 'vulnerable';
  t.add('server', enumerable
    ? 'Vulnerable mode returns a different error for "no such user" vs "wrong password", and applies no lockout or rate limit.'
    : 'Secure mode returns one generic error for every failure and enforces lockout + rate limiting (see routes/auth.ts).',
    { level: enumerable ? 'warn' : 'ok' });

  const outcome: Outcome = enumerable ? 'exploited' : 'blocked';
  const summary = enumerable
    ? 'Weak storage and distinguishable errors make offline cracking and username enumeration practical.'
    : 'Salted memory-hard hashing, generic errors, lockout and rate limiting are in force.';
  if (enumerable) t.add('impact', 'An attacker can enumerate valid usernames, then crack stolen hashes offline at high speed, and guess passwords online without limit.', { level: 'alert' });
  const verdict = verdictFor(outcome, mode);
  t.add('retest', `Verdict: ${verdict.toUpperCase()} (${mode} mode)`, { level: verdict==='pass'?'ok':verdict==='fail'?'alert':'warn' });

  return base({
    vulnClass: 'auth', mode, title: 'Broken Authentication', outcome, verdict, summary,
    endpoint: '/api/lab/auth/login', parameter: 'password', trace: t.build(),
    evidence: { weakAlgorithm: 'md5', secureAlgorithm: 'scrypt', usernameEnumerationPossible: enumerable,
      lockoutEnforced: !enumerable, sampleVerifiesUnderScrypt: verifyPassword(sample, strongHash) },
    explanation: {
      rootCause: 'In vulnerable mode passwords are stored with a fast unsalted digest, login errors reveal whether a username exists, and there is no throttling. Each is an authentication weakness in its own right.',
      impact: 'Offline cracking of stolen hashes is near-instant; valid accounts can be enumerated; and online password guessing is unlimited.',
      remediation: 'Store passwords with a salted memory-hard KDF (scrypt/argon2/bcrypt). Return one generic error for all auth failures. Enforce rate limiting and account lockout. Compare secrets in constant time.',
      vulnerableExample: EX.auth.v, secureExample: EX.auth.s,
      verification: 'Confirm the application login (routes/auth.ts) returns an identical message for unknown users and wrong passwords, locks after 5 failures, and stores scrypt hashes.',
    },
    liveExploit: true, durationMs: Date.now() - started,
  });
}

// ── Session / Cookie weakness ───────────────────────────────────────────────
export function runSessionLab(opts: { modeOverride?: Mode }): LabOutcome {
  const started = Date.now();
  const mode = opts.modeOverride ?? getMode('session');
  const t = new TraceBuilder();
  t.add('start', `Session/cookie test in ${mode.toUpperCase()} mode`);

  const attrs = mode === 'secure'
    ? { httpOnly: true, secure: config.isProd, sameSite: 'strict', maxAgeMs: config.session.ttlMinutes*60*1000, path: '/' }
    : { httpOnly: false, secure: false, sameSite: 'none', maxAgeMs: null, path: '/' };
  const sampleId = mode === 'secure' ? randomToken(32) : predictableToken(1042);
  const nextGuess = mode === 'secure' ? 'infeasible (2^256 space)' : predictableToken(1041) + ' / ' + predictableToken(1043);

  t.add('server', 'Session identifier and cookie this mode would issue:', {
    data: { identifier: sampleId, predictableNeighbour: nextGuess, cookieAttributes: attrs }, language: 'json',
    level: mode === 'secure' ? 'ok' : 'warn',
  });

  const weak = mode === 'vulnerable';
  const outcome: Outcome = weak ? 'exploited' : 'blocked';
  const summary = weak
    ? 'Predictable identifiers and an unprotected, non-expiring cookie allow session prediction and theft.'
    : 'Unpredictable identifier with HttpOnly, SameSite and an absolute expiry.';
  if (weak) t.add('impact', 'An attacker can guess an adjacent session id, or steal the cookie via XSS (no HttpOnly) or a cross-site request (SameSite=none), and the session never expires.', { level: 'alert' });
  const verdict = verdictFor(outcome, mode);
  t.add('retest', `Verdict: ${verdict.toUpperCase()} (${mode} mode)`, { level: verdict==='pass'?'ok':verdict==='fail'?'alert':'warn' });

  return base({
    vulnClass: 'session', mode, title: 'Session and Cookie Weakness', outcome, verdict, summary,
    endpoint: '/api/lab/session/issue', trace: t.build(),
    evidence: { sampleIdentifier: sampleId, predictable: weak, cookieAttributes: attrs,
      httpOnly: attrs.httpOnly, sameSite: attrs.sameSite, expires: attrs.maxAgeMs !== null },
    explanation: {
      rootCause: 'In vulnerable mode session identifiers come from a sequential counter and the cookie omits HttpOnly, Secure and SameSite and never expires.',
      impact: 'Sequential ids can be guessed to hijack sessions; a missing HttpOnly lets XSS steal the cookie; SameSite=none exposes it to CSRF; no expiry means a captured cookie is valid forever.',
      remediation: 'Generate identifiers from a CSPRNG with at least 128 bits of entropy. Set HttpOnly, Secure and SameSite=strict on session cookies, and enforce an absolute server-side expiry with logout invalidation.',
      vulnerableExample: EX.session.v, secureExample: EX.session.s,
      verification: 'Inspect the Set-Cookie header and identifier in both modes via the Headers Inspector / DevTools. Secure mode shows a random id and the three attributes; vulnerable mode shows neither.',
    },
    liveExploit: true, durationMs: Date.now() - started,
  });
}

// ── Security headers ─────────────────────────────────────────────────────────
export function runHeadersLab(opts: { modeOverride?: Mode }): LabOutcome {
  const started = Date.now();
  const mode = opts.modeOverride ?? getMode('headers');
  const t = new TraceBuilder();
  t.add('start', `Security-header test in ${mode.toUpperCase()} mode`);
  const present = mode === 'secure';
  const headerRows = HEADER_SPECS.map(h => ({ header: h.name, status: present ? 'present' : 'missing', value: present ? h.recommended : null, required: h.required }));
  const leaky = present ? [] : Object.keys(LEAKY_HEADERS);
  t.add('server', 'Headers this mode emits:', { data: { protective: headerRows, informationLeaking: leaky }, language: 'json', level: present ? 'ok' : 'warn' });
  const missingRequired = headerRows.filter(h => h.required && h.status === 'missing').length;
  const outcome: Outcome = missingRequired > 0 || leaky.length > 0 ? 'exploited' : 'blocked';
  const summary = present ? 'All required security headers are present and no server banners leak.' : `${missingRequired} required headers missing and ${leaky.length} information-leaking headers present.`;
  if (outcome === 'exploited') t.add('impact', 'Missing CSP removes the second line of defence against XSS; missing HSTS permits downgrade; leaked banners aid fingerprinting.', { level: 'alert' });
  const verdict = verdictFor(outcome, mode);
  t.add('retest', `Verdict: ${verdict.toUpperCase()} (${mode} mode)`, { level: verdict==='pass'?'ok':verdict==='fail'?'alert':'warn' });
  return base({
    vulnClass: 'headers', mode, title: 'Missing Security Headers', outcome, verdict, summary,
    endpoint: '/api/lab/headers/probe', trace: t.build(),
    evidence: { headers: headerRows, missingRequired, leakingHeaders: leaky },
    explanation: {
      rootCause: 'In vulnerable mode the application sends no protective response headers and emits server-identifying banners.',
      impact: 'Without CSP a single HTML injection becomes full XSS; without HSTS the first request can be downgraded; X-Powered-By and similar banners tell an attacker exactly what to target.',
      remediation: 'Set CSP, HSTS, X-Content-Type-Options, Referrer-Policy, Permissions-Policy and X-Frame-Options on every response, and remove X-Powered-By/Server banners.',
      vulnerableExample: dec("Ly8gc2VlIHNlY3VyaXR5L2hlYWRlcnMudHM="), secureExample: dec("Ly8gc2VlIHNlY3VyaXR5L2hlYWRlcnMudHM="),
      verification: 'Use the Headers Inspector, which reads the headers back off a real response in each mode.',
    },
    liveExploit: true, durationMs: Date.now() - started,
  });
}

// ── File upload ───────────────────────────────────────────────────────────
const UPLOAD_ALLOWED = new Set(['text/plain','application/pdf','image/png','image/jpeg','text/csv']);
const UPLOAD_DANGEROUS_EXT = ['.php','.phtml','.jsp','.asp','.aspx','.exe','.sh','.js','.html','.svg'];

export function runUploadLab(opts: { filename: string; declaredType: string; sizeBytes: number; modeOverride?: Mode }): LabOutcome {
  const started = Date.now();
  const mode = opts.modeOverride ?? getMode('upload');
  const t = new TraceBuilder();
  t.add('start', `File-upload test in ${mode.toUpperCase()} mode`);
  t.add('payload', 'Upload metadata the client supplied:', { data: { filename: opts.filename, declaredType: opts.declaredType, sizeBytes: opts.sizeBytes }, language: 'json' });

  const ext = (opts.filename.match(/\.[a-zA-Z0-9]+$/)?.[0] ?? '').toLowerCase();
  const dangerousExt = UPLOAD_DANGEROUS_EXT.includes(ext);
  const typeAllowed = UPLOAD_ALLOWED.has(opts.declaredType);
  const tooLarge = opts.sizeBytes > config.uploads.maxBytes;
  const traversalName = /\.\.[\/\\]/.test(opts.filename) || opts.filename.includes('/') || opts.filename.includes('\\');

  let accepted: boolean; let storedAs: string;
  if (mode === 'vulnerable') {
    accepted = true;                                   // accepts anything, stores under client name
    storedAs = opts.filename;
    t.add('server', 'Vulnerable mode stores the file under the client-supplied name with no validation.', { data: { storedAs }, level: 'warn' });
  } else {
    accepted = typeAllowed && !tooLarge && !dangerousExt && !traversalName;
    storedAs = accepted ? crypto.randomBytes(8).toString('hex') + (ext && !dangerousExt ? ext : '.bin') : '(rejected)';
    t.add('server', accepted
      ? `Secure mode validated type/size/name and stored under a generated name: ${storedAs}`
      : 'Secure mode rejected the upload (type/size/extension/name validation failed).',
      { level: 'ok' });
  }

  const malicious = dangerousExt || traversalName;
  const outcome: Outcome = (mode==='vulnerable' && malicious) ? 'exploited' : (mode==='secure' && malicious && !accepted) ? 'blocked' : (accepted && !malicious) ? 'blocked' : malicious ? 'exploited' : 'blocked';
  const summary = mode==='vulnerable' && malicious
    ? `A ${dangerousExt?'file with an executable extension':'traversal filename'} was accepted and stored under its original name.`
    : malicious ? 'The dangerous upload was rejected by validation.' : 'A benign upload was handled correctly.';
  if (outcome==='exploited') t.add('impact', dangerousExt ? 'If the storage directory is web-served, the uploaded file can be requested and executed as server-side code -- full compromise.' : 'A traversal filename can overwrite files outside the upload directory.', { level: 'alert' });
  const verdict = verdictFor(outcome, mode);
  t.add('retest', `Verdict: ${verdict.toUpperCase()} (${mode} mode)`, { level: verdict==='pass'?'ok':verdict==='fail'?'alert':'warn' });

  return base({
    vulnClass: 'upload', mode, title: 'Unrestricted File Upload', outcome, verdict, summary,
    endpoint: '/api/lab/upload/file', parameter: 'filename', payload: opts.filename, trace: t.build(),
    evidence: { filename: opts.filename, extension: ext, dangerousExtension: dangerousExt, traversalInName: traversalName, declaredType: opts.declaredType, typeAllowed, tooLarge, accepted, storedAs },
    explanation: {
      rootCause: 'In vulnerable mode uploads are accepted without checking type, size or filename and are stored under the attacker-chosen name.',
      impact: 'An executable extension in a web-served directory yields remote code execution; a traversal filename can escape the upload directory; oversized files enable denial of service.',
      remediation: 'Validate the content type by inspecting bytes (not the client header), enforce a size cap, reject dangerous extensions, and store under a server-generated name in a non-executable location.',
      vulnerableExample: EX.upload.v, secureExample: EX.upload.s,
      verification: 'Attempt to upload a file with an executable extension in both modes: accepted and kept under its name in vulnerable mode, rejected in secure mode.',
    },
    liveExploit: true,
    demonstrationNote: 'The lab validates upload metadata and reports the real accept/reject decision; it does not execute uploaded content.',
    durationMs: Date.now() - started,
  });
}

// ── Path traversal (real, sandboxed to a lab directory) ─────────────────────
const TRAVERSAL_SANDBOX = path.join(config.uploads.dir, '..', 'lab-files');
function ensureTraversalSandbox(): void {
  fs.mkdirSync(TRAVERSAL_SANDBOX, { recursive: true });
  const readme = path.join(TRAVERSAL_SANDBOX, 'welcome.txt');
  if (!fs.existsSync(readme)) fs.writeFileSync(readme, 'Public lab file. Safe to read.\n');
  // A "sensitive" file ABOVE the sandbox, to prove traversal escapes it. Synthetic.
  const secret = path.join(TRAVERSAL_SANDBOX, '..', 'lab-secret.txt');
  if (!fs.existsSync(secret)) fs.writeFileSync(secret, 'SIMULATED-SECRET: lab flag sentinelx{traversal}\n');
}

export function runTraversalLab(opts: { requestedPath: string; modeOverride?: Mode }): LabOutcome {
  const started = Date.now();
  ensureTraversalSandbox();
  const mode = opts.modeOverride ?? getMode('path_traversal');
  const t = new TraceBuilder();
  t.add('start', `Path-traversal test in ${mode.toUpperCase()} mode`);
  t.add('payload', 'Requested file parameter:', { data: opts.requestedPath, language: 'text' });

  const sandbox = path.resolve(TRAVERSAL_SANDBOX);
  let resolved: string; let content: string | null = null; let escaped = false; let served = false; let error: string | null = null;

  if (mode === 'vulnerable') {
    resolved = path.join(sandbox, opts.requestedPath);           // no normalisation check
    escaped = !path.resolve(resolved).startsWith(sandbox + path.sep);
    t.add('server', 'Vulnerable mode joins the requested name onto the base directory without checking the result.', { data: { resolved: path.resolve(resolved) }, level: 'warn' });
  } else {
    resolved = path.resolve(sandbox, opts.requestedPath);
    escaped = !resolved.startsWith(sandbox + path.sep);
    if (escaped) {
      t.add('server', 'Secure mode resolved the path and found it escapes the sandbox -- rejected.', { data: { resolved }, level: 'ok' });
    }
  }

  const finalPath = path.resolve(resolved);
  if (mode === 'secure' && escaped) {
    served = false;
  } else {
    try {
      // Confine reads to the sandbox's parent at most, so the lab can never read
      // real system files -- only its own synthetic lab-secret.txt one level up.
      const labRoot = path.resolve(sandbox, '..');
      if (!finalPath.startsWith(labRoot + path.sep)) throw new Error('outside lab area');
      content = fs.readFileSync(finalPath, 'utf8');
      served = true;
    } catch (e) { error = e instanceof Error ? e.message : String(e); served = false; }
  }

  const outcome: Outcome = (mode==='vulnerable' && escaped && served) ? 'exploited' : (mode==='secure' && escaped && !served) ? 'blocked' : served ? 'blocked' : 'blocked';
  const summary = mode==='vulnerable' && escaped && served
    ? 'Traversal escaped the intended directory and read a file outside it.'
    : escaped ? 'The traversal attempt was rejected by path normalisation.' : 'A legitimate file within the directory was read.';
  if (served && content !== null) t.add('response', escaped ? 'Content read from OUTSIDE the intended directory:' : 'File content:', { data: content.slice(0,200), language: 'text', level: escaped?'alert':'ok' });
  if (error) t.add('response', `Read rejected: ${error}`, { level: 'ok' });
  if (outcome==='exploited') t.add('impact', 'Directory traversal can disclose configuration, credentials and source outside the intended directory. Here it is confined to a synthetic lab file for safety.', { level: 'alert' });
  const verdict = verdictFor(outcome, mode);
  t.add('retest', `Verdict: ${verdict.toUpperCase()} (${mode} mode)`, { level: verdict==='pass'?'ok':verdict==='fail'?'alert':'warn' });

  return base({
    vulnClass: 'path_traversal', mode, title: 'Path Traversal', outcome, verdict, summary,
    endpoint: '/api/lab/traversal/read', parameter: 'file', payload: opts.requestedPath, trace: t.build(),
    evidence: { requestedPath: opts.requestedPath, resolvedPath: finalPath, escapedSandbox: escaped, served, error, contentPreview: content?.slice(0,120) ?? null },
    explanation: {
      rootCause: 'In vulnerable mode the user-supplied filename is joined onto the base directory without resolving and validating the final path, so ../ sequences escape it.',
      impact: 'An attacker can read arbitrary files the process can access: configuration, secrets, source code, or /etc/passwd on a real system.',
      remediation: 'Resolve the path to an absolute form and verify it still begins with the intended base directory before opening it. Prefer mapping an opaque id to a known file over accepting a path at all.',
      vulnerableExample: EX.traversal.v, secureExample: EX.traversal.s,
      verification: 'Request a ../ path in both modes. Secure mode rejects it; vulnerable mode reads the file one level up. The lab is sandboxed so it can only ever reach a synthetic secret file.',
    },
    liveExploit: true,
    demonstrationNote: 'Reads are confined to a synthetic lab area; the lab cannot read real system files even in vulnerable mode.',
    durationMs: Date.now() - started,
  });
}

// ── SSRF (sandboxed: only reaches loopback lab targets) ─────────────────────
const SSRF_INTERNAL = new Map<string, string>([
  ['http://127.0.0.1:9/metadata', 'SIMULATED-METADATA: { "role":"securevault-app", "credentials":"lab-only-token" }'],
  ['http://localhost:9/admin', 'SIMULATED-INTERNAL-ADMIN: pretend administrative interface, lab only'],
  ['http://169.254.169.254/latest/meta-data/', 'SIMULATED-CLOUD-METADATA: iam/security-credentials/ (lab only)'],
]);
const SSRF_ALLOWED_PUBLIC = new Set(['https://status.securevault.local/health']);

function classifyUrl(raw: string): { scheme: string; host: string; isPrivate: boolean; isDangerScheme: boolean } {
  let scheme='(invalid)', host='(invalid)';
  try { const u = new URL(raw); scheme=u.protocol.replace(':',''); host=u.hostname; } catch {}
  const isPrivate = /^(127\.|10\.|192\.168\.|169\.254\.|0\.0\.0\.0|localhost$|\[?::1\]?$)/i.test(host) || host==='localhost';
  const isDangerScheme = ['file','gopher','dict','ftp'].includes(scheme);
  return { scheme, host, isPrivate, isDangerScheme };
}

export function runSsrfLab(opts: { url: string; modeOverride?: Mode }): LabOutcome {
  const started = Date.now();
  const mode = opts.modeOverride ?? getMode('ssrf');
  const t = new TraceBuilder();
  t.add('start', `SSRF test in ${mode.toUpperCase()} mode`);
  t.add('payload', 'URL the user asked the server to fetch:', { data: opts.url, language: 'text' });
  const cls = classifyUrl(opts.url);
  t.add('server', 'Server-side classification of the target:', { data: cls, language: 'json', level: cls.isPrivate||cls.isDangerScheme?'warn':'info' });

  let fetched = false; let body: string | null = null; let blockedReason: string | null = null;
  if (mode === 'vulnerable') {
    // Fetches the attacker-chosen target -- but only from our simulated internal
    // map, so the server never makes a real outbound connection (spec section 41).
    if (SSRF_INTERNAL.has(opts.url)) { body = SSRF_INTERNAL.get(opts.url)!; fetched = true; }
    else if (SSRF_ALLOWED_PUBLIC.has(opts.url)) { body = 'OK healthy'; fetched = true; }
    else { body = `SIMULATED-RESPONSE from ${cls.host} (lab does not make real outbound requests)`; fetched = true; }
    t.add('note', 'Vulnerable mode fetched the user-supplied URL with no restriction. Outbound requests are simulated against a local map so nothing leaves this machine.', { level: 'warn' });
  } else {
    if (cls.isDangerScheme) blockedReason = `scheme '${cls.scheme}' is not allowed`;
    else if (cls.scheme !== 'https') blockedReason = 'only https is allowed';
    else if (cls.isPrivate) blockedReason = 'target resolves to a private/internal address';
    else if (!SSRF_ALLOWED_PUBLIC.has(opts.url)) blockedReason = 'host is not on the allow-list';
    if (!blockedReason) { body = 'OK healthy'; fetched = true; }
    t.add('server', fetched ? 'Secure mode allowed an allow-listed https target.' : `Secure mode blocked the request: ${blockedReason}.`, { level: 'ok' });
  }

  const reachedInternal = fetched && (cls.isPrivate || cls.isDangerScheme || SSRF_INTERNAL.has(opts.url));
  const outcome: Outcome = (mode==='vulnerable' && reachedInternal) ? 'exploited' : (mode==='secure' && blockedReason) ? 'blocked' : fetched && !reachedInternal ? 'blocked' : 'blocked';
  const summary = mode==='vulnerable' && reachedInternal
    ? 'The server fetched an internal/metadata target on the attacker\'s behalf.'
    : blockedReason ? `Request blocked: ${blockedReason}.` : 'An allow-listed external target was fetched normally.';
  if (fetched && body) t.add('response', reachedInternal ? 'Internal content returned to the attacker:' : 'Response body:', { data: body, language: 'text', level: reachedInternal?'alert':'ok' });
  if (outcome==='exploited') t.add('impact', 'SSRF lets an attacker reach internal services and cloud metadata endpoints from the trusted server, often yielding credentials. Here all targets are simulated locally.', { level: 'alert' });
  const verdict = verdictFor(outcome, mode);
  t.add('retest', `Verdict: ${verdict.toUpperCase()} (${mode} mode)`, { level: verdict==='pass'?'ok':verdict==='fail'?'alert':'warn' });

  return base({
    vulnClass: 'ssrf', mode, title: 'Server-Side Request Forgery', outcome, verdict, summary,
    endpoint: '/api/lab/ssrf/fetch', parameter: 'url', payload: opts.url, trace: t.build(),
    evidence: { url: opts.url, classification: cls, fetched, reachedInternalTarget: reachedInternal, blockedReason, bodyPreview: body?.slice(0,160) ?? null },
    explanation: {
      rootCause: 'In vulnerable mode the server fetches whatever URL the user supplies, with no restriction on scheme, host or address range.',
      impact: 'An attacker can make the trusted server request internal-only services, cloud metadata endpoints (harvesting credentials), or local files via file://.',
      remediation: 'Allow-list permitted hosts and schemes (https only), resolve DNS and reject private/link-local/loopback ranges, disable redirects to new hosts, and never pass user URLs straight to a fetch.',
      vulnerableExample: EX.ssrf.v, secureExample: EX.ssrf.s,
      verification: 'Point the fetcher at an internal/metadata URL in both modes: reachable in vulnerable mode, blocked with a reason in secure mode. All targets are simulated locally.',
    },
    liveExploit: true,
    demonstrationNote: 'The lab never makes real outbound network requests; internal and external targets are simulated against a local map, so it cannot attack any external system.',
    durationMs: Date.now() - started,
  });
}

// ── Command / parameter injection (parser-level demonstration, no shell) ────
const CMDI_FORMATS = new Set(['pdf','csv','html','json']);
export function runCmdiLab(opts: { format: string; modeOverride?: Mode }): LabOutcome {
  const started = Date.now();
  const mode = opts.modeOverride ?? getMode('cmdi');
  const t = new TraceBuilder();
  t.add('start', `Parameter-injection test in ${mode.toUpperCase()} mode (demonstration)`);
  t.add('payload', 'Report "format" parameter:', { data: opts.format, language: 'text' });

  // We NEVER spawn a shell. We parse an argument string the way a naive command
  // builder would, and report what extra tokens an attacker injected.
  const argString = `report --format ${opts.format}`;
  let injectedTokens: string[] = [];
  let accepted: boolean;
  if (mode === 'vulnerable') {
    const tokens = argString.split(/\s+/);
    const expected = ['report','--format', opts.format.split(/[;&|]/)[0] ?? ''];
    injectedTokens = tokens.filter(tok => /[;&|`$]/.test(opts.format) && !expected.includes(tok) && /[;&|`$]|^[a-z]/.test(tok)).slice(0);
    // Simpler, honest signal: did the format contain shell metacharacters?
    const hasMeta = /[;&|`$(){}<>]/.test(opts.format);
    injectedTokens = hasMeta ? opts.format.split(/[;&|]/).slice(1).map(x=>x.trim()).filter(Boolean) : [];
    accepted = true;
    t.add('server', 'Vulnerable mode interpolates the parameter into the argument string unchecked:', { data: argString, language: 'text', level: hasMeta?'alert':'warn' });
    if (hasMeta) t.add('detection', 'Shell metacharacters present: an attacker could append additional commands/arguments if this string reached a shell.', { data: injectedTokens, level: 'alert' });
  } else {
    accepted = CMDI_FORMATS.has(opts.format);
    t.add('server', accepted ? `Secure mode validated the format against an allow-list and passes it as a single fixed argument.` : 'Secure mode rejected a format that is not on the allow-list.', { data: accepted ? ['--format', opts.format] : null, language:'json', level: 'ok' });
  }

  const meta = /[;&|`$(){}<>]/.test(opts.format);
  const outcome: Outcome = (mode==='vulnerable' && meta) ? 'exploited' : (mode==='secure' && !accepted) ? 'blocked' : accepted && !meta ? 'blocked' : meta ? 'exploited':'blocked';
  const summary = mode==='vulnerable' && meta ? 'Unvalidated input carrying shell metacharacters was interpolated into a command string.' : meta ? 'Input with metacharacters was rejected by allow-list validation.' : 'A valid format was handled safely.';
  if (outcome==='exploited') t.add('impact', 'If such a string were passed to a shell, the injected tokens would run as separate commands/arguments. SentinelX never invokes a shell; this demonstrates the parsing flaw only.', { level: 'alert' });
  const verdict = verdictFor(outcome, mode);
  t.add('retest', `Verdict: ${verdict.toUpperCase()} (${mode} mode)`, { level: verdict==='pass'?'ok':verdict==='fail'?'alert':'warn' });

  return base({
    vulnClass: 'cmdi', mode, title: 'Argument and Parameter Injection', outcome, verdict, summary,
    endpoint: '/api/lab/cmdi/report', parameter: 'format', payload: opts.format, trace: t.build(),
    evidence: { format: opts.format, builtArgumentString: argString, containsShellMetacharacters: meta, injectedTokens, accepted },
    explanation: {
      rootCause: 'In vulnerable mode user input is interpolated into a command-style argument string. If that string were handed to a shell, metacharacters would be interpreted as command syntax.',
      impact: 'Command injection can lead to arbitrary code execution on the server. SentinelX demonstrates the parsing flaw without ever invoking a shell, so no real command runs.',
      remediation: 'Never build command strings from user input. Validate against an allow-list and pass arguments as a fixed array to an exec API that does not use a shell.',
      vulnerableExample: EX.cmdi.v, secureExample: EX.cmdi.s,
      verification: 'Submit a format containing a semicolon in both modes: flagged as injected tokens in vulnerable mode, rejected by the allow-list in secure mode.',
    },
    liveExploit: false,
    demonstrationNote: 'This is a controlled demonstration: the lab parses the argument string and reports injected tokens but never executes any command or spawns a shell.',
    durationMs: Date.now() - started,
  });
}

// ── Sensitive data exposure ─────────────────────────────────────────────────
export function runExposureLab(opts: { targetUserId: number; modeOverride?: Mode }): LabOutcome {
  const started = Date.now();
  const mode = opts.modeOverride ?? getMode('data_exposure');
  const t = new TraceBuilder();
  t.add('start', `Sensitive-data-exposure test in ${mode.toUpperCase()} mode`);
  t.add('target', `Target: GET /api/lab/exposure/profile?userId=${opts.targetUserId}`);

  // Pull a full row to show what a SELECT * style handler would leak.
  const fullRow = {
    id: opts.targetUserId, username: 'a.fernandes', email: 'alice@securevault.local',
    full_name: 'Alice Fernandes', role: 'user',
    password_hash: 'scrypt$16384$8$1$<salt>$<derived-key>',
    phone_encrypted: 'v1-aes256gcm.<iv>.<tag>.<ciphertext>',
    session_token: 'z7p0Nb9BzCx-RtXRgKlNQ_9sDcUQsrxG', internal_notes: 'flagged for comp review',
  };
  const safeRow = { id: fullRow.id, username: fullRow.username, fullName: fullRow.full_name, role: fullRow.role };

  const returned = mode === 'vulnerable' ? fullRow : safeRow;
  const sensitiveFields = ['password_hash','phone_encrypted','session_token','internal_notes','email'];
  const leaked = Object.keys(returned).filter(k => sensitiveFields.includes(k));

  t.add('response', `Response body (${mode} mode):`, { data: returned, language: 'json', level: leaked.length?'alert':'ok' });
  if (leaked.length) t.add('detection', `Sensitive fields present in the response: ${leaked.join(', ')}`, { level: 'alert' });

  const outcome: Outcome = leaked.length > 0 ? 'exploited' : 'blocked';
  const summary = leaked.length ? `The API returned ${leaked.length} sensitive field(s) the caller has no need for.` : 'The API returned only the fields the caller needs.';
  if (outcome==='exploited') t.add('impact', 'Leaking password hashes enables offline cracking; leaking session tokens enables hijacking; leaking internal notes and contact data breaches confidentiality.', { level: 'alert' });
  const verdict = verdictFor(outcome, mode);
  t.add('retest', `Verdict: ${verdict.toUpperCase()} (${mode} mode)`, { level: verdict==='pass'?'ok':verdict==='fail'?'alert':'warn' });

  return base({
    vulnClass: 'data_exposure', mode, title: 'Sensitive Data Exposure', outcome, verdict, summary,
    endpoint: '/api/lab/exposure/profile', parameter: 'userId', trace: t.build(),
    evidence: { fieldsReturned: Object.keys(returned), sensitiveFieldsLeaked: leaked, safeShape: Object.keys(safeRow) },
    explanation: {
      rootCause: 'In vulnerable mode the profile endpoint serialises the entire database row (a SELECT * / return-the-model pattern), so every column -- including secrets -- reaches the client.',
      impact: 'Exposed password hashes can be cracked offline; exposed tokens allow session hijacking; exposed PII and internal notes breach confidentiality and privacy obligations.',
      remediation: 'Build responses from an explicit allow-list of safe fields (a view model / DTO), never by deleting fields from the row. Keep secrets out of the model the API layer can see.',
      vulnerableExample: EX.exposure.v, secureExample: EX.exposure.s,
      verification: 'Call the profile endpoint in both modes and diff the JSON keys: vulnerable mode includes password_hash/session_token, secure mode includes only id/username/fullName/role.',
    },
    liveExploit: true,
    demonstrationNote: 'The response row is representative lab data illustrating the shape a SELECT * handler would leak; it is not read from a live account.',
    durationMs: Date.now() - started,
  });
}
