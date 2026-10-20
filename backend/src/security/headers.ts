/**
 * Security response headers (§12).
 *
 * The `headers` mode toggle decides whether these are sent. In vulnerable mode
 * they are genuinely absent from the response — the Headers Inspector reads
 * them back off a real HTTP response, so it reports what is actually on the
 * wire, never a stored expectation (§12: "Do not fake these values").
 */
import type { RequestHandler } from 'express';
import { isSecure } from './modes.js';

export interface HeaderSpec {
  name: string;
  /** The value we set in hardened mode. */
  recommended: string;
  purpose: string;
  /** What an attacker gains when it is missing. */
  risk: string;
  /** Whether absence should be treated as a finding by the scanner. */
  required: boolean;
}

export const HEADER_SPECS: HeaderSpec[] = [
  {
    name: 'content-security-policy',
    recommended:
      "default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'",
    purpose:
      'Declares which sources the browser may load scripts, styles and frames from, and forbids inline script execution.',
    risk:
      'Without CSP, any successful HTML injection runs with no second line of defence. CSP is what turns an XSS from critical to largely inert.',
    required: true,
  },
  {
    name: 'strict-transport-security',
    recommended: 'max-age=31536000; includeSubDomains',
    purpose:
      'Instructs the browser to refuse plaintext HTTP to this origin for the stated period.',
    risk:
      'Without HSTS the first request can be downgraded to HTTP and intercepted, so session cookies travel in clear text.',
    // Honest caveat: the demo runs over loopback HTTP, where a browser ignores
    // HSTS. We still set and check it so the control is demonstrable, and the
    // inspector says plainly that it has no effect without TLS.
    required: true,
  },
  {
    name: 'x-content-type-options',
    recommended: 'nosniff',
    purpose: 'Stops the browser second-guessing a declared Content-Type.',
    risk:
      'Without it, a file served as text/plain can be sniffed as HTML and executed, turning an upload into stored XSS.',
    required: true,
  },
  {
    name: 'referrer-policy',
    recommended: 'strict-origin-when-cross-origin',
    purpose: 'Limits how much of the current URL is disclosed in the Referer header.',
    risk:
      'Full-URL referrers leak document identifiers, session tokens in query strings and internal paths to third parties.',
    required: true,
  },
  {
    name: 'permissions-policy',
    recommended: 'camera=(), microphone=(), geolocation=(), payment=(), usb=()',
    purpose: 'Switches off powerful browser APIs the application has no need for.',
    risk:
      'Leaving them enabled widens the attack surface available to injected script (attack-surface reduction).',
    required: true,
  },
  {
    name: 'x-frame-options',
    recommended: 'DENY',
    purpose: 'Legacy clickjacking protection for browsers predating frame-ancestors.',
    risk: 'The application can be framed by an attacker page and clicks hijacked.',
    required: true,
  },
  {
    name: 'cross-origin-opener-policy',
    recommended: 'same-origin',
    purpose: 'Severs the window reference between this page and cross-origin openers.',
    risk: 'A cross-origin opener retains a handle that can be used for XS-Leaks.',
    required: false,
  },
  {
    name: 'cross-origin-resource-policy',
    recommended: 'same-origin',
    purpose: 'Blocks other origins from embedding this resource.',
    risk: 'Resources can be read cross-origin in speculative-execution style attacks.',
    required: false,
  },
];

/** Headers that disclose server internals and should be removed (§: attack surface). */
export const HEADERS_TO_REMOVE = ['x-powered-by', 'server'];

/**
 * Headers deliberately added in vulnerable mode.
 *
 * These are not merely "missing controls" — they are a positive information
 * leak, and the scanner reports them as such.
 */
export const LEAKY_HEADERS: Record<string, string> = {
  'x-powered-by': 'Express 4.21.2',
  'x-aspnet-version': '4.0.30319',
  'x-backend-server': 'securevault-app-01.internal',
  'x-debug-mode': 'enabled',
};

export const securityHeaders: RequestHandler = (_req, res, next) => {
  if (isSecure('headers')) {
    for (const spec of HEADER_SPECS) {
      res.setHeader(spec.name, spec.recommended);
    }
    for (const name of HEADERS_TO_REMOVE) {
      res.removeHeader(name);
    }
  } else {
    // Vulnerable mode: emit the leaky banners an attacker would use for
    // fingerprinting, and send no protective headers at all.
    for (const [name, value] of Object.entries(LEAKY_HEADERS)) {
      res.setHeader(name, value);
    }
  }
  next();
};
