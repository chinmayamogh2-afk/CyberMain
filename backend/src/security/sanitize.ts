/**
 * Output encoding and input sanitisation.
 *
 * The distinction this module exists to make explicit: XSS is not fixed by
 * "filtering bad input", it is fixed by encoding output correctly *for the
 * context it lands in*. The same string needs different treatment in HTML text,
 * in an attribute, in a URL and inside a <script> block — which is why there are
 * several functions here rather than one `clean()`.
 */

/**
 * Encodes text for interpolation into HTML element content.
 *
 * Encodes the five characters that can break out of text context. With this
 * applied, `<script>` arrives at the browser as literal text and is displayed,
 * not parsed — which is the whole fix for reflected and stored XSS.
 */
export function encodeHtml(input: string): string {
  return input
    .replace(/&/g, '&amp;') // must be first, or later entities get double-encoded
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;');
}

/**
 * Encodes text for an unquoted-attribute-safe context.
 *
 * Stricter than `encodeHtml`: anything that is not alphanumeric is escaped as a
 * hex entity. Needed because inside an attribute a space or backtick can
 * terminate the value and introduce a new attribute such as `onerror=`.
 */
export function encodeHtmlAttribute(input: string): string {
  return input.replace(/[^a-zA-Z0-9\-_.]/g, (ch) => {
    const code = ch.codePointAt(0)!;
    return `&#x${code.toString(16)};`;
  });
}

/** Encodes for inclusion in a URL query component. */
export function encodeUrlComponent(input: string): string {
  return encodeURIComponent(input);
}

/**
 * Encodes a string for embedding inside a <script> block as a JS string literal.
 *
 * `</script>` must be broken up even inside a quoted string, because the HTML
 * parser finds the closing tag before the JS parser ever sees the string.
 */
export function encodeJsString(input: string): string {
  return input
    .replace(/\\/g, '\\\\')
    .replace(/'/g, "\\'")
    .replace(/"/g, '\\"')
    .replace(/\n/g, '\\n')
    .replace(/\r/g, '\\r')
    .replace(/</g, '\\u003c')
    .replace(/>/g, '\\u003e')
    .replace(/\u2028/g, '\\u2028') // line separator: a literal newline in JS
    .replace(/\u2029/g, '\\u2029');
}

/**
 * Removes markup entirely, keeping only text.
 *
 * Used where the field is specified as plain text (a display name, a search
 * term). Sanitisation by removal is appropriate when markup is never legitimate;
 * it is NOT a substitute for output encoding elsewhere.
 */
export function stripTags(input: string): string {
  return input.replace(/<[^>]*>/g, '');
}

/** Tags permitted when a field is genuinely allowed to carry limited markup. */
const ALLOWED_TAGS = new Set(['b', 'i', 'em', 'strong', 'code', 'p', 'br', 'ul', 'ol', 'li']);

/**
 * Allow-list sanitiser for rich text.
 *
 * Deliberately an allow-list, not a deny-list. Deny-lists fail: blocking
 * `<script>` still permits `<img onerror=…>`, `<svg onload=…>`, `<iframe
 * srcdoc=…>` and every tag invented after the list was written. Here, anything
 * not explicitly named is encoded, and ALL attributes are dropped — including
 * every `on*` handler and `javascript:` URL — because none of the permitted
 * tags needs one.
 */
export function sanitizeRichText(input: string): string {
  return input.replace(/<\/?([a-zA-Z0-9]+)(\s[^>]*)?>/g, (match, rawTag: string) => {
    const tag = rawTag.toLowerCase();
    if (!ALLOWED_TAGS.has(tag)) return encodeHtml(match);
    const closing = match.startsWith('</') ? '/' : '';
    return `<${closing}${tag}>`;
  });
}

/**
 * Heuristics that recognise common attack payloads.
 *
 * These power *detection and alerting* — the live event console and the
 * request flagger — not prevention. That distinction matters: a WAF-style
 * pattern match is trivially bypassed and must never be the control a system
 * relies on. Parameterised queries and output encoding are the controls; this
 * is the smoke alarm.
 */
export interface PayloadSignature {
  id: string;
  label: string;
  vulnClass: string;
  pattern: RegExp;
}

export const PAYLOAD_SIGNATURES: PayloadSignature[] = [
  {
    id: 'sqli-tautology',
    label: "SQL tautology (e.g. ' OR '1'='1)",
    vulnClass: 'sqli',
    pattern: /('|%27)\s*(or|and)\s*('?\d+'?\s*=\s*'?\d+'?|'[^']*'\s*=\s*'[^']*')/i,
  },
  {
    id: 'sqli-comment',
    label: 'SQL comment terminator (-- or /*)',
    vulnClass: 'sqli',
    pattern: /('|%27)?\s*(--|#|\/\*)/,
  },
  {
    id: 'sqli-union',
    label: 'UNION SELECT injection',
    vulnClass: 'sqli',
    pattern: /\bunion\b[\s\S]{0,40}\bselect\b/i,
  },
  {
    id: 'sqli-stacked',
    label: 'Stacked statement (; DROP/INSERT/UPDATE)',
    vulnClass: 'sqli',
    pattern: /;\s*(drop|insert|update|delete|alter|create)\b/i,
  },
  {
    id: 'xss-script-tag',
    label: '<script> tag',
    vulnClass: 'xss_reflected',
    pattern: /<\s*script\b/i,
  },
  {
    id: 'xss-event-handler',
    label: 'Inline event handler (onerror/onload/onclick)',
    vulnClass: 'xss_reflected',
    pattern: /\bon(error|load|click|mouseover|focus|animationstart)\s*=/i,
  },
  {
    id: 'xss-js-uri',
    label: 'javascript: URI',
    vulnClass: 'xss_reflected',
    pattern: /javascript\s*:/i,
  },
  {
    id: 'xss-svg-img',
    label: 'Markup injection via <svg>/<img>/<iframe>',
    vulnClass: 'xss_reflected',
    pattern: /<\s*(svg|img|iframe|object|embed|body|details)\b/i,
  },
  {
    id: 'traversal-dotdot',
    label: 'Directory traversal sequence (../)',
    vulnClass: 'path_traversal',
    pattern: /(\.\.[/\\]|%2e%2e[/\\%]|\.\.%2f)/i,
  },
  {
    id: 'traversal-abs-path',
    label: 'Absolute path to a sensitive file',
    vulnClass: 'path_traversal',
    pattern: /(\/etc\/passwd|\/proc\/self|\.ssh\/id_|\.env\b)/i,
  },
  {
    id: 'cmdi-separator',
    label: 'Command separator or substitution',
    vulnClass: 'cmdi',
    pattern: /(\|\||&&|;\s*\w+|\$\(|`)/,
  },
  {
    id: 'ssrf-internal-target',
    label: 'URL aimed at an internal or metadata address',
    vulnClass: 'ssrf',
    pattern: /(169\.254\.169\.254|127\.0\.0\.1|localhost|0\.0\.0\.0|\[::1\]|metadata\.)/i,
  },
  {
    id: 'ssrf-scheme',
    label: 'Dangerous URL scheme (file:/gopher:/dict:)',
    vulnClass: 'ssrf',
    pattern: /\b(file|gopher|dict|ftp):\/\//i,
  },
];

export interface DetectedPayload {
  id: string;
  label: string;
  vulnClass: string;
  matched: string;
}

/** Returns every signature matching the text. */
export function detectPayloads(text: string): DetectedPayload[] {
  if (!text) return [];
  const hits: DetectedPayload[] = [];
  for (const sig of PAYLOAD_SIGNATURES) {
    const m = sig.pattern.exec(text);
    if (m) {
      hits.push({
        id: sig.id,
        label: sig.label,
        vulnClass: sig.vulnClass,
        matched: m[0].slice(0, 120),
      });
    }
  }
  return hits;
}

/** Scans every value in an object tree, returning hits with their field paths. */
export function scanForPayloads(
  source: unknown,
  pathPrefix = '',
): { field: string; hit: DetectedPayload }[] {
  const out: { field: string; hit: DetectedPayload }[] = [];
  const walk = (value: unknown, fieldPath: string, depth: number): void => {
    if (depth > 5) return;
    if (typeof value === 'string') {
      for (const hit of detectPayloads(value)) out.push({ field: fieldPath || '(body)', hit });
      return;
    }
    if (Array.isArray(value)) {
      value.forEach((v, i) => walk(v, `${fieldPath}[${i}]`, depth + 1));
      return;
    }
    if (value && typeof value === 'object') {
      for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
        walk(v, fieldPath ? `${fieldPath}.${k}` : k, depth + 1);
      }
    }
  };
  walk(source, pathPrefix, 0);
  return out;
}
