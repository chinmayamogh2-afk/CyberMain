/**
 * Cross-Site Scripting laboratory -- reflected and stored (spec section 7).
 *
 * The lab does not "show a popup and call it XSS". It demonstrates the full
 * data flow: where attacker input enters (source), where it is written into a
 * response (sink), the execution context, and whether the browser would parse
 * it as markup. The determination is made by actually attempting to HTML-encode
 * the value the way the secure path does and comparing the result, rather than
 * by guessing.
 *
 * No payload is executed on the server. The lab reports whether the OUTPUT would
 * carry live markup to a browser; it is the encoding decision that is under
 * test, which is the real control for XSS.
 */
import { getMode, type Mode, type VulnClass } from '../security/modes.js';
import { encodeHtml, detectPayloads } from '../security/sanitize.js';
import { TraceBuilder, verdictFor, type LabOutcome, type Outcome } from '../engine/types.js';

const dec = (s: string): string => Buffer.from(s, 'base64').toString('utf8');

export interface XssPayloadDef {
  id: string;
  label: string;
  input: string;
  teaches: string;
}

export const XSS_PAYLOADS: XssPayloadDef[] = [
  { id: "benign", label: "Plain text (control)", input: dec("aGVsbG8gZnJvbSB0aGUgZmluYW5jZSB0ZWFt"), teaches: "Ordinary text, to show the normal rendering path before any markup is introduced." },
  { id: "img-onerror", label: "Markup with an event handler", input: dec("PGltZyBzcmM9eCBvbmVycm9yPSJkb2N1bWVudC50aXRsZT0neHNzJyI+"), teaches: "A broken image whose error handler runs script. This is the classic payload that survives naive '<script> blocking' because it uses a different tag and an attribute handler." },
  { id: "script-tag", label: "Script element", input: dec("PHNjcmlwdD53aW5kb3cuX194c3NfZGVtbz0xPFwvc2NyaXB0Pg=="), teaches: "The textbook case: a script element injected into the page. Blocked entirely by output encoding, which turns the angle brackets into visible text." },
  { id: "svg-onload", label: "SVG load handler", input: dec("PHN2ZyBvbmxvYWQ9IndpbmRvdy5fX3hzc19kZW1vPTEiPjwvc3ZnPg=="), teaches: "An SVG element with a load handler, demonstrating that the browser executes handlers on many elements, not just script tags." }
];

const VULN_EXAMPLE = dec("Ly8gVlVMTkVSQUJMRTogdGhlIHN0b3JlZCB2YWx1ZSBpcyBwbGFjZWQgaW50byB0aGUgSFRNTCByZXNwb25zZSBhcy1pcy4KcmVzLnNlbmQoYDxkaXYgY2xhc3M9ImNvbW1lbnQiPiR7Y29tbWVudC5ib2R5fTwvZGl2PmApOwovLyBJZiBib2R5IGNvbnRhaW5zIG1hcmt1cCwgdGhlIGJyb3dzZXIgcGFyc2VzIGl0IGFzIHBhcnQgb2YgdGhlIGRvY3VtZW50Lg==");
const SECURE_EXAMPLE = dec("Ly8gU0VDVVJFOiB0aGUgdmFsdWUgaXMgSFRNTC1lbmNvZGVkIGZvciB0aGUgY29udGV4dCBpdCBsYW5kcyBpbi4KcmVzLnNlbmQoYDxkaXYgY2xhc3M9ImNvbW1lbnQiPiR7ZW5jb2RlSHRtbChjb21tZW50LmJvZHkpfTwvZGl2PmApOwovLyA8IGJlY29tZXMgJmx0Oywgc28gdGhlIGJyb3dzZXIgcmVuZGVycyB0aGUgbWFya3VwIGFzIGxpdGVyYWwgdGV4dCwgbm90IG5vZGVzLgovLyBBIHJlc3RyaWN0aXZlIENvbnRlbnQtU2VjdXJpdHktUG9saWN5IHByb3ZpZGVzIGEgc2Vjb25kLCBpbmRlcGVuZGVudCBsYXllci4=");

/**
 * Does this string, as written into HTML element content, carry markup the
 * browser would parse into nodes?
 *
 * The decisive question in this (element-content) context is whether a literal
 * tag-opening `<` survives in the output. Once the value is HTML-encoded that
 * `<` becomes `&lt;`, no tag can form, and any `onerror=`/`javascript:` text
 * left inside is inert because it is not inside a real attribute. So we test
 * for a literal `<` beginning a tag and nothing else -- checking for `on...=`
 * substrings would wrongly flag already-encoded output as dangerous.
 */
function carriesLiveMarkup(html: string): boolean {
  return /<\s*\/?[a-zA-Z]/.test(html);
}

export type XssVariant = 'reflected' | 'stored';

export interface XssInput {
  input: string;
  variant: XssVariant;
  modeOverride?: Mode;
}

export function runXssLab(input: XssInput): LabOutcome {
  const started = Date.now();
  const vulnClass: VulnClass = input.variant === 'stored' ? 'xss_stored' : 'xss_reflected';
  const mode: Mode = input.modeOverride ?? getMode(vulnClass);
  const t = new TraceBuilder();
  const endpoint = input.variant === 'stored' ? '/api/lab/xss/comments' : '/api/lab/xss/search';

  t.add('start', `${input.variant === 'stored' ? 'Stored' : 'Reflected'} XSS test starting in ${mode.toUpperCase()} mode`);
  t.add('target', `Target endpoint: ${endpoint}`);
  t.add('payload', 'Attacker-supplied input (the source):', { data: input.input, language: 'html' });

  const signatures = detectPayloads(input.input);
  if (signatures.length > 0) {
    t.add('detection', `Input matches ${signatures.length} XSS signature(s)`, {
      data: signatures.map((s) => s.label),
      level: 'warn',
    });
  }

  // The secure path encodes the value; the vulnerable path emits it verbatim.
  const emitted = mode === 'secure' ? encodeHtml(input.input) : input.input;
  t.add('server', input.variant === 'stored'
    ? 'Server persists the value, then writes it into a page served to other users (the sink).'
    : 'Server reflects the value straight back into the response page (the sink).');
  t.add('response', `HTML written to the response (${mode} mode):`, {
    data: `<div class="comment">${emitted}</div>`,
    language: 'html',
    level: mode === 'secure' ? 'ok' : 'warn',
  });

  const live = carriesLiveMarkup(emitted);
  const inputHadMarkup = carriesLiveMarkup(input.input);

  let outcome: Outcome;
  let summary: string;
  if (!inputHadMarkup) {
    outcome = 'blocked';
    summary = 'Control: the input contained no markup, so nothing executes in either mode.';
  } else if (live) {
    outcome = 'exploited';
    summary = 'The injected markup reaches the browser intact and would execute in the victim\'s session context.';
  } else {
    outcome = 'blocked';
    summary = 'Output encoding neutralised the markup: the browser renders it as visible text, not nodes.';
  }

  t.add('detection', outcome === 'exploited' ? 'VULNERABILITY CONFIRMED: live markup in output' : 'No executable markup in output', {
    level: outcome === 'exploited' ? 'alert' : 'ok',
  });
  if (outcome === 'exploited') {
    t.add('impact', input.variant === 'stored'
      ? 'Stored XSS executes for every user who views the content -- session theft, action-on-behalf, credential capture.'
      : 'Reflected XSS executes when a victim follows a crafted link -- session theft, action-on-behalf, credential capture.',
      { level: 'alert' });
  }

  const verdict = verdictFor(outcome, mode);
  t.add('retest', `Verdict: ${verdict.toUpperCase()} (${mode} mode)`, {
    level: verdict === 'pass' ? 'ok' : verdict === 'fail' ? 'alert' : 'warn',
  });

  return {
    vulnClass,
    mode,
    title: input.variant === 'stored' ? 'Stored Cross-Site Scripting' : 'Reflected Cross-Site Scripting',
    outcome,
    verdict,
    summary,
    endpoint,
    parameter: input.variant === 'stored' ? 'body' : 'q',
    payload: input.input,
    trace: t.build(),
    exchange: {
      method: input.variant === 'stored' ? 'POST' : 'GET',
      url: endpoint,
      headers: { 'content-type': input.variant === 'stored' ? 'application/json' : 'text/html' },
      body: input.variant === 'stored' ? { body: input.input } : undefined,
      response: {
        status: 200,
        headers: { 'content-type': 'text/html; charset=utf-8' },
        body: `<div class="comment">${emitted}</div>`,
      },
    },
    evidence: {
      rawInput: input.input,
      emittedOutput: emitted,
      outputCarriesLiveMarkup: live,
      encodingApplied: mode === 'secure',
      cspWouldBlockInlineScript: mode === 'secure',
      signatures: signatures.map((s) => s.label),
    },
    explanation: {
      rootCause:
        'In vulnerable mode the application writes user input into an HTML response without encoding it for that context, so characters like < and > are parsed as markup. XSS is fundamentally an output-encoding failure, not an input-filtering one.',
      impact:
        'Injected script runs with the victim\'s privileges in their browser: it can read HttpOnly-free cookies, forge requests as the user, capture keystrokes, or deface the page. Stored XSS is worse because it affects every viewer automatically.',
      remediation:
        'Encode output for its context (HTML text, attribute, URL, JS). Add a restrictive Content-Security-Policy that forbids inline script as an independent second layer. Validate input where a format is known, but never rely on input filtering alone.',
      vulnerableExample: VULN_EXAMPLE,
      secureExample: SECURE_EXAMPLE,
      verification:
        'Submit a markup payload in both modes. In secure mode the response contains the encoded entities (&lt;img ...&gt;) shown as text; in vulnerable mode the raw tag is present and would execute.',
      dataFlow: {
        source: input.variant === 'stored' ? 'comment body stored by one user' : 'search query parameter in the request',
        sink: 'HTML element content written into the response',
        context: 'HTML body parsed by the victim\'s browser',
      },
    },
    liveExploit: true,
    demonstrationNote:
      'The payload is analysed on the server and never executed there. The result reflects whether the generated OUTPUT would carry live markup to a browser -- which is precisely the condition that determines XSS.',
    durationMs: Date.now() - started,
  };
}
