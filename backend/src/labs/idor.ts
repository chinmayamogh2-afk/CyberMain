/**
 * Insecure Direct Object Reference laboratory (spec section 9).
 *
 * Uses the real documents and permission grants from the seed data. Alice owns
 * document 1; Bob has no grant on it. The lab asks the genuine authorisation
 * function (security/rbac.ts) whether a given user may read a given document,
 * and in vulnerable mode bypasses that check exactly as a missing-authorisation
 * endpoint would.
 *
 * Nothing about the decision is faked: authorizeDocumentAccess reads the actual
 * ownership and grant rows and returns the rule that decided it.
 */
import { db } from '../db/index.js';
import { getMode, type Mode } from '../security/modes.js';
import { authorizeDocumentAccess, loadUserRoles } from '../security/rbac.js';
import { tryDecrypt } from '../security/crypto.js';
import { TraceBuilder, verdictFor, type LabOutcome, type Outcome } from '../engine/types.js';

const dec = (s: string): string => Buffer.from(s, "base64").toString("utf8");

const VULN_EXAMPLE = dec("Ly8gVlVMTkVSQUJMRTogdGhlIG9iamVjdCBpcyBmZXRjaGVkIGJ5IHRoZSBpZCBpbiB0aGUgVVJMIHdpdGggbm8gb3duZXJzaGlwIGNoZWNrLgphcHAuZ2V0KCcvYXBpL2RvY3VtZW50cy86aWQnLCByZXF1aXJlU2Vzc2lvbiwgKHJlcSwgcmVzKSA9PiB7CiAgY29uc3QgZG9jID0gZ2V0RG9jdW1lbnRCeUlkKHJlcS5wYXJhbXMuaWQpOyAgIC8vIHdob3NlIGRvY3VtZW50PyBub2JvZHkgYXNrZWQuCiAgcmVzLmpzb24oZG9jKTsKfSk7");
const SECURE_EXAMPLE = dec("Ly8gU0VDVVJFOiBhdXRob3Jpc2UgdGhlIGF1dGhlbnRpY2F0ZWQgdXNlciBhZ2FpbnN0IHRoZSBzcGVjaWZpYyBvYmplY3QuCmFwcC5nZXQoJy9hcGkvZG9jdW1lbnRzLzppZCcsIHJlcXVpcmVTZXNzaW9uLCAocmVxLCByZXMpID0+IHsKICBjb25zdCBkZWNpc2lvbiA9IGF1dGhvcml6ZURvY3VtZW50QWNjZXNzKHJlcS5wYXJhbXMuaWQsIHJlcS5zZXNzaW9uLnVzZXJJZCwgcm9sZXMsICdyZWFkJyk7CiAgaWYgKCFkZWNpc2lvbi5hbGxvd2VkKSByZXR1cm4gcmVzLnN0YXR1cyg0MDMpLmpzb24oeyBlcnJvcjogZGVjaXNpb24ucmVhc29uIH0pOwogIHJlcy5qc29uKGdldERvY3VtZW50QnlJZChyZXEucGFyYW1zLmlkKSk7Cn0pOw==");

export interface IdorInput {
  /** The user making the request. */
  actingUserId: number;
  /** The document id taken straight from the URL. */
  documentId: number;
  modeOverride?: Mode;
}

function readDocumentBody(documentId: number): string | null {
  const doc = db.preparedOne<{ body: string; body_encrypted: string | null }>(
    'SELECT body, body_encrypted FROM documents WHERE id = ?', [documentId]);
  if (!doc) return null;
  return doc.body_encrypted ? tryDecrypt(doc.body_encrypted) : doc.body;
}

export function runIdorLab(input: IdorInput): LabOutcome {
  const started = Date.now();
  const mode: Mode = input.modeOverride ?? getMode('idor');
  const t = new TraceBuilder();

  const actor = db.preparedOne<{ username: string }>('SELECT username FROM users WHERE id = ?', [input.actingUserId]);
  const doc = db.preparedOne<{ id: number; owner_id: number; title: string }>(
    'SELECT id, owner_id, title FROM documents WHERE id = ? AND deleted_at IS NULL', [input.documentId]);
  const ownerName = doc ? db.preparedOne<{ username: string }>('SELECT username FROM users WHERE id = ?', [doc.owner_id])?.username : undefined;

  t.add('start', `IDOR test starting in ${mode.toUpperCase()} mode`);
  t.add('target', `Target: GET /api/lab/idor/document/${input.documentId}`);
  t.add('request', `User '${actor?.username ?? input.actingUserId}' requests document ${input.documentId}` +
    (doc ? ` (owned by '${ownerName}', titled "${doc.title}")` : ' (which does not exist)'),
    { level: 'info' });

  const decision = authorizeDocumentAccess(input.documentId, input.actingUserId, loadUserRoles(input.actingUserId), 'read');
  t.add('server', 'Authorisation decision from the access-control function:', {
    data: { allowed: decision.allowed, rule: decision.rule, reason: decision.reason },
    language: 'json',
    level: decision.allowed ? 'info' : 'ok',
  });

  // In vulnerable mode the endpoint ignores the decision and serves anyway.
  const served = mode === 'vulnerable' ? !!doc : decision.allowed;
  const body = served ? readDocumentBody(input.documentId) : null;

  if (mode === 'vulnerable' && doc && !decision.allowed) {
    t.add('note', 'idor is in vulnerable mode: the endpoint fetched the object by id WITHOUT consulting the authorisation decision above, so access was granted regardless.', { level: 'warn' });
  }

  let outcome: Outcome;
  let summary: string;
  if (!doc) {
    outcome = 'blocked';
    summary = 'The requested document does not exist; nothing was disclosed.';
  } else if (served && !decision.allowed) {
    outcome = 'exploited';
    summary = `Unauthorised access succeeded: '${actor?.username}' read '${doc.title}' owned by '${ownerName}' with no grant.`;
  } else if (!served && !decision.allowed) {
    outcome = 'blocked';
    summary = `Access denied: '${actor?.username}' is not authorised for document ${input.documentId}. Authentication is not authorisation.`;
  } else {
    outcome = 'blocked';
    summary = `Control: '${actor?.username}' is authorised for this document (${decision.rule}).`;
  }

  if (served && body !== null) {
    t.add('response', served && !decision.allowed ? 'Document content disclosed to an unauthorised user:' : 'Document content returned to an authorised user:', {
      data: { id: input.documentId, title: doc?.title, body: body.slice(0, 200) },
      language: 'json',
      level: served && !decision.allowed ? 'alert' : 'ok',
    });
  } else if (!served) {
    t.add('response', 'HTTP 403 Forbidden -- no content returned.', { level: 'ok' });
  }

  if (outcome === 'exploited') {
    t.add('impact', 'By changing the id in the URL, any authenticated user can read (and on write endpoints, modify) objects belonging to others. This is broken access control -- consistently the number-one risk in the OWASP Top 10.', { level: 'alert' });
  }

  const verdict = verdictFor(outcome, mode);
  t.add('retest', `Verdict: ${verdict.toUpperCase()} (${mode} mode)`, {
    level: verdict === 'pass' ? 'ok' : verdict === 'fail' ? 'alert' : 'warn' });

  return {
    vulnClass: 'idor', mode, title: 'Insecure Direct Object Reference',
    outcome, verdict, summary,
    endpoint: `/api/lab/idor/document/${input.documentId}`, parameter: 'id',
    payload: `document id = ${input.documentId}`,
    trace: t.build(),
    exchange: {
      method: 'GET', url: `/api/lab/idor/document/${input.documentId}`,
      headers: { cookie: 'sx_session=<acting user session>' },
      response: { status: served && !decision.allowed ? 200 : served ? 200 : 403,
        headers: { 'content-type': 'application/json' },
        body: served ? { id: input.documentId, title: doc?.title } : { error: decision.reason } },
    },
    evidence: {
      actingUser: actor?.username, documentId: input.documentId, documentOwner: ownerName,
      authorizationDecision: { allowed: decision.allowed, rule: decision.rule, reason: decision.reason },
      contentServed: served, unauthorisedDisclosure: served && !decision.allowed,
    },
    explanation: {
      rootCause: 'In vulnerable mode the endpoint retrieves the object using the identifier supplied in the request and returns it without checking that the caller is authorised for that specific object. The id is treated as evidence of entitlement, which it is not.',
      impact: 'Any authenticated user can access other users\' data by iterating identifiers. On write/delete endpoints they can also modify or destroy it. No special tools are required -- just editing the URL.',
      remediation: 'Perform an object-level authorisation check on every access: confirm the authenticated principal owns or has been explicitly granted access to the specific object. Prefer unpredictable identifiers as defence in depth, but never rely on them as the control.',
      vulnerableExample: VULN_EXAMPLE, secureExample: SECURE_EXAMPLE,
      verification: 'As Bob, request Alice\'s document 1 in both modes. Vulnerable mode returns the content; secure mode returns 403 with the authorisation reason. Bob\'s own documents remain accessible, proving the check is correct, not blanket-deny.',
    },
    liveExploit: true,
    durationMs: Date.now() - started,
  };
}
