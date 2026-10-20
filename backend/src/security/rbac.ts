/**
 * Role-based access control (§4).
 *
 * Three roles with increasing privilege. Authorisation decisions are made from
 * roles loaded out of the database for the authenticated user — never from a
 * claim supplied by the client, which would be parameter manipulation waiting to
 * happen.
 *
 * Every decision returns a *reason*, so the IDOR lab and the attack-surface view
 * can show the authorisation logic rather than just its verdict (§9).
 */
import { db } from '../db/index.js';

export type RoleName = 'user' | 'analyst' | 'admin';

export const ROLE_RANK: Record<RoleName, number> = { user: 10, analyst: 20, admin: 30 };

export interface RoleDefinition {
  name: RoleName;
  label: string;
  description: string;
  rank: number;
  /** Capabilities granted, for display in the Users console. */
  capabilities: string[];
}

export const ROLES: Record<RoleName, RoleDefinition> = {
  user: {
    name: 'user',
    label: 'User',
    description:
      'Standard SecureVault account. Can manage its own documents and messages and nothing else.',
    rank: 10,
    capabilities: [
      'documents:read:own',
      'documents:write:own',
      'documents:share:own',
      'messages:send',
      'profile:manage:own',
      'sessions:manage:own',
    ],
  },
  analyst: {
    name: 'analyst',
    label: 'Security Analyst',
    description:
      'Runs assessments and triages findings. Can read security data but cannot alter user accounts.',
    rank: 20,
    capabilities: [
      'documents:read:own',
      'documents:write:own',
      'messages:send',
      'profile:manage:own',
      'sessions:manage:own',
      'security:scan',
      'security:simulate',
      'findings:read',
      'findings:triage',
      'reports:generate',
      'audit:read',
      'modes:read',
    ],
  },
  admin: {
    name: 'admin',
    label: 'Administrator',
    description:
      'Full administrative control, including the security mode registry and user management.',
    rank: 30,
    capabilities: [
      'documents:read:any',
      'documents:write:any',
      'messages:send',
      'profile:manage:any',
      'sessions:manage:any',
      'security:scan',
      'security:simulate',
      'findings:read',
      'findings:triage',
      'reports:generate',
      'audit:read',
      'modes:read',
      'modes:write',
      'users:manage',
    ],
  },
};

export function loadUserRoles(userId: number): RoleName[] {
  const rows = db.prepared<{ name: string }>(
    `SELECT r.name
       FROM user_roles ur
       JOIN roles r ON r.id = ur.role_id
      WHERE ur.user_id = ?
      ORDER BY r.rank DESC`,
    [userId],
  );
  return rows
    .map((r) => r.name)
    .filter((n): n is RoleName => n === 'user' || n === 'analyst' || n === 'admin');
}

export function highestRole(roles: RoleName[]): RoleName {
  return roles.reduce<RoleName>(
    (best, r) => (ROLE_RANK[r] > ROLE_RANK[best] ? r : best),
    'user',
  );
}

export function capabilitiesFor(roles: RoleName[]): string[] {
  const set = new Set<string>();
  for (const role of roles) {
    for (const cap of ROLES[role].capabilities) set.add(cap);
  }
  return [...set].sort();
}

export function hasCapability(roles: RoleName[], capability: string): boolean {
  return capabilitiesFor(roles).includes(capability);
}

export function hasRole(roles: RoleName[], required: RoleName): boolean {
  return roles.some((r) => ROLE_RANK[r] >= ROLE_RANK[required]);
}

// ── Object-level authorisation ──────────────────────────────────────────────

export type AccessCapability = 'read' | 'write' | 'owner';

export interface AuthorizationDecision {
  allowed: boolean;
  /** The rule that decided it, in words the UI can display verbatim. */
  reason: string;
  /** Which check produced the decision. */
  rule:
    | 'ownership'
    | 'explicit_grant'
    | 'administrative_override'
    | 'no_matching_grant'
    | 'object_missing';
  matchedGrant?: { capability: string; grantedBy: number | null; grantedAt: string };
}

const CAPABILITY_IMPLIES: Record<AccessCapability, AccessCapability[]> = {
  read: ['read', 'write', 'owner'],
  write: ['write', 'owner'],
  owner: ['owner'],
};

/**
 * Decides whether a user may act on a document.
 *
 * This is THE function the IDOR lab turns on. Checks, in order:
 *   1. does the object exist,
 *   2. is the caller the owner,
 *   3. is there an explicit permission grant of sufficient capability,
 *   4. is the caller an administrator (logged as an override, not a free pass).
 *
 * Note what is absent: the document identifier from the URL is never itself
 * treated as evidence of entitlement. Authentication proves *who* you are;
 * authorisation — this function — decides *what* you may touch.
 */
export function authorizeDocumentAccess(
  documentId: number,
  userId: number,
  roles: RoleName[],
  required: AccessCapability,
): AuthorizationDecision {
  const doc = db.preparedOne<{ id: number; owner_id: number; title: string }>(
    'SELECT id, owner_id, title FROM documents WHERE id = ? AND deleted_at IS NULL',
    [documentId],
  );

  if (!doc) {
    return {
      allowed: false,
      reason: `Document ${documentId} does not exist (or has been deleted).`,
      rule: 'object_missing',
    };
  }

  if (doc.owner_id === userId) {
    return {
      allowed: true,
      reason: `User ${userId} is the owner of document ${documentId}.`,
      rule: 'ownership',
    };
  }

  const accepted = CAPABILITY_IMPLIES[required];
  const grant = db.preparedOne<{ capability: string; granted_by: number | null; granted_at: string }>(
    `SELECT capability, granted_by, granted_at
       FROM document_permissions
      WHERE document_id = ? AND user_id = ?
        AND capability IN (${accepted.map(() => '?').join(', ')})
      LIMIT 1`,
    [documentId, userId, ...accepted],
  );

  if (grant) {
    return {
      allowed: true,
      reason: `User ${userId} holds an explicit '${grant.capability}' grant on document ${documentId}, which satisfies '${required}'.`,
      rule: 'explicit_grant',
      matchedGrant: {
        capability: grant.capability,
        grantedBy: grant.granted_by,
        grantedAt: grant.granted_at,
      },
    };
  }

  if (hasRole(roles, 'admin')) {
    return {
      allowed: true,
      reason: `User ${userId} is an administrator; access granted by administrative override and recorded in the audit log.`,
      rule: 'administrative_override',
    };
  }

  return {
    allowed: false,
    reason: `User ${userId} is not the owner of document ${documentId} and holds no '${required}' grant. Authentication succeeded, authorisation did not.`,
    rule: 'no_matching_grant',
  };
}

/** Document ids a user may read, used for list endpoints. */
export function readableDocumentIds(userId: number, roles: RoleName[]): number[] {
  if (hasRole(roles, 'admin')) {
    return db
      .prepared<{ id: number }>('SELECT id FROM documents WHERE deleted_at IS NULL')
      .map((r) => r.id);
  }
  return db
    .prepared<{ id: number }>(
      `SELECT d.id FROM documents d
        WHERE d.deleted_at IS NULL
          AND (d.owner_id = ?
               OR EXISTS (SELECT 1 FROM document_permissions p
                           WHERE p.document_id = d.id AND p.user_id = ?))`,
      [userId, userId],
    )
    .map((r) => r.id);
}
