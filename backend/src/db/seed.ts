/**
 * Seed data.
 *
 * Creates the accounts, documents and permission grants that the labs and Demo
 * Mode depend on. In particular the IDOR lab needs a document owned by Alice
 * that Bob has no grant on — that relationship is established here, not faked at
 * request time.
 *
 * Demo passwords are intentionally simple and are printed on seed so they can be
 * typed during a presentation. ENABLE_DEMO_SEED=false skips this entirely.
 */
import { db, migrate } from './index.js';
import { hashPassword, encrypt } from '../security/crypto.js';
import { ROLES, type RoleName } from '../security/rbac.js';
import { VULN_CLASSES } from '../security/modes.js';
import { config } from '../config/env.js';

interface SeedUser {
  username: string;
  email: string;
  password: string;
  fullName: string;
  roles: RoleName[];
  bio: string;
  phone: string;
  recoveryNote: string;
  avatarColour: string;
}

const SEED_USERS: SeedUser[] = [
  {
    username: 'admin',
    email: 'admin@securevault.local',
    password: 'Admin#2024!Vault',
    fullName: 'Priya Raghavan',
    roles: ['admin', 'user'],
    bio: 'Platform administrator. Owns the security mode registry and user lifecycle.',
    phone: '+91-98200-11001',
    recoveryNote: 'Break-glass recovery handled via offline procedure RUN-004.',
    avatarColour: '#f472b6',
  },
  {
    username: 'analyst',
    email: 'analyst@securevault.local',
    password: 'Analyst#2024!Vault',
    fullName: 'Marcus Oyelaran',
    roles: ['analyst', 'user'],
    bio: 'Application security analyst. Runs assessments and triages findings.',
    phone: '+91-98200-11002',
    recoveryNote: 'Assessment notes archived in ticket SEC-1182.',
    avatarColour: '#38bdf8',
  },
  {
    username: 'alice',
    email: 'alice@securevault.local',
    password: 'Alice#2024!Vault',
    fullName: 'Alice Fernandes',
    roles: ['user'],
    bio: 'Finance team. Owns the quarterly reporting pack.',
    phone: '+91-98200-11003',
    recoveryNote: 'Secondary contact: finance-ops@securevault.local',
    avatarColour: '#34d399',
  },
  {
    username: 'bob',
    email: 'bob@securevault.local',
    password: 'Bob#2024!Vault',
    fullName: 'Bob Mehta',
    roles: ['user'],
    bio: 'Engineering. No access to finance documents — the IDOR lab depends on this.',
    phone: '+91-98200-11004',
    recoveryNote: 'Secondary contact: eng-ops@securevault.local',
    avatarColour: '#fbbf24',
  },
];

interface SeedDoc {
  owner: string;
  title: string;
  body: string;
  classification: 'public' | 'internal' | 'confidential' | 'restricted';
  /** username → capability */
  shares?: { user: string; capability: 'read' | 'write' }[];
}

const SEED_DOCS: SeedDoc[] = [
  {
    owner: 'alice',
    title: 'Q3 Financial Summary',
    body:
      'Consolidated revenue 4.82 Cr against a 4.40 Cr plan. Treasury balance held at 1.9 Cr. ' +
      'Audit adjustment pending on deferred revenue recognition for the APAC contracts.',
    classification: 'confidential',
  },
  {
    owner: 'alice',
    title: 'Payroll Variance Notes',
    body:
      'Band-4 adjustments effective next cycle. Three retention cases escalated to the ' +
      'compensation committee. Figures are provisional until HR sign-off.',
    classification: 'restricted',
  },
  {
    owner: 'alice',
    title: 'Vendor Contract — Northwind Logistics',
    body:
      'Three-year term with an annual escalation cap of 6%. Termination for convenience ' +
      'requires 90 days notice. Signed copy held with legal.',
    classification: 'internal',
    shares: [{ user: 'bob', capability: 'read' }],
  },
  {
    owner: 'bob',
    title: 'Service Architecture Notes',
    body:
      'Gateway terminates TLS and forwards to the document service over the internal network. ' +
      'Session store is shared; see the threat model for trust-boundary detail.',
    classification: 'internal',
  },
  {
    owner: 'bob',
    title: 'Incident Retrospective — 2026-08-14',
    body:
      'Elevated 5xx rate for 22 minutes caused by a connection-pool exhaustion. ' +
      'Remediated by bounding pool checkout time. No data loss; no security impact identified.',
    classification: 'internal',
    shares: [{ user: 'analyst', capability: 'read' }],
  },
  {
    owner: 'analyst',
    title: 'Assessment Scope — SecureVault',
    body:
      'In scope: the SecureVault application and its API surface on loopback. ' +
      'Out of scope: every third-party system. Testing is confined to this host (see SECURITY.md).',
    classification: 'internal',
    shares: [{ user: 'admin', capability: 'read' }],
  },
  {
    owner: 'admin',
    title: 'Platform Runbook',
    body:
      'Mode registry defaults to hardened on a fresh install. Reseed with scripts/reset-demo.sh. ' +
      'Secrets are read from the environment only; nothing is committed.',
    classification: 'internal',
  },
];

interface SeedMessage {
  from: string;
  to: string;
  subject: string;
  body: string;
}

const SEED_MESSAGES: SeedMessage[] = [
  {
    from: 'alice',
    to: 'bob',
    subject: 'Northwind contract review',
    body: 'Shared the vendor contract with you — read access only. Could you check clause 7?',
  },
  {
    from: 'bob',
    to: 'alice',
    subject: 'Re: Northwind contract review',
    body: 'Looked at it. Clause 7 escalation cap matches what we agreed. No concerns.',
  },
  {
    from: 'analyst',
    to: 'admin',
    subject: 'Assessment window',
    body: 'Starting the scheduled assessment against the loopback instance this afternoon.',
  },
];

function seedRoles(): void {
  for (const role of Object.values(ROLES)) {
    db.run(
      `INSERT INTO roles (name, label, description, rank) VALUES (?, ?, ?, ?)
         ON CONFLICT(name) DO UPDATE SET label = excluded.label,
                                         description = excluded.description,
                                         rank = excluded.rank`,
      [role.name, role.label, role.description, role.rank],
    );
  }
}

function seedModes(): void {
  // Secure by default: a fresh install should not be exploitable until someone
  // deliberately switches a class to vulnerable mode.
  for (const key of VULN_CLASSES) {
    db.run('INSERT OR IGNORE INTO security_modes (key, mode) VALUES (?, ?)', [key, 'secure']);
  }
}

function seedUsers(): Map<string, number> {
  const ids = new Map<string, number>();
  for (const user of SEED_USERS) {
    const existing = db.preparedOne<{ id: number }>('SELECT id FROM users WHERE username = ?', [
      user.username,
    ]);
    if (existing) {
      ids.set(user.username, existing.id);
      continue;
    }
    const result = db.run(
      `INSERT INTO users
         (username, email, password_hash, full_name, phone_encrypted,
          recovery_note_encrypted, bio, avatar_colour)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        user.username,
        user.email,
        hashPassword(user.password),
        user.fullName,
        encrypt(user.phone),
        encrypt(user.recoveryNote),
        user.bio,
        user.avatarColour,
      ],
    );
    const id = Number(result.lastInsertRowid);
    ids.set(user.username, id);

    for (const roleName of user.roles) {
      const role = db.preparedOne<{ id: number }>('SELECT id FROM roles WHERE name = ?', [roleName]);
      if (role) {
        db.run('INSERT OR IGNORE INTO user_roles (user_id, role_id) VALUES (?, ?)', [id, role.id]);
      }
    }
  }
  return ids;
}

function seedDocuments(userIds: Map<string, number>): void {
  for (const doc of SEED_DOCS) {
    const ownerId = userIds.get(doc.owner);
    if (!ownerId) continue;

    const existing = db.preparedOne<{ id: number }>(
      'SELECT id FROM documents WHERE title = ? AND owner_id = ?',
      [doc.title, ownerId],
    );
    if (existing) continue;

    // Confidential and restricted bodies are encrypted at rest; lower
    // classifications are stored as-is, which is itself a teaching point in the
    // Cryptography Center about classifying before encrypting.
    const shouldEncrypt = doc.classification === 'confidential' || doc.classification === 'restricted';

    const result = db.run(
      `INSERT INTO documents
         (owner_id, title, body, body_encrypted, classification, size_bytes)
       VALUES (?, ?, ?, ?, ?, ?)`,
      [
        ownerId,
        doc.title,
        shouldEncrypt ? '' : doc.body,
        shouldEncrypt ? encrypt(doc.body) : null,
        doc.classification,
        Buffer.byteLength(doc.body, 'utf8'),
      ],
    );
    const docId = Number(result.lastInsertRowid);

    db.run(
      'INSERT OR IGNORE INTO document_permissions (document_id, user_id, capability, granted_by) VALUES (?, ?, ?, ?)',
      [docId, ownerId, 'owner', ownerId],
    );

    for (const share of doc.shares ?? []) {
      const granteeId = userIds.get(share.user);
      if (!granteeId) continue;
      db.run(
        'INSERT OR IGNORE INTO document_permissions (document_id, user_id, capability, granted_by) VALUES (?, ?, ?, ?)',
        [docId, granteeId, share.capability, ownerId],
      );
    }
  }
}

function seedMessages(userIds: Map<string, number>): void {
  for (const msg of SEED_MESSAGES) {
    const senderId = userIds.get(msg.from);
    const recipientId = userIds.get(msg.to);
    if (!senderId || !recipientId) continue;

    const existing = db.preparedOne<{ id: number }>(
      'SELECT id FROM messages WHERE sender_id = ? AND recipient_id = ? AND subject = ?',
      [senderId, recipientId, msg.subject],
    );
    if (existing) continue;

    db.run(
      'INSERT INTO messages (sender_id, recipient_id, subject, body) VALUES (?, ?, ?, ?)',
      [senderId, recipientId, msg.subject, msg.body],
    );
  }
}

export function runSeed(): void {
  migrate();
  db.transaction(() => {
    seedRoles();
    seedModes();
    if (!config.demoSeed) return;
    const userIds = seedUsers();
    seedDocuments(userIds);
    seedMessages(userIds);
  });
}

const isDirectRun = process.argv[1]?.includes('seed');
if (isDirectRun) {
  runSeed();
  // eslint-disable-next-line no-console
  console.log('[db] seed complete');
  if (config.demoSeed) {
    // eslint-disable-next-line no-console
    console.log('\n  Demo accounts (local demonstration only):');
    for (const u of SEED_USERS) {
      // eslint-disable-next-line no-console
      console.log(`    ${u.username.padEnd(8)} ${u.password.padEnd(20)} [${u.roles.join(', ')}]`);
    }
    // eslint-disable-next-line no-console
    console.log('');
  }
}
