-- ════════════════════════════════════════════════════════════════════════════
-- SentinelX relational schema
--
-- Design notes (spec §28):
--   * Normalised: roles, permissions and findings live in their own tables with
--     real foreign keys rather than being flattened into a single blob.
--   * Every table that records security-relevant activity carries a timestamp
--     and, where meaningful, the acting user and request context (§23).
--   * Columns holding confidential values are stored as AES-256-GCM envelopes
--     (see security/crypto.ts), never plaintext.
-- ════════════════════════════════════════════════════════════════════════════

PRAGMA foreign_keys = ON;

-- ── Identity ────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS roles (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  name        TEXT NOT NULL UNIQUE,          -- 'user' | 'analyst' | 'admin'
  label       TEXT NOT NULL,
  description TEXT NOT NULL,
  -- Lower rank = fewer privileges. Used for least-privilege comparisons.
  rank        INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
  id                   INTEGER PRIMARY KEY AUTOINCREMENT,
  username             TEXT NOT NULL UNIQUE,
  email                TEXT NOT NULL UNIQUE,
  -- scrypt envelope: scrypt$N$r$p$<salt-b64>$<hash-b64>. Never plaintext (§10).
  password_hash        TEXT NOT NULL,
  full_name            TEXT NOT NULL,
  -- AES-256-GCM ciphertext. Demonstrates encryption at rest (§11).
  phone_encrypted      TEXT,
  recovery_note_encrypted TEXT,
  bio                  TEXT NOT NULL DEFAULT '',
  avatar_colour        TEXT NOT NULL DEFAULT '#38bdf8',
  is_active            INTEGER NOT NULL DEFAULT 1,
  -- Account lockout / throttling state (§10).
  failed_login_count   INTEGER NOT NULL DEFAULT 0,
  locked_until         TEXT,
  password_changed_at  TEXT NOT NULL DEFAULT (datetime('now')),
  last_login_at        TEXT,
  created_at           TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at           TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS user_roles (
  user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role_id    INTEGER NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
  granted_at TEXT NOT NULL DEFAULT (datetime('now')),
  granted_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
  PRIMARY KEY (user_id, role_id)
);

-- ── Sessions ────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS sessions (
  id             TEXT PRIMARY KEY,            -- opaque 256-bit random id
  user_id        INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at     TEXT NOT NULL DEFAULT (datetime('now')),
  last_seen_at   TEXT NOT NULL DEFAULT (datetime('now')),
  expires_at     TEXT NOT NULL,
  ip_address     TEXT,
  user_agent     TEXT,
  -- Set when the session is explicitly destroyed, so logout invalidation is
  -- auditable rather than just a deleted row (§10).
  revoked_at     TEXT,
  revoked_reason TEXT,
  -- Records which mode minted the session, so the Session lab can show how a
  -- session issued in vulnerable mode differs from a hardened one.
  issued_mode    TEXT NOT NULL DEFAULT 'secure'
);

CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expiry ON sessions(expires_at);

CREATE TABLE IF NOT EXISTS login_attempts (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  username     TEXT NOT NULL,
  user_id      INTEGER REFERENCES users(id) ON DELETE SET NULL,
  succeeded    INTEGER NOT NULL,
  ip_address   TEXT,
  user_agent   TEXT,
  failure_kind TEXT,                          -- 'bad_password' | 'no_user' | 'locked' | 'rate_limited'
  created_at   TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_login_attempts_user_time
  ON login_attempts(username, created_at);

-- ── SecureVault application domain ──────────────────────────────────────────

CREATE TABLE IF NOT EXISTS documents (
  id             INTEGER PRIMARY KEY AUTOINCREMENT,
  owner_id       INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  title          TEXT NOT NULL,
  -- Body is stored encrypted when the document is marked confidential.
  body           TEXT NOT NULL DEFAULT '',
  body_encrypted TEXT,
  classification TEXT NOT NULL DEFAULT 'internal',  -- public|internal|confidential|restricted
  -- Original filename as supplied by the client. Untrusted: never used to build
  -- a filesystem path directly in secure mode (§5 file upload / path traversal).
  original_name  TEXT,
  stored_name    TEXT,
  mime_type      TEXT,
  size_bytes     INTEGER NOT NULL DEFAULT 0,
  checksum_sha256 TEXT,
  created_at     TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at     TEXT NOT NULL DEFAULT (datetime('now')),
  deleted_at     TEXT
);

CREATE INDEX IF NOT EXISTS idx_documents_owner ON documents(owner_id);

CREATE TABLE IF NOT EXISTS document_permissions (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  document_id INTEGER NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
  user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  -- 'read' | 'write' | 'owner'
  capability  TEXT NOT NULL,
  granted_by  INTEGER REFERENCES users(id) ON DELETE SET NULL,
  granted_at  TEXT NOT NULL DEFAULT (datetime('now')),
  UNIQUE (document_id, user_id, capability)
);

CREATE INDEX IF NOT EXISTS idx_docperm_lookup
  ON document_permissions(document_id, user_id);

CREATE TABLE IF NOT EXISTS messages (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  sender_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  recipient_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  document_id  INTEGER REFERENCES documents(id) ON DELETE SET NULL,
  subject      TEXT NOT NULL DEFAULT '',
  -- Stored exactly as submitted. Whether it is encoded on the way OUT is what
  -- distinguishes vulnerable from secure mode in the stored-XSS lab (§7).
  body         TEXT NOT NULL,
  created_at   TEXT NOT NULL DEFAULT (datetime('now')),
  read_at      TEXT
);

CREATE INDEX IF NOT EXISTS idx_messages_recipient ON messages(recipient_id);

-- ── Security mode registry ──────────────────────────────────────────────────
-- The heart of the platform. One row per vulnerability class; flipping `mode`
-- changes real application behaviour at request time (§6 vulnerable/secure).

CREATE TABLE IF NOT EXISTS security_modes (
  key          TEXT PRIMARY KEY,
  mode         TEXT NOT NULL DEFAULT 'secure',   -- 'vulnerable' | 'secure'
  changed_at   TEXT NOT NULL DEFAULT (datetime('now')),
  changed_by   INTEGER REFERENCES users(id) ON DELETE SET NULL,
  change_count INTEGER NOT NULL DEFAULT 0
);

-- ── Observability: audit, events, HTTP transactions ─────────────────────────

CREATE TABLE IF NOT EXISTS audit_logs (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  occurred_at   TEXT NOT NULL DEFAULT (datetime('now')),
  actor_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
  actor_label   TEXT NOT NULL DEFAULT 'anonymous',
  action        TEXT NOT NULL,                  -- e.g. 'auth.login.failed'
  category      TEXT NOT NULL,                  -- auth|access|admin|security|data
  outcome       TEXT NOT NULL,                  -- success|failure|blocked|detected
  severity      TEXT NOT NULL DEFAULT 'info',   -- info|low|medium|high|critical
  target_type   TEXT,
  target_id     TEXT,
  ip_address    TEXT,
  user_agent    TEXT,
  request_method TEXT,
  request_path  TEXT,
  -- JSON. Scrubbed of credentials before it is written (§30).
  detail_json   TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_audit_time ON audit_logs(occurred_at);
CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_logs(action);
CREATE INDEX IF NOT EXISTS idx_audit_actor ON audit_logs(actor_user_id);

CREATE TABLE IF NOT EXISTS security_events (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  occurred_at TEXT NOT NULL DEFAULT (datetime('now')),
  level       TEXT NOT NULL DEFAULT 'info',     -- info|notice|warn|alert
  source      TEXT NOT NULL,                    -- scanner|simulator|app|auth|mode
  message     TEXT NOT NULL,
  detail_json TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_events_time ON security_events(occurred_at);

-- Captured request/response pairs that power the HTTP inspector (§15).
CREATE TABLE IF NOT EXISTS http_transactions (
  id               INTEGER PRIMARY KEY AUTOINCREMENT,
  started_at       TEXT NOT NULL DEFAULT (datetime('now')),
  duration_ms      INTEGER NOT NULL DEFAULT 0,
  method           TEXT NOT NULL,
  path             TEXT NOT NULL,
  query_json       TEXT NOT NULL DEFAULT '{}',
  request_headers_json  TEXT NOT NULL DEFAULT '{}',
  request_body_preview  TEXT,
  status_code      INTEGER NOT NULL DEFAULT 0,
  response_headers_json TEXT NOT NULL DEFAULT '{}',
  response_body_preview TEXT,
  actor_user_id    INTEGER REFERENCES users(id) ON DELETE SET NULL,
  -- Set when this exchange was produced by the simulator or scanner, so the
  -- inspector can distinguish organic traffic from security tests.
  origin           TEXT NOT NULL DEFAULT 'app', -- app|scanner|simulator
  flagged          INTEGER NOT NULL DEFAULT 0,
  flag_reason      TEXT
);

CREATE INDEX IF NOT EXISTS idx_http_time ON http_transactions(started_at);

-- ── Security assessment domain ──────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS scans (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  started_at    TEXT NOT NULL DEFAULT (datetime('now')),
  finished_at   TEXT,
  status        TEXT NOT NULL DEFAULT 'running', -- running|completed|failed
  target        TEXT NOT NULL,
  initiated_by  INTEGER REFERENCES users(id) ON DELETE SET NULL,
  checks_total  INTEGER NOT NULL DEFAULT 0,
  checks_run    INTEGER NOT NULL DEFAULT 0,
  -- Snapshot of the mode registry when the scan ran, so a historic scan can be
  -- explained even after modes change.
  mode_snapshot_json TEXT NOT NULL DEFAULT '{}',
  error_message TEXT
);

CREATE TABLE IF NOT EXISTS findings (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id         INTEGER REFERENCES scans(id) ON DELETE CASCADE,
  -- Stable identity for a finding across scans, so remediation state persists:
  -- e.g. 'sqli:/api/lab/sqli/login:username'
  fingerprint     TEXT NOT NULL,
  check_id        TEXT NOT NULL,
  title           TEXT NOT NULL,
  vuln_class      TEXT NOT NULL,              -- matches security_modes.key
  owasp_category  TEXT NOT NULL,
  cwe             TEXT,
  severity        TEXT NOT NULL,              -- critical|high|medium|low|info
  -- Numeric risk from the risk engine, 0-10, with the factors that produced it.
  risk_score      REAL NOT NULL DEFAULT 0,
  risk_factors_json TEXT NOT NULL DEFAULT '{}',
  confidence      TEXT NOT NULL DEFAULT 'firm', -- confirmed|firm|tentative
  endpoint        TEXT,
  parameter       TEXT,
  description     TEXT NOT NULL,
  root_cause      TEXT NOT NULL,
  attack_scenario TEXT NOT NULL,
  impact          TEXT NOT NULL,
  remediation     TEXT NOT NULL,
  secure_example  TEXT NOT NULL DEFAULT '',
  vulnerable_example TEXT NOT NULL DEFAULT '',
  verification    TEXT NOT NULL DEFAULT '',
  -- The actual request/response that proves the finding (§18 evidence).
  evidence_json   TEXT NOT NULL DEFAULT '{}',
  status          TEXT NOT NULL DEFAULT 'open', -- open|remediated|verified|accepted|false_positive
  detected_at     TEXT NOT NULL DEFAULT (datetime('now')),
  remediated_at   TEXT,
  verified_at     TEXT,
  notes           TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_findings_fingerprint ON findings(fingerprint);
CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);

-- Individual security test executions: simulator runs, retests and the
-- automated control tests (§32). Each row records PASS / FAIL / WARN and why.
CREATE TABLE IF NOT EXISTS security_tests (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  executed_at   TEXT NOT NULL DEFAULT (datetime('now')),
  duration_ms   INTEGER NOT NULL DEFAULT 0,
  test_id       TEXT NOT NULL,
  vuln_class    TEXT NOT NULL,
  kind          TEXT NOT NULL,                -- simulation|retest|control
  mode_at_run   TEXT NOT NULL,                -- vulnerable|secure
  outcome       TEXT NOT NULL,                -- exploited|blocked|inconclusive
  verdict       TEXT NOT NULL,                -- pass|fail|warn
  explanation   TEXT NOT NULL,
  finding_id    INTEGER REFERENCES findings(id) ON DELETE SET NULL,
  executed_by   INTEGER REFERENCES users(id) ON DELETE SET NULL,
  -- Full step-by-step trace: request, response, detection reasoning.
  trace_json    TEXT NOT NULL DEFAULT '[]'
);

CREATE INDEX IF NOT EXISTS idx_tests_class ON security_tests(vuln_class);
CREATE INDEX IF NOT EXISTS idx_tests_time ON security_tests(executed_at);

CREATE TABLE IF NOT EXISTS score_snapshots (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  captured_at   TEXT NOT NULL DEFAULT (datetime('now')),
  overall       REAL NOT NULL,
  domains_json  TEXT NOT NULL DEFAULT '{}',
  -- What caused the score to move, e.g. 'remediated sqli'.
  trigger       TEXT NOT NULL DEFAULT 'periodic'
);

CREATE TABLE IF NOT EXISTS reports (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at    TEXT NOT NULL DEFAULT (datetime('now')),
  title         TEXT NOT NULL,
  scan_id       INTEGER REFERENCES scans(id) ON DELETE SET NULL,
  generated_by  INTEGER REFERENCES users(id) ON DELETE SET NULL,
  format        TEXT NOT NULL DEFAULT 'json',
  -- Complete immutable snapshot of the assessment at generation time.
  payload_json  TEXT NOT NULL
);
