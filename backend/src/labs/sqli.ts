/**
 * SQL Injection laboratory (spec section 6).
 *
 * This runs a genuine query against a real SQLite table. In vulnerable mode the
 * supplied values are concatenated into the statement text and the database
 * parses whatever that produces -- the result is not pattern-matched or faked.
 * In secure mode the identical logic uses bound parameters, so the same input
 * can no longer change the parsed statement.
 *
 * Safety: the lab operates only on a dedicated `lab_accounts` table of synthetic
 * records (no real credentials), isolated from the platform's own data, and the
 * table is rebuilt on demand. Everything runs against this local application
 * only (spec section 41).
 */
import { db } from '../db/index.js';
import { getMode, type Mode } from '../security/modes.js';
import { TraceBuilder, verdictFor, type LabOutcome, type Outcome } from '../engine/types.js';
import { detectPayloads } from '../security/sanitize.js';

/** Decodes a base64-stored literal. Used for demonstration payload strings. */
const dec = (s: string): string => Buffer.from(s, 'base64').toString('utf8');

interface LabAccount {
  id: number;
  username: string;
  password: string;
  department: string;
  clearance: string;
}

/** Synthetic records. None of these are real credentials. */
const LAB_ACCOUNTS: LabAccount[] = [
  { id: 1, username: 'a.fernandes', password: 'vault-demo-1', department: 'Finance', clearance: 'confidential' },
  { id: 2, username: 'b.mehta', password: 'vault-demo-2', department: 'Engineering', clearance: 'internal' },
  { id: 3, username: 'm.oyelaran', password: 'vault-demo-3', department: 'Security', clearance: 'restricted' },
  { id: 4, username: 'p.raghavan', password: 'vault-demo-4', department: 'Executive', clearance: 'restricted' },
  { id: 5, username: 'svc.backup', password: 'vault-demo-5', department: 'Service', clearance: 'restricted' },
];

export function ensureLabSchema(): void {
  db.handle.exec(`
    CREATE TABLE IF NOT EXISTS lab_accounts (
      id         INTEGER PRIMARY KEY,
      username   TEXT NOT NULL,
      password   TEXT NOT NULL,
      department TEXT NOT NULL,
      clearance  TEXT NOT NULL
    );
  `);
  const count = db.preparedOne<{ n: number }>('SELECT COUNT(*) AS n FROM lab_accounts');
  if ((count?.n ?? 0) === 0) resetLabAccounts();
}

export function resetLabAccounts(): void {
  db.transaction(() => {
    db.run('DELETE FROM lab_accounts');
    for (const a of LAB_ACCOUNTS) {
      db.run(
        'INSERT INTO lab_accounts (id, username, password, department, clearance) VALUES (?, ?, ?, ?, ?)',
        [a.id, a.username, a.password, a.department, a.clearance],
      );
    }
  });
}

export function labAccountCount(): number {
  ensureLabSchema();
  return db.preparedOne<{ n: number }>('SELECT COUNT(*) AS n FROM lab_accounts')?.n ?? 0;
}

export interface SqliPayloadDef {
  id: string;
  label: string;
  username: string;
  password: string;
  teaches: string;
}

/** Demonstration inputs offered in the UI, each with the concept it illustrates. */
export const SQLI_PAYLOADS: SqliPayloadDef[] = [
  {
    id: "benign",
    label: "Benign login (control)",
    username: dec("YS5mZXJuYW5kZXM="),
    password: dec("dmF1bHQtZGVtby0x"),
    teaches: "The baseline: a legitimate credential pair, so you can see the normal query shape first.",
  },
  {
    id: "tautology",
    label: "Authentication bypass via always-true condition",
    username: dec("JyBPUiAnMSc9JzEnIC0tIA=="),
    password: dec("YW55dGhpbmc="),
    teaches: "The quote closes the string literal; an always-true OR condition makes the WHERE clause match every row; the comment marker discards the remainder of the statement including the password comparison.",
  },
  {
    id: "union",
    label: "Data extraction via appended result set",
    username: dec("JyBVTklPTiBTRUxFQ1QgaWQsIHVzZXJuYW1lIHx8ICc6JyB8fCBwYXNzd29yZCwgZGVwYXJ0bWVudCwgY2xlYXJhbmNlIEZST00gbGFiX2FjY291bnRzIC0tIA=="),
    password: dec("YW55dGhpbmc="),
    teaches: "An appended SELECT whose column count matches the original returns every row of the table; here the username and password are concatenated into one column so both are exfiltrated through a single visible field.",
  },
  {
    id: "comment-truncate",
    label: "Password check removal via comment",
    username: dec("YS5mZXJuYW5kZXMnIC0tIA=="),
    password: dec("d3JvbmctcGFzc3dvcmQtZW50aXJlbHk="),
    teaches: "A valid username followed by a comment marker discards the trailing password condition, so an incorrect password is never actually compared.",
  }
];

const VULN_EXAMPLE = dec("Ly8gVlVMTkVSQUJMRTogdXNlciBpbnB1dCBpcyBjb25jYXRlbmF0ZWQgaW50byB0aGUgc3RhdGVtZW50IHRleHQuCmNvbnN0IHNxbCA9CiAgIlNFTEVDVCBpZCwgdXNlcm5hbWUsIGRlcGFydG1lbnQsIGNsZWFyYW5jZSBGUk9NIGxhYl9hY2NvdW50cyAiICsKICAiV0hFUkUgdXNlcm5hbWUgPSAnIiArIHVzZXJuYW1lICsgIicgQU5EIHBhc3N3b3JkID0gJyIgKyBwYXNzd29yZCArICInIjsKY29uc3Qgcm93cyA9IGRiLnByZXBhcmUoc3FsKS5hbGwoKTsgIC8vIHRoZSBkYXRhYmFzZSBwYXJzZXMgYXR0YWNrZXItY29udHJvbGxlZCBzeW50YXg=");
const SECURE_EXAMPLE = dec("Ly8gU0VDVVJFOiB0aGUgc3RhdGVtZW50IGlzIGZpeGVkOyB2YWx1ZXMgYXJlIGJvdW5kIGFzIHBhcmFtZXRlcnMuCmNvbnN0IHNxbCA9CiAgIlNFTEVDVCBpZCwgdXNlcm5hbWUsIGRlcGFydG1lbnQsIGNsZWFyYW5jZSBGUk9NIGxhYl9hY2NvdW50cyAiICsKICAiV0hFUkUgdXNlcm5hbWUgPSA/IEFORCBwYXNzd29yZCA9ID8iOwpjb25zdCByb3dzID0gZGIucHJlcGFyZShzcWwpLmFsbCh1c2VybmFtZSwgcGFzc3dvcmQpOyAgLy8gdmFsdWVzIGNhbiBuZXZlciBhbHRlciB0aGUgcXVlcnkncyBzdHJ1Y3R1cmU=");

export interface SqliInput {
  username: string;
  password: string;
  /** Forces a mode regardless of the registry, used for side-by-side retests. */
  modeOverride?: Mode;
}

/**
 * Builds the statement text for display and (in vulnerable mode) execution.
 * Kept as a single function so the UI can show the exact string the database
 * will parse.
 */
function buildConcatenatedQuery(username: string, password: string): string {
  return (
    "SELECT id, username, department, clearance FROM lab_accounts " +
    "WHERE username = '" + username + "' AND password = '" + password + "'"
  );
}

/** Ground truth: is this exact pair a legitimate account? Always parameterised. */
function isLegitimatePair(username: string, password: string): boolean {
  const row = db.preparedOne<{ n: number }>(
    'SELECT COUNT(*) AS n FROM lab_accounts WHERE username = ? AND password = ?',
    [username, password],
  );
  return (row?.n ?? 0) > 0;
}

export function runSqliLab(input: SqliInput): LabOutcome {
  ensureLabSchema();
  const started = Date.now();
  const mode: Mode = input.modeOverride ?? getMode('sqli');
  const { username, password } = input;
  const t = new TraceBuilder();

  t.add('start', `SQL Injection test starting in ${mode.toUpperCase()} mode`);
  t.add('target', 'Target endpoint: POST /api/lab/sqli/login (lab_accounts table)');
  t.add('payload', `Submitted username field`, { data: { username, password }, language: 'json' });

  const detected = detectPayloads(username).concat(detectPayloads(password));
  if (detected.length > 0) {
    t.add('detection', `Input matches ${detected.length} injection signature(s)`, {
      data: detected.map((d) => d.label),
      level: 'warn',
    });
  }

  const legitimate = isLegitimatePair(username, password);
  let authenticated = false;
  let rows: Record<string, unknown>[] = [];
  let executedQuery: string;
  let dbError: string | null = null;

  if (mode === 'vulnerable') {
    executedQuery = buildConcatenatedQuery(username, password);
    t.add('query', 'Statement sent to the database (values concatenated):', {
      data: executedQuery,
      language: 'sql',
      level: 'warn',
    });
    const attempt = db.rawSafeAttempt<Record<string, unknown>>(executedQuery);
    if (attempt.ok) {
      rows = attempt.rows;
      authenticated = rows.length > 0;
    } else {
      // A database error reaching the surface is itself a finding.
      dbError = attempt.error;
      t.add('response', 'The database returned an error, which a vulnerable app would expose:', {
        data: dbError,
        language: 'text',
        level: 'alert',
      });
    }
  } else {
    executedQuery =
      "SELECT id, username, department, clearance FROM lab_accounts WHERE username = ? AND password = ?";
    t.add('query', 'Prepared statement with bound parameters:', {
      data: executedQuery + '\n-- parameters: [ ' + JSON.stringify(username) + ', ' + JSON.stringify(password) + ' ]',
      language: 'sql',
      level: 'ok',
    });
    rows = db.prepared<Record<string, unknown>>(executedQuery, [username, password]);
    authenticated = rows.length > 0;
  }

  // Decide the outcome honestly from what the database actually returned.
  let outcome: Outcome;
  let summary: string;
  const extractedExtra = rows.length > 1;
  const leakedPasswordColumn = rows.some((r) => 'password' in r);

  if (!authenticated && dbError === null) {
    outcome = 'blocked';
    summary =
      legitimate && mode === 'secure'
        ? 'Control: no injection attempted; the query behaved normally.'
        : 'Injection did not alter the query; no unauthorised rows were returned.';
  } else if (authenticated && legitimate && detected.length === 0) {
    outcome = 'blocked';
    summary = 'Control: a legitimate credential pair authenticated as expected.';
  } else if (authenticated && !legitimate) {
    outcome = 'exploited';
    summary = extractedExtra
      ? `Injection succeeded: ${rows.length} rows were extracted from a query meant to check one login.`
      : 'Injection succeeded: authentication was bypassed without a valid password.';
  } else if (dbError !== null) {
    outcome = 'exploited';
    summary = 'Injection caused a database error that a vulnerable application would disclose verbatim.';
  } else {
    outcome = 'blocked';
    summary = 'The query behaved as intended.';
  }

  if (outcome === 'exploited') {
    t.add('detection', 'VULNERABILITY CONFIRMED', { level: 'alert' });
    t.add('impact', summary, { level: 'alert' });
    if (rows.length > 0) {
      t.add('response', `Rows returned to the caller (${rows.length}):`, {
        data: rows,
        language: 'json',
        level: 'alert',
      });
    }
  } else {
    t.add('detection', 'No exploitation: the statement structure was preserved.', { level: 'ok' });
    if (rows.length > 0) {
      t.add('response', `Rows returned (${rows.length}):`, { data: rows, language: 'json', level: 'ok' });
    }
  }

  const verdict = verdictFor(outcome, mode);
  t.add('retest', `Verdict: ${verdict.toUpperCase()} (${mode} mode)`, {
    level: verdict === 'pass' ? 'ok' : verdict === 'fail' ? 'alert' : 'warn',
  });

  return {
    vulnClass: 'sqli',
    mode,
    title: 'SQL Injection',
    outcome,
    verdict,
    summary,
    endpoint: '/api/lab/sqli/login',
    parameter: 'username',
    payload: username,
    trace: t.build(),
    exchange: {
      method: 'POST',
      url: '/api/lab/sqli/login',
      headers: { 'content-type': 'application/json' },
      body: { username, password: '[submitted]' },
      response: {
        status: outcome === 'exploited' ? 200 : authenticated ? 200 : 401,
        headers: { 'content-type': 'application/json' },
        body: { authenticated, rowsReturned: rows.length },
      },
    },
    evidence: {
      executedQuery,
      rowsReturned: rows.length,
      rows,
      authenticatedWithoutValidCredentials: authenticated && !legitimate,
      extractedMoreThanOneRow: extractedExtra,
      leakedPasswordColumn,
      databaseError: dbError,
      injectionSignatures: detected.map((d) => d.label),
    },
    explanation: {
      rootCause:
        'In vulnerable mode the username and password are concatenated directly into the SQL statement, so characters such as a single quote are interpreted as SQL syntax rather than data. The database parses a statement whose structure the attacker partly controls.',
      impact:
        'An attacker can bypass authentication, read every row of the table (including other accounts), and depending on privileges modify or destroy data. SQL injection is consistently ranked among the highest-impact web vulnerabilities.',
      remediation:
        'Use parameterised queries / prepared statements so user input is always bound as a value and can never change the parsed statement. Apply least-privilege database accounts and input validation as defence in depth.',
      vulnerableExample: VULN_EXAMPLE,
      secureExample: SECURE_EXAMPLE,
      verification:
        'Submit an injection payload in both modes. In secure mode the prepared statement returns zero rows for the payload and the identical benign login still works, proving the fix did not break functionality.',
      dataFlow: {
        source: 'username / password fields of the login request body',
        sink: 'the concatenated string passed to db.prepare().all()',
        context: 'SQL statement text parsed by the SQLite engine',
      },
    },
    liveExploit: true,
    durationMs: Date.now() - started,
  };
}
