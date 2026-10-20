/**
 * Resets the platform to a clean demonstration baseline:
 *   - all vulnerability classes hardened (secure)
 *   - findings, scans, tests, events, score snapshots and reports cleared
 *   - captured HTTP transactions and audit logs cleared
 *   - demo users/documents/messages re-seeded (idempotent)
 *
 * Use before a presentation so the demo starts from a known, clean state.
 */
import { db, migrate } from './index.js';
import { runSeed } from './seed.js';
import { resetLabAccounts } from '../labs/sqli.js';

migrate();

db.transaction(() => {
  for (const table of [
    'findings', 'scans', 'security_tests', 'security_events',
    'score_snapshots', 'reports', 'http_transactions', 'audit_logs',
    'login_attempts',
  ]) {
    db.run(`DELETE FROM ${table}`);
  }
  // Return every control to its secure default.
  db.run("UPDATE security_modes SET mode = 'secure', change_count = 0");
  // Clear any sessions so the demo starts signed out.
  db.run('DELETE FROM sessions');
});

runSeed();
resetLabAccounts();

// eslint-disable-next-line no-console
console.log('[db] reset to clean demo baseline — all controls hardened, history cleared');
