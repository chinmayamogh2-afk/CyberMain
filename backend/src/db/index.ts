/**
 * Database access.
 *
 * SQLite via better-sqlite3 is the supported driver. It is synchronous, needs no
 * server, and — importantly for this project — executes raw SQL strings, which
 * is what makes the SQL-injection laboratory a genuine demonstration rather
 * than a mock.
 *
 * `db.raw()` and `db.prepared()` below are deliberately separate entry points.
 * The vulnerable code paths call `raw()` with a concatenated string; the secure
 * paths call `prepared()` with bound parameters. Keeping them as two visibly
 * different APIs is what lets the UI show the difference truthfully.
 */
import Database from 'better-sqlite3';
import fs from 'node:fs';
import path from 'node:path';
import { config } from '../config/env.js';

if (config.db.driver !== 'sqlite') {
  // eslint-disable-next-line no-console
  console.error(
    `[db] DB_DRIVER=${config.db.driver} is not implemented. SQLite is the supported driver; ` +
      `see docs/ARCHITECTURE.md for the Postgres migration path.`,
  );
  process.exit(1);
}

const connection = new Database(config.db.sqlitePath);

// Durability and concurrency settings appropriate for a local demo platform.
connection.pragma('journal_mode = WAL');
connection.pragma('foreign_keys = ON');
connection.pragma('busy_timeout = 5000');

export type Row = Record<string, unknown>;

export const db = {
  /** The underlying handle, for transactions and pragmas. */
  handle: connection,

  /**
   * Parameterised query — the secure path. Values are bound by the driver and
   * can never alter the parsed structure of the statement.
   */
  prepared<T = Row>(sql: string, params: unknown[] = []): T[] {
    return connection.prepare(sql).all(...(params as never[])) as T[];
  },

  preparedOne<T = Row>(sql: string, params: unknown[] = []): T | undefined {
    return connection.prepare(sql).get(...(params as never[])) as T | undefined;
  },

  run(sql: string, params: unknown[] = []): Database.RunResult {
    return connection.prepare(sql).run(...(params as never[]));
  },

  /**
   * Executes SQL with no parameter binding at all.
   *
   * This exists ONLY so the vulnerable mode of the SQL-injection lab can run a
   * query whose structure the attacker controls. Production code paths must use
   * `prepared()`. The query text is returned to the caller so the UI can show
   * the exact statement the database parsed.
   */
  raw<T = Row>(sql: string): T[] {
    return connection.prepare(sql).all() as T[];
  },

  /**
   * Like `raw`, but tolerates statements that return no rows and surfaces the
   * driver's own error message. The SQLi lab shows that message verbatim in
   * vulnerable mode — verbose database errors are themselves a finding (§30).
   */
  rawSafeAttempt<T = Row>(sql: string): { ok: true; rows: T[] } | { ok: false; error: string } {
    try {
      return { ok: true, rows: connection.prepare(sql).all() as T[] };
    } catch (err) {
      return { ok: false, error: err instanceof Error ? err.message : String(err) };
    }
  },

  transaction<T>(fn: () => T): T {
    return connection.transaction(fn)();
  },
};

/** Applies schema.sql. Idempotent — every statement is CREATE ... IF NOT EXISTS. */
export function migrate(): void {
  const schemaPath = path.join(import.meta.dirname, 'schema.sql');
  const sql = fs.readFileSync(schemaPath, 'utf8');
  connection.exec(sql);
}

export function closeDb(): void {
  connection.close();
}
