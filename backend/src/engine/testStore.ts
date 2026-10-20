/**
 * Persistence for security test executions (§32).
 *
 * Every simulator run, retest and automated control test is recorded here so the
 * platform can show history, feed the score, and prove that a retest actually
 * ran against the current mode rather than replaying an old result.
 */
import { db } from '../db/index.js';
import type { Outcome, Verdict, TraceStep } from './types.js';
import type { Mode, VulnClass } from '../security/modes.js';

export interface RecordTestInput {
  testId: string;
  vulnClass: VulnClass;
  kind: 'simulation' | 'retest' | 'control';
  modeAtRun: Mode;
  outcome: Outcome;
  verdict: Verdict;
  explanation: string;
  trace?: TraceStep[];
  findingId?: number;
  executedBy?: number;
  durationMs?: number;
}

export function recordSecurityTest(input: RecordTestInput): number {
  const result = db.run(
    `INSERT INTO security_tests
       (duration_ms, test_id, vuln_class, kind, mode_at_run, outcome, verdict,
        explanation, finding_id, executed_by, trace_json)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [
      input.durationMs ?? 0,
      input.testId,
      input.vulnClass,
      input.kind,
      input.modeAtRun,
      input.outcome,
      input.verdict,
      input.explanation,
      input.findingId ?? null,
      input.executedBy ?? null,
      JSON.stringify(input.trace ?? []),
    ],
  );
  return Number(result.lastInsertRowid);
}

export interface TestRecord {
  id: number;
  executedAt: string;
  testId: string;
  vulnClass: string;
  kind: string;
  modeAtRun: string;
  outcome: string;
  verdict: string;
  explanation: string;
  findingId: number | null;
}

export function recentTests(limit = 50, vulnClass?: string): TestRecord[] {
  const rows = vulnClass
    ? db.prepared<Record<string, never>>(
        'SELECT * FROM security_tests WHERE vuln_class = ? ORDER BY id DESC LIMIT ?',
        [vulnClass, limit],
      )
    : db.prepared<Record<string, never>>('SELECT * FROM security_tests ORDER BY id DESC LIMIT ?', [limit]);
  return (rows as unknown as {
    id: number; executed_at: string; test_id: string; vuln_class: string;
    kind: string; mode_at_run: string; outcome: string; verdict: string;
    explanation: string; finding_id: number | null;
  }[]).map((r) => ({
    id: r.id, executedAt: r.executed_at, testId: r.test_id, vulnClass: r.vuln_class,
    kind: r.kind, modeAtRun: r.mode_at_run, outcome: r.outcome, verdict: r.verdict,
    explanation: r.explanation, findingId: r.finding_id,
  }));
}

export function getTestTrace(id: number): TraceStep[] | null {
  const row = db.preparedOne<{ trace_json: string }>('SELECT trace_json FROM security_tests WHERE id = ?', [id]);
  return row ? (JSON.parse(row.trace_json) as TraceStep[]) : null;
}
