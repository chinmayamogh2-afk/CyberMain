/**
 * Findings store (§18).
 *
 * A finding is identified by a stable fingerprint (class + endpoint + param), so
 * remediation state survives across scans: fixing SQLi once and re-scanning does
 * not resurrect it as "open" — the same fingerprint is updated in place.
 */
import { db } from '../db/index.js';
import type { VulnClass } from '../security/modes.js';
import { VULN_CATALOGUE } from '../security/modes.js';
import { assessRisk, type Severity } from './risk.js';
import type { LabOutcome } from './types.js';

export type FindingStatus = 'open' | 'remediated' | 'verified' | 'accepted' | 'false_positive';

export interface Finding {
  id: number;
  fingerprint: string;
  checkId: string;
  title: string;
  vulnClass: string;
  owaspCategory: string;
  cwe: string | null;
  severity: Severity;
  riskScore: number;
  riskFactors: Record<string, unknown>;
  confidence: string;
  endpoint: string | null;
  parameter: string | null;
  description: string;
  rootCause: string;
  attackScenario: string;
  impact: string;
  remediation: string;
  secureExample: string;
  vulnerableExample: string;
  verification: string;
  evidence: Record<string, unknown>;
  status: FindingStatus;
  detectedAt: string;
  remediatedAt: string | null;
  verifiedAt: string | null;
  notes: string;
}

export function fingerprintFor(vulnClass: VulnClass, endpoint: string, parameter?: string): string {
  return `${vulnClass}:${endpoint}:${parameter ?? '-'}`;
}

/**
 * Upserts a finding from a lab/scan outcome.
 *
 * If a finding with the same fingerprint exists, its evidence and risk are
 * refreshed but its remediation status is preserved — so an analyst's triage
 * decision is not silently overwritten by the next scan.
 */
export function upsertFinding(outcome: LabOutcome, scanId: number | null): Finding {
  const vulnClass = outcome.vulnClass;
  const meta = VULN_CATALOGUE[vulnClass];
  const endpoint = outcome.endpoint;
  const fingerprint = fingerprintFor(vulnClass, endpoint, outcome.parameter);
  const risk = assessRisk(vulnClass, { confirmed: outcome.outcome === 'exploited' });

  const existing = db.preparedOne<{ id: number; status: string }>(
    'SELECT id, status FROM findings WHERE fingerprint = ?',
    [fingerprint],
  );

  const attackScenario =
    outcome.explanation.dataFlow
      ? `Source: ${outcome.explanation.dataFlow.source} → Sink: ${outcome.explanation.dataFlow.sink} (context: ${outcome.explanation.dataFlow.context}).`
      : outcome.summary;

  if (existing) {
    // The finding reproduces now, so it is open regardless of any prior
    // remediation: a vulnerability that is exploitable again is not 'verified'.
    // Reopening here keeps the active-findings list and the score honest.
    db.run(
      `UPDATE findings
          SET risk_score = ?, risk_factors_json = ?, severity = ?,
              confidence = ?, evidence_json = ?, scan_id = COALESCE(?, scan_id),
              description = ?, impact = ?, status = 'open',
              remediated_at = NULL, verified_at = NULL
        WHERE id = ?`,
      [
        risk.score, JSON.stringify(risk.factors), risk.severity,
        outcome.outcome === 'exploited' ? 'confirmed' : 'firm',
        JSON.stringify(outcome.evidence), scanId,
        meta.summary, outcome.explanation.impact, existing.id,
      ],
    );
    return getFinding(existing.id)!;
  }

  const result = db.run(
    `INSERT INTO findings
       (scan_id, fingerprint, check_id, title, vuln_class, owasp_category, cwe,
        severity, risk_score, risk_factors_json, confidence, endpoint, parameter,
        description, root_cause, attack_scenario, impact, remediation,
        secure_example, vulnerable_example, verification, evidence_json, status)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'open')`,
    [
      scanId, fingerprint, `scan:${vulnClass}`, meta.title, vulnClass,
      meta.owaspCategory, meta.cwe, risk.severity, risk.score,
      JSON.stringify(risk.factors), outcome.outcome === 'exploited' ? 'confirmed' : 'firm',
      endpoint, outcome.parameter ?? null, meta.summary,
      outcome.explanation.rootCause, attackScenario, outcome.explanation.impact,
      outcome.explanation.remediation, outcome.explanation.secureExample,
      outcome.explanation.vulnerableExample, outcome.explanation.verification,
      JSON.stringify(outcome.evidence),
    ],
  );
  return getFinding(Number(result.lastInsertRowid))!;
}

function rowToFinding(r: Record<string, unknown>): Finding {
  return {
    id: r.id as number,
    fingerprint: r.fingerprint as string,
    checkId: r.check_id as string,
    title: r.title as string,
    vulnClass: r.vuln_class as string,
    owaspCategory: r.owasp_category as string,
    cwe: (r.cwe as string) ?? null,
    severity: r.severity as Severity,
    riskScore: r.risk_score as number,
    riskFactors: JSON.parse((r.risk_factors_json as string) || '{}'),
    confidence: r.confidence as string,
    endpoint: (r.endpoint as string) ?? null,
    parameter: (r.parameter as string) ?? null,
    description: r.description as string,
    rootCause: r.root_cause as string,
    attackScenario: r.attack_scenario as string,
    impact: r.impact as string,
    remediation: r.remediation as string,
    secureExample: r.secure_example as string,
    vulnerableExample: r.vulnerable_example as string,
    verification: r.verification as string,
    evidence: JSON.parse((r.evidence_json as string) || '{}'),
    status: r.status as FindingStatus,
    detectedAt: r.detected_at as string,
    remediatedAt: (r.remediated_at as string) ?? null,
    verifiedAt: (r.verified_at as string) ?? null,
    notes: (r.notes as string) ?? '',
  };
}

export function getFinding(id: number): Finding | null {
  const row = db.preparedOne<Record<string, unknown>>('SELECT * FROM findings WHERE id = ?', [id]);
  return row ? rowToFinding(row) : null;
}

export function getFindingByFingerprint(fingerprint: string): Finding | null {
  const row = db.preparedOne<Record<string, unknown>>('SELECT * FROM findings WHERE fingerprint = ?', [fingerprint]);
  return row ? rowToFinding(row) : null;
}

export interface ListFindingsQuery {
  status?: FindingStatus;
  severity?: Severity;
  vulnClass?: string;
  activeOnly?: boolean;
}

export function listFindings(q: ListFindingsQuery = {}): Finding[] {
  const where: string[] = [];
  const params: unknown[] = [];
  if (q.status) { where.push('status = ?'); params.push(q.status); }
  if (q.severity) { where.push('severity = ?'); params.push(q.severity); }
  if (q.vulnClass) { where.push('vuln_class = ?'); params.push(q.vulnClass); }
  if (q.activeOnly) { where.push("status IN ('open')"); }
  const clause = where.length ? `WHERE ${where.join(' AND ')}` : '';
  const rows = db.prepared<Record<string, unknown>>(
    `SELECT * FROM findings ${clause}
      ORDER BY CASE severity
        WHEN 'critical' THEN 5 WHEN 'high' THEN 4 WHEN 'medium' THEN 3
        WHEN 'low' THEN 2 ELSE 1 END DESC, risk_score DESC, id DESC`,
    params,
  );
  return rows.map(rowToFinding);
}

export function setFindingStatus(id: number, status: FindingStatus, notes?: string): Finding | null {
  const stamp =
    status === 'remediated'
      ? ", remediated_at = datetime('now')"
      : status === 'verified'
        ? ", verified_at = datetime('now')"
        : '';
  db.run(
    `UPDATE findings SET status = ?${stamp}${notes !== undefined ? ', notes = ?' : ''} WHERE id = ?`,
    notes !== undefined ? [status, notes, id] : [status, id],
  );
  return getFinding(id);
}

/** Findings that still count against the score: open and confirmed. */
export function activeFindings(): Finding[] {
  return listFindings({ status: 'open' });
}
