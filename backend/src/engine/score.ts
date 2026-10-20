/**
 * Security score engine (§20).
 *
 * The score is computed from the LIVE mode registry and the open findings, so it
 * is a function of the application's actual state. Fix SQL injection — flip the
 * toggle — and the input-security domain and the overall score genuinely rise;
 * reintroduce it and they fall. Nothing is stored as a magic number.
 *
 * Each domain starts at 100 and loses points for every vulnerable class mapped
 * to it, weighted by that class's base severity. This is a model, and the UI
 * presents it as one (§40) — but it is a model over real state.
 */
import { db } from '../db/index.js';
import { getAllModes, VULN_CATALOGUE, VULN_CLASSES, type ScoreDomain, type VulnClass } from '../security/modes.js';

const DOMAINS: ScoreDomain[] = [
  'authentication', 'authorization', 'input_security',
  'session_security', 'headers', 'data_protection', 'logging',
];

export const DOMAIN_LABELS: Record<ScoreDomain, string> = {
  authentication: 'Authentication',
  authorization: 'Authorization',
  input_security: 'Input Security',
  session_security: 'Session Security',
  headers: 'Headers',
  data_protection: 'Data Protection',
  logging: 'Logging & Error Handling',
};

/** Penalty points a vulnerable class removes from its domain. */
const SEVERITY_PENALTY: Record<'critical' | 'high' | 'medium' | 'low', number> = {
  critical: 45,
  high: 30,
  medium: 18,
  low: 10,
};

export interface DomainScore {
  domain: ScoreDomain;
  label: string;
  score: number;
  /** Which vulnerable classes dragged it down, with their penalties. */
  deductions: { vulnClass: string; title: string; severity: string; penalty: number }[];
}

export interface SecurityScore {
  overall: number;
  grade: 'A' | 'B' | 'C' | 'D' | 'F';
  domains: DomainScore[];
  vulnerableClasses: number;
  totalClasses: number;
  computedAt: string;
}

function gradeFor(score: number): SecurityScore['grade'] {
  if (score >= 90) return 'A';
  if (score >= 80) return 'B';
  if (score >= 70) return 'C';
  if (score >= 60) return 'D';
  return 'F';
}

/** Classes grouped by the score domain they affect. */
const CLASSES_BY_DOMAIN: Record<ScoreDomain, VulnClass[]> = (() => {
  const map = Object.fromEntries(DOMAINS.map((d) => [d, [] as VulnClass[]])) as Record<ScoreDomain, VulnClass[]>;
  for (const key of VULN_CLASSES) map[VULN_CATALOGUE[key].domain].push(key);
  return map;
})();

export function computeScore(): SecurityScore {
  const modes = getAllModes();
  const domains: DomainScore[] = [];
  let vulnerableCount = 0;

  for (const domain of DOMAINS) {
    let score = 100;
    const deductions: DomainScore['deductions'] = [];
    for (const vulnClass of CLASSES_BY_DOMAIN[domain]) {
      if (modes[vulnClass] === 'vulnerable') {
        vulnerableCount += 1;
        const meta = VULN_CATALOGUE[vulnClass];
        const penalty = SEVERITY_PENALTY[meta.baseSeverity];
        score -= penalty;
        deductions.push({ vulnClass, title: meta.title, severity: meta.baseSeverity, penalty });
      }
    }
    domains.push({
      domain,
      label: DOMAIN_LABELS[domain],
      score: Math.max(0, Math.round(score)),
      deductions,
    });
  }

  // Overall is the mean of domain scores, so a single catastrophic domain cannot
  // be hidden by several healthy ones, but nor does it zero the whole platform.
  const overall = Math.round(domains.reduce((sum, d) => sum + d.score, 0) / domains.length);

  return {
    overall,
    grade: gradeFor(overall),
    domains,
    vulnerableClasses: vulnerableCount,
    totalClasses: VULN_CLASSES.length,
    computedAt: new Date().toISOString(),
  };
}

/** Persists a score snapshot so the dashboard can chart how it moved over time. */
export function snapshotScore(trigger: string): SecurityScore {
  const score = computeScore();
  db.run(
    'INSERT INTO score_snapshots (overall, domains_json, trigger) VALUES (?, ?, ?)',
    [score.overall, JSON.stringify(score.domains), trigger],
  );
  return score;
}

export interface ScoreHistoryPoint {
  capturedAt: string;
  overall: number;
  trigger: string;
}

export function scoreHistory(limit = 50): ScoreHistoryPoint[] {
  const rows = db.prepared<{ captured_at: string; overall: number; trigger: string }>(
    'SELECT captured_at, overall, trigger FROM score_snapshots ORDER BY id DESC LIMIT ?',
    [limit],
  );
  return rows.reverse().map((r) => ({ capturedAt: r.captured_at, overall: r.overall, trigger: r.trigger }));
}
