/**
 * Security report generator (§22).
 *
 * Assembles a full assessment report from real platform state: the live score,
 * the current findings with their evidence and risk rationale, the retest
 * history, and the mode registry. The report is an immutable snapshot stored in
 * the reports table, so a report generated during a demo reflects that moment.
 */
import { db } from '../db/index.js';
import { config } from '../config/env.js';
import { computeScore } from './score.js';
import { listFindings } from './findings.js';
import { recentTests } from './testStore.js';
import { getAllModes, VULN_CATALOGUE, VULN_CLASSES } from '../security/modes.js';
import { describeChecks } from './scanner.js';

export interface SecurityReport {
  id?: number;
  title: string;
  generatedAt: string;
  platform: string;
  target: string;
  executiveSummary: string;
  scope: { inScope: string[]; outOfScope: string[] };
  methodology: string[];
  architectureNotes: string[];
  attackSurface: { component: string; endpoints: string[]; controls: string[] }[];
  score: ReturnType<typeof computeScore>;
  findings: ReturnType<typeof listFindings>;
  retestHistory: ReturnType<typeof recentTests>;
  secureDevelopmentRecommendations: string[];
  disclaimer: string;
}

export function generateReport(options: { title?: string; generatedBy?: number } = {}): SecurityReport {
  const score = computeScore();
  const findings = listFindings();
  const activeFindings = findings.filter((f) => f.status === 'open');
  const modes = getAllModes();
  const vulnerableClasses = VULN_CLASSES.filter((k) => modes[k] === 'vulnerable');

  const criticalCount = activeFindings.filter((f) => f.severity === 'critical').length;
  const highCount = activeFindings.filter((f) => f.severity === 'high').length;

  const executiveSummary =
    activeFindings.length === 0
      ? `This assessment of the SecureVault application found no active vulnerabilities across the ${VULN_CLASSES.length} security controls evaluated. The overall security posture scored ${score.overall}/100 (grade ${score.grade}). All vulnerability classes are currently in their hardened configuration. This is a controlled educational platform; results reflect its configurable security modes.`
      : `This assessment of the SecureVault application evaluated ${VULN_CLASSES.length} security controls and identified ${activeFindings.length} active finding(s): ${criticalCount} critical and ${highCount} high severity. The overall security posture scored ${score.overall}/100 (grade ${score.grade}). The most significant risks stem from ${vulnerableClasses.slice(0, 3).map((k) => VULN_CATALOGUE[k].title).join(', ')}. Each finding below includes evidence, a risk rationale, and a verified remediation path. This is a controlled educational platform; the vulnerabilities are intentional and configurable.`;

  const report: SecurityReport = {
    title: options.title ?? `SecureVault Security Assessment — ${new Date().toISOString().slice(0, 10)}`,
    generatedAt: new Date().toISOString(),
    platform: 'SentinelX',
    target: config.selfBaseUrl,
    executiveSummary,
    scope: {
      inScope: [
        'The SecureVault application and its REST API, served on loopback',
        `${VULN_CLASSES.length} vulnerability classes across 7 security domains`,
        'Authentication, authorization, session, input, header, data-protection and logging controls',
      ],
      outOfScope: [
        'Any third-party or external system (the platform never contacts one — spec section 41)',
        'Network, host and physical security of the machine running the demo',
        'Denial-of-service and load testing',
      ],
    },
    methodology: [
      'Automated controlled checks: each vulnerability class is exercised against its own endpoint and the real response is inspected.',
      'Manual verification: findings can be reproduced via the Security Lab and intercepted with Burp Suite / OWASP ZAP.',
      'Risk classification: a transparent weighted model over impact, exploitability, exposure, authentication requirement and asset value (not arbitrary severities).',
      'Remediation verification: each fix flips the real control and is confirmed by re-running the identical check (retest).',
    ],
    architectureNotes: [
      'Presentation (React) → API (Express) → business logic → data (SQLite) with security middleware at the boundary.',
      'Security controls are centralised: headers, CSRF, rate limiting, session and RBAC middleware apply uniformly.',
      'A mode registry governs each vulnerability class independently, enabling before/after comparison.',
    ],
    attackSurface: [
      { component: 'Authentication API', endpoints: ['/api/auth/login', '/api/auth/register', '/api/auth/password'], controls: ['scrypt hashing', 'rate limiting', 'account lockout', 'generic errors'] },
      { component: 'Document API', endpoints: ['/api/documents', '/api/documents/:id', '/api/documents/:id/share'], controls: ['object-level authorization', 'classification-based encryption'] },
      { component: 'Security API', endpoints: ['/api/security/scan', '/api/security/score', '/api/security/findings'], controls: ['role requirement (analyst/admin)', 'audit logging'] },
      { component: 'Lab endpoints', endpoints: describeChecks().map((c) => VULN_CATALOGUE[c.vulnClass as keyof typeof VULN_CATALOGUE].probeEndpoint), controls: ['mode registry', 'loopback-only', 'sandboxed'] },
    ],
    score,
    findings,
    retestHistory: recentTests(30),
    secureDevelopmentRecommendations: [
      'Adopt parameterised queries everywhere and ban string-built SQL in code review.',
      'Encode output for its context and enforce a strict Content-Security-Policy.',
      'Make object-level authorization a mandatory, centralised check — never trust an identifier as entitlement.',
      'Store secrets only in environment configuration; keep them out of source and client code.',
      'Keep security headers, CSRF protection and rate limiting as default-on middleware.',
      'Log security events and audit sensitive actions; never leak internal detail in error responses.',
      'Treat input validation as defence in depth, not the primary control against injection.',
    ],
    disclaimer:
      'SentinelX is an educational platform for a Web Application Security course. Its vulnerabilities are intentional, controlled and confined to localhost. No claim of being "unhackable", "100% secure" or "enterprise-grade" is made or implied (spec section 40). Findings reflect the platform\'s configurable security modes at the time of generation.',
  };

  const result = db.run(
    'INSERT INTO reports (title, generated_by, format, payload_json) VALUES (?, ?, ?, ?)',
    [report.title, options.generatedBy ?? null, 'json', JSON.stringify(report)],
  );
  report.id = Number(result.lastInsertRowid);
  return report;
}

export function getReport(id: number): SecurityReport | null {
  const row = db.preparedOne<{ payload_json: string; id: number }>('SELECT id, payload_json FROM reports WHERE id = ?', [id]);
  if (!row) return null;
  return { ...(JSON.parse(row.payload_json) as SecurityReport), id: row.id };
}

export function listReports(limit = 20): { id: number; title: string; createdAt: string }[] {
  const rows = db.prepared<{ id: number; title: string; created_at: string }>(
    'SELECT id, title, created_at FROM reports ORDER BY id DESC LIMIT ?', [limit]);
  return rows.map((r) => ({ id: r.id, title: r.title, createdAt: r.created_at }));
}

/** Renders a report as Markdown for export (§22 "allow exporting"). */
export function reportToMarkdown(report: SecurityReport): string {
  const sevBadge = (s: string) => s.toUpperCase();
  const lines: string[] = [];
  lines.push(`# ${report.title}`, '');
  lines.push(`**Platform:** ${report.platform}  `, `**Target:** ${report.target}  `, `**Generated:** ${report.generatedAt}`, '');
  lines.push('## Executive Summary', '', report.executiveSummary, '');
  lines.push('## Security Score', '', `**Overall: ${report.score.overall}/100 (Grade ${report.score.grade})**`, '');
  for (const d of report.score.domains) lines.push(`- ${d.label}: ${d.score}/100`);
  lines.push('', '## Scope', '', '**In scope:**');
  for (const s of report.scope.inScope) lines.push(`- ${s}`);
  lines.push('', '**Out of scope:**');
  for (const s of report.scope.outOfScope) lines.push(`- ${s}`);
  lines.push('', '## Methodology', '');
  for (const m of report.methodology) lines.push(`- ${m}`);
  lines.push('', `## Findings (${report.findings.length})`, '');
  for (const f of report.findings) {
    lines.push(`### [${sevBadge(f.severity)}] ${f.title}`, '');
    lines.push(`- **Status:** ${f.status}`, `- **OWASP:** ${f.owaspCategory}`, `- **CWE:** ${f.cwe ?? 'n/a'}`, `- **Risk score:** ${f.riskScore}/10`, `- **Endpoint:** ${f.endpoint ?? 'n/a'}${f.parameter ? ` (parameter: ${f.parameter})` : ''}`, '');
    lines.push(`**Root cause:** ${f.rootCause}`, '', `**Impact:** ${f.impact}`, '', `**Remediation:** ${f.remediation}`, '');
  }
  lines.push('## Secure Development Recommendations', '');
  for (const r of report.secureDevelopmentRecommendations) lines.push(`- ${r}`);
  lines.push('', '---', '', `_${report.disclaimer}_`);
  return lines.join('\n');
}
