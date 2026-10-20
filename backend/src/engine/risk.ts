/**
 * Risk engine (§19).
 *
 * Severity is computed from weighted factors, not assigned arbitrarily. The
 * engine returns both the number and the reasoning, so the Vulnerability Details
 * page can explain *why* a finding is Critical rather than just stamping it.
 *
 * The model is a transparent linear combination in the spirit of CVSS base
 * metrics — deliberately simple enough to explain in a viva, and honest about
 * being a model rather than a measurement.
 */
import type { VulnClass } from '../security/modes.js';
import { VULN_CATALOGUE } from '../security/modes.js';

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export interface RiskFactors {
  /** Technical damage if exploited. 0-1. */
  impact: number;
  /** How easy the attack is to perform. 0-1. */
  exploitability: number;
  /** How reachable the weakness is (anonymous vs admin-only). 0-1. */
  exposure: number;
  /** Does exploitation require prior authentication? Lower = riskier. 0-1. */
  authenticationRequired: number;
  /** Value of the asset the weakness touches. 0-1. */
  affectedAsset: number;
}

export interface RiskAssessment {
  score: number; // 0-10
  severity: Severity;
  factors: RiskFactors;
  /** Human-readable justification for each factor and the final rating. */
  rationale: string[];
}

const WEIGHTS: Record<keyof RiskFactors, number> = {
  impact: 0.3,
  exploitability: 0.25,
  exposure: 0.2,
  authenticationRequired: 0.15,
  affectedAsset: 0.1,
};

/** Default factor profiles per vulnerability class, tuned to their real nature. */
const PROFILES: Record<VulnClass, RiskFactors> = {
  sqli: { impact: 1.0, exploitability: 0.9, exposure: 0.9, authenticationRequired: 0.9, affectedAsset: 1.0 },
  api_authz: { impact: 0.95, exploitability: 0.85, exposure: 0.8, authenticationRequired: 0.7, affectedAsset: 0.9 },
  auth: { impact: 0.95, exploitability: 0.7, exposure: 1.0, authenticationRequired: 1.0, affectedAsset: 0.9 },
  idor: { impact: 0.8, exploitability: 0.9, exposure: 0.7, authenticationRequired: 0.5, affectedAsset: 0.9 },
  xss_stored: { impact: 0.8, exploitability: 0.7, exposure: 0.8, authenticationRequired: 0.5, affectedAsset: 0.7 },
  csrf: { impact: 0.75, exploitability: 0.6, exposure: 0.7, authenticationRequired: 0.5, affectedAsset: 0.7 },
  ssrf: { impact: 0.85, exploitability: 0.6, exposure: 0.6, authenticationRequired: 0.6, affectedAsset: 0.8 },
  upload: { impact: 0.9, exploitability: 0.6, exposure: 0.6, authenticationRequired: 0.5, affectedAsset: 0.8 },
  path_traversal: { impact: 0.8, exploitability: 0.7, exposure: 0.6, authenticationRequired: 0.6, affectedAsset: 0.8 },
  cmdi: { impact: 0.95, exploitability: 0.5, exposure: 0.5, authenticationRequired: 0.6, affectedAsset: 0.9 },
  data_exposure: { impact: 0.7, exploitability: 0.8, exposure: 0.7, authenticationRequired: 0.5, affectedAsset: 0.8 },
  xss_reflected: { impact: 0.6, exploitability: 0.6, exposure: 0.8, authenticationRequired: 0.3, affectedAsset: 0.6 },
  session: { impact: 0.75, exploitability: 0.5, exposure: 0.7, authenticationRequired: 0.5, affectedAsset: 0.7 },
  rate_limit: { impact: 0.5, exploitability: 0.8, exposure: 0.9, authenticationRequired: 0.2, affectedAsset: 0.6 },
  headers: { impact: 0.4, exploitability: 0.5, exposure: 0.9, authenticationRequired: 0.1, affectedAsset: 0.5 },
  error_handling: { impact: 0.4, exploitability: 0.6, exposure: 0.8, authenticationRequired: 0.2, affectedAsset: 0.5 },
};

function severityFor(score: number): Severity {
  if (score >= 9) return 'critical';
  if (score >= 7) return 'high';
  if (score >= 4) return 'medium';
  if (score >= 1) return 'low';
  return 'info';
}

const FACTOR_LABELS: Record<keyof RiskFactors, string> = {
  impact: 'Impact',
  exploitability: 'Exploitability',
  exposure: 'Exposure',
  authenticationRequired: 'Pre-authentication reachability',
  affectedAsset: 'Asset value',
};

function describeFactor(name: keyof RiskFactors, value: number): string {
  const band = value >= 0.8 ? 'very high' : value >= 0.6 ? 'high' : value >= 0.4 ? 'moderate' : 'low';
  return `${FACTOR_LABELS[name]}: ${band} (${value.toFixed(2)}, weight ${(WEIGHTS[name] * 100).toFixed(0)}%)`;
}

/**
 * Assesses risk for a vulnerability class.
 *
 * `confirmed` nudges the score up: a weakness we have actually exploited in a
 * test carries more certainty than one merely inferred, which is reflected
 * honestly rather than hidden.
 */
export function assessRisk(vulnClass: VulnClass, options: { confirmed?: boolean; overrides?: Partial<RiskFactors> } = {}): RiskAssessment {
  const base = PROFILES[vulnClass];
  const factors: RiskFactors = { ...base, ...options.overrides };

  let weighted = 0;
  for (const key of Object.keys(WEIGHTS) as (keyof RiskFactors)[]) {
    weighted += factors[key] * WEIGHTS[key];
  }
  let score = weighted * 10;

  const rationale: string[] = [];
  for (const key of Object.keys(WEIGHTS) as (keyof RiskFactors)[]) {
    rationale.push(describeFactor(key, factors[key]));
  }

  if (options.confirmed) {
    score = Math.min(10, score + 0.5);
    rationale.push('Confidence: confirmed by an executed test against this application (+0.5).');
  } else {
    rationale.push('Confidence: inferred from configuration, not yet exploited in a test.');
  }

  score = Math.round(score * 10) / 10;
  const severity = severityFor(score);
  rationale.push(
    `Overall: ${score.toFixed(1)}/10 → ${severity.toUpperCase()}. ` +
      `${VULN_CATALOGUE[vulnClass].owaspCategory}.`,
  );

  return { score, severity, factors, rationale };
}

export const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 5, high: 4, medium: 3, low: 2, info: 1,
};
