// Shared types mirroring the backend contracts. Kept deliberately light — the
// frontend trusts the server as the source of truth for all security state.

export type Mode = 'vulnerable' | 'secure';
export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type Outcome = 'exploited' | 'blocked' | 'inconclusive';
export type Verdict = 'pass' | 'fail' | 'warn';

export interface User {
  id: number; username: string; email: string; fullName: string;
  bio: string; avatarColour: string; phone: string | null;
  roles: string[]; primaryRole: string; roleLabel: string;
  capabilities: string[]; passwordChangedAt: string; lastLoginAt: string | null; createdAt: string;
}

export interface TraceStep {
  step: number; phase: string; message: string;
  data?: unknown; language?: string; level?: 'info' | 'warn' | 'alert' | 'ok';
}

export interface Explanation {
  rootCause: string; impact: string; remediation: string;
  vulnerableExample: string; secureExample: string; verification: string;
  dataFlow?: { source: string; sink: string; context: string };
}

export interface LabOutcome {
  vulnClass: string; mode: Mode; title: string; outcome: Outcome; verdict: Verdict;
  summary: string; endpoint: string; parameter?: string; payload?: string;
  trace: TraceStep[]; exchange?: ExchangeRecord; evidence: Record<string, unknown>;
  explanation: Explanation; liveExploit: boolean; demonstrationNote?: string; durationMs: number;
}

export interface ExchangeRecord {
  method: string; url: string; headers: Record<string, string>; body?: unknown;
  response?: { status: number; headers: Record<string, string>; body: unknown };
}

export interface VulnClassMeta {
  key: string; title: string; summary: string; owaspCategory: string; cwe: string;
  domain: string; baseSeverity: string; liveExploit: boolean; probeEndpoint: string; mode: Mode;
}

export interface Finding {
  id: number; fingerprint: string; title: string; vulnClass: string;
  owaspCategory: string; cwe: string | null; severity: Severity; riskScore: number;
  riskFactors: Record<string, number>; confidence: string; endpoint: string | null;
  parameter: string | null; description: string; rootCause: string; attackScenario: string;
  impact: string; remediation: string; secureExample: string; vulnerableExample: string;
  verification: string; evidence: Record<string, unknown>; status: string;
  detectedAt: string; remediatedAt: string | null; verifiedAt: string | null; notes: string;
}

export interface DomainScore {
  domain: string; label: string; score: number;
  deductions: { vulnClass: string; title: string; severity: string; penalty: number }[];
}
export interface SecurityScore {
  overall: number; grade: string; domains: DomainScore[];
  vulnerableClasses: number; totalClasses: number; computedAt: string;
}

export interface SecurityEvent {
  id: number; occurredAt: string; level: 'info' | 'notice' | 'warn' | 'alert';
  source: string; message: string; detail: Record<string, unknown>;
}

export interface AuditRecord {
  id: number; occurredAt: string; actorLabel: string; action: string;
  category: string; outcome: string; severity: string; requestMethod: string | null;
  requestPath: string | null; ipAddress: string | null; detail: Record<string, unknown>;
}

export interface TransactionRecord {
  id: number; startedAt: string; durationMs: number; method: string; path: string;
  query: Record<string, unknown>; requestHeaders: Record<string, unknown>; requestBody: string;
  statusCode: number; responseHeaders: Record<string, unknown>; responseBody: string;
  origin: string; flagged: boolean; flagReason: string | null;
}
