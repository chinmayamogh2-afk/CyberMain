/**
 * Shared types for the laboratories, the scanner and the attack simulator.
 *
 * A `LabOutcome` is the contract every lab honours. It carries the full
 * lifecycle the spec asks for — where, what, why, impact, fix, retest — so the
 * UI can render the whole story from one response without inventing anything.
 */
import type { Mode, VulnClass } from '../security/modes.js';

/** One step in the execution trace, rendered as the terminal panel (§16). */
export interface TraceStep {
  /** Monotonic step number. */
  step: number;
  /** Short machine label, e.g. 'request', 'query', 'detection'. */
  phase:
    | 'start'
    | 'target'
    | 'payload'
    | 'request'
    | 'server'
    | 'query'
    | 'response'
    | 'detection'
    | 'impact'
    | 'remediation'
    | 'retest'
    | 'note';
  /** Human-readable line for the terminal. */
  message: string;
  /** Optional structured body shown in a code block. */
  data?: unknown;
  /** Monospace language hint for syntax highlighting. */
  language?: 'sql' | 'http' | 'json' | 'html' | 'text' | 'javascript';
  level?: 'info' | 'warn' | 'alert' | 'ok';
}

export class TraceBuilder {
  private steps: TraceStep[] = [];

  add(
    phase: TraceStep['phase'],
    message: string,
    options: { data?: unknown; language?: TraceStep['language']; level?: TraceStep['level'] } = {},
  ): this {
    this.steps.push({
      step: this.steps.length + 1,
      phase,
      message,
      data: options.data,
      language: options.language,
      level: options.level ?? 'info',
    });
    return this;
  }

  build(): TraceStep[] {
    return this.steps;
  }
}

/** The HTTP exchange a lab performed or simulated. */
export interface ExchangeRecord {
  method: string;
  url: string;
  headers: Record<string, string>;
  body?: unknown;
  response?: {
    status: number;
    headers: Record<string, string>;
    body: unknown;
  };
}

/**
 * Whether the test achieved the attacker's goal.
 *
 *   exploited    — the weakness was present and the attack succeeded
 *   blocked      — the control held and the attack failed
 *   inconclusive — the test could not determine either way
 */
export type Outcome = 'exploited' | 'blocked' | 'inconclusive';

/** PASS means "the application behaved securely", independent of outcome. */
export type Verdict = 'pass' | 'fail' | 'warn';

export interface Explanation {
  /** Why the vulnerability exists, in terms of this code path. */
  rootCause: string;
  /** Concretely what an attacker achieves. */
  impact: string;
  /** What to change. */
  remediation: string;
  /** The insecure pattern, as source. */
  vulnerableExample: string;
  /** The corrected pattern, as source. */
  secureExample: string;
  /** How to confirm the fix independently. */
  verification: string;
  /** Source → sink → context, for the injection labs (§7). */
  dataFlow?: {
    source: string;
    sink: string;
    context: string;
  };
}

export interface LabOutcome {
  vulnClass: VulnClass;
  /** Mode the application was in when the test ran. */
  mode: Mode;
  title: string;
  outcome: Outcome;
  verdict: Verdict;
  /** One-sentence result, suitable for a headline. */
  summary: string;
  /** The endpoint under test. */
  endpoint: string;
  /** The specific parameter that carried the payload, when applicable. */
  parameter?: string;
  /** The payload or test condition used. */
  payload?: string;
  /** Full step-by-step trace for the terminal panel. */
  trace: TraceStep[];
  /** The request/response pair, for the inspector. */
  exchange?: ExchangeRecord;
  /** Evidence proving the outcome — rows returned, markup reflected, etc. */
  evidence: Record<string, unknown>;
  explanation: Explanation;
  /**
   * True when this lab ran a real exploit against our own endpoint; false when
   * it ran a controlled demonstration instead. The UI must label the difference
   * (§2, §40) rather than implying every result is a live exploit.
   */
  liveExploit: boolean;
  /** Set when liveExploit is false, explaining what was demonstrated instead. */
  demonstrationNote?: string;
  durationMs: number;
}

export function verdictFor(outcome: Outcome, mode: Mode): Verdict {
  if (outcome === 'inconclusive') return 'warn';
  // Secure mode must block; vulnerable mode is expected to be exploitable, and
  // reporting that as a "pass" would be dishonest about the app's real state.
  if (mode === 'secure') return outcome === 'blocked' ? 'pass' : 'fail';
  return outcome === 'exploited' ? 'fail' : 'warn';
}
