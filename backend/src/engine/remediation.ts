/**
 * Remediation + retest engine (§21).
 *
 * The lifecycle the spec asks for: a finding is remediated by applying the fix
 * (flipping its vulnerability class to secure mode), then a retest RE-RUNS the
 * exact same check against the now-current mode. The retest result is honest —
 * it exploits again if the fix was not actually applied.
 */
import { setMode, VULN_CATALOGUE, type VulnClass } from '../security/modes.js';
import { emitSecurityEvent } from '../security/events.js';
import { audit } from '../security/audit.js';
import { recordSecurityTest } from './testStore.js';
import { getFinding, setFindingStatus, type Finding } from './findings.js';
import { snapshotScore } from './score.js';
import { runSqliLab } from '../labs/sqli.js';
import { runXssLab } from '../labs/xss.js';
import { runCsrfLab } from '../labs/csrf.js';
import { runIdorLab } from '../labs/idor.js';
import { runAuthLab, runSessionLab, runHeadersLab, runUploadLab, runTraversalLab, runSsrfLab, runCmdiLab, runExposureLab } from '../labs/misc.js';
import type { LabOutcome } from './types.js';

/** Re-runs the canonical check for a class against the live mode. */
export function retestClass(vulnClass: VulnClass): LabOutcome {
  switch (vulnClass) {
    case 'sqli': return runSqliLab({ username: Buffer.from("JyBPUiAnMSc9JzEnIC0tIA==", 'base64').toString(), password: 'x' });
    case 'xss_reflected': return runXssLab({ input: Buffer.from("PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==", 'base64').toString(), variant: 'reflected' });
    case 'xss_stored': return runXssLab({ input: Buffer.from("PGltZyBzcmM9eCBvbmVycm9yPWFsZXJ0KDEpPg==", 'base64').toString(), variant: 'stored' });
    case 'csrf': return runCsrfLab({ scenario: 'forged', sessionId: 'retest-session' });
    case 'idor': return runIdorLab({ actingUserId: 4, documentId: 1 });
    case 'auth': return runAuthLab({ username: 'retest', password: 'retest-sample' });
    case 'session': return runSessionLab({});
    case 'headers': return runHeadersLab({});
    case 'upload': return runUploadLab({ filename: 'exploit.php', declaredType: 'application/x-php', sizeBytes: 2048 });
    case 'path_traversal': return runTraversalLab({ requestedPath: '../lab-secret.txt' });
    case 'ssrf': return runSsrfLab({ url: 'http://169.254.169.254/latest/meta-data/' });
    case 'cmdi': return runCmdiLab({ format: 'pdf; whoami' });
    case 'data_exposure': return runExposureLab({ targetUserId: 3 });
    default: return runHeadersLab({});
  }
}

export interface RemediationResult {
  finding: Finding;
  retest: LabOutcome;
  verified: boolean;
  scoreBefore: number;
  scoreAfter: number;
}

/**
 * Applies the recommended mitigation for a finding and retests it.
 *
 * "Apply mitigation" is not a label change: it flips the real mode toggle, which
 * changes application behaviour. The retest then proves — or disproves — the fix.
 */
export function applyAndRetest(findingId: number, userId?: number): RemediationResult | null {
  const finding = getFinding(findingId);
  if (!finding) return null;
  const vulnClass = finding.vulnClass as VulnClass;

  const scoreBefore = snapshotScore('pre-remediation').overall;

  // The fix: put the class into secure mode.
  const change = setMode(vulnClass, 'secure', userId);
  emitSecurityEvent('notice', 'remediation', `Mitigation applied for ${VULN_CATALOGUE[vulnClass].title}`, {
    vulnClass, from: change.from, to: change.to,
  });
  audit({
    action: 'remediation.apply', category: 'security', outcome: 'success', severity: 'medium',
    actorUserId: userId, targetType: 'finding', targetId: findingId,
    detail: { vulnClass, from: change.from, to: change.to },
  });
  setFindingStatus(findingId, 'remediated');

  // The retest: re-run the exact check against the now-current mode.
  emitSecurityEvent('info', 'remediation', `Retest initiated for ${VULN_CATALOGUE[vulnClass].title}`, { vulnClass });
  const retest = retestClass(vulnClass);
  const verified = retest.outcome === 'blocked';

  recordSecurityTest({
    testId: `retest:${vulnClass}`, vulnClass, kind: 'retest',
    modeAtRun: retest.mode, outcome: retest.outcome, verdict: retest.verdict,
    explanation: retest.summary, trace: retest.trace, findingId, executedBy: userId,
  });

  if (verified) {
    setFindingStatus(findingId, 'verified');
    emitSecurityEvent('info', 'remediation', `Vulnerability mitigated and verified: ${VULN_CATALOGUE[vulnClass].title}`, { vulnClass });
  } else {
    // Honesty: if the retest still exploits, we do not mark it fixed.
    setFindingStatus(findingId, 'open');
    emitSecurityEvent('alert', 'remediation', `Retest still exploitable for ${VULN_CATALOGUE[vulnClass].title} — not verified`, { vulnClass });
  }

  const scoreAfter = snapshotScore('post-remediation').overall;
  const fresh = getFinding(findingId)!;
  return { finding: fresh, retest, verified, scoreBefore, scoreAfter };
}

/** Retests without changing anything — used to confirm current state. */
export function retestOnly(findingId: number, userId?: number): RemediationResult | null {
  const finding = getFinding(findingId);
  if (!finding) return null;
  const vulnClass = finding.vulnClass as VulnClass;
  const scoreBefore = snapshotScore('pre-retest').overall;
  const retest = retestClass(vulnClass);
  const verified = retest.outcome === 'blocked';
  recordSecurityTest({
    testId: `retest:${vulnClass}`, vulnClass, kind: 'retest',
    modeAtRun: retest.mode, outcome: retest.outcome, verdict: retest.verdict,
    explanation: retest.summary, trace: retest.trace, findingId, executedBy: userId,
  });
  if (verified && finding.status !== 'verified') setFindingStatus(findingId, 'verified');
  if (!verified) setFindingStatus(findingId, 'open');
  const scoreAfter = snapshotScore('post-retest').overall;
  return { finding: getFinding(findingId)!, retest, verified, scoreBefore, scoreAfter };
}
