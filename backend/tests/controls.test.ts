/**
 * Vulnerability control tests (spec section 32).
 *
 * For every class the suite asserts the control actually works: the attack is
 * blocked in secure mode and genuinely exploitable in vulnerable mode. These run
 * the real lab runners against the real database, so a regression that silently
 * breaks a control fails the build.
 */
import { describe, it, expect } from 'vitest';
import { runSqliLab } from '../src/labs/sqli.ts';
import { runXssLab } from '../src/labs/xss.ts';
import { runCsrfLab } from '../src/labs/csrf.ts';
import { runIdorLab } from '../src/labs/idor.ts';
import {
  runAuthLab, runSessionLab, runHeadersLab, runUploadLab,
  runTraversalLab, runSsrfLab, runCmdiLab, runExposureLab,
} from '../src/labs/misc.ts';

const SQLI_BYPASS = Buffer.from("JyBPUiAnMSc9JzEnIC0tIA==", 'base64').toString();
const XSS_IMG = Buffer.from("PGltZyBzcmM9eCBvbmVycm9yPWFsZXJ0KDEpPg==", 'base64').toString();

describe('SQL injection control', () => {
  it('blocks the bypass payload in secure mode (0 unauthorised rows)', () => {
    const r = runSqliLab({ username: SQLI_BYPASS, password: 'x', modeOverride: 'secure' });
    expect(r.outcome).toBe('blocked');
    expect((r.evidence as { authenticatedWithoutValidCredentials: boolean }).authenticatedWithoutValidCredentials).toBe(false);
  });
  it('is genuinely exploitable in vulnerable mode', () => {
    const r = runSqliLab({ username: SQLI_BYPASS, password: 'x', modeOverride: 'vulnerable' });
    expect(r.outcome).toBe('exploited');
    expect((r.evidence as { rowsReturned: number }).rowsReturned).toBeGreaterThan(0);
  });
  it('still authenticates a legitimate credential in secure mode', () => {
    const r = runSqliLab({ username: 'a.fernandes', password: 'vault-demo-1', modeOverride: 'secure' });
    expect((r.evidence as { rowsReturned: number }).rowsReturned).toBe(1);
  });
});

describe('XSS control', () => {
  it('encodes markup in secure mode so no live tag reaches the browser', () => {
    const r = runXssLab({ input: XSS_IMG, variant: 'stored', modeOverride: 'secure' });
    expect(r.outcome).toBe('blocked');
    expect((r.evidence as { outputCarriesLiveMarkup: boolean }).outputCarriesLiveMarkup).toBe(false);
  });
  it('reflects live markup in vulnerable mode', () => {
    const r = runXssLab({ input: XSS_IMG, variant: 'reflected', modeOverride: 'vulnerable' });
    expect(r.outcome).toBe('exploited');
  });
});

describe('CSRF control', () => {
  it('rejects a forged cross-site request in secure mode', () => {
    const r = runCsrfLab({ scenario: 'forged', sessionId: 's1', modeOverride: 'secure' });
    expect(r.outcome).toBe('blocked');
    expect((r.evidence as { requestAccepted: boolean }).requestAccepted).toBe(false);
  });
  it('accepts the forgery in vulnerable mode', () => {
    const r = runCsrfLab({ scenario: 'forged', sessionId: 's1', modeOverride: 'vulnerable' });
    expect(r.outcome).toBe('exploited');
  });
  it('accepts a legitimate same-origin request with a token in secure mode', () => {
    const r = runCsrfLab({ scenario: 'legitimate', sessionId: 's1', modeOverride: 'secure' });
    expect((r.evidence as { requestAccepted: boolean }).requestAccepted).toBe(true);
  });
});

describe('IDOR control', () => {
  it('denies Bob access to Alice\'s private document in secure mode', () => {
    const r = runIdorLab({ actingUserId: 4, documentId: 1, modeOverride: 'secure' });
    expect(r.outcome).toBe('blocked');
    expect((r.evidence as { contentServed: boolean }).contentServed).toBe(false);
  });
  it('leaks it in vulnerable mode', () => {
    const r = runIdorLab({ actingUserId: 4, documentId: 1, modeOverride: 'vulnerable' });
    expect(r.outcome).toBe('exploited');
    expect((r.evidence as { unauthorisedDisclosure: boolean }).unauthorisedDisclosure).toBe(true);
  });
  it('still allows Bob his own document in secure mode', () => {
    const r = runIdorLab({ actingUserId: 4, documentId: 4, modeOverride: 'secure' });
    expect((r.evidence as { contentServed: boolean }).contentServed).toBe(true);
  });
});

describe('remaining controls block in secure and expose in vulnerable', () => {
  const cases: [string, (m: 'vulnerable'|'secure') => { outcome: string }][] = [
    ['auth', (m) => runAuthLab({ username: 'x', password: 'y', modeOverride: m })],
    ['session', (m) => runSessionLab({ modeOverride: m })],
    ['headers', (m) => runHeadersLab({ modeOverride: m })],
    ['upload', (m) => runUploadLab({ filename: 'x.php', declaredType: 'application/x-php', sizeBytes: 10, modeOverride: m })],
    ['traversal', (m) => runTraversalLab({ requestedPath: '../lab-secret.txt', modeOverride: m })],
    ['ssrf', (m) => runSsrfLab({ url: 'http://169.254.169.254/latest/meta-data/', modeOverride: m })],
    ['cmdi', (m) => runCmdiLab({ format: 'pdf; whoami', modeOverride: m })],
    ['exposure', (m) => runExposureLab({ targetUserId: 3, modeOverride: m })],
  ];
  for (const [name, fn] of cases) {
    it(`${name}: blocked in secure`, () => expect(fn('secure').outcome).toBe('blocked'));
    it(`${name}: exploited in vulnerable`, () => expect(fn('vulnerable').outcome).toBe('exploited'));
  }
});
