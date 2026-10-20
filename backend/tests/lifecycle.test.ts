/**
 * Finding-lifecycle tests (spec §21).
 *
 * Verify the honest behaviours added for the demo: a scan reopens a finding that
 * reproduces, resolves one that no longer does, and the score tracks both.
 */
import { describe, it, expect, beforeAll } from 'vitest';

let runScan: typeof import('../src/engine/scanner.ts')['runScan'];
let setMode: typeof import('../src/security/modes.ts')['setMode'];
let setAllModes: typeof import('../src/security/modes.ts')['setAllModes'];
let listFindings: typeof import('../src/engine/findings.ts')['listFindings'];
let computeScore: typeof import('../src/engine/score.ts')['computeScore'];

beforeAll(async () => {
  ({ runScan } = await import('../src/engine/scanner.ts'));
  ({ setMode, setAllModes } = await import('../src/security/modes.ts'));
  ({ listFindings } = await import('../src/engine/findings.ts'));
  ({ computeScore } = await import('../src/engine/score.ts'));
});

describe('finding lifecycle across scans', () => {
  it('opens a critical finding when SQLi is vulnerable, and the score drops', async () => {
    setAllModes('secure');
    const cleanScore = computeScore().overall;
    expect(cleanScore).toBe(100);

    setMode('sqli', 'vulnerable');
    await runScan({ fast: true });

    const open = listFindings({ status: 'open' });
    const sqli = open.find((f) => f.vulnClass === 'sqli');
    expect(sqli).toBeDefined();
    expect(sqli!.severity).toBe('critical');
    expect(computeScore().overall).toBeLessThan(cleanScore);
  });

  it('resolves the finding on rescan once SQLi is secured, and the score recovers', async () => {
    setMode('sqli', 'secure');
    await runScan({ fast: true });

    const open = listFindings({ status: 'open' });
    expect(open.find((f) => f.vulnClass === 'sqli')).toBeUndefined();
    expect(computeScore().overall).toBe(100);
  });

  it('reopens the same finding if the vulnerability is reintroduced', async () => {
    setMode('sqli', 'vulnerable');
    await runScan({ fast: true });
    const open = listFindings({ status: 'open' });
    const sqli = open.find((f) => f.vulnClass === 'sqli');
    expect(sqli).toBeDefined();
    expect(sqli!.status).toBe('open');
    setMode('sqli', 'secure');
  });
});
