import { useState } from 'react';
import { api } from '@/lib/api';
import { useModes } from '@/lib/useSecurity';
import { Panel, Button, Spinner, Empty, VerdictBadge } from '@/components/ui';
import { LabResult } from '@/components/LabResult';
import { IconTarget, IconPlay } from '@/components/icons';
import type { LabOutcome } from '@/lib/types';

/**
 * Attack Simulator (spec §16). Select an attack and a mode, press RUN TEST, and
 * the platform executes the controlled test and streams the lifecycle into a
 * terminal-style panel alongside the graphical result.
 */

// Canonical attack per class with a fixed representative payload, so the
// simulator is one-click. The Lab is where inputs are customised.
const ATTACKS: { key: string; label: string; endpoint: string; body: Record<string, unknown> }[] = [
  { key: 'sqli', label: 'SQL Injection', endpoint: '/lab/run/sqli', body: { username: atob('JyBPUiAnMSc9JzEnIC0tIA=='), password: 'x' } },
  { key: 'xss_reflected', label: 'Reflected XSS', endpoint: '/lab/run/xss', body: { input: atob('PHNjcmlwdD5hbGVydChkb2N1bWVudC5jb29raWUpPC9zY3JpcHQ+'), variant: 'reflected' } },
  { key: 'xss_stored', label: 'Stored XSS', endpoint: '/lab/run/xss', body: { input: atob('PGltZyBzcmM9eCBvbmVycm9yPWFsZXJ0KDEpPg=='), variant: 'stored' } },
  { key: 'csrf', label: 'CSRF', endpoint: '/lab/run/csrf', body: { scenario: 'forged' } },
  { key: 'idor', label: 'IDOR', endpoint: '/lab/run/idor', body: { actingUserId: 4, documentId: 1 } },
  { key: 'auth', label: 'Broken Authentication', endpoint: '/lab/run/auth', body: { username: 'alice', password: 'password123' } },
  { key: 'session', label: 'Session Weakness', endpoint: '/lab/run/session', body: {} },
  { key: 'headers', label: 'Security Headers', endpoint: '/lab/run/headers', body: {} },
  { key: 'upload', label: 'File Upload', endpoint: '/lab/run/upload', body: { filename: 'shell.php', declaredType: 'application/x-php', sizeBytes: 2048 } },
  { key: 'path_traversal', label: 'Path Traversal', endpoint: '/lab/run/traversal', body: { requestedPath: '../lab-secret.txt' } },
  { key: 'ssrf', label: 'SSRF', endpoint: '/lab/run/ssrf', body: { url: 'http://169.254.169.254/latest/meta-data/' } },
  { key: 'cmdi', label: 'Parameter Injection', endpoint: '/lab/run/cmdi', body: { format: 'pdf; whoami' } },
  { key: 'data_exposure', label: 'Sensitive Data Exposure', endpoint: '/lab/run/exposure', body: { targetUserId: 3 } },
];

export function AttackSimulator() {
  const { classes, setMode } = useModes();
  const [attack, setAttack] = useState(ATTACKS[0]!.key);
  const [mode, setModeSel] = useState<'vulnerable' | 'secure'>('vulnerable');
  const [result, setResult] = useState<LabOutcome | null>(null);
  const [vulnResult, setVulnResult] = useState<LabOutcome | null>(null);
  const [secureResult, setSecureResult] = useState<LabOutcome | null>(null);
  const [busy, setBusy] = useState(false);

  const def = ATTACKS.find((a) => a.key === attack)!;
  const meta = classes.find((c) => c.key === attack);

  async function run() {
    setBusy(true);
    try {
      const r = await api.post<LabOutcome>(def.endpoint, { ...def.body, mode });
      setResult(r);
      if (mode === 'vulnerable') setVulnResult(r); else setSecureResult(r);
    } finally { setBusy(false); }
  }

  async function runBoth() {
    setBusy(true);
    try {
      const v = await api.post<LabOutcome>(def.endpoint, { ...def.body, mode: 'vulnerable' });
      const s = await api.post<LabOutcome>(def.endpoint, { ...def.body, mode: 'secure' });
      setVulnResult(v); setSecureResult(s); setResult(mode === 'vulnerable' ? v : s);
    } finally { setBusy(false); }
  }

  function selectAttack(k: string) {
    setAttack(k); setResult(null); setVulnResult(null); setSecureResult(null);
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-bold text-white">Attack Simulator</h1>
        <p className="text-sm text-slate-400">Select an attack and a mode, then run the controlled test against SecureVault's own endpoints.</p>
      </div>

      <div className="grid gap-6 lg:grid-cols-[300px_1fr]">
        <div className="space-y-4">
          <Panel title="1 · Select attack">
            <div className="grid grid-cols-2 gap-1.5">
              {ATTACKS.map((a) => (
                <button key={a.key} onClick={() => selectAttack(a.key)}
                  className={`rounded-lg px-2.5 py-2 text-left text-xs transition ${attack === a.key ? 'bg-accent/10 text-accent ring-1 ring-accent/30' : 'text-slate-300 hover:bg-white/5'}`}>
                  {a.label}
                </button>
              ))}
            </div>
          </Panel>

          <Panel title="2 · Select mode">
            <div className="flex gap-2">
              {(['vulnerable', 'secure'] as const).map((m) => (
                <button key={m} onClick={() => setModeSel(m)}
                  className={`flex-1 rounded-lg px-3 py-2 text-xs font-semibold capitalize transition ring-1 ${mode === m ? (m === 'vulnerable' ? 'bg-sev-critical/15 text-sev-critical ring-sev-critical/40' : 'bg-sev-ok/15 text-sev-ok ring-sev-ok/40') : 'text-slate-400 ring-white/10 hover:bg-white/5'}`}>
                  {m === 'vulnerable' ? 'Vulnerable' : 'Hardened'}
                </button>
              ))}
            </div>
            {meta && (
              <p className="mt-3 text-[11px] text-slate-500">
                Running the test only executes it; it does not change the live mode. Use
                <button className="mx-1 text-accent hover:underline" onClick={() => setMode(attack, mode)}>set live mode → {mode}</button>
                to persist it (current live: <span className={meta.mode === 'vulnerable' ? 'text-sev-critical' : 'text-sev-ok'}>{meta.mode}</span>).
              </p>
            )}
          </Panel>

          <Panel title="3 · Execute">
            <div className="space-y-2">
              <Button onClick={run} disabled={busy} className="w-full"><IconPlay className="h-4 w-4" /> RUN TEST</Button>
              <Button variant="ghost" onClick={runBoth} disabled={busy} className="w-full"><IconTarget className="h-4 w-4" /> Run both modes (compare)</Button>
              {busy && <div className="pt-1"><Spinner label="Executing controlled test…" /></div>}
            </div>
          </Panel>
        </div>

        <div className="space-y-4">
          {vulnResult && secureResult ? (
            <Panel title="Before / After comparison" subtitle={`${def.label}: same test, both modes`}>
              <div className="grid gap-4 md:grid-cols-2">
                {[['Vulnerable', vulnResult], ['Hardened', secureResult]].map(([label, r]) => {
                  const res = r as LabOutcome;
                  return (
                    <div key={label as string} className={`rounded-xl p-4 ring-1 ${res.outcome === 'exploited' ? 'bg-sev-critical/5 ring-sev-critical/20' : 'bg-sev-ok/5 ring-sev-ok/20'}`}>
                      <div className="mb-2 flex items-center justify-between">
                        <span className="text-xs font-semibold uppercase tracking-wide text-slate-400">{label as string}</span>
                        <VerdictBadge verdict={res.verdict} />
                      </div>
                      <p className="text-sm text-slate-300">{res.summary}</p>
                    </div>
                  );
                })}
              </div>
            </Panel>
          ) : null}
          {result ? <Panel title="Test result"><LabResult result={result} /></Panel> : <Empty>Select an attack and press RUN TEST.</Empty>}
        </div>
      </div>
    </div>
  );
}
