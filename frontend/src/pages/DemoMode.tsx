import { useState } from 'react';
import { api } from '@/lib/api';
import { useScore, useModes, useFindings } from '@/lib/useSecurity';
import { Panel, Button, Spinner } from '@/components/ui';
import { ScoreRing } from '@/components/ScoreRing';
import { LabResult } from '@/components/LabResult';
import type { LabOutcome, Finding } from '@/lib/types';

/**
 * Presentation / Demo Mode (spec §33). A guided, scripted walkthrough that
 * drives the real platform — every step performs an actual operation, so the
 * demonstration is genuine, not a slideshow.
 */
interface Step { title: string; detail: string; run: () => Promise<string | null> }

export function DemoMode() {
  const { score, reloadScore } = useScore();
  const { setMode, reloadModes } = useModes();
  const { reloadFindings } = useFindings();
  const [current, setCurrent] = useState(0);
  const [log, setLog] = useState<{ step: string; note: string }[]>([]);
  const [lastResult, setLastResult] = useState<LabOutcome | null>(null);
  const [busy, setBusy] = useState(false);
  const [findingId, setFindingId] = useState<number | null>(null);

  const SQLI_PAYLOAD = atob('JyBPUiAnMSc9JzEnIC0tIA==');

  const steps: Step[] = [
    { title: 'Reset to hardened baseline', detail: 'Put every control into secure mode so we start from a clean, defensible posture.',
      run: async () => { await setMode('sqli', 'secure'); await api.put('/security/modes', { mode: 'secure' }); await reloadModes(); await reloadScore(); return 'All controls hardened. Security score at baseline.'; } },
    { title: 'Run SQL Injection in Hardened mode', detail: 'Confirm the attack is blocked when the control is in place.',
      run: async () => { const r = await api.post<LabOutcome>('/lab/run/sqli', { username: SQLI_PAYLOAD, password: 'x', mode: 'secure' }); setLastResult(r); return `Hardened: ${r.outcome} — ${r.summary}`; } },
    { title: 'Introduce the vulnerability', detail: 'Flip SQL Injection to vulnerable mode — a deliberate weakening to demonstrate the attack.',
      run: async () => { await setMode('sqli', 'vulnerable'); await reloadModes(); await reloadScore(); return 'SQL Injection control is now VULNERABLE. Watch the score drop.'; } },
    { title: 'Exploit it', detail: 'Run the identical test. This time the injection succeeds and extracts data.',
      run: async () => { const r = await api.post<LabOutcome>('/lab/run/sqli', { username: SQLI_PAYLOAD, password: 'x', mode: 'vulnerable' }); setLastResult(r); return `Vulnerable: ${r.outcome} — ${r.summary}`; } },
    { title: 'Run a full security scan', detail: 'The scanner probes every endpoint and generates findings from real responses.',
      run: async () => { const r = await api.post<{ findings: Finding[]; summary: Record<string, number> }>('/security/scan'); await reloadFindings(); await reloadScore(); const sqli = r.findings.find((f) => f.vulnClass === 'sqli'); if (sqli) setFindingId(sqli.id); return `Scan complete: ${r.findings.length} finding(s) — ${r.summary.critical} critical, ${r.summary.high} high.`; } },
    { title: 'Open the vulnerability detail', detail: 'Review the root cause, evidence and risk rationale for the SQL Injection finding.',
      run: async () => { if (!findingId) return 'No SQLi finding to open.'; const r = await api.get<{ finding: Finding }>(`/security/findings/${findingId}`); return `Finding #${r.finding.id}: ${r.finding.title} — ${r.finding.severity.toUpperCase()}, risk ${r.finding.riskScore}/10.`; } },
    { title: 'Apply mitigation & retest', detail: 'Apply the parameterised-query fix and re-run the exact same test to verify.',
      run: async () => { if (!findingId) return 'No finding to remediate.'; const r = await api.post<{ verified: boolean; retest: LabOutcome; scoreBefore: number; scoreAfter: number }>(`/security/findings/${findingId}/remediate`); setLastResult(r.retest); await reloadScore(); await reloadModes(); await reloadFindings(); return `Retest: ${r.retest.outcome}. Verified: ${r.verified}. Score ${r.scoreBefore} → ${r.scoreAfter}.`; } },
    { title: 'Generate the security report', detail: 'Produce the final assessment report from the current state.',
      run: async () => { const r = await api.post<{ report: { id: number; title: string; score: { overall: number } } }>('/security/reports'); return `Report #${r.report.id} generated. Overall score now ${r.report.score.overall}/100.`; } },
  ];

  async function runStep(i: number) {
    setBusy(true);
    try {
      const note = await steps[i]!.run();
      setLog((prev) => [...prev, { step: steps[i]!.title, note: note ?? 'done' }]);
      setCurrent(Math.min(i + 1, steps.length));
    } catch (e) {
      setLog((prev) => [...prev, { step: steps[i]!.title, note: `Error: ${e instanceof Error ? e.message : 'failed'}` }]);
    } finally { setBusy(false); }
  }

  async function reset() { setCurrent(0); setLog([]); setLastResult(null); setFindingId(null); }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-white">Demo Mode</h1>
          <p className="text-sm text-slate-400">A guided walkthrough of the complete lifecycle. Each step performs a real operation on the platform.</p>
        </div>
        <div className="flex gap-2">
          <Button variant="ghost" size="sm" onClick={reset}>Reset</Button>
          <Button onClick={() => runStep(current)} disabled={busy || current >= steps.length}>
            {busy ? 'Running…' : current >= steps.length ? 'Complete ✓' : `Run step ${current + 1}`}
          </Button>
        </div>
      </div>

      <div className="grid gap-6 lg:grid-cols-[1fr_300px]">
        <div className="space-y-4">
          <Panel title="Guided scenario" subtitle={`Step ${Math.min(current + 1, steps.length)} of ${steps.length}`}>
            <div className="space-y-2">
              {steps.map((s, i) => {
                const done = i < current, active = i === current;
                return (
                  <div key={i} className={`rounded-lg px-3 py-2.5 transition ${active ? 'bg-accent/10 ring-1 ring-accent/30' : done ? 'glass-soft opacity-70' : 'glass-soft'}`}>
                    <div className="flex items-center gap-2.5">
                      <span className={`grid h-6 w-6 shrink-0 place-items-center rounded-full text-[11px] font-bold ${done ? 'bg-sev-ok/20 text-sev-ok' : active ? 'bg-accent/20 text-accent' : 'bg-white/5 text-slate-500'}`}>{done ? '✓' : i + 1}</span>
                      <div className="min-w-0">
                        <div className="text-sm font-medium text-slate-200">{s.title}</div>
                        <div className="text-[11px] text-slate-500">{s.detail}</div>
                      </div>
                      {active && !busy && <Button size="sm" className="ml-auto shrink-0" onClick={() => runStep(i)}>Run</Button>}
                    </div>
                  </div>
                );
              })}
            </div>
          </Panel>

          {lastResult && <Panel title="Latest step result"><LabResult result={lastResult} /></Panel>}
        </div>

        <div className="space-y-4">
          <Panel title="Live score">
            {score ? <div className="flex justify-center"><ScoreRing score={score.overall} grade={score.grade} size={130} /></div> : <Spinner />}
          </Panel>
          <Panel title="Walkthrough log">
            {log.length === 0 ? <p className="text-xs text-slate-500">Steps you run will be logged here.</p> : (
              <div className="terminal max-h-80 overflow-y-auto rounded-lg p-3">
                {log.map((l, i) => (
                  <div key={i} className="mb-2"><div className="text-accent/70">▸ {l.step}</div><div className="pl-3 text-slate-400">{l.note}</div></div>
                ))}
              </div>
            )}
          </Panel>
        </div>
      </div>
    </div>
  );
}
