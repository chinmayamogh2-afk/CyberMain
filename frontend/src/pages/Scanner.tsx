import { useState } from 'react';
import { api } from '@/lib/api';
import { useScore } from '@/lib/useSecurity';
import { useEventStream } from '@/lib/useEventStream';
import { Panel, Button, SeverityBadge, Empty, Spinner } from '@/components/ui';
import { IconSearch } from '@/components/icons';
import type { Finding } from '@/lib/types';

/** Security scanner (spec §13). Runs a real assessment; live events show progress. */
const STAGES = ['Reconnaissance', 'Endpoint discovery', 'Security checks', 'Finding generation', 'Risk classification'];

export function Scanner() {
  const { reloadScore } = useScore();
  const { events } = useEventStream(60);
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<{ scanId: number; checksRun: number; findings: Finding[]; summary: Record<string, number> } | null>(null);
  const scanEvents = events.filter((e) => e.source === 'scanner').slice(0, 14);

  async function scan() {
    setBusy(true); setResult(null);
    try {
      const r = await api.post<typeof result>('/security/scan');
      setResult(r);
      await reloadScore();
    } finally { setBusy(false); }
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-white">Security Scan</h1>
          <p className="text-sm text-slate-400">A real assessment: each check sends requests to SecureVault's own endpoints and inspects the genuine responses.</p>
        </div>
        <Button onClick={scan} disabled={busy}><IconSearch className="h-4 w-4" /> {busy ? 'Scanning…' : 'Run Full Assessment'}</Button>
      </div>

      <div className="grid gap-6 lg:grid-cols-2">
        <Panel title="Scan Workflow" subtitle="Stages of the assessment">
          <div className="space-y-2">
            {STAGES.map((stage, i) => {
              const active = busy || result;
              return (
                <div key={stage} className="flex items-center gap-3">
                  <span className={`grid h-6 w-6 place-items-center rounded-full text-[11px] font-bold ${active ? 'bg-accent/20 text-accent' : 'bg-white/5 text-slate-500'}`}>{i + 1}</span>
                  <span className={`text-sm ${active ? 'text-slate-200' : 'text-slate-500'}`}>{stage}</span>
                  {busy && <span className="ml-auto h-1.5 w-1.5 animate-pulse-dot rounded-full bg-accent" />}
                </div>
              );
            })}
          </div>
          {busy && (
            <div className="mt-4 overflow-hidden rounded-full bg-white/5">
              <div className="h-1 w-1/3 animate-scan-sweep bg-gradient-to-r from-transparent via-accent to-transparent" />
            </div>
          )}
        </Panel>

        <Panel title="Live Scan Output" subtitle="Events emitted by the running scan">
          <div className="terminal max-h-56 overflow-y-auto rounded-lg p-3">
            {scanEvents.length === 0 ? <div className="text-slate-600">No scan running. Press Run Full Assessment.</div> :
              scanEvents.map((e) => (
                <div key={e.id}><span className="text-slate-600">[{new Date(e.occurredAt).toLocaleTimeString()}]</span> <span className={e.level === 'warn' ? 'text-sev-high' : e.level === 'alert' ? 'text-sev-critical' : 'text-slate-300'}>{e.message}</span></div>
              ))}
          </div>
        </Panel>
      </div>

      {busy && !result && <Panel><Spinner label="Running checks against live endpoints…" /></Panel>}

      {result && (
        <Panel title={`Scan #${result.scanId} complete`} subtitle={`${result.checksRun} checks run`}>
          <div className="mb-4 flex flex-wrap gap-2">
            {(['critical', 'high', 'medium', 'low', 'info'] as const).map((s) => (
              <span key={s} className="rounded-lg glass-soft px-3 py-1.5 text-xs">
                <span className="capitalize text-slate-400">{s}:</span> <span className="font-semibold text-slate-100">{result.summary[s] ?? 0}</span>
              </span>
            ))}
            <span className="rounded-lg glass-soft px-3 py-1.5 text-xs"><span className="text-slate-400">Passed:</span> <span className="font-semibold text-sev-ok">{result.summary.passed ?? 0}</span></span>
          </div>
          {result.findings.length === 0 ? <Empty>No active findings — all checks passed. Flip a control to vulnerable and rescan to see findings appear.</Empty> : (
            <div className="space-y-2">
              {result.findings.map((f) => (
                <div key={f.id} className="flex items-center justify-between rounded-lg glass-soft px-4 py-3">
                  <div>
                    <div className="flex items-center gap-2"><SeverityBadge severity={f.severity} /><span className="text-sm font-medium text-slate-200">{f.title}</span></div>
                    <div className="mt-0.5 text-[11px] text-slate-500">{f.endpoint} · {f.owaspCategory} · risk {f.riskScore}/10</div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </Panel>
      )}
    </div>
  );
}
