import { useState } from 'react';
import { api } from '@/lib/api';
import { useFindings, useScore } from '@/lib/useSecurity';
import { Panel, Button, SeverityBadge, Empty, VerdictBadge, Spinner } from '@/components/ui';
import { LabResult } from '@/components/LabResult';
import type { Finding, LabOutcome } from '@/lib/types';

/** Remediation Center (spec §21): problem → fix → implementation → verification. */
interface RemediationResult { finding: Finding; retest: LabOutcome; verified: boolean; scoreBefore: number; scoreAfter: number }

export function Remediation() {
  const { findings, loading, reloadFindings } = useFindings();
  const { reloadScore } = useScore();
  const [busyId, setBusyId] = useState<number | null>(null);
  const [outcome, setOutcome] = useState<RemediationResult | null>(null);

  const active = findings.filter((f) => f.status === 'open');
  const verified = findings.filter((f) => f.status === 'verified');

  async function remediate(id: number) {
    setBusyId(id); setOutcome(null);
    try {
      const r = await api.post<RemediationResult>(`/security/findings/${id}/remediate`);
      setOutcome(r);
      await Promise.all([reloadFindings(), reloadScore()]);
    } finally { setBusyId(null); }
  }
  async function retest(id: number) {
    setBusyId(id); setOutcome(null);
    try {
      const r = await api.post<RemediationResult>(`/security/findings/${id}/retest`);
      setOutcome(r);
      await Promise.all([reloadFindings(), reloadScore()]);
    } finally { setBusyId(null); }
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-bold text-white">Remediation Center</h1>
        <p className="text-sm text-slate-400">Apply the recommended mitigation, then retest. Applying a fix flips the real control; the retest re-runs the identical check to verify it.</p>
      </div>

      {outcome && (
        <Panel title="Remediation result" subtitle={outcome.verified ? 'Mitigation verified' : 'Mitigation not verified'}>
          <div className="mb-4 flex flex-wrap items-center gap-4">
            <VerdictBadge verdict={outcome.retest.verdict} />
            <span className="text-sm text-slate-300">{outcome.retest.summary}</span>
            <span className="ml-auto flex items-center gap-2 text-sm">
              <span className="text-slate-400">Score</span>
              <span className="font-semibold text-slate-200">{outcome.scoreBefore}</span>
              <span className="text-slate-600">→</span>
              <span className={`font-semibold ${outcome.scoreAfter >= outcome.scoreBefore ? 'text-sev-ok' : 'text-sev-critical'}`}>{outcome.scoreAfter}</span>
            </span>
          </div>
          <LabResult result={outcome.retest} />
        </Panel>
      )}

      <div className="grid gap-6 lg:grid-cols-2">
        <Panel title={`Open findings (${active.length})`}>
          {loading ? <Spinner /> : active.length === 0 ? <Empty>Nothing to remediate. Run a scan or simulate an attack in vulnerable mode first.</Empty> : (
            <div className="space-y-3">
              {active.map((f) => (
                <div key={f.id} className="rounded-lg glass-soft p-4">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2"><SeverityBadge severity={f.severity} /><span className="text-sm font-medium text-slate-200">{f.title}</span></div>
                  </div>
                  <div className="mt-3 space-y-2 text-xs">
                    <Step label="Problem" body={f.description} />
                    <Step label="Root cause" body={f.rootCause} />
                    <Step label="Recommended fix" body={f.remediation} />
                  </div>
                  <div className="mt-3 flex gap-2">
                    <Button size="sm" onClick={() => remediate(f.id)} disabled={busyId === f.id}>{busyId === f.id ? 'Applying…' : 'Apply mitigation & retest'}</Button>
                    <Button size="sm" variant="ghost" onClick={() => retest(f.id)} disabled={busyId === f.id}>Retest only</Button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </Panel>

        <Panel title={`Verified (${verified.length})`} subtitle="Findings whose fix was confirmed by a retest">
          {verified.length === 0 ? <Empty>No verified remediations yet.</Empty> : (
            <div className="space-y-2">
              {verified.map((f) => (
                <div key={f.id} className="flex items-center justify-between rounded-lg glass-soft px-4 py-3">
                  <div className="flex items-center gap-2"><span className="text-sev-ok">✓</span><span className="text-sm text-slate-300">{f.title}</span></div>
                  <Button size="sm" variant="ghost" onClick={() => retest(f.id)} disabled={busyId === f.id}>Retest</Button>
                </div>
              ))}
            </div>
          )}
        </Panel>
      </div>
    </div>
  );
}

function Step({ label, body }: { label: string; body: string }) {
  return <div><span className="font-semibold text-slate-400">{label}:</span> <span className="text-slate-400">{body}</span></div>;
}
