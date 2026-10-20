import { useEffect, useState, useCallback } from 'react';
import { api, getText } from '@/lib/api';
import { Panel, Button, Empty, SeverityBadge } from '@/components/ui';

interface ReportListItem { id: number; title: string; createdAt: string }
interface ReportPayload {
  id: number; title: string; generatedAt: string; executiveSummary: string;
  score: { overall: number; grade: string; domains: { label: string; score: number }[] };
  findings: { id: number; title: string; severity: string; status: string; owaspCategory: string }[];
  methodology: string[]; secureDevelopmentRecommendations: string[]; disclaimer: string;
  scope: { inScope: string[]; outOfScope: string[] };
}

/** Security Report generator (spec §22). */
export function Reports() {
  const [list, setList] = useState<ReportListItem[]>([]);
  const [report, setReport] = useState<ReportPayload | null>(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    const data = await api.get<{ reports: ReportListItem[] }>('/security/reports');
    setList(data.reports);
  }, []);
  useEffect(() => { void load(); }, [load]);

  async function generate() {
    setBusy(true);
    try { const r = await api.post<{ report: ReportPayload }>('/security/reports'); setReport(r.report); await load(); }
    finally { setBusy(false); }
  }
  async function open(id: number) { const r = await api.get<{ report: ReportPayload }>(`/security/reports/${id}`); setReport(r.report); }
  async function download(id: number) {
    const md = await getText(`/security/reports/${id}?format=markdown`);
    const blob = new Blob([md], { type: 'text/markdown' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a'); a.href = url; a.download = `sentinelx-report-${id}.md`; a.click();
    URL.revokeObjectURL(url);
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-white">Security Reports</h1>
          <p className="text-sm text-slate-400">A professional assessment report assembled from live platform state — score, findings, evidence and recommendations.</p>
        </div>
        <Button onClick={generate} disabled={busy}>{busy ? 'Generating…' : 'Generate Report'}</Button>
      </div>

      <div className="grid gap-6 lg:grid-cols-[260px_1fr]">
        <Panel title="Generated reports">
          {list.length === 0 ? <Empty>No reports yet.</Empty> : (
            <div className="space-y-1">
              {list.map((r) => (
                <button key={r.id} onClick={() => open(r.id)} className={`w-full rounded-lg px-3 py-2 text-left text-xs transition ${report?.id === r.id ? 'bg-accent/10 text-accent ring-1 ring-accent/20' : 'text-slate-300 hover:bg-white/5'}`}>
                  <div className="truncate font-medium">{r.title}</div>
                  <div className="text-[10px] text-slate-500">{new Date(r.createdAt).toLocaleString()}</div>
                </button>
              ))}
            </div>
          )}
        </Panel>

        {report ? (
          <div className="space-y-4">
            <Panel title={report.title} subtitle={`Generated ${new Date(report.generatedAt).toLocaleString()}`}
              actions={<Button size="sm" variant="ghost" onClick={() => download(report.id)}>Export Markdown</Button>}>
              <div className="mb-4 flex items-center gap-4">
                <div className="rounded-xl bg-accent/10 px-4 py-2 text-center ring-1 ring-accent/20">
                  <div className="text-2xl font-bold text-accent">{report.score.overall}</div>
                  <div className="text-[10px] text-slate-400">Grade {report.score.grade}</div>
                </div>
                <p className="flex-1 text-sm leading-relaxed text-slate-300">{report.executiveSummary}</p>
              </div>
            </Panel>

            <Panel title={`Findings (${report.findings.length})`}>
              {report.findings.length === 0 ? <Empty>No findings recorded.</Empty> : (
                <div className="space-y-2">
                  {report.findings.map((f) => (
                    <div key={f.id} className="flex items-center justify-between rounded-lg glass-soft px-3 py-2">
                      <div className="flex items-center gap-2"><SeverityBadge severity={f.severity as never} /><span className="text-sm text-slate-200">{f.title}</span></div>
                      <span className="text-[11px] text-slate-500">{f.owaspCategory} · {f.status}</span>
                    </div>
                  ))}
                </div>
              )}
            </Panel>

            <div className="grid gap-4 md:grid-cols-2">
              <Panel title="Methodology"><ul className="space-y-1.5 text-xs text-slate-400">{report.methodology.map((m, i) => <li key={i}>• {m}</li>)}</ul></Panel>
              <Panel title="Secure Development Recommendations"><ul className="space-y-1.5 text-xs text-slate-400">{report.secureDevelopmentRecommendations.map((m, i) => <li key={i}>• {m}</li>)}</ul></Panel>
            </div>

            <Panel title="Scope">
              <div className="grid gap-3 text-xs sm:grid-cols-2">
                <div><div className="mb-1 font-semibold text-sev-ok">In scope</div><ul className="space-y-1 text-slate-400">{report.scope.inScope.map((s, i) => <li key={i}>• {s}</li>)}</ul></div>
                <div><div className="mb-1 font-semibold text-slate-400">Out of scope</div><ul className="space-y-1 text-slate-500">{report.scope.outOfScope.map((s, i) => <li key={i}>• {s}</li>)}</ul></div>
              </div>
              <p className="mt-4 border-t border-white/5 pt-3 text-[11px] italic text-slate-500">{report.disclaimer}</p>
            </Panel>
          </div>
        ) : <Empty>Generate or select a report to view it.</Empty>}
      </div>
    </div>
  );
}
