import { useEffect, useState, useCallback } from 'react';
import { api } from '@/lib/api';
import { Panel, Button, Empty } from '@/components/ui';
import type { AuditRecord } from '@/lib/types';

/** Audit log viewer with filtering + search (spec §23). */
const SEV_COLOUR: Record<string, string> = { info: 'text-slate-400', low: 'text-slate-300', medium: 'text-sev-medium', high: 'text-sev-high', critical: 'text-sev-critical' };
const OUT_COLOUR: Record<string, string> = { success: 'text-sev-ok', failure: 'text-sev-high', blocked: 'text-sev-medium', detected: 'text-sev-critical' };

export function AuditLogs() {
  const [rows, setRows] = useState<AuditRecord[]>([]);
  const [total, setTotal] = useState(0);
  const [search, setSearch] = useState('');
  const [category, setCategory] = useState('');
  const [expanded, setExpanded] = useState<number | null>(null);

  const load = useCallback(async () => {
    const qs = new URLSearchParams();
    if (search) qs.set('search', search);
    if (category) qs.set('category', category);
    qs.set('limit', '150');
    const data = await api.get<{ total: number; rows: AuditRecord[] }>(`/admin/audit?${qs}`);
    setRows(data.rows); setTotal(data.total);
  }, [search, category]);
  useEffect(() => { void load(); }, [load]);

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-bold text-white">Audit Logs</h1>
        <p className="text-sm text-slate-400">Every security-relevant action, with actor, context and outcome. Credentials are redacted before anything is written.</p>
      </div>

      <Panel>
        <div className="mb-4 flex flex-wrap gap-2">
          <input value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Search action, actor, path…"
            className="flex-1 rounded-lg border border-white/10 bg-base-900/60 px-3 py-2 text-sm text-slate-100 outline-none focus:border-accent/50" />
          <select value={category} onChange={(e) => setCategory(e.target.value)}
            className="rounded-lg border border-white/10 bg-base-900/60 px-3 py-2 text-sm text-slate-200 outline-none focus:border-accent/50">
            <option value="">All categories</option>
            {['auth', 'access', 'admin', 'security', 'data'].map((c) => <option key={c} value={c}>{c}</option>)}
          </select>
          <Button variant="ghost" onClick={() => void load()}>Search</Button>
        </div>
        <div className="mb-2 text-xs text-slate-500">{total} record(s)</div>
        {rows.length === 0 ? <Empty>No audit records match.</Empty> : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="text-slate-500"><tr>
                <th className="pb-2 pr-3">Time</th><th className="pb-2 pr-3">Actor</th><th className="pb-2 pr-3">Action</th>
                <th className="pb-2 pr-3">Category</th><th className="pb-2 pr-3">Outcome</th><th className="pb-2 pr-3">Severity</th><th className="pb-2">Request</th>
              </tr></thead>
              <tbody>
                {rows.map((r) => (
                  <>
                    <tr key={r.id} className="cursor-pointer border-t border-white/5 hover:bg-white/5" onClick={() => setExpanded(expanded === r.id ? null : r.id)}>
                      <td className="py-2 pr-3 text-slate-500">{new Date(r.occurredAt).toLocaleTimeString()}</td>
                      <td className="py-2 pr-3 text-slate-300">{r.actorLabel}</td>
                      <td className="py-2 pr-3 font-mono text-slate-300">{r.action}</td>
                      <td className="py-2 pr-3 text-slate-400">{r.category}</td>
                      <td className={`py-2 pr-3 ${OUT_COLOUR[r.outcome] ?? 'text-slate-400'}`}>{r.outcome}</td>
                      <td className={`py-2 pr-3 uppercase ${SEV_COLOUR[r.severity] ?? ''}`}>{r.severity}</td>
                      <td className="py-2 font-mono text-slate-500">{r.requestMethod} {r.requestPath}</td>
                    </tr>
                    {expanded === r.id && (
                      <tr key={`${r.id}-d`} className="bg-base-900/40"><td colSpan={7} className="px-3 py-2">
                        <pre className="overflow-x-auto font-mono text-[11px] text-slate-400">{JSON.stringify(r.detail, null, 2)}</pre>
                      </td></tr>
                    )}
                  </>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>
    </div>
  );
}
