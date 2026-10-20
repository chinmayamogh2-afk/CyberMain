import { useEffect, useState, useCallback } from 'react';
import { api } from '@/lib/api';
import { Panel, Button, Empty, CodeBlock } from '@/components/ui';
import type { TransactionRecord } from '@/lib/types';

/** HTTP Request Inspector (spec §15). Shows real captured request/response pairs. */
export function Requests() {
  const [rows, setRows] = useState<TransactionRecord[]>([]);
  const [selected, setSelected] = useState<TransactionRecord | null>(null);
  const [flaggedOnly, setFlaggedOnly] = useState(false);

  const load = useCallback(async () => {
    const data = await api.get<{ rows: TransactionRecord[] }>(`/admin/requests?limit=80${flaggedOnly ? '&flagged=true' : ''}`);
    setRows(data.rows);
  }, [flaggedOnly]);
  useEffect(() => { void load(); }, [load]);

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-white">Request Inspector</h1>
          <p className="text-sm text-slate-400">Real request/response pairs the application handled. Credentials are redacted. Also interceptable with Burp Suite / ZAP.</p>
        </div>
        <div className="flex gap-2">
          <Button variant={flaggedOnly ? 'primary' : 'ghost'} size="sm" onClick={() => setFlaggedOnly((v) => !v)}>Flagged only</Button>
          <Button variant="ghost" size="sm" onClick={() => void load()}>Refresh</Button>
        </div>
      </div>

      <div className="grid gap-6 lg:grid-cols-[1fr_1.4fr]">
        <Panel title={`Transactions (${rows.length})`}>
          {rows.length === 0 ? <Empty>No captured traffic yet.</Empty> : (
            <div className="max-h-[32rem] space-y-1 overflow-y-auto">
              {rows.map((r) => (
                <button key={r.id} onClick={() => setSelected(r)}
                  className={`flex w-full items-center gap-2 rounded-lg px-2.5 py-2 text-left text-xs transition ${selected?.id === r.id ? 'bg-accent/10 ring-1 ring-accent/30' : 'hover:bg-white/5'}`}>
                  <span className={`w-12 shrink-0 font-mono font-semibold ${METHOD_COLOUR[r.method] ?? 'text-slate-400'}`}>{r.method}</span>
                  <span className={`w-9 shrink-0 font-mono ${r.statusCode >= 500 ? 'text-sev-critical' : r.statusCode >= 400 ? 'text-sev-high' : 'text-sev-ok'}`}>{r.statusCode}</span>
                  <span className="min-w-0 flex-1 truncate font-mono text-slate-300">{r.path}</span>
                  {r.flagged && <span className="shrink-0 rounded bg-sev-high/15 px-1 text-[9px] text-sev-high" title={r.flagReason ?? ''}>⚑</span>}
                  {r.origin !== 'app' && <span className="shrink-0 rounded bg-accent/15 px-1 text-[9px] text-accent">{r.origin}</span>}
                </button>
              ))}
            </div>
          )}
        </Panel>

        {selected ? (
          <Panel title={`${selected.method} ${selected.path}`} subtitle={`${selected.statusCode} · ${selected.durationMs} ms · ${new Date(selected.startedAt).toLocaleTimeString()}`}>
            {selected.flagged && <div className="mb-3 rounded-lg border border-sev-high/20 bg-sev-high/5 px-3 py-2 text-xs text-sev-high">Flagged: {selected.flagReason}</div>}
            <div className="grid gap-3 xl:grid-cols-2">
              <div>
                <div className="mb-1 text-[11px] uppercase tracking-wider text-slate-500">Request</div>
                <CodeBlock language="http" code={`${selected.method} ${selected.path}\n${headerLines(selected.requestHeaders)}\n\n${selected.requestBody || '(no body)'}`} />
              </div>
              <div>
                <div className="mb-1 text-[11px] uppercase tracking-wider text-slate-500">Response</div>
                <CodeBlock language="http" code={`HTTP/1.1 ${selected.statusCode}\n${headerLines(selected.responseHeaders)}\n\n${truncate(selected.responseBody)}`} />
              </div>
            </div>
          </Panel>
        ) : <Empty>Select a transaction to inspect its full request and response.</Empty>}
      </div>
    </div>
  );
}

const METHOD_COLOUR: Record<string, string> = { GET: 'text-sev-ok', POST: 'text-accent', PUT: 'text-sev-medium', PATCH: 'text-sev-medium', DELETE: 'text-sev-critical' };
function headerLines(h: Record<string, unknown>): string { return Object.entries(h).map(([k, v]) => `${k}: ${typeof v === 'string' ? v : JSON.stringify(v)}`).join('\n'); }
function truncate(s: string, n = 1200): string { return s.length > n ? `${s.slice(0, n)}…` : s || '(empty)'; }
