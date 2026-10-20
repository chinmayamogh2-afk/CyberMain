import { useEffect, useState, useCallback } from 'react';
import { api } from '@/lib/api';
import { useModes } from '@/lib/useSecurity';
import { Panel, Button, ModePill, Empty } from '@/components/ui';

/** Security Headers Inspector (spec §12). Reads headers off a live response. */
interface HeaderRow { header: string; status: string; icon: string; purpose: string; risk: string; current: string | null; recommended: string; required: boolean }
interface Inspection { mode: string; headers: HeaderRow[]; leakingHeaders: { header: string; value: string; risk: string }[]; note: string }

const ICON: Record<string, { sym: string; cls: string }> = {
  ok: { sym: '✓', cls: 'text-sev-ok' }, missing: { sym: '✕', cls: 'text-sev-critical' }, warn: { sym: '⚠', cls: 'text-sev-medium' },
};

export function Headers() {
  const { classes, setMode } = useModes();
  const [data, setData] = useState<Inspection | null>(null);
  const headersMode = classes.find((c) => c.key === 'headers')?.mode ?? 'secure';

  const load = useCallback(async () => {
    setData(await api.get<Inspection>('/admin/headers/inspect'));
  }, []);
  useEffect(() => { void load(); }, [load, headersMode]);

  async function toggle() {
    await setMode('headers', headersMode === 'vulnerable' ? 'secure' : 'vulnerable');
    await load();
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-white">Security Headers Inspector</h1>
          <p className="text-sm text-slate-400">Values are read from a live HTTP response — not stored. Toggle the mode to watch them change.</p>
        </div>
        <div className="flex items-center gap-2">
          <ModePill mode={headersMode as never} onToggle={toggle} />
          <Button variant="ghost" size="sm" onClick={() => void load()}>Re-inspect</Button>
        </div>
      </div>

      {!data ? <Empty>Inspecting…</Empty> : (
        <>
          <Panel title="Response Headers" subtitle={data.note}>
            <div className="space-y-2">
              {data.headers.map((h) => {
                const ic = ICON[h.icon] ?? ICON.warn!;
                return (
                  <div key={h.header} className="rounded-lg glass-soft p-3">
                    <div className="flex items-start justify-between gap-3">
                      <div className="flex items-center gap-2">
                        <span className={`text-base font-bold ${ic.cls}`}>{ic.sym}</span>
                        <span className="font-mono text-sm text-slate-200">{h.header}</span>
                        {h.required && <span className="rounded bg-white/5 px-1.5 text-[9px] uppercase text-slate-500">required</span>}
                      </div>
                      <span className={`text-[11px] font-semibold uppercase ${ic.cls}`}>{h.status.replace('-', ' ')}</span>
                    </div>
                    <p className="mt-1.5 text-xs text-slate-400">{h.purpose}</p>
                    {h.status !== 'secure' && <p className="mt-1 text-[11px] text-sev-high">Risk: {h.risk}</p>}
                    <div className="mt-2 grid gap-1 text-[11px] sm:grid-cols-2">
                      <div className="font-mono"><span className="text-slate-600">current: </span><span className={h.current ? 'text-slate-300' : 'text-sev-critical'}>{h.current ?? 'not set'}</span></div>
                      <div className="font-mono"><span className="text-slate-600">recommended: </span><span className="text-sev-ok">{h.recommended}</span></div>
                    </div>
                  </div>
                );
              })}
            </div>
          </Panel>

          {data.leakingHeaders.length > 0 && (
            <Panel title="Information-Leaking Headers" subtitle="Headers present that disclose server internals">
              <div className="space-y-2">
                {data.leakingHeaders.map((h) => (
                  <div key={h.header} className="rounded-lg bg-sev-critical/5 px-3 py-2 ring-1 ring-sev-critical/20">
                    <span className="font-mono text-sm text-sev-critical">{h.header}: {h.value}</span>
                    <p className="mt-0.5 text-[11px] text-slate-400">{h.risk}</p>
                  </div>
                ))}
              </div>
            </Panel>
          )}
        </>
      )}
    </div>
  );
}
