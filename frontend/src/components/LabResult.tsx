import { useState } from 'react';
import type { LabOutcome } from '@/lib/types';
import { VerdictBadge, CodeBlock } from './ui';

/**
 * Renders a full LabOutcome: the terminal trace, the request/response exchange,
 * evidence, and the "why / how to fix" explanation. Shared by the Lab, the
 * Simulator and the Vulnerability detail view so the whole lifecycle is shown
 * consistently (spec §16, §18).
 */
const LEVEL: Record<string, string> = {
  info: 'text-slate-300', ok: 'text-sev-ok', warn: 'text-sev-high', alert: 'text-sev-critical',
};

export function LabResult({ result }: { result: LabOutcome }) {
  const [tab, setTab] = useState<'trace' | 'exchange' | 'why' | 'fix'>('trace');
  const exploited = result.outcome === 'exploited';

  return (
    <div className="space-y-4">
      {/* Headline */}
      <div className={`rounded-xl p-4 ring-1 ${exploited ? 'bg-sev-critical/5 ring-sev-critical/20' : result.outcome === 'blocked' ? 'bg-sev-ok/5 ring-sev-ok/20' : 'bg-sev-medium/5 ring-sev-medium/20'}`}>
        <div className="flex items-center justify-between gap-3">
          <div className="flex items-center gap-3">
            <VerdictBadge verdict={result.verdict} />
            <span className="text-sm font-semibold text-slate-100">{result.title}</span>
            <span className="rounded bg-white/5 px-2 py-0.5 text-[10px] uppercase tracking-wide text-slate-400">{result.mode}</span>
          </div>
          <span className="text-xs text-slate-500">{result.durationMs} ms</span>
        </div>
        <p className="mt-2 text-sm text-slate-300">{result.summary}</p>
        {!result.liveExploit && result.demonstrationNote && (
          <p className="mt-2 rounded-lg border border-sev-medium/20 bg-sev-medium/5 px-3 py-2 text-xs text-sev-medium">
            Controlled demonstration — {result.demonstrationNote}
          </p>
        )}
      </div>

      {/* Tabs */}
      <div className="flex gap-1 border-b border-white/5">
        {([['trace', 'Terminal'], ['exchange', 'HTTP'], ['why', 'Why vulnerable'], ['fix', 'How to fix']] as const).map(([k, label]) => (
          <button key={k} onClick={() => setTab(k)}
            className={`px-3 py-2 text-xs font-medium transition ${tab === k ? 'border-b-2 border-accent text-accent' : 'text-slate-400 hover:text-slate-200'}`}>
            {label}
          </button>
        ))}
      </div>

      {tab === 'trace' && (
        <div className="terminal max-h-96 overflow-y-auto rounded-lg p-3.5">
          {result.trace.map((s) => (
            <div key={s.step} className="mb-2">
              <div>
                <span className="text-slate-600">{String(s.step).padStart(2, '0')}</span>{' '}
                <span className="text-accent/60">{s.phase}</span>{' '}
                <span className={LEVEL[s.level ?? 'info']}>{s.message}</span>
              </div>
              {s.data !== undefined && s.data !== null && (
                <pre className="mt-1 overflow-x-auto whitespace-pre-wrap pl-6 text-[11px] text-slate-400">
                  {typeof s.data === 'string' ? s.data : JSON.stringify(s.data, null, 2)}
                </pre>
              )}
            </div>
          ))}
        </div>
      )}

      {tab === 'exchange' && result.exchange && (
        <div className="grid gap-3 md:grid-cols-2">
          <div>
            <div className="mb-1 text-[11px] uppercase tracking-wider text-slate-500">Request</div>
            <CodeBlock language="http" code={formatRequest(result.exchange)} />
          </div>
          <div>
            <div className="mb-1 text-[11px] uppercase tracking-wider text-slate-500">Response</div>
            <CodeBlock language="http" code={formatResponse(result.exchange)} />
          </div>
        </div>
      )}
      {tab === 'exchange' && !result.exchange && <p className="text-sm text-slate-500">No HTTP exchange captured for this test.</p>}

      {tab === 'why' && (
        <div className="space-y-3 text-sm">
          <Field label="Root cause" value={result.explanation.rootCause} />
          <Field label="Potential impact" value={result.explanation.impact} />
          {result.explanation.dataFlow && (
            <div className="rounded-lg glass-soft p-3">
              <div className="text-[11px] uppercase tracking-wider text-slate-500">Data flow</div>
              <div className="mt-2 flex flex-wrap items-center gap-2 text-xs">
                <span className="rounded bg-sev-critical/10 px-2 py-1 text-sev-critical">source: {result.explanation.dataFlow.source}</span>
                <span className="text-slate-600">→</span>
                <span className="rounded bg-sev-high/10 px-2 py-1 text-sev-high">sink: {result.explanation.dataFlow.sink}</span>
                <span className="text-slate-600">→</span>
                <span className="rounded bg-white/5 px-2 py-1 text-slate-300">context: {result.explanation.dataFlow.context}</span>
              </div>
            </div>
          )}
          <div>
            <div className="mb-1 text-[11px] uppercase tracking-wider text-slate-500">Vulnerable implementation</div>
            <CodeBlock language="code" code={result.explanation.vulnerableExample} />
          </div>
        </div>
      )}

      {tab === 'fix' && (
        <div className="space-y-3 text-sm">
          <Field label="Remediation" value={result.explanation.remediation} />
          <div>
            <div className="mb-1 text-[11px] uppercase tracking-wider text-sev-ok">Secure implementation</div>
            <CodeBlock language="code" code={result.explanation.secureExample} />
          </div>
          <Field label="Verification procedure" value={result.explanation.verification} />
        </div>
      )}
    </div>
  );
}

function Field({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <div className="text-[11px] uppercase tracking-wider text-slate-500">{label}</div>
      <p className="mt-1 leading-relaxed text-slate-300">{value}</p>
    </div>
  );
}

function formatRequest(ex: LabOutcome['exchange']): string {
  if (!ex) return '';
  const lines = [`${ex.method} ${ex.url} HTTP/1.1`];
  for (const [k, v] of Object.entries(ex.headers)) lines.push(`${k}: ${v}`);
  if (ex.body !== undefined) lines.push('', JSON.stringify(ex.body, null, 2));
  return lines.join('\n');
}
function formatResponse(ex: LabOutcome['exchange']): string {
  if (!ex?.response) return '(no response)';
  const r = ex.response;
  const lines = [`HTTP/1.1 ${r.status}`];
  for (const [k, v] of Object.entries(r.headers)) lines.push(`${k}: ${v}`);
  lines.push('', typeof r.body === 'string' ? r.body : JSON.stringify(r.body, null, 2));
  return lines.join('\n');
}
