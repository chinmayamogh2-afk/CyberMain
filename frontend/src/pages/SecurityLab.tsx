import { useState, useEffect } from 'react';
import { api } from '@/lib/api';
import { useModes } from '@/lib/useSecurity';
import { Panel, Button, ModePill, Spinner, Empty } from '@/components/ui';
import { LabResult } from '@/components/LabResult';
import type { LabOutcome, VulnClassMeta } from '@/lib/types';

/**
 * The Security Lab (spec §5). Each vulnerability class is an interactive lab:
 * pick a payload or input, run it, and see the full lifecycle. The mode toggle
 * next to each lab flips the real control so you can run the same test in both
 * modes and compare.
 */

interface LabConfig {
  key: string;
  endpoint: string;
  fields: { name: string; label: string; placeholder?: string; type?: 'select'; options?: { label: string; value: string }[]; default?: string }[];
  payloadSource?: string; // endpoint returning { payloads: [...] }
}

const LABS: Record<string, LabConfig> = {
  sqli: { key: 'sqli', endpoint: '/lab/run/sqli', payloadSource: '/lab/sqli/payloads',
    fields: [{ name: 'username', label: 'Username field' }, { name: 'password', label: 'Password field', default: 'anything' }] },
  xss_stored: { key: 'xss_stored', endpoint: '/lab/run/xss', payloadSource: '/lab/xss/payloads',
    fields: [{ name: 'input', label: 'Comment input' }] },
  csrf: { key: 'csrf', endpoint: '/lab/run/csrf',
    fields: [{ name: 'scenario', label: 'Scenario', type: 'select', default: 'forged', options: [{ label: 'Forged cross-site request', value: 'forged' }, { label: 'Legitimate same-origin request', value: 'legitimate' }] }] },
  idor: { key: 'idor', endpoint: '/lab/run/idor',
    fields: [{ name: 'actingUserId', label: 'Acting user id', default: '4' }, { name: 'documentId', label: 'Document id', default: '1' }] },
  auth: { key: 'auth', endpoint: '/lab/run/auth',
    fields: [{ name: 'username', label: 'Username', default: 'alice' }, { name: 'password', label: 'Sample password', default: 'password123' }] },
  session: { key: 'session', endpoint: '/lab/run/session', fields: [] },
  headers: { key: 'headers', endpoint: '/lab/run/headers', fields: [] },
  upload: { key: 'upload', endpoint: '/lab/run/upload',
    fields: [{ name: 'filename', label: 'Filename', default: 'invoice.php' }, { name: 'declaredType', label: 'Declared MIME type', default: 'application/x-php' }, { name: 'sizeBytes', label: 'Size (bytes)', default: '2048' }] },
  path_traversal: { key: 'path_traversal', endpoint: '/lab/run/traversal',
    fields: [{ name: 'requestedPath', label: 'Requested file path', default: '../lab-secret.txt' }] },
  ssrf: { key: 'ssrf', endpoint: '/lab/run/ssrf',
    fields: [{ name: 'url', label: 'Target URL', default: 'http://169.254.169.254/latest/meta-data/' }] },
  cmdi: { key: 'cmdi', endpoint: '/lab/run/cmdi',
    fields: [{ name: 'format', label: 'Report format', default: 'pdf; whoami' }] },
  data_exposure: { key: 'data_exposure', endpoint: '/lab/run/exposure',
    fields: [{ name: 'targetUserId', label: 'Target user id', default: '3' }] },
};

export function SecurityLab() {
  const { classes, setMode } = useModes();
  const [selected, setSelected] = useState<string>('sqli');
  const current = classes.find((c) => c.key === selected);
  const config = LABS[selected];

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-bold text-white">Security Lab</h1>
        <p className="text-sm text-slate-400">Each vulnerability has its own interactive laboratory. Run a test, then flip the mode and run it again to see the difference.</p>
      </div>

      <div className="grid gap-6 lg:grid-cols-[260px_1fr]">
        {/* Lab selector */}
        <Panel title="Vulnerability Labs">
          <div className="space-y-1">
            {classes.filter((c) => LABS[c.key]).map((c) => (
              <button key={c.key} onClick={() => setSelected(c.key)}
                className={`flex w-full items-center justify-between rounded-lg px-3 py-2 text-left text-sm transition ${selected === c.key ? 'bg-accent/10 text-accent ring-1 ring-accent/20' : 'text-slate-300 hover:bg-white/5'}`}>
                <span className="truncate">{c.title}</span>
                <span className={`ml-2 h-1.5 w-1.5 shrink-0 rounded-full ${c.mode === 'vulnerable' ? 'bg-sev-critical' : 'bg-sev-ok'}`} />
              </button>
            ))}
          </div>
        </Panel>

        {config && current && <LabWorkspace key={config.key} config={config} meta={current} onToggle={(m) => setMode(selected, m)} />}
      </div>
    </div>
  );
}

function LabWorkspace({ config, meta, onToggle }: { config: LabConfig; meta: VulnClassMeta; onToggle: (m: 'vulnerable' | 'secure') => void }) {
  const [values, setValues] = useState<Record<string, string>>(() => Object.fromEntries(config.fields.map((f) => [f.name, f.default ?? ''])));
  const [payloads, setPayloads] = useState<{ id: string; label: string; teaches: string; [k: string]: string }[]>([]);
  const [result, setResult] = useState<LabOutcome | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  // Load payload menu for this lab.
  useEffect(() => {
    if (config.payloadSource) {
      void api.get<{ payloads: typeof payloads }>(config.payloadSource).then((d) => setPayloads(d.payloads)).catch(() => {});
    } else {
      setPayloads([]);
    }
  }, [config.payloadSource]);

  async function run(modeOverride?: 'vulnerable' | 'secure') {
    setBusy(true); setErr(null);
    try {
      const body: Record<string, unknown> = { ...values };
      if (modeOverride) body.mode = modeOverride;
      const r = await api.post<LabOutcome>(config.endpoint, body);
      setResult(r);
    } catch (e) {
      setErr(e instanceof Error ? e.message : 'Test failed.');
    } finally { setBusy(false); }
  }

  function applyPayload(p: Record<string, string>) {
    const next = { ...values };
    for (const f of config.fields) if (p[f.name] !== undefined) next[f.name] = p[f.name]!;
    if (p.input !== undefined && config.fields.some((f) => f.name === 'input')) next.input = p.input;
    if (p.username !== undefined && config.fields.some((f) => f.name === 'username')) next.username = p.username;
    if (p.password !== undefined && config.fields.some((f) => f.name === 'password')) next.password = p.password;
    setValues(next);
  }

  return (
    <div className="space-y-4">
      <Panel title={meta.title} subtitle={meta.summary}
        actions={<div className="flex items-center gap-2"><span className="text-[11px] text-slate-500">{meta.owaspCategory}</span><ModePill mode={meta.mode} onToggle={() => onToggle(meta.mode === 'vulnerable' ? 'secure' : 'vulnerable')} /></div>}>
        {!meta.liveExploit && (
          <div className="mb-3 rounded-lg border border-sev-medium/20 bg-sev-medium/5 px-3 py-2 text-xs text-sev-medium">
            This lab is a controlled demonstration — a full live exploit would be unsafe or unreliable to automate, so the mechanism is shown against a safe local target.
          </div>
        )}

        {payloads.length > 0 && (
          <div className="mb-4">
            <div className="mb-1.5 text-[11px] uppercase tracking-wider text-slate-500">Example payloads</div>
            <div className="flex flex-wrap gap-2">
              {payloads.map((p) => (
                <button key={p.id} onClick={() => applyPayload(p)} title={p.teaches}
                  className="rounded-lg border border-white/10 bg-white/5 px-2.5 py-1.5 text-xs text-slate-300 transition hover:border-accent/40 hover:bg-accent/5">
                  {p.label}
                </button>
              ))}
            </div>
          </div>
        )}

        <div className="grid gap-3 sm:grid-cols-2">
          {config.fields.map((f) => (
            <label key={f.name} className="block">
              <span className="text-xs text-slate-400">{f.label}</span>
              {f.type === 'select' ? (
                <select value={values[f.name]} onChange={(e) => setValues({ ...values, [f.name]: e.target.value })}
                  className="mt-1 w-full rounded-lg border border-white/10 bg-base-900/60 px-3 py-2 text-sm text-slate-100 outline-none focus:border-accent/50">
                  {f.options?.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
                </select>
              ) : (
                <input value={values[f.name] ?? ''} onChange={(e) => setValues({ ...values, [f.name]: e.target.value })} placeholder={f.placeholder}
                  className="mt-1 w-full rounded-lg border border-white/10 bg-base-900/60 px-3 py-2 font-mono text-sm text-slate-100 outline-none focus:border-accent/50" />
              )}
            </label>
          ))}
          {config.fields.length === 0 && <p className="text-sm text-slate-500">This lab takes no input — it inspects the current configuration directly.</p>}
        </div>

        <div className="mt-4 flex flex-wrap items-center gap-2">
          <Button onClick={() => run()} disabled={busy}>{busy ? 'Running…' : `Run test (${meta.mode})`}</Button>
          <Button variant="ghost" onClick={() => run('vulnerable')} disabled={busy}>Run in Vulnerable</Button>
          <Button variant="ghost" onClick={() => run('secure')} disabled={busy}>Run in Hardened</Button>
          {busy && <Spinner />}
        </div>
        {err && <p className="mt-2 text-xs text-sev-critical">{err}</p>}
      </Panel>

      {result ? <Panel>{<LabResult result={result} />}</Panel> : <Empty>Run a test to see the full attack → detect → explain → fix lifecycle.</Empty>}
    </div>
  );
}
