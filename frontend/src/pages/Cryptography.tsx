import { useState } from 'react';
import { api } from '@/lib/api';
import { Panel, Button, Empty } from '@/components/ui';

/** Cryptography Center (spec §11): hashing vs encryption vs encoding. */
interface DemoResult {
  input: string;
  hashing: Record<string, { value: string; note: string }>;
  encryption: { algorithm: string; ciphertext: string; decrypted: string; note: string };
  encoding: { base64: { value: string; decoded: string; note: string }; hex: { value: string; note: string } };
}

export function Cryptography() {
  const [text, setText] = useState('confidential: Q3 revenue 4.82 Cr');
  const [result, setResult] = useState<DemoResult | null>(null);
  const [busy, setBusy] = useState(false);

  async function run() {
    setBusy(true);
    try { setResult(await api.post<DemoResult>('/crypto/demonstrate', { text })); }
    finally { setBusy(false); }
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-bold text-white">Cryptography Center</h1>
        <p className="text-sm text-slate-400">The same input, three ways — so the difference between hashing, encryption and encoding is unmistakable. Keys never leave the server.</p>
      </div>

      <Panel title="Transform sample data" subtitle="Processed in memory, never stored or logged">
        <div className="flex gap-2">
          <input value={text} onChange={(e) => setText(e.target.value)}
            className="flex-1 rounded-lg border border-white/10 bg-base-900/60 px-3 py-2 font-mono text-sm text-slate-100 outline-none focus:border-accent/50" />
          <Button onClick={run} disabled={busy}>{busy ? 'Working…' : 'Transform'}</Button>
        </div>
      </Panel>

      {!result ? <Empty>Enter some text and transform it to see all three families.</Empty> : (
        <div className="grid gap-6 lg:grid-cols-3">
          <Panel title="Hashing" subtitle="One-way · for verification">
            <div className="space-y-3">
              {Object.entries(result.hashing).map(([algo, h]) => (
                <div key={algo}>
                  <div className="flex items-center gap-2"><span className="text-xs font-semibold uppercase text-slate-300">{algo}</span>{algo === 'scrypt' ? <span className="rounded bg-sev-ok/15 px-1.5 text-[9px] text-sev-ok">USE FOR PASSWORDS</span> : algo === 'md5' ? <span className="rounded bg-sev-critical/15 px-1.5 text-[9px] text-sev-critical">BROKEN</span> : null}</div>
                  <div className="mt-1 break-all rounded bg-base-900/60 p-2 font-mono text-[10px] text-slate-400">{h.value.slice(0, 80)}{h.value.length > 80 ? '…' : ''}</div>
                  <p className="mt-1 text-[11px] text-slate-500">{h.note}</p>
                </div>
              ))}
            </div>
          </Panel>

          <Panel title="Encryption" subtitle="Two-way · for confidentiality">
            <div className="space-y-2 text-xs">
              <div className="text-slate-400">Algorithm: <span className="font-mono text-accent">{result.encryption.algorithm}</span></div>
              <div><div className="text-[10px] uppercase tracking-wider text-slate-500">Ciphertext</div><div className="mt-1 break-all rounded bg-base-900/60 p-2 font-mono text-[10px] text-slate-400">{result.encryption.ciphertext.slice(0, 90)}…</div></div>
              <div><div className="text-[10px] uppercase tracking-wider text-sev-ok">Decrypted (with key)</div><div className="mt-1 rounded bg-sev-ok/5 p-2 font-mono text-slate-300">{result.encryption.decrypted}</div></div>
              <p className="text-[11px] text-slate-500">{result.encryption.note}</p>
            </div>
          </Panel>

          <Panel title="Encoding" subtitle="Reversible · NOT security">
            <div className="space-y-2 text-xs">
              <div><div className="text-[10px] uppercase tracking-wider text-slate-500">Base64</div><div className="mt-1 break-all rounded bg-base-900/60 p-2 font-mono text-[10px] text-slate-400">{result.encoding.base64.value}</div></div>
              <div className="rounded bg-sev-critical/5 p-2 ring-1 ring-sev-critical/20"><span className="text-[10px] uppercase text-sev-critical">Decoded by anyone →</span> <span className="font-mono text-slate-300">{result.encoding.base64.decoded}</span></div>
              <p className="text-[11px] text-sev-high">{result.encoding.base64.note}</p>
            </div>
          </Panel>
        </div>
      )}

      <Panel title="Data flow" subtitle="Plain data → encrypt → ciphertext → decrypt → original">
        <div className="flex flex-wrap items-center gap-2 text-xs">
          {['Plain data', 'Encryption (AES-256-GCM)', 'Ciphertext', 'Decryption', 'Original data'].map((s, i, arr) => (
            <span key={s} className="flex items-center gap-2">
              <span className="rounded-lg glass-soft px-3 py-2 text-slate-300">{s}</span>
              {i < arr.length - 1 && <span className="text-accent">→</span>}
            </span>
          ))}
        </div>
        <div className="mt-4 grid gap-2 text-xs text-slate-400 sm:grid-cols-3">
          <div className="rounded-lg glass-soft p-3"><div className="font-semibold text-slate-300">Confidentiality</div>Encryption keeps data unreadable without the key.</div>
          <div className="rounded-lg glass-soft p-3"><div className="font-semibold text-slate-300">Integrity</div>GCM's auth tag detects any tampering.</div>
          <div className="rounded-lg glass-soft p-3"><div className="font-semibold text-slate-300">Key management</div>Keys come from environment config, never the frontend.</div>
        </div>
      </Panel>
    </div>
  );
}
