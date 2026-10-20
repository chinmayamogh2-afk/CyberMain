import { useState } from 'react';
import { useModes } from '@/lib/useSecurity';
import { Panel, Empty } from '@/components/ui';

/** Interactive attack-surface map (spec §27) + request pipeline (§26). */
interface Component { id: string; label: string; x: number; y: number; endpoints: string[]; controls: string[]; classes: string[] }

const COMPONENTS: Component[] = [
  { id: 'frontend', label: 'Frontend (React)', x: 60, y: 40, endpoints: ['/ (SPA)'], controls: ['CSP', 'output encoding', 'SameSite cookies'], classes: ['xss_reflected', 'xss_stored'] },
  { id: 'api', label: 'API (Express)', x: 320, y: 40, endpoints: ['/api/auth/*', '/api/vault/*', '/api/security/*'], controls: ['rate limiting', 'validation', 'security headers', 'CSRF'], classes: ['csrf', 'rate_limit', 'headers', 'error_handling'] },
  { id: 'auth', label: 'Authentication', x: 320, y: 180, endpoints: ['/api/auth/login', '/api/auth/password'], controls: ['scrypt hashing', 'lockout', 'generic errors'], classes: ['auth', 'session'] },
  { id: 'authz', label: 'Authorization', x: 580, y: 110, endpoints: ['requireRole', 'authorizeDocumentAccess'], controls: ['RBAC', 'object-level checks'], classes: ['idor', 'api_authz'] },
  { id: 'db', label: 'Database (SQLite)', x: 580, y: 250, endpoints: ['parameterised queries'], controls: ['prepared statements', 'least privilege'], classes: ['sqli'] },
  { id: 'storage', label: 'File Storage', x: 320, y: 320, endpoints: ['/api/lab/upload', '/api/lab/traversal'], controls: ['type/size validation', 'path normalisation'], classes: ['upload', 'path_traversal'] },
  { id: 'external', label: 'External Fetch', x: 60, y: 250, endpoints: ['/api/lab/ssrf'], controls: ['host allow-list', 'private-range block'], classes: ['ssrf'] },
  { id: 'data', label: 'Data Protection', x: 60, y: 160, endpoints: ['encrypted columns'], controls: ['AES-256-GCM at rest', 'field allow-lists'], classes: ['data_exposure', 'cmdi'] },
];

const EDGES: [string, string][] = [
  ['frontend', 'api'], ['api', 'auth'], ['api', 'authz'], ['authz', 'db'], ['auth', 'db'],
  ['api', 'storage'], ['data', 'api'], ['external', 'api'], ['authz', 'storage'],
];

export function AttackSurface() {
  const { classes } = useModes();
  const [selected, setSelected] = useState<Component | null>(null);

  function worstMode(comp: Component): 'vulnerable' | 'secure' {
    return comp.classes.some((k) => classes.find((c) => c.key === k)?.mode === 'vulnerable') ? 'vulnerable' : 'secure';
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-bold text-white">Attack Surface Map</h1>
        <p className="text-sm text-slate-400">How data moves through SecureVault. Red nodes have at least one vulnerable control. Click a component for detail.</p>
      </div>

      <div className="grid gap-6 lg:grid-cols-[1fr_320px]">
        <Panel title="Data flow & components">
          <svg viewBox="0 0 720 390" className="w-full">
            {EDGES.map(([a, b], i) => {
              const ca = COMPONENTS.find((c) => c.id === a)!, cb = COMPONENTS.find((c) => c.id === b)!;
              return <line key={i} x1={ca.x + 70} y1={ca.y + 22} x2={cb.x + 70} y2={cb.y + 22} stroke="rgba(148,163,184,0.2)" strokeWidth="1.5" strokeDasharray="4 3" />;
            })}
            {COMPONENTS.map((c) => {
              const mode = worstMode(c);
              const active = selected?.id === c.id;
              const colour = mode === 'vulnerable' ? '#f43f5e' : '#34d399';
              return (
                <g key={c.id} onClick={() => setSelected(c)} className="cursor-pointer">
                  <rect x={c.x} y={c.y} width="140" height="44" rx="8"
                    fill={active ? 'rgba(56,189,248,0.12)' : 'rgba(13,21,36,0.9)'}
                    stroke={active ? '#38bdf8' : colour} strokeWidth={active ? 2 : 1.3} />
                  <circle cx={c.x + 14} cy={c.y + 22} r="4" fill={colour} />
                  <text x={c.x + 26} y={c.y + 26} fill="#cbd5e1" style={{ fontSize: 11, fontWeight: 500 }}>{c.label}</text>
                </g>
              );
            })}
          </svg>
          <div className="mt-2 flex gap-4 text-[11px] text-slate-500">
            <span className="flex items-center gap-1.5"><span className="h-2 w-2 rounded-full bg-sev-ok" /> all controls hardened</span>
            <span className="flex items-center gap-1.5"><span className="h-2 w-2 rounded-full bg-sev-critical" /> has a vulnerable control</span>
          </div>
        </Panel>

        <Panel title={selected ? selected.label : 'Component detail'}>
          {!selected ? <Empty>Click a component to inspect it.</Empty> : (
            <div className="space-y-3 text-sm">
              <div><div className="text-[11px] uppercase tracking-wider text-slate-500">Endpoints</div><ul className="mt-1 space-y-0.5 font-mono text-xs text-slate-300">{selected.endpoints.map((e) => <li key={e}>{e}</li>)}</ul></div>
              <div><div className="text-[11px] uppercase tracking-wider text-slate-500">Security controls</div><div className="mt-1 flex flex-wrap gap-1">{selected.controls.map((c) => <span key={c} className="rounded bg-sev-ok/10 px-1.5 py-0.5 text-[10px] text-sev-ok">{c}</span>)}</div></div>
              <div><div className="text-[11px] uppercase tracking-wider text-slate-500">Potential vulnerabilities</div>
                <div className="mt-1 space-y-1">
                  {selected.classes.map((k) => {
                    const meta = classes.find((c) => c.key === k);
                    if (!meta) return null;
                    return <div key={k} className="flex items-center justify-between rounded glass-soft px-2 py-1.5"><span className="text-xs text-slate-300">{meta.title}</span><span className={`text-[10px] ${meta.mode === 'vulnerable' ? 'text-sev-critical' : 'text-sev-ok'}`}>{meta.mode}</span></div>;
                  })}
                </div>
              </div>
            </div>
          )}
        </Panel>
      </div>

      <Panel title="Request processing pipeline" subtitle="Each request passes through these stages (spec §26)">
        <div className="flex flex-wrap items-center gap-2">
          {['Request', 'Security Headers', 'Authentication', 'CSRF', 'Authorization', 'Input Validation', 'Business Logic', 'Database', 'Safe Response'].map((stage, i, arr) => (
            <span key={stage} className="flex items-center gap-2">
              <span className="rounded-lg glass-soft px-3 py-2 text-xs text-slate-300">{stage}</span>
              {i < arr.length - 1 && <span className="text-accent/50">→</span>}
            </span>
          ))}
        </div>
      </Panel>
    </div>
  );
}
