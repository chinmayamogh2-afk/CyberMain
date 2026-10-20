import { useEffect, useState, useCallback } from 'react';
import { api } from '@/lib/api';
import { useAuth } from '@/lib/auth';
import { Panel, Button, Empty } from '@/components/ui';

interface SessionRow { id: string; fullId: string; username?: string; createdAt: string; lastSeenAt: string; expiresAt: string; ipAddress: string | null; revokedAt: string | null; issuedMode: string; active: boolean; current?: boolean }

/** Sessions: own sessions for everyone; all sessions for analyst/admin (§24). */
export function Sessions() {
  const { user } = useAuth();
  const isAnalyst = user ? user.roles.some((r) => r === 'analyst' || r === 'admin') : false;
  const [own, setOwn] = useState<SessionRow[]>([]);
  const [all, setAll] = useState<SessionRow[]>([]);
  const [cookieAttrs, setCookieAttrs] = useState<Record<string, unknown> | null>(null);

  const load = useCallback(async () => {
    const mine = await api.get<{ sessions: SessionRow[]; cookieAttributes: Record<string, unknown> }>('/auth/sessions');
    setOwn(mine.sessions); setCookieAttrs(mine.cookieAttributes);
    if (isAnalyst) { const a = await api.get<{ sessions: SessionRow[] }>('/admin/sessions'); setAll(a.sessions); }
  }, [isAnalyst]);
  useEffect(() => { void load(); }, [load]);

  async function revokeOwn(id: string) { await api.del(`/auth/sessions/${id}`); await load(); }
  async function revokeAny(id: string) { await api.del(`/admin/sessions/${id}`); await load(); }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-bold text-white">Sessions</h1>
        <p className="text-sm text-slate-400">Server-side sessions with secure cookie attributes. Logging out invalidates the session on the server, not just in the browser.</p>
      </div>

      {cookieAttrs && (
        <Panel title="Current cookie attributes" subtitle="Applied to session cookies in the active mode">
          <div className="flex flex-wrap gap-2">
            {Object.entries(cookieAttrs).map(([k, v]) => (
              <span key={k} className="rounded-lg glass-soft px-3 py-1.5 font-mono text-xs"><span className="text-slate-500">{k}:</span> <span className="text-slate-200">{String(v)}</span></span>
            ))}
          </div>
        </Panel>
      )}

      <Panel title="My sessions">
        <SessionTable rows={own} onRevoke={revokeOwn} showUser={false} />
      </Panel>

      {isAnalyst && (
        <Panel title="All sessions" subtitle="Analyst / administrator view">
          <SessionTable rows={all} onRevoke={revokeAny} showUser />
        </Panel>
      )}
    </div>
  );
}

function SessionTable({ rows, onRevoke, showUser }: { rows: SessionRow[]; onRevoke: (id: string) => void; showUser: boolean }) {
  if (rows.length === 0) return <Empty>No sessions.</Empty>;
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-left text-xs">
        <thead className="text-slate-500"><tr>
          {showUser && <th className="pb-2 pr-3">User</th>}
          <th className="pb-2 pr-3">ID</th><th className="pb-2 pr-3">Issued</th><th className="pb-2 pr-3">Last seen</th>
          <th className="pb-2 pr-3">IP</th><th className="pb-2 pr-3">Mode</th><th className="pb-2 pr-3">Status</th><th className="pb-2"></th>
        </tr></thead>
        <tbody>
          {rows.map((s) => (
            <tr key={s.fullId} className="border-t border-white/5">
              {showUser && <td className="py-2 pr-3 text-slate-300">{s.username}</td>}
              <td className="py-2 pr-3 font-mono text-slate-400">{s.id}{s.current && <span className="ml-1 rounded bg-accent/15 px-1 text-[9px] text-accent">current</span>}</td>
              <td className="py-2 pr-3 text-slate-500">{new Date(s.createdAt).toLocaleTimeString()}</td>
              <td className="py-2 pr-3 text-slate-500">{new Date(s.lastSeenAt).toLocaleTimeString()}</td>
              <td className="py-2 pr-3 font-mono text-slate-500">{s.ipAddress ?? '—'}</td>
              <td className="py-2 pr-3"><span className={s.issuedMode === 'vulnerable' ? 'text-sev-critical' : 'text-sev-ok'}>{s.issuedMode}</span></td>
              <td className="py-2 pr-3"><span className={s.active ? 'text-sev-ok' : 'text-slate-500'}>{s.active ? 'active' : 'ended'}</span></td>
              <td className="py-2">{s.active && !s.current && <Button size="sm" variant="ghost" onClick={() => onRevoke(s.fullId)}>Revoke</Button>}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
