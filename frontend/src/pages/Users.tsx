import { useEffect, useState, useCallback } from 'react';
import { api } from '@/lib/api';
import { useAuth } from '@/lib/auth';
import { Panel, Button, Empty } from '@/components/ui';

interface UserRow { id: number; username: string; email: string; fullName: string; roles: string[]; roleLabel: string; active: boolean; lastLoginAt: string | null; failedLoginCount: number; locked: boolean }
interface RoleDef { name: string; label: string; description: string; capabilities: string[] }

/** Users & Roles console (spec §24). RBAC management is admin-only. */
export function Users() {
  const { user } = useAuth();
  const isAdmin = user?.roles.includes('admin') ?? false;
  const [users, setUsers] = useState<UserRow[]>([]);
  const [roles, setRoles] = useState<RoleDef[]>([]);

  const load = useCallback(async () => {
    const [u, r] = await Promise.all([api.get<{ users: UserRow[] }>('/admin/users'), api.get<{ roles: RoleDef[] }>('/admin/roles')]);
    setUsers(u.users); setRoles(r.roles);
  }, []);
  useEffect(() => { void load(); }, [load]);

  async function toggleRole(u: UserRow, role: string) {
    const next = u.roles.includes(role) ? u.roles.filter((r) => r !== role) : [...u.roles, role];
    if (next.length === 0) return;
    await api.put(`/admin/users/${u.id}/roles`, { roles: next });
    await load();
  }
  async function toggleActive(u: UserRow) { await api.put(`/admin/users/${u.id}/active`, { active: !u.active }); await load(); }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-bold text-white">Users &amp; Roles</h1>
        <p className="text-sm text-slate-400">Role-based access control. Roles are assigned here and enforced on every request from the database — never from a client claim.</p>
      </div>

      <div className="grid gap-3 md:grid-cols-3">
        {roles.map((r) => (
          <Panel key={r.name} title={r.label} subtitle={r.description}>
            <div className="flex flex-wrap gap-1">
              {r.capabilities.map((c) => <span key={c} className="rounded bg-white/5 px-1.5 py-0.5 font-mono text-[10px] text-slate-400">{c}</span>)}
            </div>
          </Panel>
        ))}
      </div>

      <Panel title={`Users (${users.length})`}>
        {users.length === 0 ? <Empty>No users.</Empty> : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="text-slate-500"><tr>
                <th className="pb-2 pr-3">User</th><th className="pb-2 pr-3">Roles</th><th className="pb-2 pr-3">Last login</th>
                <th className="pb-2 pr-3">Failures</th><th className="pb-2 pr-3">Status</th>{isAdmin && <th className="pb-2">Actions</th>}
              </tr></thead>
              <tbody>
                {users.map((u) => (
                  <tr key={u.id} className="border-t border-white/5 align-middle">
                    <td className="py-2.5 pr-3"><div className="text-slate-200">{u.fullName}</div><div className="text-[10px] text-slate-500">{u.username} · {u.email}</div></td>
                    <td className="py-2.5 pr-3">
                      <div className="flex flex-wrap gap-1">
                        {['user', 'analyst', 'admin'].map((role) => {
                          const has = u.roles.includes(role);
                          return (
                            <button key={role} disabled={!isAdmin} onClick={() => toggleRole(u, role)}
                              className={`rounded px-1.5 py-0.5 text-[10px] font-medium transition ${has ? 'bg-accent/15 text-accent ring-1 ring-accent/30' : 'bg-white/5 text-slate-500'} ${isAdmin ? 'hover:brightness-125' : 'cursor-default'}`}>
                              {role}
                            </button>
                          );
                        })}
                      </div>
                    </td>
                    <td className="py-2.5 pr-3 text-slate-500">{u.lastLoginAt ? new Date(u.lastLoginAt).toLocaleString() : 'never'}</td>
                    <td className="py-2.5 pr-3"><span className={u.failedLoginCount > 0 ? 'text-sev-high' : 'text-slate-500'}>{u.failedLoginCount}</span>{u.locked && <span className="ml-1 rounded bg-sev-critical/15 px-1 text-[9px] text-sev-critical">LOCKED</span>}</td>
                    <td className="py-2.5 pr-3"><span className={u.active ? 'text-sev-ok' : 'text-slate-500'}>{u.active ? 'active' : 'disabled'}</span></td>
                    {isAdmin && <td className="py-2.5"><Button size="sm" variant="ghost" onClick={() => toggleActive(u)}>{u.active ? 'Disable' : 'Enable'}</Button></td>}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>
    </div>
  );
}
