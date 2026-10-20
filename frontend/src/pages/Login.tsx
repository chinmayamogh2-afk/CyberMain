import { useState } from 'react';
import { useAuth } from '@/lib/auth';
import { ApiError } from '@/lib/api';
import { Button } from '@/components/ui';
import { IconShield } from '@/components/icons';

const DEMO_ACCOUNTS = [
  { username: 'admin', password: 'Admin#2024!Vault', role: 'Administrator' },
  { username: 'analyst', password: 'Analyst#2024!Vault', role: 'Security Analyst' },
  { username: 'alice', password: 'Alice#2024!Vault', role: 'User (owns finance docs)' },
  { username: 'bob', password: 'Bob#2024!Vault', role: 'User (for IDOR demo)' },
];

export function Login() {
  const { login } = useAuth();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setBusy(true);
    try {
      await login(username, password);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Sign-in failed.');
    } finally {
      setBusy(false);
    }
  }

  function quickFill(u: string, p: string) {
    setUsername(u); setPassword(p); setError(null);
  }

  return (
    <div className="flex min-h-screen items-center justify-center p-6">
      <div className="grid w-full max-w-4xl gap-6 md:grid-cols-2">
        {/* Identity / what this is — the first screen must say so (spec §46). */}
        <div className="flex flex-col justify-center">
          <div className="mb-4 inline-flex items-center gap-2.5">
            <span className="grid h-11 w-11 place-items-center rounded-xl bg-accent-deep/20 text-accent ring-1 ring-accent/30">
              <IconShield className="h-6 w-6" />
            </span>
            <div>
              <div className="text-xl font-bold tracking-tight text-white">SentinelX</div>
              <div className="text-xs text-slate-400">Web Application Security Platform</div>
            </div>
          </div>
          <p className="text-sm leading-relaxed text-slate-400">
            A controlled environment to <span className="text-accent">attack, detect, explain, remediate and verify</span> web
            vulnerabilities against a realistic application — SecureVault. Every finding is derived from a real test, and
            every control can be toggled between vulnerable and hardened to show the difference.
          </p>
          <p className="mt-4 rounded-lg border border-white/10 bg-base-850/50 p-3 text-xs text-slate-500">
            Educational platform for local demonstration only. Vulnerabilities are intentional and confined to this host.
          </p>
        </div>

        {/* Sign-in */}
        <div className="glass rounded-2xl p-6 shadow-glass">
          <h1 className="text-base font-semibold text-white">Sign in</h1>
          <form onSubmit={submit} className="mt-4 space-y-3">
            <label className="block">
              <span className="text-xs text-slate-400">Username</span>
              <input value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="username"
                className="mt-1 w-full rounded-lg border border-white/10 bg-base-900/60 px-3 py-2 text-sm text-slate-100 outline-none focus:border-accent/50" />
            </label>
            <label className="block">
              <span className="text-xs text-slate-400">Password</span>
              <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password"
                className="mt-1 w-full rounded-lg border border-white/10 bg-base-900/60 px-3 py-2 text-sm text-slate-100 outline-none focus:border-accent/50" />
            </label>
            {error && <div className="rounded-lg bg-sev-critical/10 px-3 py-2 text-xs text-sev-critical ring-1 ring-sev-critical/20">{error}</div>}
            <Button type="submit" disabled={busy} className="w-full">{busy ? 'Signing in…' : 'Sign in'}</Button>
          </form>

          <div className="mt-5 border-t border-white/5 pt-4">
            <div className="mb-2 text-[11px] uppercase tracking-wider text-slate-500">Demo accounts — click to fill</div>
            <div className="grid grid-cols-2 gap-2">
              {DEMO_ACCOUNTS.map((a) => (
                <button key={a.username} onClick={() => quickFill(a.username, a.password)}
                  className="rounded-lg border border-white/10 bg-white/5 px-2.5 py-2 text-left transition hover:border-accent/40 hover:bg-accent/5">
                  <div className="text-xs font-semibold text-slate-200">{a.username}</div>
                  <div className="text-[10px] text-slate-500">{a.role}</div>
                </button>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
