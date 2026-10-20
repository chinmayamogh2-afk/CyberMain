import { Routes, Route, NavLink, Navigate, useLocation } from 'react-router-dom';
import { useAuth } from './lib/auth';
import { Login } from './pages/Login';
import { Dashboard } from './pages/Dashboard';
import { SecurityLab } from './pages/SecurityLab';
import { AttackSimulator } from './pages/AttackSimulator';
import { Vulnerabilities } from './pages/Vulnerabilities';
import { Remediation } from './pages/Remediation';
import { Scanner } from './pages/Scanner';
import { Requests } from './pages/Requests';
import { Sessions } from './pages/Sessions';
import { Users } from './pages/Users';
import { AuditLogs } from './pages/AuditLogs';
import { Headers } from './pages/Headers';
import { Cryptography } from './pages/Cryptography';
import { Reports } from './pages/Reports';
import { AttackSurface } from './pages/AttackSurface';
import { DemoMode } from './pages/DemoMode';
import { EventConsole } from './components/EventConsole';
import {
  IconShield, IconGrid, IconFlask, IconTarget, IconBug, IconWrench, IconSearch,
  IconList, IconKey, IconDoc, IconActivity, IconUsers, IconLock, IconGlobe, IconMap, IconPlay,
} from './components/icons';
import type { ReactNode } from 'react';

interface NavItem { to: string; label: string; icon: ReactNode; group: string; minRole?: string }

const NAV: NavItem[] = [
  { to: '/', label: 'Dashboard', icon: <IconGrid />, group: 'Overview' },
  { to: '/demo', label: 'Demo Mode', icon: <IconPlay />, group: 'Overview' },
  { to: '/surface', label: 'Attack Surface', icon: <IconMap />, group: 'Overview' },
  { to: '/lab', label: 'Security Lab', icon: <IconFlask />, group: 'Assess' },
  { to: '/simulator', label: 'Attack Simulator', icon: <IconTarget />, group: 'Assess' },
  { to: '/scanner', label: 'Security Scan', icon: <IconSearch />, group: 'Assess' },
  { to: '/vulnerabilities', label: 'Vulnerabilities', icon: <IconBug />, group: 'Assess' },
  { to: '/remediation', label: 'Remediation', icon: <IconWrench />, group: 'Assess' },
  { to: '/requests', label: 'Request Inspector', icon: <IconActivity />, group: 'Inspect' },
  { to: '/headers', label: 'Security Headers', icon: <IconGlobe />, group: 'Inspect' },
  { to: '/crypto', label: 'Cryptography', icon: <IconKey />, group: 'Inspect' },
  { to: '/sessions', label: 'Sessions', icon: <IconLock />, group: 'Administer' },
  { to: '/users', label: 'Users & Roles', icon: <IconUsers />, group: 'Administer', minRole: 'analyst' },
  { to: '/audit', label: 'Audit Logs', icon: <IconList />, group: 'Administer', minRole: 'analyst' },
  { to: '/reports', label: 'Reports', icon: <IconDoc />, group: 'Administer', minRole: 'analyst' },
];

const RANK: Record<string, number> = { user: 10, analyst: 20, admin: 30 };

function Shell() {
  const { user, logout } = useAuth();
  const location = useLocation();
  if (!user) return null;
  const userRank = Math.max(...user.roles.map((r) => RANK[r] ?? 0));

  const visible = NAV.filter((n) => !n.minRole || userRank >= (RANK[n.minRole] ?? 99));
  const groups = [...new Set(visible.map((n) => n.group))];

  return (
    <div className="flex h-screen overflow-hidden">
      {/* Sidebar */}
      <aside className="flex w-60 shrink-0 flex-col border-r border-white/5 bg-base-850/60">
        <div className="flex items-center gap-2.5 px-5 py-4">
          <span className="grid h-9 w-9 place-items-center rounded-lg bg-accent-deep/20 text-accent ring-1 ring-accent/30">
            <IconShield className="h-5 w-5" />
          </span>
          <div>
            <div className="text-sm font-bold tracking-tight text-white">SentinelX</div>
            <div className="text-[10px] text-slate-500">Security Platform</div>
          </div>
        </div>
        <nav className="flex-1 overflow-y-auto px-3 py-2">
          {groups.map((group) => (
            <div key={group} className="mb-3">
              <div className="px-2 py-1 text-[10px] font-semibold uppercase tracking-wider text-slate-600">{group}</div>
              {visible.filter((n) => n.group === group).map((n) => (
                <NavLink key={n.to} to={n.to} end={n.to === '/'}
                  className={({ isActive }) => `mb-0.5 flex items-center gap-2.5 rounded-lg px-2.5 py-2 text-sm transition
                    ${isActive ? 'bg-accent/10 text-accent ring-1 ring-accent/20' : 'text-slate-400 hover:bg-white/5 hover:text-slate-200'}`}>
                  <span className="opacity-80">{n.icon}</span>{n.label}
                </NavLink>
              ))}
            </div>
          ))}
        </nav>
        <div className="border-t border-white/5 p-3">
          <div className="flex items-center gap-2.5 rounded-lg px-2 py-1.5">
            <span className="grid h-8 w-8 place-items-center rounded-full text-xs font-bold text-base-900" style={{ background: user.avatarColour }}>
              {user.username.slice(0, 2).toUpperCase()}
            </span>
            <div className="min-w-0 flex-1">
              <div className="truncate text-xs font-semibold text-slate-200">{user.fullName}</div>
              <div className="text-[10px] text-slate-500">{user.roleLabel}</div>
            </div>
          </div>
          <button onClick={() => void logout()} className="mt-1 w-full rounded-lg px-2 py-1.5 text-left text-xs text-slate-500 hover:bg-white/5 hover:text-slate-300">
            Sign out
          </button>
        </div>
      </aside>

      {/* Main */}
      <div className="flex min-w-0 flex-1 flex-col">
        <main className="flex-1 overflow-y-auto">
          <div key={location.pathname} className="mx-auto max-w-[1400px] animate-fade-in p-6">
            <Routes>
              <Route path="/" element={<Dashboard />} />
              <Route path="/demo" element={<DemoMode />} />
              <Route path="/surface" element={<AttackSurface />} />
              <Route path="/lab" element={<SecurityLab />} />
              <Route path="/simulator" element={<AttackSimulator />} />
              <Route path="/scanner" element={<Scanner />} />
              <Route path="/vulnerabilities" element={<Vulnerabilities />} />
              <Route path="/remediation" element={<Remediation />} />
              <Route path="/requests" element={<Requests />} />
              <Route path="/headers" element={<Headers />} />
              <Route path="/crypto" element={<Cryptography />} />
              <Route path="/sessions" element={<Sessions />} />
              <Route path="/users" element={<Users />} />
              <Route path="/audit" element={<AuditLogs />} />
              <Route path="/reports" element={<Reports />} />
              <Route path="*" element={<Navigate to="/" replace />} />
            </Routes>
          </div>
        </main>
      </div>

      {/* Live event console rail */}
      <EventConsole />
    </div>
  );
}

export function App() {
  const { user, loading } = useAuth();
  if (loading) {
    return (
      <div className="grid h-screen place-items-center">
        <div className="flex items-center gap-3 text-slate-400">
          <span className="h-4 w-4 animate-spin rounded-full border-2 border-accent/30 border-t-accent" />
          Loading SentinelX…
        </div>
      </div>
    );
  }
  return user ? <Shell /> : <Login />;
}
