import { useScore, useModes, useFindings } from '@/lib/useSecurity';
import { Panel, Stat, SeverityBadge, Empty, Button } from '@/components/ui';
import { ScoreRing } from '@/components/ScoreRing';
import { useAuth } from '@/lib/auth';
import { Link } from 'react-router-dom';
import { LineChart, Line, ResponsiveContainer, XAxis, YAxis, Tooltip, BarChart, Bar, Cell } from 'recharts';

export function Dashboard() {
  const { user } = useAuth();
  const { score, history } = useScore();
  const { classes } = useModes();
  const { findings } = useFindings(true);

  if (!score) return <Panel><Empty>Loading security posture…</Empty></Panel>;

  const vulnerable = classes.filter((c) => c.mode === 'vulnerable');
  const sevCounts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 } as Record<string, number>;
  findings.forEach((f) => { sevCounts[f.severity] = (sevCounts[f.severity] ?? 0) + 1; });

  const domainData = score.domains.map((d) => ({ name: d.label, score: d.score }));

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-bold text-white">Security Dashboard</h1>
        <p className="text-sm text-slate-400">Welcome back, {user?.fullName}. This is the current security posture of SecureVault — all figures are computed from live application state.</p>
      </div>

      <div className="grid gap-6 lg:grid-cols-3">
        <Panel title="Overall Security Score" subtitle="Mean of seven domain scores" className="lg:col-span-1">
          <div className="flex items-center gap-5">
            <ScoreRing score={score.overall} grade={score.grade} />
            <div className="space-y-2 text-sm">
              <div><span className="text-slate-400">Controls hardened:</span> <span className="font-semibold text-sev-ok">{score.totalClasses - score.vulnerableClasses}/{score.totalClasses}</span></div>
              <div><span className="text-slate-400">Vulnerable:</span> <span className="font-semibold text-sev-critical">{score.vulnerableClasses}</span></div>
              <div><span className="text-slate-400">Active findings:</span> <span className="font-semibold text-slate-100">{findings.length}</span></div>
            </div>
          </div>
        </Panel>

        <Panel title="Domain Breakdown" subtitle="Score contribution by security domain" className="lg:col-span-2">
          <ResponsiveContainer width="100%" height={190}>
            <BarChart data={domainData} layout="vertical" margin={{ left: 40, right: 16 }}>
              <XAxis type="number" domain={[0, 100]} tick={{ fill: '#64748b', fontSize: 11 }} axisLine={false} tickLine={false} />
              <YAxis type="category" dataKey="name" width={120} tick={{ fill: '#94a3b8', fontSize: 11 }} axisLine={false} tickLine={false} />
              <Tooltip contentStyle={{ background: '#0d1524', border: '1px solid rgba(148,163,184,0.2)', borderRadius: 8, fontSize: 12 }} />
              <Bar dataKey="score" radius={[0, 4, 4, 0]} barSize={14}>
                {domainData.map((d, i) => <Cell key={i} fill={d.score >= 90 ? '#34d399' : d.score >= 70 ? '#38bdf8' : d.score >= 50 ? '#facc15' : '#f43f5e'} />)}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </Panel>
      </div>

      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-5">
        <Stat label="Critical" value={sevCounts.critical} tone={sevCounts.critical ? 'bad' : 'good'} />
        <Stat label="High" value={sevCounts.high} tone={sevCounts.high ? 'warn' : 'good'} />
        <Stat label="Medium" value={sevCounts.medium} tone={sevCounts.medium ? 'warn' : 'good'} />
        <Stat label="Low" value={sevCounts.low} />
        <Stat label="Info" value={sevCounts.info} />
      </div>

      <div className="grid gap-6 lg:grid-cols-2">
        <Panel title="Security Score Trend" subtitle="How the score has moved as controls changed">
          {history.length > 1 ? (
            <ResponsiveContainer width="100%" height={180}>
              <LineChart data={history.map((h, i) => ({ i, overall: h.overall, trigger: h.trigger }))}>
                <XAxis dataKey="i" hide />
                <YAxis domain={[0, 100]} tick={{ fill: '#64748b', fontSize: 11 }} axisLine={false} tickLine={false} width={28} />
                <Tooltip contentStyle={{ background: '#0d1524', border: '1px solid rgba(148,163,184,0.2)', borderRadius: 8, fontSize: 12 }}
                  labelFormatter={(_, p) => (p?.[0]?.payload as { trigger?: string })?.trigger ?? ''} />
                <Line type="monotone" dataKey="overall" stroke="#38bdf8" strokeWidth={2} dot={{ r: 2.5, fill: '#38bdf8' }} />
              </LineChart>
            </ResponsiveContainer>
          ) : <Empty>Run a scan or toggle a control to start charting the score over time.</Empty>}
        </Panel>

        <Panel title="Active Vulnerable Controls" subtitle="Classes currently in vulnerable mode"
          actions={<Link to="/vulnerabilities"><Button variant="ghost" size="sm">View all</Button></Link>}>
          {vulnerable.length === 0 ? (
            <Empty>All {classes.length} controls are hardened. Flip one in the Security Lab or Simulator to demonstrate an attack.</Empty>
          ) : (
            <div className="space-y-2">
              {vulnerable.map((c) => (
                <div key={c.key} className="flex items-center justify-between rounded-lg glass-soft px-3 py-2">
                  <div>
                    <div className="text-sm font-medium text-slate-200">{c.title}</div>
                    <div className="text-[11px] text-slate-500">{c.owaspCategory}</div>
                  </div>
                  <SeverityBadge severity={c.baseSeverity as never} />
                </div>
              ))}
            </div>
          )}
        </Panel>
      </div>
    </div>
  );
}
