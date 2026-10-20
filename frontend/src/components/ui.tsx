import type { ReactNode } from 'react';
import type { Severity, Verdict, Mode } from '@/lib/types';

/** Reusable presentation primitives, so pages stay consistent and uncluttered. */

export function Panel({ children, className = '', title, subtitle, actions }: {
  children: ReactNode; className?: string; title?: string; subtitle?: string; actions?: ReactNode;
}) {
  return (
    <section className={`glass rounded-xl shadow-glass ${className}`}>
      {(title || actions) && (
        <header className="flex items-start justify-between gap-4 border-b border-white/5 px-5 py-3.5">
          <div>
            {title && <h2 className="text-sm font-semibold text-slate-100">{title}</h2>}
            {subtitle && <p className="mt-0.5 text-xs text-slate-400">{subtitle}</p>}
          </div>
          {actions}
        </header>
      )}
      <div className="p-5">{children}</div>
    </section>
  );
}

const SEV_STYLE: Record<Severity, string> = {
  critical: 'bg-sev-critical/15 text-sev-critical ring-sev-critical/30',
  high: 'bg-sev-high/15 text-sev-high ring-sev-high/30',
  medium: 'bg-sev-medium/15 text-sev-medium ring-sev-medium/30',
  low: 'bg-sev-low/15 text-sev-low ring-sev-low/30',
  info: 'bg-sev-info/15 text-sev-info ring-sev-info/30',
};

export function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span className={`inline-flex items-center rounded-md px-2 py-0.5 text-[11px] font-semibold uppercase tracking-wide ring-1 ring-inset ${SEV_STYLE[severity]}`}>
      {severity}
    </span>
  );
}

export function VerdictBadge({ verdict }: { verdict: Verdict }) {
  const map: Record<Verdict, { label: string; cls: string }> = {
    pass: { label: 'PASS', cls: 'bg-sev-ok/15 text-sev-ok ring-sev-ok/30' },
    fail: { label: 'FAIL', cls: 'bg-sev-critical/15 text-sev-critical ring-sev-critical/30' },
    warn: { label: 'WARN', cls: 'bg-sev-medium/15 text-sev-medium ring-sev-medium/30' },
  };
  const v = map[verdict];
  return <span className={`inline-flex items-center rounded-md px-2 py-0.5 text-[11px] font-bold tracking-wide ring-1 ring-inset ${v.cls}`}>{v.label}</span>;
}

export function ModePill({ mode, onToggle, disabled }: { mode: Mode; onToggle?: () => void; disabled?: boolean }) {
  const vulnerable = mode === 'vulnerable';
  return (
    <button
      type="button"
      onClick={onToggle}
      disabled={disabled || !onToggle}
      className={`group inline-flex items-center gap-2 rounded-full px-3 py-1 text-xs font-semibold transition
        ${vulnerable ? 'bg-sev-critical/15 text-sev-critical ring-1 ring-sev-critical/40' : 'bg-sev-ok/15 text-sev-ok ring-1 ring-sev-ok/40'}
        ${onToggle && !disabled ? 'cursor-pointer hover:brightness-125' : 'cursor-default'}`}
      title={onToggle ? 'Toggle security mode' : undefined}
    >
      <span className={`h-1.5 w-1.5 rounded-full ${vulnerable ? 'bg-sev-critical animate-pulse-dot' : 'bg-sev-ok'}`} />
      {vulnerable ? 'Vulnerable' : 'Hardened'}
    </button>
  );
}

export function Button({ children, onClick, variant = 'primary', disabled, type = 'button', className = '', size = 'md' }: {
  children: ReactNode; onClick?: () => void; variant?: 'primary' | 'ghost' | 'danger' | 'subtle';
  disabled?: boolean; type?: 'button' | 'submit'; className?: string; size?: 'sm' | 'md';
}) {
  const variants = {
    primary: 'bg-accent-deep text-base-900 font-semibold hover:bg-accent shadow-glow',
    danger: 'bg-sev-critical/90 text-white font-semibold hover:bg-sev-critical',
    ghost: 'bg-white/5 text-slate-200 hover:bg-white/10 ring-1 ring-white/10',
    subtle: 'text-slate-300 hover:text-white hover:bg-white/5',
  };
  const sizes = { sm: 'px-2.5 py-1 text-xs', md: 'px-4 py-2 text-sm' };
  return (
    <button type={type} onClick={onClick} disabled={disabled}
      className={`inline-flex items-center justify-center gap-2 rounded-lg transition disabled:cursor-not-allowed disabled:opacity-50 ${variants[variant]} ${sizes[size]} ${className}`}>
      {children}
    </button>
  );
}

export function Stat({ label, value, hint, tone = 'default' }: {
  label: string; value: ReactNode; hint?: string; tone?: 'default' | 'good' | 'bad' | 'warn';
}) {
  const toneCls = { default: 'text-slate-100', good: 'text-sev-ok', bad: 'text-sev-critical', warn: 'text-sev-medium' }[tone];
  return (
    <div className="glass-soft rounded-lg px-4 py-3">
      <div className="text-[11px] uppercase tracking-wider text-slate-400">{label}</div>
      <div className={`mt-1 text-2xl font-semibold tabular-nums ${toneCls}`}>{value}</div>
      {hint && <div className="mt-0.5 text-[11px] text-slate-500">{hint}</div>}
    </div>
  );
}

export function Spinner({ label }: { label?: string }) {
  return (
    <div className="flex items-center gap-2 text-sm text-slate-400">
      <span className="h-3.5 w-3.5 animate-spin rounded-full border-2 border-accent/30 border-t-accent" />
      {label}
    </div>
  );
}

export function Empty({ children }: { children: ReactNode }) {
  return <div className="rounded-lg border border-dashed border-white/10 px-4 py-8 text-center text-sm text-slate-500">{children}</div>;
}

export function CodeBlock({ code, language }: { code: string; language?: string }) {
  return (
    <pre className="terminal overflow-x-auto rounded-lg p-3.5 text-slate-200">
      {language && <div className="mb-1.5 text-[10px] uppercase tracking-widest text-accent/60">{language}</div>}
      <code>{code}</code>
    </pre>
  );
}
