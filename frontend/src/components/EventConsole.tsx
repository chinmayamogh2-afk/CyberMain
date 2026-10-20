import { useState } from 'react';
import { useEventStream } from '@/lib/useEventStream';
import { IconActivity } from './icons';

/** The live security event stream rail (spec §17). Collapsible. */
const LEVEL_COLOUR: Record<string, string> = {
  info: 'text-slate-400', notice: 'text-accent', warn: 'text-sev-high', alert: 'text-sev-critical',
};

export function EventConsole() {
  const { events, connected } = useEventStream(120);
  const [open, setOpen] = useState(true);

  if (!open) {
    return (
      <button onClick={() => setOpen(true)}
        className="fixed bottom-4 right-4 z-20 flex items-center gap-2 rounded-full glass px-3 py-2 text-xs text-slate-300 shadow-glass">
        <IconActivity className="h-4 w-4 text-accent" /> Event Stream
        <span className={`h-1.5 w-1.5 rounded-full ${connected ? 'bg-sev-ok animate-pulse-dot' : 'bg-slate-600'}`} />
      </button>
    );
  }

  return (
    <aside className="flex w-80 shrink-0 flex-col border-l border-white/5 bg-base-900/70">
      <header className="flex items-center justify-between border-b border-white/5 px-4 py-3">
        <div className="flex items-center gap-2">
          <IconActivity className="h-4 w-4 text-accent" />
          <span className="text-xs font-semibold text-slate-200">Live Security Events</span>
          <span className={`h-1.5 w-1.5 rounded-full ${connected ? 'bg-sev-ok animate-pulse-dot' : 'bg-slate-600'}`}
            title={connected ? 'Connected' : 'Reconnecting…'} />
        </div>
        <button onClick={() => setOpen(false)} className="text-slate-500 hover:text-slate-300" title="Collapse">✕</button>
      </header>
      <div className="terminal flex-1 overflow-y-auto p-3">
        {events.length === 0 && <div className="text-slate-600">Waiting for activity… events appear here as the platform works.</div>}
        {events.map((e) => (
          <div key={e.id} className="mb-1.5 animate-fade-in">
            <span className="text-slate-600">[{new Date(e.occurredAt).toLocaleTimeString()}]</span>{' '}
            <span className="text-slate-600">{e.source}</span>{' '}
            <span className={LEVEL_COLOUR[e.level] ?? 'text-slate-400'}>{e.message}</span>
          </div>
        ))}
      </div>
    </aside>
  );
}
