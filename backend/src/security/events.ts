/**
 * Live security event stream (§17).
 *
 * Events are emitted by real activity — a login attempt, a scanner check, a mode
 * change, a detected payload — and pushed to connected clients over
 * Server-Sent Events. Nothing on this bus is synthetic: if the console is
 * quiet, the application genuinely is.
 */
import { EventEmitter } from 'node:events';
import { db } from '../db/index.js';
import { redact } from '../core/errors.js';

export type EventLevel = 'info' | 'notice' | 'warn' | 'alert';
export type EventSource = 'app' | 'auth' | 'scanner' | 'simulator' | 'mode' | 'remediation';

export interface SecurityEvent {
  id: number;
  occurredAt: string;
  level: EventLevel;
  source: EventSource;
  message: string;
  detail: Record<string, unknown>;
}

const bus = new EventEmitter();
// Each SSE client attaches a listener; the default cap of 10 is far too low.
bus.setMaxListeners(200);

/** Recent events kept in memory so a newly-connected console has backlog. */
const recent: SecurityEvent[] = [];
const RECENT_LIMIT = 200;

export function emitSecurityEvent(
  level: EventLevel,
  source: EventSource,
  message: string,
  detail: Record<string, unknown> = {},
): SecurityEvent {
  const safeDetail = redact(detail) as Record<string, unknown>;
  const result = db.run(
    'INSERT INTO security_events (level, source, message, detail_json) VALUES (?, ?, ?, ?)',
    [level, source, message, JSON.stringify(safeDetail)],
  );
  const event: SecurityEvent = {
    id: Number(result.lastInsertRowid),
    occurredAt: new Date().toISOString(),
    level,
    source,
    message,
    detail: safeDetail,
  };
  recent.push(event);
  if (recent.length > RECENT_LIMIT) recent.shift();
  bus.emit('event', event);
  return event;
}

export function subscribe(listener: (event: SecurityEvent) => void): () => void {
  bus.on('event', listener);
  return () => bus.off('event', listener);
}

export function recentEvents(limit = 50): SecurityEvent[] {
  return recent.slice(-limit).reverse();
}

export function storedEvents(limit = 200): SecurityEvent[] {
  const rows = db.prepared<{
    id: number;
    occurred_at: string;
    level: string;
    source: string;
    message: string;
    detail_json: string;
  }>('SELECT * FROM security_events ORDER BY id DESC LIMIT ?', [limit]);
  return rows.map((r) => ({
    id: r.id,
    occurredAt: r.occurred_at,
    level: r.level as EventLevel,
    source: r.source as EventSource,
    message: r.message,
    detail: JSON.parse(r.detail_json) as Record<string, unknown>,
  }));
}
