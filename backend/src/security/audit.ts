/**
 * Audit logging (§23).
 *
 * Every security-relevant action is recorded with who did it, what they did,
 * from where, and whether it succeeded. Detail objects pass through `redact`
 * first, so the audit trail never becomes a credential store.
 *
 * Accountability is one of the properties the syllabus asks us to implement, and
 * an audit log that can be written but not read, filtered or searched does not
 * deliver it — hence `queryAuditLogs` below.
 */
import type { Request } from 'express';
import { db } from '../db/index.js';
import { redact } from '../core/errors.js';
import { emitSecurityEvent, type EventLevel } from './events.js';

export type AuditCategory = 'auth' | 'access' | 'admin' | 'security' | 'data';
export type AuditOutcome = 'success' | 'failure' | 'blocked' | 'detected';
export type AuditSeverity = 'info' | 'low' | 'medium' | 'high' | 'critical';

export interface AuditInput {
  action: string;
  category: AuditCategory;
  outcome: AuditOutcome;
  severity?: AuditSeverity;
  actorUserId?: number | null;
  actorLabel?: string;
  targetType?: string;
  targetId?: string | number;
  detail?: Record<string, unknown>;
  req?: Request;
  /** Also publish to the live event console. Defaults to true for non-info. */
  emitEvent?: boolean;
}

/**
 * Derives the client address.
 *
 * Note that `x-forwarded-for` is attacker-controlled unless a trusted proxy
 * sets it. We only honour it when Express itself has decided the peer is a
 * trusted proxy, otherwise an attacker could forge the IP in their own audit
 * records — which would corrupt the evidence trail.
 */
function clientIp(req?: Request): string | null {
  if (!req) return null;
  return req.ip ?? req.socket.remoteAddress ?? null;
}

const SEVERITY_TO_LEVEL: Record<AuditSeverity, EventLevel> = {
  info: 'info',
  low: 'info',
  medium: 'notice',
  high: 'warn',
  critical: 'alert',
};

export function audit(input: AuditInput): void {
  const severity = input.severity ?? 'info';
  const detail = redact(input.detail ?? {}) as Record<string, unknown>;
  const actorLabel =
    input.actorLabel ??
    (input.req as (Request & { auth?: { username?: string } }) | undefined)?.auth?.username ??
    'anonymous';
  const actorUserId =
    input.actorUserId ??
    (input.req as (Request & { auth?: { userId?: number } }) | undefined)?.auth?.userId ??
    null;

  db.run(
    `INSERT INTO audit_logs
       (actor_user_id, actor_label, action, category, outcome, severity,
        target_type, target_id, ip_address, user_agent,
        request_method, request_path, detail_json)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [
      actorUserId,
      actorLabel,
      input.action,
      input.category,
      input.outcome,
      severity,
      input.targetType ?? null,
      input.targetId !== undefined ? String(input.targetId) : null,
      clientIp(input.req),
      input.req?.get('user-agent') ?? null,
      input.req?.method ?? null,
      input.req?.originalUrl ?? null,
      JSON.stringify(detail),
    ],
  );

  const shouldEmit = input.emitEvent ?? severity !== 'info';
  if (shouldEmit) {
    emitSecurityEvent(SEVERITY_TO_LEVEL[severity], 'app', describeAction(input.action, input.outcome), {
      actor: actorLabel,
      target: input.targetId,
      ...detail,
    });
  }
}

function describeAction(action: string, outcome: AuditOutcome): string {
  const verb =
    outcome === 'success'
      ? ''
      : outcome === 'failure'
        ? ' failed'
        : outcome === 'blocked'
          ? ' blocked'
          : ' detected';
  return `${action.replace(/\./g, ' ')}${verb}`;
}

export interface AuditQuery {
  search?: string;
  category?: AuditCategory;
  outcome?: AuditOutcome;
  severity?: AuditSeverity;
  actorUserId?: number;
  limit?: number;
  offset?: number;
}

export interface AuditRecord {
  id: number;
  occurredAt: string;
  actorUserId: number | null;
  actorLabel: string;
  action: string;
  category: string;
  outcome: string;
  severity: string;
  targetType: string | null;
  targetId: string | null;
  ipAddress: string | null;
  userAgent: string | null;
  requestMethod: string | null;
  requestPath: string | null;
  detail: Record<string, unknown>;
}

/**
 * Filtered, paginated audit query.
 *
 * Every user-supplied filter is bound as a parameter. This module handles
 * attacker-influenced search terms, so it is exactly the place where a
 * concatenated query would be most damaging — the secure pattern is used here
 * unconditionally, with no vulnerable variant.
 */
export function queryAuditLogs(q: AuditQuery): { total: number; rows: AuditRecord[] } {
  const where: string[] = [];
  const params: unknown[] = [];

  if (q.search) {
    where.push('(action LIKE ? OR actor_label LIKE ? OR request_path LIKE ? OR detail_json LIKE ?)');
    const like = `%${q.search}%`;
    params.push(like, like, like, like);
  }
  if (q.category) {
    where.push('category = ?');
    params.push(q.category);
  }
  if (q.outcome) {
    where.push('outcome = ?');
    params.push(q.outcome);
  }
  if (q.severity) {
    where.push('severity = ?');
    params.push(q.severity);
  }
  if (q.actorUserId !== undefined) {
    where.push('actor_user_id = ?');
    params.push(q.actorUserId);
  }

  const clause = where.length ? `WHERE ${where.join(' AND ')}` : '';
  const limit = Math.min(Math.max(q.limit ?? 50, 1), 500);
  const offset = Math.max(q.offset ?? 0, 0);

  const countRow = db.preparedOne<{ n: number }>(
    `SELECT COUNT(*) AS n FROM audit_logs ${clause}`,
    params,
  );

  const rows = db.prepared<Record<string, never>>(
    `SELECT * FROM audit_logs ${clause} ORDER BY id DESC LIMIT ? OFFSET ?`,
    [...params, limit, offset],
  ) as unknown as {
    id: number;
    occurred_at: string;
    actor_user_id: number | null;
    actor_label: string;
    action: string;
    category: string;
    outcome: string;
    severity: string;
    target_type: string | null;
    target_id: string | null;
    ip_address: string | null;
    user_agent: string | null;
    request_method: string | null;
    request_path: string | null;
    detail_json: string;
  }[];

  return {
    total: countRow?.n ?? 0,
    rows: rows.map((r) => ({
      id: r.id,
      occurredAt: r.occurred_at,
      actorUserId: r.actor_user_id,
      actorLabel: r.actor_label,
      action: r.action,
      category: r.category,
      outcome: r.outcome,
      severity: r.severity,
      targetType: r.target_type,
      targetId: r.target_id,
      ipAddress: r.ip_address,
      userAgent: r.user_agent,
      requestMethod: r.request_method,
      requestPath: r.request_path,
      detail: JSON.parse(r.detail_json) as Record<string, unknown>,
    })),
  };
}
