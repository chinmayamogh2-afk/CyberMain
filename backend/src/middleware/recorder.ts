/**
 * HTTP transaction recorder (§15).
 *
 * Captures real request/response pairs so the inspector shows traffic the
 * application actually handled. Bodies and headers pass through `redact` first:
 * a request inspector that displayed the login password in plaintext would
 * itself be a sensitive-data-exposure finding.
 */
import type { RequestHandler, Response as ExpressResponse } from 'express';
import { db } from '../db/index.js';
import { redact, redactBodyPreview } from '../core/errors.js';
import { scanForPayloads } from '../security/sanitize.js';
import { emitSecurityEvent } from '../security/events.js';

const BODY_PREVIEW_LIMIT = 4000;

/** Paths excluded to avoid the recorder recording its own reads, or SSE streams. */
const EXCLUDED_PREFIXES = [
  '/api/security/events/stream',
  '/api/security/requests',
  '/api/health',
];

function headerMap(raw: Record<string, unknown>): Record<string, unknown> {
  return redact(raw) as Record<string, unknown>;
}

export const recordTransactions: RequestHandler = (req, res, next) => {
  if (EXCLUDED_PREFIXES.some((p) => req.path.startsWith(p))) return next();

  const startedAt = Date.now();
  const chunks: Buffer[] = [];
  let captured = 0;
  const CAPTURE_CAP = 64 * 1024;

  // Tap the response stream so the inspector can show what was actually sent,
  // rather than re-serialising a guess at it.
  const originalWrite = res.write.bind(res);
  const originalEnd = res.end.bind(res);

  res.write = function patchedWrite(chunk: unknown, ...rest: unknown[]): boolean {
    if (chunk && captured < CAPTURE_CAP) {
      const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk));
      chunks.push(buf);
      captured += buf.length;
    }
    return (originalWrite as unknown as (...a: unknown[]) => boolean)(chunk, ...rest);
  } as unknown as typeof res.write;

  res.end = function patchedEnd(chunk?: unknown, ...rest: unknown[]): ExpressResponse {
    if (chunk && typeof chunk !== 'function' && captured < CAPTURE_CAP) {
      const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk));
      chunks.push(buf);
      captured += buf.length;
    }
    return (originalEnd as unknown as (...a: unknown[]) => ExpressResponse)(chunk, ...rest);
  } as unknown as typeof res.end;

  res.on('finish', () => {
    try {
      const durationMs = Date.now() - startedAt;
      const responseBody = Buffer.concat(chunks).toString('utf8').slice(0, BODY_PREVIEW_LIMIT);

      // Flag the exchange when attack-shaped input is present. This is
      // detection for the analyst's benefit, not a control — see sanitize.ts.
      // Scan a redacted copy of the body so secret fields (passwords, tokens)
      // are never inspected for attack patterns -- a '#' in a password is not an
      // injection, and we should not be reading secret values here anyway.
      const payloadHits = [
        ...scanForPayloads(req.query, 'query'),
        ...scanForPayloads(redact(req.body), 'body'),
        ...scanForPayloads(req.params, 'params'),
      ];

      const origin = req.get('x-sentinelx-origin');
      const transactionOrigin =
        origin === 'scanner' || origin === 'simulator' ? origin : 'app';

      db.run(
        `INSERT INTO http_transactions
           (duration_ms, method, path, query_json, request_headers_json, request_body_preview,
            status_code, response_headers_json, response_body_preview, actor_user_id,
            origin, flagged, flag_reason)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [
          durationMs,
          req.method,
          req.originalUrl.split('?')[0] ?? req.path,
          JSON.stringify(redact(req.query)),
          JSON.stringify(headerMap(req.headers as Record<string, unknown>)),
          redactBodyPreview(req.body, BODY_PREVIEW_LIMIT),
          res.statusCode,
          JSON.stringify(headerMap(res.getHeaders() as Record<string, unknown>)),
          responseBody,
          req.auth?.userId ?? null,
          transactionOrigin,
          payloadHits.length > 0 ? 1 : 0,
          payloadHits.length > 0
            ? payloadHits.map((h) => `${h.field}: ${h.hit.label}`).join('; ')
            : null,
        ],
      );

      if (payloadHits.length > 0 && transactionOrigin === 'app') {
        const first = payloadHits[0]!;
        emitSecurityEvent(
          'warn',
          'app',
          `Suspicious input identified in ${req.method} ${req.path}`,
          {
            field: first.field,
            signature: first.hit.label,
            vulnClass: first.hit.vulnClass,
            totalMatches: payloadHits.length,
          },
        );
      }
    } catch {
      // Recording must never break the request it is observing.
    }
  });

  next();
};

export interface TransactionRecord {
  id: number;
  startedAt: string;
  durationMs: number;
  method: string;
  path: string;
  query: Record<string, unknown>;
  requestHeaders: Record<string, unknown>;
  requestBody: string;
  statusCode: number;
  responseHeaders: Record<string, unknown>;
  responseBody: string;
  actorUserId: number | null;
  origin: string;
  flagged: boolean;
  flagReason: string | null;
}

export interface TransactionQuery {
  limit?: number;
  offset?: number;
  method?: string;
  pathContains?: string;
  flaggedOnly?: boolean;
  origin?: string;
  minStatus?: number;
}

export function queryTransactions(q: TransactionQuery): {
  total: number;
  rows: TransactionRecord[];
} {
  const where: string[] = [];
  const params: unknown[] = [];

  if (q.method) {
    where.push('method = ?');
    params.push(q.method.toUpperCase());
  }
  if (q.pathContains) {
    where.push('path LIKE ?');
    params.push(`%${q.pathContains}%`);
  }
  if (q.flaggedOnly) where.push('flagged = 1');
  if (q.origin) {
    where.push('origin = ?');
    params.push(q.origin);
  }
  if (q.minStatus !== undefined) {
    where.push('status_code >= ?');
    params.push(q.minStatus);
  }

  const clause = where.length ? `WHERE ${where.join(' AND ')}` : '';
  const limit = Math.min(Math.max(q.limit ?? 50, 1), 200);
  const offset = Math.max(q.offset ?? 0, 0);

  const count = db.preparedOne<{ n: number }>(
    `SELECT COUNT(*) AS n FROM http_transactions ${clause}`,
    params,
  );

  const rows = db.prepared<{
    id: number;
    started_at: string;
    duration_ms: number;
    method: string;
    path: string;
    query_json: string;
    request_headers_json: string;
    request_body_preview: string | null;
    status_code: number;
    response_headers_json: string;
    response_body_preview: string | null;
    actor_user_id: number | null;
    origin: string;
    flagged: number;
    flag_reason: string | null;
  }>(
    `SELECT * FROM http_transactions ${clause} ORDER BY id DESC LIMIT ? OFFSET ?`,
    [...params, limit, offset],
  );

  return {
    total: count?.n ?? 0,
    rows: rows.map((r) => ({
      id: r.id,
      startedAt: r.started_at,
      durationMs: r.duration_ms,
      method: r.method,
      path: r.path,
      query: JSON.parse(r.query_json) as Record<string, unknown>,
      requestHeaders: JSON.parse(r.request_headers_json) as Record<string, unknown>,
      requestBody: r.request_body_preview ?? '',
      statusCode: r.status_code,
      responseHeaders: JSON.parse(r.response_headers_json) as Record<string, unknown>,
      responseBody: r.response_body_preview ?? '',
      actorUserId: r.actor_user_id,
      origin: r.origin,
      flagged: r.flagged === 1,
      flagReason: r.flag_reason,
    })),
  };
}
