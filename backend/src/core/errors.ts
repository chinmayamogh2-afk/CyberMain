/**
 * Error types and the redaction rules that keep internal detail out of
 * responses (§30).
 *
 * The contract: an `AppError` carries BOTH a safe client-facing message and an
 * optional internal detail. The error handler sends the first and logs the
 * second. Any error that is not an `AppError` is treated as unexpected and
 * collapsed to a generic message, because we cannot know what an arbitrary
 * exception might reveal.
 */

export type ErrorCode =
  | 'bad_request'
  | 'validation_failed'
  | 'unauthenticated'
  | 'forbidden'
  | 'not_found'
  | 'conflict'
  | 'rate_limited'
  | 'csrf_failed'
  | 'payload_too_large'
  | 'unsupported_media_type'
  | 'internal';

const STATUS_BY_CODE: Record<ErrorCode, number> = {
  bad_request: 400,
  validation_failed: 422,
  unauthenticated: 401,
  forbidden: 403,
  not_found: 404,
  conflict: 409,
  rate_limited: 429,
  csrf_failed: 403,
  payload_too_large: 413,
  unsupported_media_type: 415,
  internal: 500,
};

export class AppError extends Error {
  readonly code: ErrorCode;
  readonly status: number;
  /** Shown to the client. Must contain no internal detail. */
  readonly clientMessage: string;
  /** Logged server-side only. May contain technical detail. */
  readonly internalDetail?: string;
  /** Machine-readable field errors for form validation. */
  readonly fields?: Record<string, string>;

  constructor(
    code: ErrorCode,
    clientMessage: string,
    options: { internalDetail?: string; fields?: Record<string, string> } = {},
  ) {
    super(clientMessage);
    this.name = 'AppError';
    this.code = code;
    this.status = STATUS_BY_CODE[code];
    this.clientMessage = clientMessage;
    this.internalDetail = options.internalDetail;
    this.fields = options.fields;
  }
}

export const badRequest = (msg: string, detail?: string) =>
  new AppError('bad_request', msg, { internalDetail: detail });
export const unauthenticated = (msg = 'Authentication required.') =>
  new AppError('unauthenticated', msg);
export const forbidden = (msg = 'You do not have permission to perform this action.') =>
  new AppError('forbidden', msg);
export const notFound = (msg = 'The requested resource was not found.') =>
  new AppError('not_found', msg);
export const conflict = (msg: string) => new AppError('conflict', msg);
export const validationFailed = (fields: Record<string, string>, msg = 'Invalid input.') =>
  new AppError('validation_failed', msg, { fields });

/**
 * Patterns that must never reach a client response. Used to assert in tests
 * that secure mode does not leak, and by the error handler as a last-resort
 * scrub if a message is assembled dynamically.
 */
export const LEAK_PATTERNS: { label: string; pattern: RegExp }[] = [
  { label: 'stack frame', pattern: /\s+at\s+[\w.<>]+\s+\(/ },
  { label: 'absolute filesystem path', pattern: /(?:\/Users\/|\/home\/|\/var\/www\/|[A-Z]:\\)/ },
  { label: 'SQL statement', pattern: /\b(?:SELECT|INSERT INTO|UPDATE|DELETE FROM)\b\s+\S/i },
  { label: 'SQLite driver error', pattern: /SQLITE_|no such column|unrecognized token/i },
  { label: 'node module path', pattern: /node_modules/ },
  { label: 'password hash envelope', pattern: /scrypt\$\d+\$/ },
  { label: 'private key block', pattern: /-----BEGIN [A-Z ]*PRIVATE KEY-----/ },
];

export function findLeaks(text: string): string[] {
  return LEAK_PATTERNS.filter((p) => p.pattern.test(text)).map((p) => p.label);
}

/** Keys whose values are replaced with a placeholder before anything is logged. */
const SENSITIVE_KEYS = [
  'password',
  'newpassword',
  'currentpassword',
  'confirmpassword',
  'token',
  'csrftoken',
  'authorization',
  'cookie',
  'setcookie',
  'secret',
  'apikey',
  'privatekey',
  'sessionid',
  'passwordhash',
  'encryptionkey',
];

/**
 * Recursively replaces sensitive values with '[redacted]'.
 *
 * Applied to every audit-log detail object and every captured HTTP body, so the
 * platform's own logs and its request inspector never become the place a
 * password finally ends up in plaintext.
 */
export function redact(value: unknown, depth = 0): unknown {
  if (depth > 6) return '[truncated]';
  if (value === null || value === undefined) return value;
  if (Array.isArray(value)) return value.map((v) => redact(v, depth + 1));
  if (typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      const normalised = k.toLowerCase().replace(/[-_]/g, '');
      out[k] = SENSITIVE_KEYS.includes(normalised) ? '[redacted]' : redact(v, depth + 1);
    }
    return out;
  }
  return value;
}

/** Redacts a raw body string by parsing JSON when possible. */
export function redactBodyPreview(body: unknown, limit = 2000): string {
  if (body === undefined || body === null) return '';
  let text: string;
  if (typeof body === 'string') {
    try {
      text = JSON.stringify(redact(JSON.parse(body)));
    } catch {
      text = body;
    }
  } else {
    text = JSON.stringify(redact(body));
  }
  return text.length > limit ? `${text.slice(0, limit)}… [truncated]` : text;
}
