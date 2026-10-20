/**
 * Central error handling (§30).
 *
 * The rule: the client learns *that* something failed, never *how*. Stack
 * traces, SQL text, filesystem paths and driver messages go to the server log
 * and the audit trail only.
 *
 * The `error_handling` toggle inverts this on purpose. In vulnerable mode the
 * handler returns the stack trace and internal detail to the caller, which is
 * what the error-disclosure lab demonstrates and what the scanner detects by
 * reading its own response.
 */
import type { ErrorRequestHandler, RequestHandler } from 'express';
import { ZodError } from 'zod';
import { AppError, findLeaks } from '../core/errors.js';
import { logger } from '../core/logger.js';
import { isSecure } from '../security/modes.js';
import { audit } from '../security/audit.js';
import { randomToken } from '../security/crypto.js';

export const notFoundHandler: RequestHandler = (req, res) => {
  res.status(404).json({
    error: {
      code: 'not_found',
      message: 'The requested resource was not found.',
      path: req.originalUrl.split('?')[0],
    },
  });
};

export const errorHandler: ErrorRequestHandler = (err, req, res, next) => {
  if (res.headersSent) return next(err);

  // A correlation id lets the user quote a reference and an operator find the
  // matching log line, without the response carrying any detail itself.
  const incidentId = randomToken(8);

  if (err instanceof ZodError) {
    const fields: Record<string, string> = {};
    for (const issue of err.issues) {
      fields[issue.path.join('.') || '_'] = issue.message;
    }
    res.status(422).json({
      error: {
        code: 'validation_failed',
        message: 'Some fields were not valid.',
        fields,
        incidentId,
      },
    });
    return;
  }

  if (err instanceof AppError) {
    logger.warn(`${err.code} on ${req.method} ${req.path}`, {
      incidentId,
      internalDetail: err.internalDetail,
      userId: req.auth?.userId,
    });
    res.status(err.status).json({
      error: {
        code: err.code,
        message: err.clientMessage,
        ...(err.fields ? { fields: err.fields } : {}),
        incidentId,
      },
    });
    return;
  }

  // Unexpected error. Everything below is the dangerous path.
  const error = err instanceof Error ? err : new Error(String(err));

  logger.error(`Unhandled error on ${req.method} ${req.path}`, {
    incidentId,
    name: error.name,
    message: error.message,
    stack: error.stack,
    userId: req.auth?.userId,
  });

  audit({
    action: 'app.error.unhandled',
    category: 'security',
    outcome: 'failure',
    severity: 'high',
    req,
    detail: { incidentId, name: error.name, message: error.message },
  });

  if (!isSecure('error_handling')) {
    // Vulnerable mode: disclose everything, exactly as a misconfigured
    // production server with debug mode left on would.
    const leaked = findLeaks(`${error.message}\n${error.stack ?? ''}`);
    res.status(500).json({
      error: {
        code: 'internal',
        message: error.message,
        type: error.name,
        stack: error.stack?.split('\n').map((l) => l.trim()),
        query: (error as Error & { sql?: string }).sql,
        incidentId,
      },
      _sentinelx: {
        note: 'error_handling is in VULNERABLE mode. This response is deliberately leaking internal detail.',
        disclosedCategories: leaked,
      },
    });
    return;
  }

  res.status(500).json({
    error: {
      code: 'internal',
      message: 'Something went wrong. The incident has been logged.',
      incidentId,
    },
  });
};

/** Wraps an async handler so a rejected promise reaches the error handler. */
export function asyncRoute(
  handler: (...args: Parameters<RequestHandler>) => Promise<unknown>,
): RequestHandler {
  return (req, res, next) => {
    Promise.resolve(handler(req, res, next)).catch(next);
  };
}
