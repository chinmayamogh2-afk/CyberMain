/**
 * Structured server-side logger.
 *
 * This is the "internal" half of §30: detailed technical information goes here,
 * where an operator can see it, while the client receives a generic message.
 */
import { redact } from './errors.js';
import { config } from '../config/env.js';

type Level = 'debug' | 'info' | 'warn' | 'error';

const LEVEL_ORDER: Record<Level, number> = { debug: 10, info: 20, warn: 30, error: 40 };
const MIN_LEVEL: Level = config.env === 'test' ? 'error' : config.isProd ? 'info' : 'debug';

const COLOUR: Record<Level, string> = {
  debug: '\x1b[90m',
  info: '\x1b[36m',
  warn: '\x1b[33m',
  error: '\x1b[31m',
};
const RESET = '\x1b[0m';

function emit(level: Level, message: string, context?: Record<string, unknown>): void {
  if (LEVEL_ORDER[level] < LEVEL_ORDER[MIN_LEVEL]) return;
  const time = new Date().toISOString();
  const safeContext = context ? (redact(context) as Record<string, unknown>) : undefined;
  const prefix = `${COLOUR[level]}${level.toUpperCase().padEnd(5)}${RESET}`;
  const tail = safeContext && Object.keys(safeContext).length ? ` ${JSON.stringify(safeContext)}` : '';
  // eslint-disable-next-line no-console
  console.log(`${prefix} ${time} ${message}${tail}`);
}

export const logger = {
  debug: (m: string, c?: Record<string, unknown>) => emit('debug', m, c),
  info: (m: string, c?: Record<string, unknown>) => emit('info', m, c),
  warn: (m: string, c?: Record<string, unknown>) => emit('warn', m, c),
  error: (m: string, c?: Record<string, unknown>) => emit('error', m, c),
};
