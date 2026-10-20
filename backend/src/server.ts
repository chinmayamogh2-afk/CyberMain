/**
 * Server bootstrap.
 *
 * Binds to the configured host, which defaults to 127.0.0.1. The platform hosts
 * deliberately vulnerable endpoints, so it must not be reachable from the
 * network: §41 requires this stay a local, controlled environment.
 */
import { createApp } from './app.js';
import { config } from './config/env.js';
import { logger } from './core/logger.js';
import { migrate, closeDb } from './db/index.js';
import { loadModes, getAllModes } from './security/modes.js';
import { pruneExpiredSessions } from './security/session.js';
import { ensureLabSchema } from './labs/sqli.js';
import { emitSecurityEvent } from './security/events.js';

function warnIfPubliclyBound(): void {
  if (config.host === '0.0.0.0' || config.host === '::') {
    logger.warn(
      'HOST is bound to all interfaces. SentinelX hosts intentionally vulnerable endpoints ' +
        'and should be reachable from this machine only. Set HOST=127.0.0.1.',
    );
  }
}

async function main(): Promise<void> {
  migrate();
  loadModes();
  ensureLabSchema();
  const pruned = pruneExpiredSessions();
  if (pruned > 0) logger.info(`Pruned ${pruned} expired session(s)`);

  const app = createApp();
  const server = app.listen(config.port, config.host, () => {
    const modes = getAllModes();
    const vulnerable = Object.entries(modes).filter(([, m]) => m === 'vulnerable');

    logger.info(`SentinelX API listening on http://${config.host}:${config.port}`);
    logger.info(`Database driver: ${config.db.driver} (${config.db.sqlitePath})`);
    if (vulnerable.length === 0) {
      logger.info('Security mode registry: all classes HARDENED');
    } else {
      logger.warn(
        `Security mode registry: ${vulnerable.length} class(es) VULNERABLE — ${vulnerable
          .map(([k]) => k)
          .join(', ')}`,
      );
    }
    warnIfPubliclyBound();
    emitSecurityEvent('info', 'app', 'SentinelX platform started', {
      vulnerableClasses: vulnerable.map(([k]) => k),
    });
  });

  const shutdown = (signal: string) => {
    logger.info(`${signal} received, shutting down`);
    server.close(() => {
      closeDb();
      process.exit(0);
    });
    // Do not hang forever on a stuck connection (e.g. an open SSE stream).
    setTimeout(() => process.exit(1), 5000).unref();
  };
  process.on('SIGINT', () => shutdown('SIGINT'));
  process.on('SIGTERM', () => shutdown('SIGTERM'));
}

main().catch((err) => {
  logger.error('Fatal error during startup', {
    message: err instanceof Error ? err.message : String(err),
    stack: err instanceof Error ? err.stack : undefined,
  });
  process.exit(1);
});
