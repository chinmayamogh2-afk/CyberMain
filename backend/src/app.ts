/**
 * Express application factory.
 *
 * Middleware order is itself a security control and is deliberate:
 *
 *   1. cookie parsing          — needed before anything can read the session
 *   2. body parsing (bounded)  — a size cap before we allocate for a payload
 *   3. security headers        — set early so they apply even to error responses
 *   4. CORS                    — allow-listed origin, credentials enabled
 *   5. attachAuth              — resolve identity before any guard runs
 *   6. recorder                — observe the request once identity is known
 *   7. CSRF                    — reject forged state changes before handlers
 *   8. routes
 *   9. 404 then error handler  — last, so they catch everything above
 */
import express from 'express';
import cookieParser from 'cookie-parser';
import cors from 'cors';
import { config, publicConfig } from './config/env.js';
import { securityHeaders } from './security/headers.js';
import { csrfProtection } from './security/csrf.js';
import { attachAuth } from './middleware/auth.js';
import { recordTransactions } from './middleware/recorder.js';
import { errorHandler, notFoundHandler } from './middleware/errorHandler.js';
import { rateLimit, LIMITS } from './security/ratelimit.js';
import { authRouter } from './routes/auth.js';
import { labRouter } from './routes/labRoutes.js';
import { securityRouter } from './routes/securityRoutes.js';
import { appRouter } from './routes/appRoutes.js';
import { adminRouter } from './routes/adminRoutes.js';
import { cryptoRouter } from './routes/cryptoRoutes.js';

export function createApp(): express.Express {
  const app = express();

  // Loopback only. Honouring X-Forwarded-For from an untrusted peer would let a
  // client forge its own address in our audit log and bypass rate limits.
  app.set('trust proxy', 'loopback');
  app.disable('x-powered-by');

  app.use(cookieParser());
  app.use(express.json({ limit: '1mb' }));
  app.use(express.urlencoded({ extended: false, limit: '1mb' }));

  app.use(securityHeaders);

  app.use(
    cors({
      // Explicit origin, not a wildcard: credentials cannot be sent to '*', and
      // reflecting the caller's Origin would defeat the point entirely.
      origin: [config.frontendOrigin, config.selfBaseUrl],
      credentials: true,
      methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
      allowedHeaders: ['Content-Type', 'X-CSRF-Token', 'X-SentinelX-Origin'],
      maxAge: 600,
    }),
  );

  app.use(attachAuth);
  app.use(recordTransactions);
  app.use(csrfProtection);

  app.get('/api/health', (_req, res) => {
    res.json({ status: 'ok', service: 'sentinelx', time: new Date().toISOString() });
  });

  app.get('/api/config', (_req, res) => {
    res.json(publicConfig);
  });

  app.use('/api', rateLimit(LIMITS.api));
  app.use('/api/auth', authRouter);
  app.use('/api/lab', labRouter);
  app.use('/api/security', securityRouter);
  app.use('/api/vault', appRouter);
  app.use('/api/admin', adminRouter);
  app.use('/api/crypto', cryptoRouter);

  app.use(notFoundHandler);
  app.use(errorHandler);

  return app;
}
