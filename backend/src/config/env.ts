/**
 * Environment configuration.
 *
 * Every secret used by SentinelX is read from the environment here and nowhere
 * else. No key, password or token is hardcoded in application code, and no
 * secret is ever shipped to the frontend (see `publicConfig` at the bottom).
 */
import 'dotenv/config';
import { z } from 'zod';
import crypto from 'node:crypto';
import path from 'node:path';
import fs from 'node:fs';

const ROOT = path.resolve(import.meta.dirname, '..', '..');

/**
 * In development we tolerate missing secrets by generating ephemeral ones, so a
 * fresh clone runs with zero setup. We refuse to do that in production: a
 * platform that silently invents its own signing key fails open, and §40 of the
 * spec asks us not to overclaim security we do not have.
 */
function devFallbackSecret(name: string): string {
  const generated = crypto.randomBytes(32).toString('hex');
  // eslint-disable-next-line no-console
  console.warn(
    `[config] ${name} is not set — generated an ephemeral development secret. ` +
      `Sessions and ciphertexts will not survive a restart. Set it in .env for a stable demo.`,
  );
  return generated;
}

const schema = z.object({
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
  PORT: z.coerce.number().int().positive().default(4000),
  HOST: z.string().default('127.0.0.1'),

  /** Where the browser app is served from; used for CORS and CSRF origin checks. */
  FRONTEND_ORIGIN: z.string().url().default('http://localhost:5173'),
  /** The platform's own base URL. The scanner probes this — it must stay local. */
  SELF_BASE_URL: z.string().url().default('http://127.0.0.1:4000'),

  DB_DRIVER: z.enum(['sqlite', 'postgres']).default('sqlite'),
  SQLITE_PATH: z.string().default(path.join(ROOT, '..', 'database', 'sentinelx.db')),
  DATABASE_URL: z.string().optional(),

  /** HMAC key for signing session identifiers. */
  SESSION_SECRET: z.string().min(16).optional(),
  /** 32-byte hex key for AES-256-GCM encryption of sensitive columns. */
  DATA_ENCRYPTION_KEY: z.string().optional(),
  /** Separate key for CSRF token HMAC, so one leak does not compromise both. */
  CSRF_SECRET: z.string().min(16).optional(),

  SESSION_TTL_MINUTES: z.coerce.number().int().positive().default(60),
  UPLOAD_DIR: z.string().default(path.join(ROOT, 'storage', 'uploads')),
  MAX_UPLOAD_BYTES: z.coerce.number().int().positive().default(5 * 1024 * 1024),

  /** Argon2 is not available without a native dep, so we use scrypt. */
  SCRYPT_COST: z.coerce.number().int().positive().default(16384),

  /** Allows the seeded demo accounts to exist. Never enable in production. */
  ENABLE_DEMO_SEED: z
    .enum(['true', 'false'])
    .default('true')
    .transform((v) => v === 'true'),
});

const parsed = schema.safeParse(process.env);

if (!parsed.success) {
  // eslint-disable-next-line no-console
  console.error('[config] Invalid environment configuration:');
  for (const issue of parsed.error.issues) {
    // eslint-disable-next-line no-console
    console.error(`  - ${issue.path.join('.')}: ${issue.message}`);
  }
  process.exit(1);
}

const raw = parsed.data;
const isProd = raw.NODE_ENV === 'production';

function requireSecret(name: string, value: string | undefined): string {
  if (value && value.length > 0) return value;
  if (isProd) {
    // eslint-disable-next-line no-console
    console.error(
      `[config] ${name} must be set in production. Refusing to start with a generated secret.`,
    );
    process.exit(1);
  }
  return devFallbackSecret(name);
}

/**
 * The data-encryption key must be exactly 32 bytes for AES-256-GCM. We accept
 * hex and validate the decoded length rather than silently truncating, because
 * a short key would quietly weaken every ciphertext in the database.
 */
function resolveEncryptionKey(): Buffer {
  const provided = raw.DATA_ENCRYPTION_KEY;
  if (!provided) {
    if (isProd) {
      // eslint-disable-next-line no-console
      console.error('[config] DATA_ENCRYPTION_KEY must be set in production.');
      process.exit(1);
    }
    devFallbackSecret('DATA_ENCRYPTION_KEY');
    return crypto.randomBytes(32);
  }
  let buf: Buffer;
  try {
    buf = Buffer.from(provided.trim(), 'hex');
  } catch {
    // eslint-disable-next-line no-console
    console.error('[config] DATA_ENCRYPTION_KEY must be hex-encoded.');
    process.exit(1);
  }
  if (buf!.length !== 32) {
    // eslint-disable-next-line no-console
    console.error(
      `[config] DATA_ENCRYPTION_KEY must decode to exactly 32 bytes (got ${buf!.length}). ` +
        `Generate one with: openssl rand -hex 32`,
    );
    process.exit(1);
  }
  return buf!;
}

if (raw.DB_DRIVER === 'postgres' && !raw.DATABASE_URL) {
  // eslint-disable-next-line no-console
  console.error('[config] DB_DRIVER=postgres requires DATABASE_URL.');
  process.exit(1);
}

fs.mkdirSync(path.dirname(raw.SQLITE_PATH), { recursive: true });
fs.mkdirSync(raw.UPLOAD_DIR, { recursive: true });

export const config = {
  env: raw.NODE_ENV,
  isProd,
  isTest: raw.NODE_ENV === 'test',
  port: raw.PORT,
  host: raw.HOST,
  frontendOrigin: raw.FRONTEND_ORIGIN,
  selfBaseUrl: raw.SELF_BASE_URL,

  db: {
    driver: raw.DB_DRIVER,
    sqlitePath: raw.SQLITE_PATH,
    url: raw.DATABASE_URL,
  },

  secrets: {
    session: requireSecret('SESSION_SECRET', raw.SESSION_SECRET),
    csrf: requireSecret('CSRF_SECRET', raw.CSRF_SECRET),
    encryptionKey: resolveEncryptionKey(),
  },

  session: { ttlMinutes: raw.SESSION_TTL_MINUTES },
  uploads: { dir: raw.UPLOAD_DIR, maxBytes: raw.MAX_UPLOAD_BYTES },
  crypto: { scryptCost: raw.SCRYPT_COST },
  demoSeed: raw.ENABLE_DEMO_SEED,
} as const;

/**
 * The only configuration the frontend is allowed to see. Deliberately contains
 * no secrets — the browser never needs them, and §11 forbids shipping keys to
 * client code.
 */
export const publicConfig = {
  env: config.env,
  apiBase: '/api',
  sessionTtlMinutes: config.session.ttlMinutes,
  maxUploadBytes: config.uploads.maxBytes,
  dbDriver: config.db.driver,
} as const;
