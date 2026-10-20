/**
 * Test harness setup.
 *
 * Points the app at a throwaway database and fixed secrets BEFORE any module
 * that reads config is imported, then migrates and seeds. Using a real on-disk
 * SQLite file (not a mock) means the security tests exercise the genuine query
 * paths — a mock would let an injection bug pass unnoticed.
 */
import { beforeAll, afterAll } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';

const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinelx-test-'));
process.env.NODE_ENV = 'test';
process.env.SQLITE_PATH = path.join(tmpDir, 'test.db');
process.env.SESSION_SECRET = crypto.randomBytes(32).toString('hex');
process.env.CSRF_SECRET = crypto.randomBytes(32).toString('hex');
process.env.DATA_ENCRYPTION_KEY = crypto.randomBytes(32).toString('hex');
process.env.ENABLE_DEMO_SEED = 'true';
process.env.UPLOAD_DIR = path.join(tmpDir, 'uploads');

beforeAll(async () => {
  const { runSeed } = await import('../src/db/seed.ts');
  const { loadModes, setAllModes } = await import('../src/security/modes.ts');
  const { ensureLabSchema } = await import('../src/labs/sqli.ts');
  runSeed();
  loadModes();
  ensureLabSchema();
  setAllModes('secure');
});

afterAll(() => {
  try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch { /* ignore */ }
});
