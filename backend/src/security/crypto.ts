/**
 * Cryptographic primitives.
 *
 * Everything here uses Node's audited `crypto` module. No algorithm is
 * invented, no key is hardcoded (§11): the AES key arrives from
 * DATA_ENCRYPTION_KEY via config.
 *
 * The three operations the Cryptography Center teaches are deliberately kept
 * distinct in this file, because conflating them is the single most common
 * misconception in web security:
 *
 *   hashPassword()  — one-way, salted, slow. For verification only.
 *   encrypt()       — two-way, keyed, authenticated. For confidentiality.
 *   encodeBase64()  — reversible by anyone, keyless. NOT security.
 */
import crypto from 'node:crypto';
import { config } from '../config/env.js';

// ── Password hashing (one-way) ──────────────────────────────────────────────

const SCRYPT_KEYLEN = 64;
const SCRYPT_BLOCK_SIZE = 8;
const SCRYPT_PARALLELISM = 1;

/**
 * Hashes a password with scrypt: a memory-hard KDF, so an attacker holding the
 * database cannot cheaply brute-force it on GPUs.
 *
 * A fresh 16-byte salt per password defeats rainbow tables and ensures two users
 * with the same password get different hashes. Parameters are stored alongside
 * the hash so the cost can be raised later without invalidating old hashes.
 *
 * Format: scrypt$N$r$p$<salt-base64>$<hash-base64>
 */
export function hashPassword(plaintext: string): string {
  const salt = crypto.randomBytes(16);
  const N = config.crypto.scryptCost;
  const derived = crypto.scryptSync(plaintext, salt, SCRYPT_KEYLEN, {
    N,
    r: SCRYPT_BLOCK_SIZE,
    p: SCRYPT_PARALLELISM,
    // scrypt needs roughly 128 * N * r bytes; raise the cap to match N.
    maxmem: 256 * N * SCRYPT_BLOCK_SIZE,
  });
  return [
    'scrypt',
    N,
    SCRYPT_BLOCK_SIZE,
    SCRYPT_PARALLELISM,
    salt.toString('base64'),
    derived.toString('base64'),
  ].join('$');
}

/**
 * Verifies a password against a stored envelope.
 *
 * The final comparison uses `timingSafeEqual`. A naive `===` would return faster
 * on an early-mismatching hash, leaking information byte by byte; that is a real
 * side channel, and the Authentication lab points at this line to explain it.
 */
export function verifyPassword(plaintext: string, envelope: string): boolean {
  const parts = envelope.split('$');
  if (parts.length !== 6 || parts[0] !== 'scrypt') return false;

  const N = Number(parts[1]);
  const r = Number(parts[2]);
  const p = Number(parts[3]);
  const salt = Buffer.from(parts[4]!, 'base64');
  const expected = Buffer.from(parts[5]!, 'base64');
  if (!Number.isFinite(N) || !Number.isFinite(r) || !Number.isFinite(p)) return false;

  let actual: Buffer;
  try {
    actual = crypto.scryptSync(plaintext, salt, expected.length, {
      N,
      r,
      p,
      maxmem: 256 * N * r,
    });
  } catch {
    return false;
  }
  if (actual.length !== expected.length) return false;
  return crypto.timingSafeEqual(actual, expected);
}

/**
 * An intentionally broken hash, used only by the vulnerable mode of the
 * authentication lab to show why unsalted fast digests are inadequate.
 * Never called by any real authentication path.
 */
export function insecureMd5Hash(plaintext: string): string {
  return crypto.createHash('md5').update(plaintext).digest('hex');
}

export function passwordHashAlgorithm(envelope: string): string {
  if (envelope.startsWith('scrypt$')) return 'scrypt';
  if (/^[a-f0-9]{32}$/i.test(envelope)) return 'md5 (insecure)';
  if (/^[a-f0-9]{64}$/i.test(envelope)) return 'sha256 (unsalted, insecure)';
  return 'unknown';
}

// ── Authenticated encryption (two-way) ──────────────────────────────────────

const GCM_IV_BYTES = 12; // 96 bits, the value NIST specifies for GCM
// Must not contain the '.' field separator used in the envelope below.
const ENVELOPE_PREFIX = 'v1-aes256gcm';

/**
 * Encrypts a UTF-8 string with AES-256-GCM.
 *
 * GCM is an AEAD mode: it provides confidentiality *and* integrity, so a
 * tampered ciphertext fails to decrypt rather than silently yielding garbage.
 * That is why we use it over, say, AES-CBC, which would leave us needing a
 * separate MAC and vulnerable to padding-oracle attacks if we got it wrong.
 *
 * A fresh random IV is generated per encryption. Reusing an IV under the same
 * key is catastrophic for GCM — it leaks the authentication subkey — so the IV
 * is never derived from the plaintext or a counter we might reset.
 *
 * Envelope: v1-aes256gcm.<iv-b64>.<tag-b64>.<ciphertext-b64>
 */
export function encrypt(plaintext: string, aad?: string): string {
  const iv = crypto.randomBytes(GCM_IV_BYTES);
  const cipher = crypto.createCipheriv('aes-256-gcm', config.secrets.encryptionKey, iv);
  if (aad) cipher.setAAD(Buffer.from(aad, 'utf8'));
  const ciphertext = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return [
    ENVELOPE_PREFIX,
    iv.toString('base64'),
    tag.toString('base64'),
    ciphertext.toString('base64'),
  ].join('.');
}

export class DecryptionError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'DecryptionError';
  }
}

/**
 * Decrypts an envelope produced by `encrypt`.
 *
 * Throws on any integrity failure. Callers must treat a throw as "this data was
 * tampered with or the key is wrong" and fail securely (§: fail securely) rather
 * than falling back to returning the raw bytes.
 */
export function decrypt(envelope: string, aad?: string): string {
  const parts = envelope.split('.');
  if (parts.length !== 4 || parts[0] !== ENVELOPE_PREFIX) {
    throw new DecryptionError('Unrecognised ciphertext envelope');
  }
  const iv = Buffer.from(parts[1]!, 'base64');
  const tag = Buffer.from(parts[2]!, 'base64');
  const ciphertext = Buffer.from(parts[3]!, 'base64');

  const decipher = crypto.createDecipheriv('aes-256-gcm', config.secrets.encryptionKey, iv);
  if (aad) decipher.setAAD(Buffer.from(aad, 'utf8'));
  decipher.setAuthTag(tag);
  try {
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8');
  } catch {
    throw new DecryptionError('Authentication tag mismatch — ciphertext was modified');
  }
}

/** Decrypts, or returns null for absent/corrupt data. For display paths. */
export function tryDecrypt(envelope: string | null | undefined): string | null {
  if (!envelope) return null;
  try {
    return decrypt(envelope);
  } catch {
    return null;
  }
}

// ── Integrity / MAC ─────────────────────────────────────────────────────────

/** HMAC-SHA256. Used for CSRF tokens and session-id signing. */
export function hmac(value: string, secret: string): string {
  return crypto.createHmac('sha256', secret).update(value).digest('base64url');
}

/** Constant-time string comparison for MACs and tokens. */
export function safeEqual(a: string, b: string): boolean {
  const bufA = Buffer.from(a, 'utf8');
  const bufB = Buffer.from(b, 'utf8');
  if (bufA.length !== bufB.length) return false;
  return crypto.timingSafeEqual(bufA, bufB);
}

export function sha256Hex(input: string | Buffer): string {
  return crypto.createHash('sha256').update(input).digest('hex');
}

// ── Token generation ────────────────────────────────────────────────────────

/**
 * Cryptographically secure random token.
 *
 * Uses crypto.randomBytes, NOT Math.random(). Math.random is seeded
 * predictably and is not a CSPRNG; session identifiers built from it are
 * guessable. The Session lab contrasts the two directly.
 */
export function randomToken(bytes = 32): string {
  return crypto.randomBytes(bytes).toString('base64url');
}

/** A deliberately weak, predictable identifier for the session lab only. */
export function predictableToken(seed: number): string {
  return `SESS-${seed.toString().padStart(6, '0')}`;
}

// ── Encoding (NOT encryption) ───────────────────────────────────────────────

export function encodeBase64(input: string): string {
  return Buffer.from(input, 'utf8').toString('base64');
}

export function decodeBase64(input: string): string {
  return Buffer.from(input, 'base64').toString('utf8');
}

export function encodeHex(input: string): string {
  return Buffer.from(input, 'utf8').toString('hex');
}

/**
 * Describes a cryptographic operation for the Cryptography Center UI, including
 * whether it actually provides confidentiality. Base64 does not, and the UI
 * says so plainly.
 */
export interface CryptoOperationExplanation {
  family: 'hashing' | 'encryption' | 'encoding' | 'mac';
  reversible: boolean;
  keyed: boolean;
  providesConfidentiality: boolean;
  providesIntegrity: boolean;
  appropriateFor: string;
  inappropriateFor: string;
}

export const CRYPTO_OPERATIONS: Record<string, CryptoOperationExplanation> = {
  scrypt: {
    family: 'hashing',
    reversible: false,
    keyed: false,
    providesConfidentiality: false,
    providesIntegrity: false,
    appropriateFor:
      'Storing passwords. Memory-hard and salted, so stolen hashes resist offline cracking.',
    inappropriateFor:
      'Anything you need to read back. A password hash cannot be decrypted, by design.',
  },
  'aes-256-gcm': {
    family: 'encryption',
    reversible: true,
    keyed: true,
    providesConfidentiality: true,
    providesIntegrity: true,
    appropriateFor:
      'Protecting data you must retrieve later — phone numbers, document bodies, API credentials.',
    inappropriateFor:
      'Passwords. If you can decrypt it, so can anyone who takes the key along with the database.',
  },
  'hmac-sha256': {
    family: 'mac',
    reversible: false,
    keyed: true,
    providesConfidentiality: false,
    providesIntegrity: true,
    appropriateFor: 'Proving a value was issued by the server and not modified — CSRF tokens.',
    inappropriateFor: 'Hiding a value. The input is not concealed, only authenticated.',
  },
  base64: {
    family: 'encoding',
    reversible: true,
    keyed: false,
    providesConfidentiality: false,
    providesIntegrity: false,
    appropriateFor: 'Transporting bytes through a text-only channel. A representation change.',
    inappropriateFor:
      'Security of any kind. Anyone can decode it instantly with no key. Treating base64 as encryption is a sensitive-data-exposure finding.',
  },
  md5: {
    family: 'hashing',
    reversible: false,
    keyed: false,
    providesConfidentiality: false,
    providesIntegrity: false,
    appropriateFor:
      'Nothing security-related. Collision-broken since 2004 and far too fast for passwords.',
    inappropriateFor:
      'Passwords, signatures, integrity checks. Present here only to demonstrate the weakness.',
  },
};
