/**
 * Cryptography control tests (spec section 32).
 */
import { describe, it, expect } from 'vitest';
import {
  hashPassword, verifyPassword, encrypt, decrypt, DecryptionError,
  encodeBase64, decodeBase64, safeEqual, randomToken,
} from '../src/security/crypto.ts';

describe('password hashing', () => {
  it('produces a salted scrypt envelope, never plaintext', () => {
    const h = hashPassword('correct horse battery staple');
    expect(h.startsWith('scrypt$')).toBe(true);
    expect(h).not.toContain('correct horse');
  });
  it('salts: the same password hashes differently each time', () => {
    expect(hashPassword('same-password-12')).not.toBe(hashPassword('same-password-12'));
  });
  it('verifies a correct password and rejects a wrong one', () => {
    const h = hashPassword('S3cure-pass-phrase');
    expect(verifyPassword('S3cure-pass-phrase', h)).toBe(true);
    expect(verifyPassword('wrong', h)).toBe(false);
  });
});

describe('authenticated encryption (AES-256-GCM)', () => {
  it('round-trips plaintext', () => {
    const ct = encrypt('top secret document body');
    expect(ct).not.toContain('top secret');
    expect(decrypt(ct)).toBe('top secret document body');
  });
  it('produces a different ciphertext each time (random IV)', () => {
    expect(encrypt('same')).not.toBe(encrypt('same'));
  });
  it('rejects a tampered ciphertext instead of returning garbage', () => {
    const ct = encrypt('integrity matters');
    const parts = ct.split('.');
    const tampered = `${parts[0]}.${parts[1]}.${parts[2]}.${Buffer.from('zzzz').toString('base64')}`;
    expect(() => decrypt(tampered)).toThrow(DecryptionError);
  });
});

describe('encoding is not encryption', () => {
  it('base64 is reversible by anyone with no key', () => {
    const enc = encodeBase64('not a secret');
    expect(decodeBase64(enc)).toBe('not a secret');
  });
});

describe('constant-time comparison', () => {
  it('matches equal strings and rejects unequal', () => {
    expect(safeEqual('abc', 'abc')).toBe(true);
    expect(safeEqual('abc', 'abd')).toBe(false);
    expect(safeEqual('abc', 'abcd')).toBe(false);
  });
});

describe('token generation', () => {
  it('produces high-entropy unique tokens', () => {
    const tokens = new Set(Array.from({ length: 500 }, () => randomToken(16)));
    expect(tokens.size).toBe(500);
  });
});
