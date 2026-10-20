/**
 * Cryptography Center support routes (spec section 11).
 *
 * Lets the UI demonstrate the difference between hashing, encryption and
 * encoding on user-provided sample text. The sample is processed in memory and
 * never stored or logged (it may be sensitive), and no key is ever returned to
 * the client (spec section 11: do not expose keys to the frontend).
 */
import { Router } from 'express';
import { asyncRoute } from '../middleware/errorHandler.js';
import { badRequest } from '../core/errors.js';
import {
  hashPassword, verifyPassword, encrypt, decrypt, encodeBase64, decodeBase64,
  encodeHex, sha256Hex, insecureMd5Hash, CRYPTO_OPERATIONS,
} from '../security/crypto.js';

export const cryptoRouter = Router();

cryptoRouter.get('/operations', (_req, res) => {
  res.json({ operations: CRYPTO_OPERATIONS });
});

/**
 * Demonstrates all three families on one input, so the UI can show, side by
 * side, that a hash is irreversible, encryption round-trips, and base64 is
 * trivially decodable by anyone.
 */
cryptoRouter.post('/demonstrate', asyncRoute(async (req, res) => {
  const text = (req.body as { text?: unknown }).text;
  if (typeof text !== 'string' || text.length === 0) throw badRequest('Provide some text to transform.');
  if (text.length > 500) throw badRequest('Keep the sample under 500 characters.');

  const ciphertext = encrypt(text);

  res.json({
    input: text,
    hashing: {
      scrypt: { value: hashPassword(text), reversible: false, note: 'Salted + memory-hard. Two runs differ. Cannot be decrypted, only verified.' },
      sha256: { value: sha256Hex(text), reversible: false, note: 'Fast, unsalted. Fine for integrity checksums, unsafe for passwords.' },
      md5: { value: insecureMd5Hash(text), reversible: false, note: 'Broken. Shown only to illustrate why it must not be used.' },
    },
    encryption: {
      algorithm: 'aes-256-gcm',
      ciphertext,
      decrypted: decrypt(ciphertext),
      reversible: true,
      note: 'Authenticated encryption. Round-trips with the key; tampering is detected. The key stays server-side only.',
    },
    encoding: {
      base64: { value: encodeBase64(text), decoded: decodeBase64(encodeBase64(text)), note: 'Not security. Anyone can decode it with no key.' },
      hex: { value: encodeHex(text), note: 'Also just a representation change.' },
    },
  });
}));

/** Verifies a password against a freshly-generated scrypt hash, to show verification. */
cryptoRouter.post('/verify-demo', asyncRoute(async (req, res) => {
  const { original, attempt } = req.body as { original?: unknown; attempt?: unknown };
  if (typeof original !== 'string' || typeof attempt !== 'string') throw badRequest('Provide original and attempt.');
  const hash = hashPassword(original);
  res.json({ hash, matches: verifyPassword(attempt, hash) });
}));
