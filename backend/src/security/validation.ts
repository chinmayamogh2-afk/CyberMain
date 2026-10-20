/**
 * Input validation schemas (§: input validation).
 *
 * Validation here is positive — each field declares the shape it accepts and
 * everything else is rejected. That is the opposite of trying to enumerate bad
 * input, which cannot be completed.
 *
 * Validation is a *defence in depth* layer, not the control that stops injection.
 * Parameterised queries stop SQLi and output encoding stops XSS regardless of
 * what gets through here; validation reduces the attack surface and gives users
 * decent errors.
 */
import { z } from 'zod';

/** Password policy (§10). Length is weighted most heavily — it matters most. */
export const PASSWORD_MIN_LENGTH = 12;

export const passwordSchema = z
  .string()
  .min(PASSWORD_MIN_LENGTH, `Password must be at least ${PASSWORD_MIN_LENGTH} characters.`)
  .max(200, 'Password must be at most 200 characters.')
  .refine((v) => /[a-z]/.test(v), 'Password must contain a lowercase letter.')
  .refine((v) => /[A-Z]/.test(v), 'Password must contain an uppercase letter.')
  .refine((v) => /[0-9]/.test(v), 'Password must contain a digit.')
  .refine((v) => /[^A-Za-z0-9]/.test(v), 'Password must contain a symbol.');

export const usernameSchema = z
  .string()
  .trim()
  .min(3, 'Username must be at least 3 characters.')
  .max(32, 'Username must be at most 32 characters.')
  // Allow-list: letters, digits, underscore, hyphen, dot. Nothing that could be
  // mistaken for markup, a path separator or SQL syntax.
  .regex(/^[a-zA-Z0-9._-]+$/, 'Username may contain only letters, digits, dot, underscore or hyphen.');

export const emailSchema = z
  .string()
  .trim()
  .toLowerCase()
  .email('Enter a valid email address.')
  .max(254, 'Email address is too long.');

export const registerSchema = z.object({
  username: usernameSchema,
  email: emailSchema,
  password: passwordSchema,
  fullName: z.string().trim().min(1, 'Full name is required.').max(120),
});

export const loginSchema = z.object({
  username: z.string().trim().min(1, 'Username is required.').max(64),
  password: z.string().min(1, 'Password is required.').max(200),
});

export const changePasswordSchema = z.object({
  currentPassword: z.string().min(1, 'Current password is required.'),
  newPassword: passwordSchema,
});

export const profileUpdateSchema = z.object({
  fullName: z.string().trim().min(1).max(120).optional(),
  bio: z.string().max(500).optional(),
  phone: z.string().trim().max(32).optional(),
  avatarColour: z
    .string()
    .regex(/^#[0-9a-fA-F]{6}$/, 'Colour must be a hex value such as #38bdf8.')
    .optional(),
});

export const documentCreateSchema = z.object({
  title: z.string().trim().min(1, 'Title is required.').max(200),
  body: z.string().max(100_000).default(''),
  classification: z.enum(['public', 'internal', 'confidential', 'restricted']).default('internal'),
});

export const documentUpdateSchema = documentCreateSchema.partial();

export const shareSchema = z.object({
  username: usernameSchema,
  capability: z.enum(['read', 'write']),
});

export const messageSchema = z.object({
  recipientUsername: usernameSchema,
  subject: z.string().trim().max(200).default(''),
  body: z.string().trim().min(1, 'Message body is required.').max(5000),
});

/** Password-strength assessment surfaced in the UI as a meter. */
export interface PasswordAssessment {
  score: 0 | 1 | 2 | 3 | 4;
  label: 'very weak' | 'weak' | 'fair' | 'strong' | 'very strong';
  satisfied: string[];
  failed: string[];
  warnings: string[];
}

const COMMON_PASSWORDS = new Set([
  'password', 'password1', 'password123', '123456', '12345678', '123456789',
  'qwerty', 'qwerty123', 'letmein', 'welcome', 'admin', 'admin123',
  'iloveyou', 'monkey', 'dragon', 'football', 'abc123', 'passw0rd',
  'p@ssw0rd', 'changeme', 'secret', 'test123', 'root', 'toor',
]);

export function assessPassword(password: string): PasswordAssessment {
  const satisfied: string[] = [];
  const failed: string[] = [];
  const warnings: string[] = [];

  const checks: [string, boolean][] = [
    [`At least ${PASSWORD_MIN_LENGTH} characters`, password.length >= PASSWORD_MIN_LENGTH],
    ['Contains a lowercase letter', /[a-z]/.test(password)],
    ['Contains an uppercase letter', /[A-Z]/.test(password)],
    ['Contains a digit', /[0-9]/.test(password)],
    ['Contains a symbol', /[^A-Za-z0-9]/.test(password)],
  ];
  for (const [label, ok] of checks) (ok ? satisfied : failed).push(label);

  if (COMMON_PASSWORDS.has(password.toLowerCase())) {
    warnings.push('This is one of the most commonly used passwords and would be guessed immediately.');
  }
  if (/^(.)\1+$/.test(password)) warnings.push('A single repeated character has almost no entropy.');
  if (/^(?:0123|1234|2345|abcd|qwer)/i.test(password)) {
    warnings.push('Starts with a keyboard or numeric sequence, which cracking tools try first.');
  }
  if (password.length >= 20 && failed.length > 0) {
    warnings.push('Length is doing most of the work here — a long passphrase is genuinely strong even without symbols.');
  }

  let score = satisfied.length - 1;
  if (password.length >= 16) score += 1;
  if (warnings.some((w) => w.includes('commonly used'))) score = 0;
  score = Math.max(0, Math.min(4, score)) as 0 | 1 | 2 | 3 | 4;

  const labels: PasswordAssessment['label'][] = ['very weak', 'weak', 'fair', 'strong', 'very strong'];
  return { score: score as 0|1|2|3|4, label: labels[score]!, satisfied, failed, warnings };
}
