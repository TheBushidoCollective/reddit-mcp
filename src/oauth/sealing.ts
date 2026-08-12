/**
 * Authenticated encryption for the two values this server hands out or stores
 * that an attacker would most like to read: the authorization code, which
 * travels through a browser, and the user's Reddit refresh token, which sits
 * in a database.
 *
 * AES-256-GCM rather than a signature. A signed payload is still readable, and
 * both of these carry the binding to an upstream identity: which Reddit account
 * a code will resolve to, and the durable grant on that account. Browser
 * history, referrer chains, and proxy logs all see the code, so it must be
 * opaque as well as unforgeable.
 *
 * The key is the SHA-256 of MCP_SESSION_SECRET, which lives in Secret Manager
 * and never in Firestore. A database read alone therefore yields ciphertext.
 */

import {
  createCipheriv,
  createDecipheriv,
  createHash,
  randomBytes,
  timingSafeEqual,
} from 'node:crypto';

const ALGORITHM = 'aes-256-gcm';

/** GCM's standard nonce length. Anything else costs an extra derivation step. */
const IV_BYTES = 12;

const TAG_BYTES = 16;

/**
 * Derives the sealing key from the configured session secret.
 *
 * SHA-256 rather than a KDF with a salt because the input is already a high
 * entropy random secret rather than a password, and a per-process salt would
 * have to be stored somewhere to survive the scale to zero this service does.
 */
export function deriveSealingKey(secret: string): Buffer {
  const trimmed = secret.trim();
  if (!trimmed) {
    throw new Error('Cannot derive a sealing key from an empty secret');
  }
  return createHash('sha256').update(trimmed).digest();
}

/**
 * Seals a JSON payload into a single base64url token.
 *
 * `purpose` is passed as additional authenticated data, so a sealed user record
 * cannot be presented where an authorization code is expected. The two are the
 * same shape of opaque string to anyone holding one.
 */
export function seal(key: Buffer, purpose: string, payload: unknown): string {
  const iv = randomBytes(IV_BYTES);
  const cipher = createCipheriv(ALGORITHM, key, iv);
  cipher.setAAD(Buffer.from(purpose, 'utf8'));

  const body = Buffer.concat([
    cipher.update(JSON.stringify(payload), 'utf8'),
    cipher.final(),
  ]);

  return Buffer.concat([iv, cipher.getAuthTag(), body]).toString('base64url');
}

/**
 * Opens a sealed token, returning null for anything that is not exactly what
 * this key sealed under this purpose.
 *
 * Null rather than throwing: every caller treats a bad token as an invalid
 * grant, and the reasons are indistinguishable to the caller anyway. Reporting
 * which of them failed would tell an attacker whether their forgery got as far
 * as the tag check.
 */
export function open<T>(
  key: Buffer,
  purpose: string,
  sealed: string
): T | null {
  let raw: Buffer;
  try {
    raw = Buffer.from(sealed, 'base64url');
  } catch {
    return null;
  }

  if (raw.length <= IV_BYTES + TAG_BYTES) return null;

  const iv = raw.subarray(0, IV_BYTES);
  const tag = raw.subarray(IV_BYTES, IV_BYTES + TAG_BYTES);
  const body = raw.subarray(IV_BYTES + TAG_BYTES);

  try {
    const decipher = createDecipheriv(ALGORITHM, key, iv);
    decipher.setAAD(Buffer.from(purpose, 'utf8'));
    decipher.setAuthTag(tag);
    const plaintext = Buffer.concat([
      decipher.update(body),
      decipher.final(),
    ]).toString('utf8');
    return JSON.parse(plaintext) as T;
  } catch {
    return null;
  }
}

/** SHA-256 hex of a token. Tokens are stored under this, never in the clear. */
export function fingerprint(token: string): string {
  return createHash('sha256').update(token).digest('hex');
}

/**
 * Constant time comparison for values an attacker can submit repeatedly, such
 * as the `state` echoed back from Reddit.
 */
export function secureEquals(a: string, b: string): boolean {
  const left = Buffer.from(a, 'utf8');
  const right = Buffer.from(b, 'utf8');
  if (left.length !== right.length) return false;
  return timingSafeEqual(left, right);
}
