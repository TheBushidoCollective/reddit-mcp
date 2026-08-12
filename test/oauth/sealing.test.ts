import { describe, expect, test } from 'vitest';

import {
  deriveSealingKey,
  fingerprint,
  open,
  seal,
  secureEquals,
} from '../../src/oauth/sealing.js';

const key = deriveSealingKey('a-test-session-secret');

describe('seal and open', () => {
  test('round trips a payload', () => {
    const payload = { userId: 'u1', scopes: ['identity', 'read'], n: 7 };
    const sealed = seal(key, 'authorization_code', payload);

    expect(open(key, 'authorization_code', sealed)).toEqual(payload);
  });

  test('produces ciphertext, not a readable payload', () => {
    const sealed = seal(key, 'authorization_code', { userId: 'spectacular' });

    expect(sealed).not.toContain('spectacular');
    expect(sealed).not.toContain('userId');
    expect(() =>
      JSON.parse(Buffer.from(sealed, 'base64url').toString('utf8'))
    ).toThrow();
  });

  test('is non-deterministic, so two codes never look related', () => {
    const first = seal(key, 'authorization_code', { userId: 'u1' });
    const second = seal(key, 'authorization_code', { userId: 'u1' });

    expect(first).not.toBe(second);
  });

  test('rejects a tampered ciphertext', () => {
    const sealed = seal(key, 'authorization_code', { userId: 'u1' });
    const raw = Buffer.from(sealed, 'base64url');
    // Flip a bit in the body, past the nonce and the tag.
    raw[raw.length - 1] ^= 0x01;

    expect(
      open(key, 'authorization_code', raw.toString('base64url'))
    ).toBeNull();
  });

  test('rejects a tampered nonce', () => {
    const sealed = seal(key, 'authorization_code', { userId: 'u1' });
    const raw = Buffer.from(sealed, 'base64url');
    raw[0] ^= 0x01;

    expect(
      open(key, 'authorization_code', raw.toString('base64url'))
    ).toBeNull();
  });

  test('rejects a payload sealed for another purpose', () => {
    const sealed = seal(key, 'reddit_refresh_token', 'upstream-token');

    expect(open(key, 'authorization_code', sealed)).toBeNull();
  });

  test('rejects a payload sealed under another secret', () => {
    const sealed = seal(
      deriveSealingKey('a-different-secret'),
      'authorization_code',
      { userId: 'u1' }
    );

    expect(open(key, 'authorization_code', sealed)).toBeNull();
  });

  test('rejects a truncated token without throwing', () => {
    expect(open(key, 'authorization_code', '')).toBeNull();
    expect(open(key, 'authorization_code', 'not-a-real-code')).toBeNull();
  });
});

describe('deriveSealingKey', () => {
  test('produces a 32 byte key for AES-256', () => {
    expect(deriveSealingKey('secret')).toHaveLength(32);
  });

  test('refuses an empty secret rather than keying off nothing', () => {
    expect(() => deriveSealingKey('   ')).toThrow();
  });
});

describe('fingerprint', () => {
  test('is a stable hash that does not contain the token', () => {
    const token = 'a-token-value';
    const digest = fingerprint(token);

    expect(digest).toHaveLength(64);
    expect(digest).toBe(fingerprint(token));
    expect(digest).not.toContain(token);
  });
});

describe('secureEquals', () => {
  test('matches only identical values', () => {
    expect(secureEquals('abc', 'abc')).toBe(true);
    expect(secureEquals('abc', 'abd')).toBe(false);
    expect(secureEquals('abc', 'abcd')).toBe(false);
    expect(secureEquals('', '')).toBe(true);
  });
});
