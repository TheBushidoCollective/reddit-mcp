import { beforeEach, describe, expect, test, vi } from 'vitest';

import {
  consumeAuthorizationCode,
  issueAuthorizationCode,
  readAuthorizationCode,
} from '../../src/oauth/codes.js';
import { deriveSealingKey } from '../../src/oauth/sealing.js';
import { MemoryDocumentStore, OAuthStores } from '../../src/oauth/stores.js';

const key = deriveSealingKey('a-test-session-secret');

const grant = {
  clientId: 'client-1',
  userId: 'user-1',
  scopes: ['identity', 'read'],
  codeChallenge: 'challenge-value',
  redirectUri: 'http://127.0.0.1:9999/callback',
};

let stores: OAuthStores;

beforeEach(() => {
  stores = new OAuthStores(new MemoryDocumentStore(), key);
});

describe('issueAuthorizationCode', () => {
  test('hides the identity binding it carries', () => {
    const code = issueAuthorizationCode(key, grant);

    expect(code).not.toContain('user-1');
    expect(code).not.toContain('challenge-value');
    expect(code).not.toContain('127.0.0.1');
  });

  test('gives every code its own single-use id', () => {
    const first = readAuthorizationCode(
      key,
      issueAuthorizationCode(key, grant),
      {
        clientId: grant.clientId,
      }
    );
    const second = readAuthorizationCode(
      key,
      issueAuthorizationCode(key, grant),
      {
        clientId: grant.clientId,
      }
    );

    expect('payload' in first && 'payload' in second).toBe(true);
    if ('payload' in first && 'payload' in second) {
      expect(first.payload.jti).not.toBe(second.payload.jti);
    }
  });
});

describe('readAuthorizationCode', () => {
  test('returns the PKCE challenge without spending the code', async () => {
    const code = issueAuthorizationCode(key, grant);

    const first = readAuthorizationCode(key, code, {
      clientId: grant.clientId,
    });
    const second = readAuthorizationCode(key, code, {
      clientId: grant.clientId,
    });

    expect('payload' in first && first.payload.codeChallenge).toBe(
      'challenge-value'
    );
    expect('payload' in second && second.payload.codeChallenge).toBe(
      'challenge-value'
    );

    // Nothing was spent, so the exchange that follows still works.
    const exchanged = await consumeAuthorizationCode(key, stores, code, {
      clientId: grant.clientId,
      redirectUri: grant.redirectUri,
    });
    expect('payload' in exchanged).toBe(true);
  });

  test('refuses a code issued to another client', () => {
    const code = issueAuthorizationCode(key, grant);

    expect(readAuthorizationCode(key, code, { clientId: 'client-2' })).toEqual({
      rejected: 'wrong_client',
    });
  });

  test('refuses a code that has expired', () => {
    vi.useFakeTimers();
    try {
      const code = issueAuthorizationCode(key, grant);
      // Thirty seconds is the whole life of a code, so a minute is past it.
      vi.advanceTimersByTime(60_000);

      expect(
        readAuthorizationCode(key, code, { clientId: grant.clientId })
      ).toEqual({ rejected: 'expired' });
    } finally {
      vi.useRealTimers();
    }
  });

  test('refuses anything this key did not seal', () => {
    const forged = issueAuthorizationCode(
      deriveSealingKey('another-secret'),
      grant
    );

    expect(
      readAuthorizationCode(key, forged, { clientId: grant.clientId })
    ).toEqual({ rejected: 'malformed' });
  });
});

describe('consumeAuthorizationCode', () => {
  test('exchanges once and refuses the replay', async () => {
    const code = issueAuthorizationCode(key, grant);
    const expected = {
      clientId: grant.clientId,
      redirectUri: grant.redirectUri,
    };

    const first = await consumeAuthorizationCode(key, stores, code, expected);
    const second = await consumeAuthorizationCode(key, stores, code, expected);

    expect('payload' in first && first.payload.userId).toBe('user-1');
    expect(second).toEqual({ rejected: 'replayed' });
  });

  test('lets exactly one of two concurrent exchanges win', async () => {
    const code = issueAuthorizationCode(key, grant);
    const expected = {
      clientId: grant.clientId,
      redirectUri: grant.redirectUri,
    };

    const results = await Promise.all([
      consumeAuthorizationCode(key, stores, code, expected),
      consumeAuthorizationCode(key, stores, code, expected),
    ]);

    const won = results.filter((result) => 'payload' in result);
    expect(won).toHaveLength(1);
  });

  test('refuses a code redeemed against a different redirect_uri', async () => {
    const code = issueAuthorizationCode(key, grant);

    const result = await consumeAuthorizationCode(key, stores, code, {
      clientId: grant.clientId,
      redirectUri: 'http://127.0.0.1:9999/stolen',
    });

    expect(result).toEqual({ rejected: 'wrong_redirect_uri' });
  });

  test('leaves a code unspent when the redirect binding fails', async () => {
    const code = issueAuthorizationCode(key, grant);

    await consumeAuthorizationCode(key, stores, code, {
      clientId: grant.clientId,
      redirectUri: 'http://127.0.0.1:9999/stolen',
    });
    const honest = await consumeAuthorizationCode(key, stores, code, {
      clientId: grant.clientId,
      redirectUri: grant.redirectUri,
    });

    // A refused attempt must not burn the code the rightful client still holds.
    expect('payload' in honest).toBe(true);
  });

  test('refuses an exchange that omits redirect_uri entirely', async () => {
    const code = issueAuthorizationCode(key, grant);

    const result = await consumeAuthorizationCode(key, stores, code, {
      clientId: grant.clientId,
    });

    expect(result).toEqual({ rejected: 'missing_redirect_uri' });
  });
});
