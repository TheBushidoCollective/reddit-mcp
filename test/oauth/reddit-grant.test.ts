import { describe, expect, test, vi } from 'vitest';

import {
  type CallbackResult,
  completeRedditSignIn,
  RedditGrant,
} from '../../src/oauth/reddit-grant.js';
import { deriveSealingKey, fingerprint } from '../../src/oauth/sealing.js';
import { MemoryDocumentStore, OAuthStores } from '../../src/oauth/stores.js';

const TOKEN_URL = 'https://www.reddit.com/api/v1/access_token';
const IDENTITY_URL = 'https://oauth.reddit.com/api/v1/me';
const CLIENT_CALLBACK = 'http://127.0.0.1:9999/oauth/callback';
const SEALING_KEY = deriveSealingKey('a-test-session-secret');

function redditStub(username: string): typeof fetch {
  return async (input) => {
    const url = typeof input === 'string' ? input : input.toString();
    if (url === TOKEN_URL) {
      return new Response(
        JSON.stringify({
          access_token: 'reddit-access-token',
          refresh_token: 'reddit-refresh-token',
        }),
        { status: 200, headers: { 'content-type': 'application/json' } }
      );
    }
    if (url === IDENTITY_URL) {
      return new Response(JSON.stringify({ name: username }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    }
    throw new Error(`unexpected upstream call: ${url}`);
  };
}

async function finishSignIn(
  identity: string,
  allowedUsername: string | undefined
) {
  const documents = new MemoryDocumentStore();
  const stores = new OAuthStores(documents, SEALING_KEY);
  const writes = vi.spyOn(documents, 'put');
  const creations = vi.spyOn(documents, 'create');

  await stores.putTransaction(
    'parked-transaction',
    {
      clientId: 'client-id',
      redirectUri: CLIENT_CALLBACK,
      state: 'client-state',
      codeChallenge: 'challenge',
      scopes: ['identity', 'read'],
      createdAt: Math.floor(Date.now() / 1000),
    },
    600
  );
  writes.mockClear();
  creations.mockClear();

  const grantConfig = {
    publicUrl: 'https://reddit.example.test',
    clientId: 'reddit-client-id',
    clientSecret: 'reddit-client-secret',
    userAgent: 'reddit-mcp-test',
    allowedUsername,
    fetchImpl: redditStub(identity),
  };
  const grant = new RedditGrant(grantConfig);
  const result = await completeRedditSignIn(grant, stores, SEALING_KEY, {
    state: 'parked-transaction',
    code: 'reddit-code',
  });

  return { result, stores, writes, creations };
}

function redirectFrom(result: CallbackResult): URL {
  if ('failed' in result) {
    throw new Error(`expected redirect, received HTTP ${result.status}`);
  }
  return new URL(result.redirectTo);
}

function expectAccessDenied(result: CallbackResult, description: string): void {
  const redirect = redirectFrom(result);
  expect(redirect.searchParams.get('error')).toBe('access_denied');
  expect(redirect.searchParams.get('error_description')).toBe(description);
  expect(redirect.searchParams.has('code')).toBe(false);
}

describe('the hosted Reddit account boundary', () => {
  test('the allowed username completes the grant and persists its session', async () => {
    const { result, stores } = await finishSignIn(
      'some_redditor',
      'some_redditor'
    );

    const redirect = redirectFrom(result);
    expect(redirect.searchParams.get('error')).toBeNull();
    expect(redirect.searchParams.get('code')).not.toBeNull();
    await expect(
      stores.getRedditGrant(fingerprint('some_redditor'))
    ).resolves.toEqual({
      username: 'some_redditor',
      refreshToken: 'reddit-refresh-token',
    });
  });

  test('a different username is denied without writing to storage', async () => {
    const { result, writes, creations } = await finishSignIn(
      'someone_else',
      'some_redditor'
    );

    expectAccessDenied(
      result,
      'This server is configured for a different Reddit account.'
    );
    expect(writes).not.toHaveBeenCalled();
    expect(creations).not.toHaveBeenCalled();
  });

  test('the username comparison is case-insensitive', async () => {
    const { result, stores } = await finishSignIn(
      'Some_Redditor',
      'some_redditor'
    );

    const redirect = redirectFrom(result);
    expect(redirect.searchParams.get('code')).not.toBeNull();
    await expect(
      stores.getRedditGrant(fingerprint('Some_Redditor'))
    ).resolves.toEqual({
      username: 'Some_Redditor',
      refreshToken: 'reddit-refresh-token',
    });
  });

  test.each(['u/some_redditor', '/u/some_redditor'])(
    'a configured %s prefix is ignored',
    async (allowedUsername) => {
      const { result } = await finishSignIn('some_redditor', allowedUsername);

      expect(redirectFrom(result).searchParams.get('code')).not.toBeNull();
    }
  );

  test.each([
    { label: 'unset', allowedUsername: undefined },
    { label: 'empty', allowedUsername: '' },
  ])(
    '$label configuration denies every username',
    async ({ allowedUsername }) => {
      const { result, writes, creations } = await finishSignIn(
        'some_redditor',
        allowedUsername
      );

      expectAccessDenied(
        result,
        'This server is configured for a single Reddit account, but no account is configured.'
      );
      expect(writes).not.toHaveBeenCalled();
      expect(creations).not.toHaveBeenCalled();
    }
  );
});
