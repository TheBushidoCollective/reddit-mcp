import { afterEach, describe, expect, test } from 'vitest';

import {
  anonymousClient,
  clientForSession,
  type RedditSession,
} from '../../src/reddit/session.js';

const TOKEN_URL = 'https://www.reddit.com/api/v1/access_token';

/**
 * A value that only ever reaches the code under test through the environment.
 * If it turns up in an outgoing request, something read process.env.
 */
const POISON = 'POISON-ENV-CLIENT-ID';

const realFetch = globalThis.fetch;
const realEnv = { ...process.env };

afterEach(() => {
  globalThis.fetch = realFetch;
  process.env = { ...realEnv };
});

interface Call {
  url: string;
  headers: Record<string, string>;
  body: string;
}

interface Recorded {
  tokenCalls: Call[];
  apiCalls: Call[];
}

/**
 * Routes the token endpoint to a canned token and every other request to a
 * canned body, recording both streams separately so a test can assert that no
 * token was minted at all.
 */
function stubReddit(): Recorded {
  const recorded: Recorded = { tokenCalls: [], apiCalls: [] };

  globalThis.fetch = (async (input: string, init?: RequestInit) => {
    const url = String(input);
    const call: Call = {
      url,
      headers: (init?.headers ?? {}) as Record<string, string>,
      body: String(init?.body ?? ''),
    };

    if (url.startsWith(TOKEN_URL)) {
      recorded.tokenCalls.push(call);
      return new Response(
        JSON.stringify({ access_token: 'tok-1', expires_in: 3600 }),
        { status: 200, headers: { 'Content-Type': 'application/json' } }
      );
    }

    recorded.apiCalls.push(call);
    return new Response(JSON.stringify({ ok: true }), { status: 200 });
  }) as unknown as typeof fetch;

  return recorded;
}

const session = (extra: Partial<RedditSession> = {}): RedditSession => ({
  clientId: 'session-client-id',
  clientSecret: 'session-client-secret',
  refreshToken: 'session-refresh-token',
  userAgent: 'test-agent',
  ...extra,
});

/** Everything a request could carry, flattened for a substring search. */
const wireText = (call: Call): string =>
  [call.url, JSON.stringify(call.headers), call.body].join(' ');

describe('clientForSession', () => {
  test("exchanges the caller's refresh token with the refresh_token grant", async () => {
    const recorded = stubReddit();

    await clientForSession(session()).get('/api/v1/me');

    expect(recorded.tokenCalls).toHaveLength(1);
    const body = new URLSearchParams(recorded.tokenCalls[0].body);
    expect(body.get('grant_type')).toBe('refresh_token');
    expect(body.get('refresh_token')).toBe('session-refresh-token');
  });

  test('authenticates the exchange with the credentials it was handed', async () => {
    const recorded = stubReddit();

    await clientForSession(session()).get('/api/v1/me');

    const expected = Buffer.from(
      'session-client-id:session-client-secret'
    ).toString('base64');
    expect(recorded.tokenCalls[0].headers.Authorization).toBe(
      `Basic ${expected}`
    );
    expect(recorded.tokenCalls[0].headers['User-Agent']).toBe('test-agent');
  });

  test('produces a user scoped client aimed at the OAuth host', async () => {
    const recorded = stubReddit();
    const client = clientForSession(session());

    expect(client.isUserScoped).toBe(true);

    await client.get('/api/v1/me');
    expect(recorded.apiCalls[0].url).toMatch(/^https:\/\/oauth\.reddit\.com\//);
    expect(recorded.apiCalls[0].headers.Authorization).toBe('Bearer tok-1');
  });

  test('refuses a session whose grant did not survive storage', () => {
    // A blank refresh token would otherwise fall through to client_credentials
    // and serve app-only data under a client still labelled user scoped.
    expect(() => clientForSession(session({ refreshToken: '' }))).toThrow(
      /sign in again/
    );
    expect(() => clientForSession(session({ clientId: '' }))).toThrow(
      /sign in again/
    );
  });
});

describe('anonymousClient', () => {
  test('mints no token and targets the public host', async () => {
    const recorded = stubReddit();

    await anonymousClient('test-agent').get('/r/bun/hot');

    expect(recorded.tokenCalls).toHaveLength(0);
    expect(recorded.apiCalls).toHaveLength(1);
    expect(recorded.apiCalls[0].url).toContain(
      'https://www.reddit.com/r/bun/hot.json'
    );
  });

  test('sends no authorization header at all', async () => {
    const recorded = stubReddit();

    await anonymousClient('test-agent').get('/r/bun/hot');

    expect(recorded.apiCalls[0].headers.Authorization).toBeUndefined();
    expect(anonymousClient('test-agent').isUserScoped).toBe(false);
  });
});

describe('environment isolation', () => {
  test('clientForSession ignores ambient Reddit credentials', async () => {
    // The hosted container really does carry these, so a stray process.env
    // read would silently authenticate one caller as the service itself.
    process.env.REDDIT_CLIENT_ID = POISON;
    process.env.REDDIT_CLIENT_SECRET = POISON;
    process.env.REDDIT_REFRESH_TOKEN = POISON;
    process.env.REDDIT_USER_AGENT = POISON;

    const recorded = stubReddit();
    await clientForSession(session()).get('/api/v1/me');

    for (const call of [...recorded.tokenCalls, ...recorded.apiCalls]) {
      expect(wireText(call)).not.toContain(POISON);
    }

    // The Basic header is base64, so a substring scan of the raw text cannot
    // see the poison inside it. Decode it and prove the session won there too.
    const basic = recorded.tokenCalls[0].headers.Authorization.replace(
      'Basic ',
      ''
    );
    expect(Buffer.from(basic, 'base64').toString()).toBe(
      'session-client-id:session-client-secret'
    );
  });

  test('anonymousClient ignores ambient Reddit credentials', async () => {
    process.env.REDDIT_CLIENT_ID = POISON;
    process.env.REDDIT_CLIENT_SECRET = POISON;
    process.env.REDDIT_REFRESH_TOKEN = POISON;

    const recorded = stubReddit();
    await anonymousClient('test-agent').get('/r/bun/hot');

    expect(recorded.tokenCalls).toHaveLength(0);
    expect(wireText(recorded.apiCalls[0])).not.toContain(POISON);
  });
});
