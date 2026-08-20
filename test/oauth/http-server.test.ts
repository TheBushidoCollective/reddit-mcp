/**
 * Exercises the hosted server over real HTTP, because the parts most worth
 * proving are the ones the SDK's routers own: the order it calls the provider
 * in, the PKCE check it performs on our behalf, and the WWW-Authenticate
 * header it builds. A unit test of the provider would assert our half of a
 * conversation and miss all three.
 */

import { createHash, randomBytes } from 'node:crypto';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';

import type { Express } from 'express';
import { afterAll, beforeAll, describe, expect, test } from 'vitest';

import { createHttpServer } from '../../src/http-server.js';
import { deriveSealingKey } from '../../src/oauth/sealing.js';
import { MemoryDocumentStore, OAuthStores } from '../../src/oauth/stores.js';

const REDDIT_TOKEN_URL = 'https://www.reddit.com/api/v1/access_token';
const REDDIT_IDENTITY_URL = 'https://oauth.reddit.com/api/v1/me';

const AGENT_CALLBACK = 'http://127.0.0.1:9999/oauth/callback';

let server: Server;
let origin: string;

/** Stands in for Reddit, so the sign-in can be driven end to end offline. */
const redditStub: typeof fetch = async (input) => {
  const url = typeof input === 'string' ? input : input.toString();
  if (url === REDDIT_TOKEN_URL) {
    return new Response(
      JSON.stringify({
        access_token: 'reddit-access-token',
        refresh_token: 'reddit-refresh-token',
        expires_in: 3600,
      }),
      { status: 200, headers: { 'content-type': 'application/json' } }
    );
  }
  if (url === REDDIT_IDENTITY_URL) {
    return new Response(JSON.stringify({ name: 'some_redditor' }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    });
  }
  throw new Error(`unexpected upstream call: ${url}`);
};

beforeAll(async () => {
  // The public URL has to contain the port, and the port is only known once
  // the socket is bound, so the app is built after listening and reached
  // through a thin handler rather than passed to listen directly.
  let app: Express | undefined;
  server = createServer((request, response) => {
    app?.(request, response);
  });
  await new Promise<void>((resolve) => {
    server.listen(0, '127.0.0.1', resolve);
  });

  const address = server.address() as AddressInfo;
  origin = `http://127.0.0.1:${address.port}`;

  app = createHttpServer({
    publicUrl: origin,
    redditClientId: 'reddit-app-id',
    redditClientSecret: 'reddit-app-secret',
    redditAllowedUsername: 'some_redditor',
    sealingKey: deriveSealingKey('a-test-session-secret'),
    stores: new OAuthStores(
      new MemoryDocumentStore(),
      deriveSealingKey('a-test-session-secret')
    ),
    fetchImpl: redditStub,
  });
});

afterAll(async () => {
  await new Promise<void>((resolve) => {
    server.close(() => {
      resolve();
    });
  });
});

interface RegisteredClient {
  clientId: string;
}

async function registerClient(): Promise<RegisteredClient> {
  const response = await fetch(`${origin}/register`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      redirect_uris: [AGENT_CALLBACK],
      token_endpoint_auth_method: 'none',
      grant_types: ['authorization_code', 'refresh_token'],
      response_types: ['code'],
      client_name: 'test agent',
    }),
  });
  expect(response.status).toBe(201);

  const body: unknown = await response.json();
  const clientId =
    body && typeof body === 'object' && 'client_id' in body
      ? body.client_id
      : null;
  expect(typeof clientId).toBe('string');
  return { clientId: String(clientId) };
}

interface PendingFlow {
  code: string;
  verifier: string;
}

/** Runs /authorize and the Reddit callback, returning our own code. */
async function signIn(clientId: string): Promise<PendingFlow> {
  const verifier = randomBytes(32).toString('base64url');
  const challenge = createHash('sha256').update(verifier).digest('base64url');

  const authorize = new URL('/authorize', origin);
  authorize.searchParams.set('client_id', clientId);
  authorize.searchParams.set('redirect_uri', AGENT_CALLBACK);
  authorize.searchParams.set('response_type', 'code');
  authorize.searchParams.set('code_challenge', challenge);
  authorize.searchParams.set('code_challenge_method', 'S256');
  authorize.searchParams.set('state', 'agent-state');

  const redirected = await fetch(authorize, { redirect: 'manual' });
  expect(redirected.status).toBe(302);

  const upstream = new URL(redirected.headers.get('location') ?? '');
  expect(upstream.origin).toBe('https://www.reddit.com');
  expect(upstream.pathname).toBe('/api/v1/authorize');
  expect(upstream.searchParams.get('duration')).toBe('permanent');

  const transaction = upstream.searchParams.get('state') ?? '';
  const callback = new URL('/callback/reddit', origin);
  callback.searchParams.set('state', transaction);
  callback.searchParams.set('code', 'reddit-code');

  const returned = await fetch(callback, { redirect: 'manual' });
  expect(returned.status).toBe(302);

  const back = new URL(returned.headers.get('location') ?? '');
  expect(back.origin + back.pathname).toBe(AGENT_CALLBACK);
  expect(back.searchParams.get('state')).toBe('agent-state');

  return { code: back.searchParams.get('code') ?? '', verifier };
}

async function exchange(
  clientId: string,
  body: Record<string, string>
): Promise<{ status: number; payload: Record<string, unknown> }> {
  const response = await fetch(`${origin}/token`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ client_id: clientId, ...body }).toString(),
  });
  const payload: unknown = await response.json();
  return {
    status: response.status,
    payload:
      payload && typeof payload === 'object'
        ? (payload as Record<string, unknown>)
        : {},
  };
}

describe('discovery', () => {
  test('an unauthenticated POST /mcp says where to sign in', async () => {
    const response = await fetch(`${origin}/mcp`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list' }),
    });

    expect(response.status).toBe(401);

    const challenge = response.headers.get('www-authenticate') ?? '';
    const metadataUrl = /resource_metadata="([^"]+)"/.exec(challenge)?.[1];
    expect(metadataUrl).toBeDefined();

    // The pointer has to resolve, or a client is no better off than with a
    // bare 401.
    const metadata = await fetch(String(metadataUrl));
    expect(metadata.status).toBe(200);

    const document: unknown = await metadata.json();
    expect(document).toMatchObject({
      resource: `${origin}/mcp`,
      authorization_servers: [`${origin}/`],
    });
  });

  // Regression: this returned 400 with no WWW-Authenticate, because
  // verifyAccessToken threw InvalidGrantError. The SDK's bearer middleware
  // maps only InvalidTokenError to a 401 challenge, so a client whose token
  // had expired was told its request was malformed and had nowhere to go.
  test('a forged bearer token is refused with a challenge, not a 400', async () => {
    const response = await fetch(`${origin}/mcp`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        authorization: 'Bearer not-a-real-token',
      },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list' }),
    });

    expect(response.status).toBe(401);

    const challenge = response.headers.get('www-authenticate') ?? '';
    expect(challenge).toContain('error="invalid_token"');
    expect(challenge).toContain('resource_metadata=');
  });

  // The SDK advertises scopesSupported in metadata but does not enforce it, so
  // an unchecked authorize writes whatever the client asked for into the
  // transaction and echoes it back in the token response. Naming a scope here
  // does not obtain it from Reddit, so that would be a lie to the client, and
  // the refresh grant only narrows against the original set.
  test('a scope this server cannot deliver is refused at /authorize', async () => {
    const { clientId } = await registerClient();

    const authorize = new URL('/authorize', origin);
    authorize.searchParams.set('client_id', clientId);
    authorize.searchParams.set('redirect_uri', AGENT_CALLBACK);
    authorize.searchParams.set('response_type', 'code');
    authorize.searchParams.set('code_challenge', 'x'.repeat(43));
    authorize.searchParams.set('code_challenge_method', 'S256');
    authorize.searchParams.set('scope', 'identity submit modconfig');

    const response = await fetch(authorize, { redirect: 'manual' });

    // A 302 is correct, but only back to the client. Once client_id and
    // redirect_uri check out, OAuth 2.1 returns the error to the client rather
    // than rendering it, so the thing to assert is the destination and the
    // error code, never the bare status.
    expect(response.status).toBe(302);

    const location = new URL(String(response.headers.get('location')));
    expect(location.host).not.toBe('www.reddit.com');
    expect(`${location.origin}${location.pathname}`).toBe(AGENT_CALLBACK);
    expect(location.searchParams.get('error')).toBe('invalid_scope');

    // And it names the offending scope, so the agent can fix its request
    // instead of retrying the same one.
    expect(location.searchParams.get('error_description') ?? '').toContain(
      'submit'
    );
  });

  test('the supported scopes are the ones actually asked of Reddit', async () => {
    const { clientId } = await registerClient();

    const authorize = new URL('/authorize', origin);
    authorize.searchParams.set('client_id', clientId);
    authorize.searchParams.set('redirect_uri', AGENT_CALLBACK);
    authorize.searchParams.set('response_type', 'code');
    authorize.searchParams.set('code_challenge', 'y'.repeat(43));
    authorize.searchParams.set('code_challenge_method', 'S256');
    authorize.searchParams.set('scope', 'identity history');

    const response = await fetch(authorize, { redirect: 'manual' });
    expect(response.status).toBe(302);

    const upstream = new URL(String(response.headers.get('location')));
    expect(upstream.host).toBe('www.reddit.com');

    const metadata = await fetch(
      `${origin}/.well-known/oauth-authorization-server`
    ).then((r) => r.json() as Promise<{ scopes_supported?: string[] }>);
    for (const scope of metadata.scopes_supported ?? []) {
      expect(upstream.searchParams.get('scope')?.split(' ')).toContain(scope);
    }
  });

  test('the authorization server metadata names every endpoint it serves', async () => {
    const response = await fetch(
      `${origin}/.well-known/oauth-authorization-server`
    );
    expect(response.status).toBe(200);

    expect(await response.json()).toMatchObject({
      issuer: `${origin}/`,
      authorization_endpoint: `${origin}/authorize`,
      token_endpoint: `${origin}/token`,
      registration_endpoint: `${origin}/register`,
      revocation_endpoint: `${origin}/revoke`,
      code_challenge_methods_supported: ['S256'],
      grant_types_supported: ['authorization_code', 'refresh_token'],
    });
  });

  test('health answers without a token', async () => {
    const response = await fetch(`${origin}/health`);

    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ ok: true });
  });

  test('a GET on the MCP route is refused rather than half served', async () => {
    const response = await fetch(`${origin}/mcp`);

    expect(response.status).toBe(405);
    expect(response.headers.get('allow')).toBe('POST');
  });
});

describe('the authorization code flow', () => {
  test('a full sign-in yields a usable token pair', async () => {
    const { clientId } = await registerClient();
    const { code, verifier } = await signIn(clientId);

    const { status, payload } = await exchange(clientId, {
      grant_type: 'authorization_code',
      code,
      code_verifier: verifier,
      redirect_uri: AGENT_CALLBACK,
    });

    expect(status).toBe(200);
    expect(payload.token_type).toBe('Bearer');
    expect(typeof payload.access_token).toBe('string');
    expect(typeof payload.refresh_token).toBe('string');
    expect(payload.expires_in).toBe(8 * 3600);
  });

  test('a mismatched PKCE verifier is refused', async () => {
    const { clientId } = await registerClient();
    const { code } = await signIn(clientId);

    const { status, payload } = await exchange(clientId, {
      grant_type: 'authorization_code',
      code,
      code_verifier: randomBytes(32).toString('base64url'),
      redirect_uri: AGENT_CALLBACK,
    });

    expect(status).toBe(400);
    expect(payload.error).toBe('invalid_grant');
  });

  test('a replayed code is refused the second time', async () => {
    const { clientId } = await registerClient();
    const { code, verifier } = await signIn(clientId);
    const body = {
      grant_type: 'authorization_code',
      code,
      code_verifier: verifier,
      redirect_uri: AGENT_CALLBACK,
    };

    expect((await exchange(clientId, body)).status).toBe(200);

    const replay = await exchange(clientId, body);
    expect(replay.status).toBe(400);
    expect(replay.payload.error).toBe('invalid_grant');
  });

  test('a code redeemed against another redirect_uri is refused', async () => {
    const { clientId } = await registerClient();
    const { code, verifier } = await signIn(clientId);

    const { status, payload } = await exchange(clientId, {
      grant_type: 'authorization_code',
      code,
      code_verifier: verifier,
      redirect_uri: 'http://127.0.0.1:9999/somewhere-else',
    });

    expect(status).toBe(400);
    expect(payload.error).toBe('invalid_grant');
  });

  test('a replayed Reddit callback cannot mint a second code', async () => {
    const { clientId } = await registerClient();

    const verifier = randomBytes(32).toString('base64url');
    const challenge = createHash('sha256').update(verifier).digest('base64url');
    const authorize = new URL('/authorize', origin);
    authorize.searchParams.set('client_id', clientId);
    authorize.searchParams.set('redirect_uri', AGENT_CALLBACK);
    authorize.searchParams.set('response_type', 'code');
    authorize.searchParams.set('code_challenge', challenge);
    authorize.searchParams.set('code_challenge_method', 'S256');

    const redirected = await fetch(authorize, { redirect: 'manual' });
    const transaction =
      new URL(redirected.headers.get('location') ?? '').searchParams.get(
        'state'
      ) ?? '';

    const callback = new URL('/callback/reddit', origin);
    callback.searchParams.set('state', transaction);
    callback.searchParams.set('code', 'reddit-code');

    expect((await fetch(callback, { redirect: 'manual' })).status).toBe(302);

    const replayed = await fetch(callback, { redirect: 'manual' });
    expect(replayed.status).toBe(400);
  });
});

describe('the refresh grant', () => {
  test('rotates the refresh token and refuses the spent one', async () => {
    const { clientId } = await registerClient();
    const { code, verifier } = await signIn(clientId);

    const first = await exchange(clientId, {
      grant_type: 'authorization_code',
      code,
      code_verifier: verifier,
      redirect_uri: AGENT_CALLBACK,
    });
    const refreshToken = String(first.payload.refresh_token);

    const refreshed = await exchange(clientId, {
      grant_type: 'refresh_token',
      refresh_token: refreshToken,
    });
    expect(refreshed.status).toBe(200);
    expect(refreshed.payload.refresh_token).not.toBe(refreshToken);

    const reused = await exchange(clientId, {
      grant_type: 'refresh_token',
      refresh_token: refreshToken,
    });
    expect(reused.status).toBe(400);
    expect(reused.payload.error).toBe('invalid_grant');
  });
});
