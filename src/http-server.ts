/**
 * The hosted server: an OAuth 2.1 authorization server and an MCP endpoint
 * behind it, in one express app.
 *
 * `POST /mcp` is stateless. This runs on Cloud Run and scales to zero, so the
 * default streamable-HTTP mode is wrong here: it keeps the session in the
 * instance's memory and hands the client a session id to send back, and the
 * instance holding it is gone by the next question. The client then gets
 * "session not found" instead of an answer. Stateless costs server-initiated
 * notifications, which none of these tools send.
 *
 * A fresh McpServer per request follows from that, and from multi-tenancy: two
 * requests in flight belong to two different Reddit accounts, and a server
 * built once at startup would have to hold one of them.
 */

import { requireBearerAuth } from '@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js';
import {
  getOAuthProtectedResourceMetadataUrl,
  mcpAuthRouter,
} from '@modelcontextprotocol/sdk/server/auth/router.js';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import express, { type Express, type Request, type Response } from 'express';

import { RedditBridgeProvider, SUPPORTED_SCOPES } from './oauth/provider.js';
import { completeRedditSignIn, RedditGrant } from './oauth/reddit-grant.js';
import type { OAuthStores } from './oauth/stores.js';
import { clientForSession, type RedditSession } from './reddit/session.js';
import { registerTools } from './reddit/tools.js';

export const VERSION = '2.0.0';

const DEFAULT_USER_AGENT = `reddit-mcp/${VERSION} (+https://github.com/thebushidocollective/reddit-mcp)`;

export interface HttpServerConfig {
  /** Public origin of this service. A trailing slash is trimmed. */
  publicUrl: string;
  redditClientId: string;
  redditClientSecret: string;
  /** The only Reddit username allowed to finish hosted sign-in. */
  redditAllowedUsername: string | undefined;
  sealingKey: Buffer;
  stores: OAuthStores;
  userAgent?: string;
  /** Swappable so the sign-in flow can be exercised without reaching Reddit. */
  fetchImpl?: typeof fetch;
}

export function createHttpServer(config: HttpServerConfig): Express {
  const publicUrl = config.publicUrl.replace(/\/+$/, '');
  const userAgent = config.userAgent ?? DEFAULT_USER_AGENT;

  const grant = new RedditGrant({
    publicUrl,
    clientId: config.redditClientId,
    clientSecret: config.redditClientSecret,
    allowedUsername: config.redditAllowedUsername,
    userAgent,
    fetchImpl: config.fetchImpl,
  });

  const provider = new RedditBridgeProvider({
    stores: config.stores,
    sealingKey: config.sealingKey,
    grant,
  });

  const app = express();

  // Cloud Run terminates TLS and adds exactly one hop, so the real caller is
  // the first entry in X-Forwarded-For. The SDK's auth router rate limits by
  // client address and would otherwise count every request against the proxy.
  app.set('trust proxy', 1);

  // Before the auth router, and unauthenticated: the startup probe has no
  // token and would fail closed behind one. It deliberately says nothing about
  // Reddit or about whose account this holds, because an endpoint that reports
  // whether a grant is live is a free oracle for anyone scanning Cloud Run
  // hostnames.
  app.get('/health', (_request, response) => {
    response.status(200).json({ ok: true });
  });

  // Mounts /authorize, /token, /register, /revoke, and both metadata
  // documents. The resource server is the MCP route rather than the origin, so
  // the protected-resource metadata lands at the path a client derives from
  // the endpoint it was actually refused at.
  const resourceServerUrl = new URL('/mcp', publicUrl);
  app.use(
    mcpAuthRouter({
      provider,
      issuerUrl: new URL(publicUrl),
      baseUrl: new URL(publicUrl),
      resourceServerUrl,
      resourceName: 'Reddit MCP',
      scopesSupported: SUPPORTED_SCOPES,
    })
  );

  app.get('/callback/reddit', async (request, response) => {
    const query = {
      state: stringParam(request, 'state'),
      code: stringParam(request, 'code'),
      error: stringParam(request, 'error'),
    };

    const result = await completeRedditSignIn(
      grant,
      config.stores,
      config.sealingKey,
      query
    );

    // A callback carries an authorization code in its query string, so it must
    // not be cached, framed, or leak its URL onward as a referrer.
    response.set({
      'Cache-Control': 'no-store',
      'X-Frame-Options': 'DENY',
      'Referrer-Policy': 'no-referrer',
    });

    if ('failed' in result) {
      response.status(result.status).type('text/plain').send(result.failed);
      return;
    }
    response.redirect(302, result.redirectTo);
  });

  const resourceMetadataUrl =
    getOAuthProtectedResourceMetadataUrl(resourceServerUrl);

  app.post(
    '/mcp',
    express.json(),
    // A bare 401 leaves a client with nowhere to go. Naming the resource
    // metadata document in WWW-Authenticate is how it discovers this server's
    // authorization endpoints and starts the sign-in on its own.
    requireBearerAuth({ verifier: provider, resourceMetadataUrl }),
    async (request, response) => {
      await serveMcpRequest(request, response, config, userAgent, {
        resourceMetadataUrl,
      });
    }
  );

  // Only POST is served, so a client probing for the GET event stream or
  // sending a DELETE to end a session gets a straight answer rather than the
  // default HTML 404. Both belong to the stateful mode this server does not run.
  app.all('/mcp', (_request, response) => {
    response
      .status(405)
      .set('Allow', 'POST')
      .json({
        jsonrpc: '2.0',
        error: {
          code: -32000,
          message: 'This server is stateless; use POST /mcp.',
        },
        id: null,
      });
  });

  return app;
}

/**
 * Serves one MCP request as one Reddit user.
 *
 * The bearer named a grant; this loads it, builds a client around it, and
 * throws the whole assembly away when the response closes. Nothing about the
 * user survives the request, which is what makes two concurrent callers safe.
 */
async function serveMcpRequest(
  request: Request,
  response: Response,
  config: HttpServerConfig,
  userAgent: string,
  discovery: { resourceMetadataUrl: string }
): Promise<void> {
  const userId = readUserId(request.auth?.extra);
  const session = userId ? await config.stores.getRedditGrant(userId) : null;

  if (!session) {
    // The token verified, so this is not a bad credential: the Reddit grant
    // behind it is gone, revoked upstream or sealed with a key this process no
    // longer has. Either way the repair is signing in again, so answer the way
    // a missing token is answered and point at discovery.
    response
      .status(401)
      .set(
        'WWW-Authenticate',
        `Bearer error="invalid_token", error_description="The Reddit authorization behind this token is no longer available", resource_metadata="${discovery.resourceMetadataUrl}"`
      )
      .json({
        error: 'invalid_token',
        error_description:
          'The Reddit authorization behind this token is no longer available. Sign in again.',
      });
    return;
  }

  const client = buildRedditClient({
    clientId: config.redditClientId,
    clientSecret: config.redditClientSecret,
    refreshToken: session.refreshToken,
    userAgent,
  });

  if (!client) {
    // clientForSession refuses a blank id or refresh token rather than quietly
    // degrading to app-only access behind a client still labelled user scoped.
    // A stored grant that cannot build a client is a re-auth, not a 500.
    response
      .status(401)
      .set(
        'WWW-Authenticate',
        `Bearer error="invalid_token", error_description="The stored Reddit authorization is unusable", resource_metadata="${discovery.resourceMetadataUrl}"`
      )
      .json({
        error: 'invalid_token',
        error_description:
          'The stored Reddit authorization is unusable. Sign in again.',
      });
    return;
  }

  const server = new McpServer({ name: 'reddit', version: VERSION });
  registerTools(server, client);

  const transport = new StreamableHTTPServerTransport({
    sessionIdGenerator: undefined,
  });

  // Both ends are per request, so both are closed with it. Without this the
  // transport outlives the response and the instance leaks one per call.
  response.on('close', () => {
    void transport.close();
    void server.close();
  });

  await server.connect(transport);
  await transport.handleRequest(request, response, request.body);
}

/**
 * Builds a user scoped Reddit client, or null when the stored grant cannot
 * support one. Kept apart from the request flow so the refusal is caught here
 * and a transport fault further down is not mistaken for a bad credential.
 */
function buildRedditClient(session: RedditSession) {
  try {
    return clientForSession(session);
  } catch {
    return null;
  }
}

/** Express gives `unknown` for repeated or nested query parameters. */
function stringParam(request: Request, name: string): string | undefined {
  const value: unknown = request.query[name];
  return typeof value === 'string' ? value : undefined;
}

/** Reads the grant id the provider attached when it verified the bearer. */
function readUserId(extra: Record<string, unknown> | undefined): string | null {
  const value = extra?.userId;
  return typeof value === 'string' && value ? value : null;
}
