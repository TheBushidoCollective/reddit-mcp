/**
 * The bridge between our authorization server and Reddit's.
 *
 * The human proves who they are on Reddit's own authorize page, which is the
 * whole reason this service has no login form. We never see a Reddit password,
 * so there is nothing here to leak, phish, or store by mistake, and a person
 * can revoke us from their Reddit app settings without asking us first.
 *
 * What comes back is a durable grant. `duration=permanent` is what makes the
 * refresh token appear at all, and the refresh token is what lets a stateless
 * request an hour later still act as that person.
 */

import { randomBytes } from 'node:crypto';

import { issueAuthorizationCode } from './codes.js';
import type { OAuthStores } from './stores.js';

const AUTHORIZE_URL = 'https://www.reddit.com/api/v1/authorize';
const TOKEN_URL = 'https://www.reddit.com/api/v1/access_token';
const IDENTITY_URL = 'https://oauth.reddit.com/api/v1/me';

/**
 * What the tools need, and nothing beyond it. `read` and `mysubreddits` cover
 * the public surface, `identity` names the account, `history` reaches their
 * own posts and comments, `privatemessages` reaches their inbox. No `submit`,
 * no `edit`, no `vote`: this server does not write to Reddit.
 */
export const REDDIT_SCOPES = [
  'identity',
  'history',
  'read',
  'mysubreddits',
  'privatemessages',
] as const;

export interface RedditGrantConfig {
  /** Public origin of this service, without a trailing slash. */
  publicUrl: string;
  clientId: string;
  clientSecret: string;
  userAgent: string;
  /** Swappable so the callback can be tested without reaching Reddit. */
  fetchImpl?: typeof fetch;
}

export interface RedditTokens {
  accessToken: string;
  refreshToken: string;
}

/**
 * Raised for anything Reddit refuses. The message is written for a person
 * reading a redirect, and never carries an upstream response body: a failed
 * token exchange echoes back the grant that was submitted.
 */
export class RedditGrantError extends Error {}

export class RedditGrant {
  private readonly fetchImpl: typeof fetch;

  constructor(private readonly config: RedditGrantConfig) {
    this.fetchImpl = config.fetchImpl ?? fetch;
  }

  /**
   * Where Reddit sends the person back. Registered in the Reddit app settings
   * and sent again on both legs, because Reddit compares them.
   */
  get redirectUri(): string {
    return `${this.config.publicUrl}/callback/reddit`;
  }

  /** The page the human is sent to. `state` is the id of a parked request. */
  authorizeUrl(state: string): string {
    const query = new URLSearchParams({
      client_id: this.config.clientId,
      response_type: 'code',
      state,
      redirect_uri: this.redirectUri,
      duration: 'permanent',
      scope: REDDIT_SCOPES.join(' '),
    });
    return `${AUTHORIZE_URL}?${query.toString()}`;
  }

  /** Trades Reddit's code for the durable grant behind it. */
  async exchangeCode(code: string): Promise<RedditTokens> {
    const body = new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      redirect_uri: this.redirectUri,
    });

    const response = await this.fetchImpl(TOKEN_URL, {
      method: 'POST',
      headers: {
        Authorization: `Basic ${this.basicAuth()}`,
        'Content-Type': 'application/x-www-form-urlencoded',
        'User-Agent': this.config.userAgent,
      },
      body: body.toString(),
    });

    if (!response.ok) {
      throw new RedditGrantError(
        `Reddit refused the authorization code (HTTP ${response.status})`
      );
    }

    const payload: unknown = await response.json();
    if (!payload || typeof payload !== 'object') {
      throw new RedditGrantError(
        'Reddit returned an unreadable token response'
      );
    }

    const accessToken =
      'access_token' in payload && typeof payload.access_token === 'string'
        ? payload.access_token
        : null;
    const refreshToken =
      'refresh_token' in payload && typeof payload.refresh_token === 'string'
        ? payload.refresh_token
        : null;

    if (!accessToken) {
      throw new RedditGrantError('Reddit returned no access token');
    }
    if (!refreshToken) {
      // Only a permanent grant carries one, and this server asks for nothing
      // else. Without it every later request would be unauthenticated, which
      // is a worse thing to discover during a tool call than during sign-in.
      throw new RedditGrantError(
        'Reddit returned a temporary grant, which cannot be used after sign-in'
      );
    }

    return { accessToken, refreshToken };
  }

  /** Reads the signed in username, which is how a grant is filed. */
  async identity(accessToken: string): Promise<string> {
    const response = await this.fetchImpl(IDENTITY_URL, {
      headers: {
        Authorization: `Bearer ${accessToken}`,
        'User-Agent': this.config.userAgent,
        Accept: 'application/json',
      },
    });

    if (!response.ok) {
      throw new RedditGrantError(
        `Reddit refused the identity request (HTTP ${response.status})`
      );
    }

    const payload: unknown = await response.json();
    const name =
      payload && typeof payload === 'object' && 'name' in payload
        ? payload.name
        : null;
    if (typeof name !== 'string' || !name) {
      throw new RedditGrantError(
        'Reddit did not return the signed in username'
      );
    }
    return name;
  }

  private basicAuth(): string {
    return Buffer.from(
      `${this.config.clientId}:${this.config.clientSecret}`
    ).toString('base64');
  }
}

/**
 * Parks an authorization request and returns where to send the human.
 *
 * The transaction, not the browser, carries what was asked for. A redirect URI
 * or a PKCE challenge that survives a round trip through a query string is one
 * an attacker can rewrite on the way past.
 */
export async function startRedditSignIn(
  grant: RedditGrant,
  stores: OAuthStores,
  request: {
    clientId: string;
    redirectUri: string;
    state?: string;
    codeChallenge: string;
    scopes: string[];
    resource?: string;
  },
  transactionTtl: number
): Promise<string> {
  const transaction = randomBytes(32).toString('base64url');
  await stores.putTransaction(
    transaction,
    { ...request, createdAt: Math.floor(Date.now() / 1000) },
    transactionTtl
  );
  return grant.authorizeUrl(transaction);
}

export type CallbackResult =
  | { redirectTo: string }
  | { failed: string; status: number };

/**
 * Completes a sign-in: validates the state, takes the grant, files it, and
 * mints our own code for the agent that started this.
 *
 * The failure cases split by who can act on them. A bad or expired `state` has
 * no trustworthy redirect target, so it is answered in the browser. Everything
 * after that has a claimed request behind it, so the agent hears about it as
 * an OAuth error on its own callback, which is where it is listening.
 */
export async function completeRedditSignIn(
  grant: RedditGrant,
  stores: OAuthStores,
  sealingKey: Buffer,
  query: { state?: string; code?: string; error?: string }
): Promise<CallbackResult> {
  if (!query.state) {
    return { failed: 'This sign-in link is missing its state.', status: 400 };
  }

  // Taking the transaction is what makes the callback single use: a replayed
  // callback URL finds nothing parked and cannot mint a second code against
  // the same consent.
  const parked = await stores.takeTransaction(query.state);
  if (!parked) {
    return {
      failed:
        'This sign-in link has expired. Start the connection again from your client.',
      status: 400,
    };
  }

  if (query.error) {
    // Reddit's own error code is a fixed vocabulary, not a response body, so
    // passing it on tells the agent why without echoing anything upstream sent.
    return {
      redirectTo: errorRedirect(parked.redirectUri, parked.state, {
        error:
          query.error === 'access_denied' ? 'access_denied' : 'invalid_request',
        description: 'Reddit did not grant access.',
      }),
    };
  }

  if (!query.code) {
    return {
      redirectTo: errorRedirect(parked.redirectUri, parked.state, {
        error: 'invalid_request',
        description: 'Reddit returned no authorization code.',
      }),
    };
  }

  let username: string;
  let refreshToken: string;
  try {
    const tokens = await grant.exchangeCode(query.code);
    username = await grant.identity(tokens.accessToken);
    refreshToken = tokens.refreshToken;
  } catch (error) {
    const description =
      error instanceof RedditGrantError
        ? error.message
        : 'Reddit could not be reached.';
    return {
      redirectTo: errorRedirect(parked.redirectUri, parked.state, {
        error: 'access_denied',
        description,
      }),
    };
  }

  const userId = await stores.putRedditGrant(username, refreshToken);

  const code = issueAuthorizationCode(sealingKey, {
    clientId: parked.clientId,
    userId,
    scopes: parked.scopes,
    codeChallenge: parked.codeChallenge,
    redirectUri: parked.redirectUri,
    resource: parked.resource,
  });

  const target = new URL(parked.redirectUri);
  target.searchParams.set('code', code);
  if (parked.state) target.searchParams.set('state', parked.state);
  return { redirectTo: target.href };
}

function errorRedirect(
  redirectUri: string,
  state: string | undefined,
  failure: { error: string; description: string }
): string {
  const target = new URL(redirectUri);
  target.searchParams.set('error', failure.error);
  target.searchParams.set('error_description', failure.description);
  if (state) target.searchParams.set('state', state);
  return target.href;
}
