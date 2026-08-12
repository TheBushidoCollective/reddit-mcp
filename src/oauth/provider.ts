/**
 * The authorization server.
 *
 * This implements the SDK's `OAuthServerProvider` directly rather than
 * building on `ProxyOAuthServerProvider`, and the choice is not stylistic. A
 * proxy forwards the agent's code to the upstream token endpoint and hands
 * back whatever comes out, with `skipLocalPkceValidation` on because the
 * upstream is doing the checking. Reddit does neither thing this needs: it has
 * no dynamic client registration for the agent to use and no PKCE for it to
 * validate. It also cannot be handed our client's code, because that code was
 * minted here and means nothing to Reddit.
 *
 * We are an authorization server whose idea of "who are you" happens to be a
 * Reddit account. The agent gets tokens this server minted and can reason
 * about; the Reddit refresh token stays server side and never crosses the
 * agent boundary. That is a bridge, not a proxy.
 *
 * Registration is open at /register, and that is correct rather than an
 * oversight: it is how an agent gets credentials at all, and holding a client
 * id proves nothing. The gate is the Reddit sign-in further down, which no
 * registration can skip.
 */

import { randomBytes } from 'node:crypto';
import type { OAuthRegisteredClientsStore } from '@modelcontextprotocol/sdk/server/auth/clients.js';
import {
  InvalidGrantError,
  InvalidRequestError,
  InvalidTokenError,
  ServerError,
} from '@modelcontextprotocol/sdk/server/auth/errors.js';
import type {
  AuthorizationParams,
  OAuthServerProvider,
} from '@modelcontextprotocol/sdk/server/auth/provider.js';
import type { AuthInfo } from '@modelcontextprotocol/sdk/server/auth/types.js';
import {
  type OAuthClientInformationFull,
  OAuthClientInformationFullSchema,
  type OAuthTokenRevocationRequest,
  type OAuthTokens,
} from '@modelcontextprotocol/sdk/shared/auth.js';
import type { Response } from 'express';

import {
  type CodeRejection,
  consumeAuthorizationCode,
  readAuthorizationCode,
} from './codes.js';
import {
  REDDIT_SCOPES,
  type RedditGrant,
  startRedditSignIn,
} from './reddit-grant.js';
import type { OAuthStores, TokenRecord } from './stores.js';

/**
 * A person has ten minutes to get through Reddit's consent page, an agent has
 * thirty seconds to trade a code it was just handed, and an access token lasts
 * a working day. The refresh token is the long-lived one, because that is the
 * thing designed to be.
 */
export const TRANSACTION_TTL = 600;
export const ACCESS_TTL = 8 * 3600;
export const REFRESH_TTL = 30 * 24 * 3600;

/** The scopes this server issues, which mirror what it asks Reddit for. */
export const SUPPORTED_SCOPES: string[] = [...REDDIT_SCOPES];

/**
 * Every rejection an agent can provoke says the same thing to the agent and a
 * different thing to us. The distinctions matter in a log, not in a response:
 * telling a caller that its code was well formed but replayed confirms it
 * guessed a real one.
 */
const GRANT_REFUSED: Record<CodeRejection, string> = {
  malformed: 'The authorization code is invalid or has expired.',
  expired: 'The authorization code is invalid or has expired.',
  wrong_client: 'The authorization code is invalid or has expired.',
  missing_redirect_uri:
    'The token request must include the redirect_uri the code was issued for.',
  wrong_redirect_uri: 'The authorization code is invalid or has expired.',
  replayed: 'The authorization code is invalid or has expired.',
};

export interface ProviderConfig {
  stores: OAuthStores;
  sealingKey: Buffer;
  /** Owns the public origin, so the provider never needs to know it. */
  grant: RedditGrant;
}

export class RedditBridgeProvider implements OAuthServerProvider {
  private readonly stores: OAuthStores;
  private readonly sealingKey: Buffer;

  readonly grant: RedditGrant;

  constructor(config: ProviderConfig) {
    this.stores = config.stores;
    this.sealingKey = config.sealingKey;
    this.grant = config.grant;
  }

  get clientsStore(): OAuthRegisteredClientsStore {
    return {
      getClient: (clientId) => this.stores.getClient(clientId),
      registerClient: async (client) => {
        // The SDK generates the client id and hands it over in this object,
        // but types the parameter without it. Parsing is how that promise gets
        // checked instead of assumed: if a future SDK stops filling it in, a
        // registration fails loudly here rather than storing a client nothing
        // can ever look up.
        const registered = OAuthClientInformationFullSchema.parse(client);
        await this.stores.putClient(registered);
        return registered;
      },
    };
  }

  /**
   * Parks the request and sends the human to Reddit.
   *
   * The redirect is issued here rather than returned as a URL because that is
   * the shape the SDK's authorize handler expects: this method owns the
   * response from this point on.
   */
  async authorize(
    client: OAuthClientInformationFull,
    params: AuthorizationParams,
    res: Response
  ): Promise<void> {
    const destination = await startRedditSignIn(
      this.grant,
      this.stores,
      {
        clientId: client.client_id,
        redirectUri: params.redirectUri,
        state: params.state,
        codeChallenge: params.codeChallenge,
        scopes: params.scopes?.length ? params.scopes : SUPPORTED_SCOPES,
        resource: params.resource?.href,
      },
      TRANSACTION_TTL
    );
    res.redirect(302, destination);
  }

  /**
   * Returns the PKCE challenge the flow started with.
   *
   * The SDK calls this before `exchangeAuthorizationCode` and validates the
   * verifier against what comes back, so this must not consume anything and
   * must not judge the redirect binding: the client's submitted redirect_uri
   * is not in hand here, and the exchange is where it is checked.
   */
  async challengeForAuthorizationCode(
    client: OAuthClientInformationFull,
    authorizationCode: string
  ): Promise<string> {
    const result = readAuthorizationCode(this.sealingKey, authorizationCode, {
      clientId: client.client_id,
    });
    if ('rejected' in result) {
      throw new InvalidGrantError(GRANT_REFUSED[result.rejected]);
    }
    return result.payload.codeChallenge;
  }

  /** Spends the code and issues the first pair of tokens. */
  async exchangeAuthorizationCode(
    client: OAuthClientInformationFull,
    authorizationCode: string,
    _codeVerifier?: string,
    redirectUri?: string,
    resource?: URL
  ): Promise<OAuthTokens> {
    const result = await consumeAuthorizationCode(
      this.sealingKey,
      this.stores,
      authorizationCode,
      { clientId: client.client_id, redirectUri }
    );

    if ('rejected' in result) {
      if (result.rejected === 'missing_redirect_uri') {
        throw new InvalidRequestError(GRANT_REFUSED[result.rejected]);
      }
      throw new InvalidGrantError(GRANT_REFUSED[result.rejected]);
    }

    const { payload } = result;

    // RFC 8707: a resource named at the exchange must be the one the code was
    // issued for. Silently retargeting a token is how a token minted for one
    // resource server ends up accepted by another.
    if (resource && payload.resource && resource.href !== payload.resource) {
      throw new InvalidGrantError(
        'The requested resource does not match the authorization.'
      );
    }

    return this.issue({
      clientId: client.client_id,
      userId: payload.userId,
      scopes: payload.scopes,
      resource: payload.resource ?? resource?.href,
    });
  }

  /** Rotates a refresh token, keeping the Reddit grant it points at. */
  async exchangeRefreshToken(
    client: OAuthClientInformationFull,
    refreshToken: string,
    scopes?: string[],
    resource?: URL
  ): Promise<OAuthTokens> {
    // Taken, not read, and taken only if it belongs to this client: the old
    // token dies in the same step that reads it, so two concurrent refreshes
    // cannot both mint a live family, and a client it was not issued to
    // cannot destroy it on its way to being refused.
    const record = await this.stores.takeRefreshToken(
      refreshToken,
      client.client_id
    );
    if (!record) {
      throw new InvalidGrantError(
        'The refresh token is invalid or has expired.'
      );
    }
    if (record.expiresAt <= Math.floor(Date.now() / 1000)) {
      throw new InvalidGrantError(
        'The refresh token is invalid or has expired.'
      );
    }

    // A refresh may narrow scope but never widen it, which is the only reason
    // the parameter exists.
    const requested = scopes?.length ? scopes : record.scopes;
    const granted = requested.filter((scope) => record.scopes.includes(scope));
    if (granted.length !== requested.length) {
      throw new InvalidGrantError(
        'The refresh token cannot grant scopes beyond the original authorization.'
      );
    }

    return this.issue({
      clientId: client.client_id,
      userId: record.userId,
      scopes: granted,
      resource: record.resource ?? resource?.href,
    });
  }

  /**
   * Resolves a bearer token.
   *
   * `extra.userId` is what makes the request answerable: it names the Reddit
   * grant this token acts under, which the MCP route loads to build a client.
   */
  async verifyAccessToken(token: string): Promise<AuthInfo> {
    const record = await this.stores.getAccessToken(token);
    if (!record) {
      // InvalidTokenError, not InvalidGrantError: the SDK's bearer middleware
      // maps only this class to a 401 carrying WWW-Authenticate, and every
      // other OAuthError to a bare 400. A client holding an expired token
      // needs that header to learn it should sign in again, so the wrong
      // class here reads to the agent as a malformed request it cannot fix.
      throw new InvalidTokenError(
        'The access token is invalid or has expired.'
      );
    }

    return {
      token,
      clientId: record.clientId,
      scopes: record.scopes,
      expiresAt: record.expiresAt,
      resource: record.resource ? new URL(record.resource) : undefined,
      extra: { userId: record.userId },
    };
  }

  /**
   * Drops a token belonging to the calling client.
   *
   * Deliberately says nothing about whether it existed or was theirs, per RFC
   * 7009, and deliberately does not revoke the Reddit grant behind it: signing
   * one agent out must not sign every other one out too. Reddit's own app
   * settings are where a person ends the whole thing.
   */
  async revokeToken(
    client: OAuthClientInformationFull,
    request: OAuthTokenRevocationRequest
  ): Promise<void> {
    await this.stores.revoke(request.token, client.client_id);
  }

  private async issue(grant: {
    clientId: string;
    userId: string;
    scopes: string[];
    resource?: string;
  }): Promise<OAuthTokens> {
    const accessToken = randomBytes(32).toString('base64url');
    const refreshToken = randomBytes(32).toString('base64url');
    const issuedAt = Math.floor(Date.now() / 1000);

    const record: Omit<TokenRecord, 'expiresAt'> = {
      clientId: grant.clientId,
      userId: grant.userId,
      scopes: grant.scopes,
      resource: grant.resource,
    };

    try {
      await this.stores.putAccessToken(
        accessToken,
        { ...record, expiresAt: issuedAt + ACCESS_TTL },
        ACCESS_TTL
      );
      await this.stores.putRefreshToken(
        refreshToken,
        { ...record, expiresAt: issuedAt + REFRESH_TTL },
        REFRESH_TTL
      );
    } catch {
      // The agent is about to be handed tokens the database does not know
      // about, which would fail later as an expired session for no visible
      // reason. Better a failed exchange it can retry.
      throw new ServerError('Could not persist the issued tokens.');
    }

    return {
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in: ACCESS_TTL,
      refresh_token: refreshToken,
      scope: grant.scopes.join(' '),
    };
  }
}
