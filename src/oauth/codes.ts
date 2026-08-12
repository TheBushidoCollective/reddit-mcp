/**
 * Authorization codes.
 *
 * Two decisions here differ from the obvious implementation, and both are
 * about what a code is rather than how it is stored.
 *
 * A code is sealed, not signed. It travels as a query parameter through a
 * browser, which means it lands in history, in a referrer, and in every proxy
 * log on the way. A signed payload is unforgeable and still perfectly
 * readable, and this payload names the Reddit account the exchange will bind
 * to. Sealed, it is an opaque string to everyone but this server.
 *
 * A code is single use, and the check is a write that fails rather than a read
 * that finds nothing. Two exchanges racing on the same code both pass a "is it
 * in the spent list" read; only one of them wins a create.
 *
 * The payload rides inside the code rather than in the database. The only
 * thing Firestore holds is the spent marker, so an unredeemed code costs
 * nothing and the ledger stays a list of opaque ids.
 */

import { randomBytes } from 'node:crypto';

import { open, seal } from './sealing.js';
import type { OAuthStores } from './stores.js';

/** Additional authenticated data binding a sealed blob to this one use. */
const CODE_PURPOSE = 'authorization_code';

/**
 * An agent has thirty seconds to trade a code it was just handed. It was
 * redirected straight to its own callback holding it, so anything slower is
 * not the agent.
 */
export const CODE_TTL = 30;

export interface AuthorizationCodePayload {
  /** Single-use id, and the key of the spent marker in Firestore. */
  jti: string;
  clientId: string;
  /** Which Reddit grant this code resolves to once exchanged. */
  userId: string;
  scopes: string[];
  codeChallenge: string;
  /** Bound at issue and checked at exchange, per OAuth 2.1. */
  redirectUri: string;
  /** Seconds since epoch. */
  expiresAt: number;
  resource?: string;
}

export type CodeRejection =
  | 'malformed'
  | 'expired'
  | 'wrong_client'
  | 'missing_redirect_uri'
  | 'wrong_redirect_uri'
  | 'replayed';

/** Mints a sealed code for a completed sign-in. */
export function issueAuthorizationCode(
  sealingKey: Buffer,
  payload: Omit<AuthorizationCodePayload, 'jti' | 'expiresAt'>
): string {
  const full: AuthorizationCodePayload = {
    ...payload,
    jti: randomBytes(24).toString('base64url'),
    expiresAt: Math.floor(Date.now() / 1000) + CODE_TTL,
  };
  return seal(sealingKey, CODE_PURPOSE, full);
}

/**
 * Opens a code and checks what is intrinsic to it: that this key sealed it,
 * that it has not expired, and that it belongs to this client.
 *
 * Deliberately does not touch the redirect binding or the spent ledger. The
 * SDK's token handler calls this first, to look up the PKCE challenge, and
 * again through the exchange below. Burning the code on the first call would
 * spend it during the only flow that ever succeeds, and every exchange would
 * fail as a replay of itself.
 */
export function readAuthorizationCode(
  sealingKey: Buffer,
  code: string,
  expected: { clientId: string }
): { payload: AuthorizationCodePayload } | { rejected: CodeRejection } {
  const payload = open<AuthorizationCodePayload>(
    sealingKey,
    CODE_PURPOSE,
    code
  );
  if (!payload || typeof payload.jti !== 'string') {
    return { rejected: 'malformed' };
  }
  if (payload.expiresAt <= Math.floor(Date.now() / 1000)) {
    return { rejected: 'expired' };
  }
  if (payload.clientId !== expected.clientId) {
    return { rejected: 'wrong_client' };
  }
  return { payload };
}

/**
 * Opens a code, checks its redirect binding, and spends it. Call this once, in
 * the token exchange, and only when a token is about to be issued.
 */
export async function consumeAuthorizationCode(
  sealingKey: Buffer,
  stores: OAuthStores,
  code: string,
  expected: { clientId: string; redirectUri?: string }
): Promise<
  { payload: AuthorizationCodePayload } | { rejected: CodeRejection }
> {
  const result = readAuthorizationCode(sealingKey, code, expected);
  if ('rejected' in result) return result;

  // Demanded rather than compared only when offered. OAuth 2.1 requires
  // redirect_uri in both the authorization request and the exchange, and the
  // SDK's schema marks it optional to stay compatible with 2.0. Treating an
  // absent value as "nothing to compare" would turn the binding this code
  // carries into a check any client can skip by omitting a field.
  if (expected.redirectUri === undefined) {
    return { rejected: 'missing_redirect_uri' };
  }
  if (expected.redirectUri !== result.payload.redirectUri) {
    return { rejected: 'wrong_redirect_uri' };
  }

  // The marker outlives the code by its own TTL, so a replay arriving after
  // the code would have expired anyway still meets a refusal rather than an
  // empty ledger.
  const won = await stores.spendCode(result.payload.jti, CODE_TTL);
  if (!won) return { rejected: 'replayed' };

  return result;
}
