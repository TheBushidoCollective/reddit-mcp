/**
 * Per-request Reddit clients for the hosted, multi-tenant server.
 *
 * The stdio path resolves one credential set from the environment at startup
 * and reuses a single client for the whole process. The hosted path cannot do
 * that: every request belongs to a different Reddit account, so the client has
 * to be built from that request's session and discarded with it.
 *
 * Nothing in this file reads process.env, and that is the point. The server's
 * own REDDIT_CLIENT_ID and REDDIT_CLIENT_SECRET are ambient in the container,
 * so any environment read here would be a path by which one caller's request
 * could be served under credentials that are not theirs. Every value arrives
 * in the argument.
 */

import type { RedditCredentials } from './auth.js';
import { RedditClient } from './client.js';

/** One end user's Reddit grant, plus the app credentials it was issued under. */
export interface RedditSession {
  clientId: string;
  clientSecret: string;
  /** The end user's Reddit refresh token, not the service's. */
  refreshToken: string;
  userAgent: string;
}

/**
 * Builds a user scoped client for one signed in caller.
 *
 * The missing-grant check is not defensive noise. Sessions arrive from
 * Firestore, where a truncated or half-written record can carry a blank
 * refresh token, and TokenProvider answers a blank grant by falling through to
 * client_credentials. That would hand the caller a client still labelled
 * 'user', still pointed at the OAuth host, quietly holding an app-only token
 * and returning data belonging to nobody. Failing here makes a corrupt session
 * read like the bug it is instead of like an empty account.
 */
export function clientForSession(session: RedditSession): RedditClient {
  if (!session.clientId || !session.refreshToken) {
    throw new Error(
      'Reddit session is missing its client id or refresh token. ' +
        'The caller has to sign in again.'
    );
  }

  // Copied field by field rather than spread. A session widened on its way out
  // of storage must not be able to smuggle in a username and password pair and
  // turn this into a password grant behind the caller's back.
  const credentials: RedditCredentials = {
    clientId: session.clientId,
    clientSecret: session.clientSecret,
    refreshToken: session.refreshToken,
    userAgent: session.userAgent,
  };

  return new RedditClient(credentials, 'user');
}

/**
 * Builds a client for a caller who has not signed in.
 *
 * Anonymous mode reaches public data only, and carries no credentials at all,
 * so an unauthenticated request can never be served under the service's own
 * Reddit app identity.
 */
export function anonymousClient(userAgent: string): RedditClient {
  return new RedditClient({ userAgent }, 'anonymous');
}
