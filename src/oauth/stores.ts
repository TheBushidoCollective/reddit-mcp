/**
 * Durable state for the authorization server.
 *
 * This runs on a service that scales to zero, so nothing an OAuth flow depends
 * on can live in a process. A cold start in the middle of a sign-in would
 * otherwise forget the client registration and send the person back through
 * consent to answer the same question again.
 *
 * Two storage rules, and they differ on purpose:
 *
 * Tokens this server issues are keyed by SHA-256 of themselves and the
 * cleartext is never written. A leaked database read then yields a list of
 * fingerprints rather than a set of working credentials.
 *
 * The user's Reddit refresh token cannot be fingerprinted, because every later
 * request has to replay it upstream. It is sealed with the session-secret key
 * instead, which lives in Secret Manager rather than in Firestore, so reading
 * the database is still not enough to act as anybody.
 */

import { Firestore, Timestamp } from '@google-cloud/firestore';
import {
  type OAuthClientInformationFull,
  OAuthClientInformationFullSchema,
} from '@modelcontextprotocol/sdk/shared/auth.js';

import { fingerprint, open, seal } from './sealing.js';

/**
 * Real Firestore collections rather than one collection with a logical name
 * field, because this database is shared with monarch-mcp. The prefix is what
 * keeps the two services from writing over each other.
 */
export const COLLECTIONS = {
  clients: 'reddit_clients',
  transactions: 'reddit_transactions',
  codes: 'reddit_codes',
  accessTokens: 'reddit_access_tokens',
  refreshTokens: 'reddit_refresh_tokens',
  users: 'reddit_users',
} as const;

export type CollectionName = (typeof COLLECTIONS)[keyof typeof COLLECTIONS];

/** Additional authenticated data binding a sealed blob to this one use. */
const REDDIT_TOKEN_PURPOSE = 'reddit_refresh_token';

/**
 * Every id this server stores is a fingerprint, a UUID, or random base64url.
 * Rejecting anything else means a key that could overrun Firestore's id limit,
 * carry a path separator, or collide with its reserved `__…__` names fails at
 * the call site rather than quietly landing in the wrong document.
 */
const SAFE_ID = /^[A-Za-z0-9_-]{1,1500}$/;
const FIRESTORE_RESERVED_ID = /^__.*__$/;

/**
 * The storage seam. Firestore in production, memory in tests and stdio.
 *
 * Two of these four are about deciding a winner rather than moving data, and
 * both exist because the read-then-write spelling of them is a race that mints
 * two tokens from one grant:
 *
 * `create` fails when the document already exists, which is how a code is
 * spent exactly once. `take` reads and removes in one atomic step, which is
 * how a parked transaction is claimed by exactly one callback.
 */
export interface DocumentStore {
  get<T>(collection: CollectionName, id: string): Promise<T | null>;
  put<T>(
    collection: CollectionName,
    id: string,
    value: T,
    ttlSeconds: number | null
  ): Promise<void>;
  /** Returns false when the document already exists. */
  create<T>(
    collection: CollectionName,
    id: string,
    value: T,
    ttlSeconds: number | null
  ): Promise<boolean>;
  /**
   * Returns the document to the single caller that removed it.
   *
   * `accept` runs inside the same atomic step, and a false answer leaves the
   * document where it was. Without that, a caller who is refused still
   * destroys the record on the way out, which turns "this token is not yours"
   * into a way to log out whoever it does belong to.
   */
  take<T>(
    collection: CollectionName,
    id: string,
    accept?: (value: T) => boolean
  ): Promise<T | null>;
  delete(collection: CollectionName, id: string): Promise<void>;
}

/** A parked authorization request, waiting for the human to finish at Reddit. */
export interface TransactionRecord {
  clientId: string;
  redirectUri: string;
  state?: string;
  codeChallenge: string;
  scopes: string[];
  resource?: string;
  createdAt: number;
}

/** What an issued access or refresh token is allowed to do, and for whom. */
export interface TokenRecord {
  clientId: string;
  userId: string;
  scopes: string[];
  expiresAt: number;
  resource?: string;
}

/** One Reddit account's durable grant. */
export interface UserRecord {
  username: string;
  sealedRefreshToken: string;
  updatedAt: number;
}

/** Marker for an authorization code that has already been redeemed. */
interface SpentCodeRecord {
  spentAt: number;
}

function assertSafeId(id: string): void {
  if (!SAFE_ID.test(id) || FIRESTORE_RESERVED_ID.test(id)) {
    throw new Error('Refusing to store under an unsafe document id');
  }
}

function expiryTimestamp(ttlSeconds: number | null): Timestamp | null {
  if (ttlSeconds === null) return null;
  return Timestamp.fromMillis(Date.now() + ttlSeconds * 1000);
}

/**
 * Firestore behind {@link DocumentStore}.
 *
 * Documents are `{ data, expires_at }`. The TTL policies configured in
 * terraform watch `expires_at`, so expired state is swept by the database
 * rather than by a cron job that would have to exist. Records with no natural
 * expiry, meaning client registrations and user grants, write null there and
 * are never swept.
 */
export class FirestoreDocumentStore implements DocumentStore {
  constructor(private readonly db: Firestore) {}

  async get<T>(collection: CollectionName, id: string): Promise<T | null> {
    assertSafeId(id);
    const reference = this.db.collection(collection).doc(id);
    const snapshot = await reference.get();
    const document = snapshot.data();
    if (!document) return null;

    // Read-time expiry, because Firestore's sweep is eventual. An entry that
    // has outlived its lifetime must never be handed back just because the
    // sweeper has not reached it yet.
    const expiresAt: unknown = document.expires_at;
    if (expiresAt instanceof Timestamp && expiresAt.toMillis() <= Date.now()) {
      await reference.delete();
      return null;
    }

    const stored: unknown = document.data;
    if (stored === undefined) return null;
    // Storage cannot check T at runtime. The generic is the caller's contract
    // with itself, and every write to these collections goes through the typed
    // facade at the bottom of this file.
    return stored as T;
  }

  async put<T>(
    collection: CollectionName,
    id: string,
    value: T,
    ttlSeconds: number | null
  ): Promise<void> {
    assertSafeId(id);
    await this.db
      .collection(collection)
      .doc(id)
      .set({ data: value, expires_at: expiryTimestamp(ttlSeconds) });
  }

  async create<T>(
    collection: CollectionName,
    id: string,
    value: T,
    ttlSeconds: number | null
  ): Promise<boolean> {
    assertSafeId(id);
    try {
      await this.db
        .collection(collection)
        .doc(id)
        .create({ data: value, expires_at: expiryTimestamp(ttlSeconds) });
      return true;
    } catch (error) {
      // ALREADY_EXISTS is the answer we asked the question to get, so it is a
      // false return rather than a throw. Anything else is a real fault and
      // must not be reported as "someone got here first".
      const code: unknown =
        error && typeof error === 'object' && 'code' in error
          ? error.code
          : undefined;
      if (code === 6) return false;
      throw error;
    }
  }

  async take<T>(
    collection: CollectionName,
    id: string,
    accept?: (value: T) => boolean
  ): Promise<T | null> {
    assertSafeId(id);
    const reference = this.db.collection(collection).doc(id);

    // A real Firestore transaction rather than get-then-delete. Two callers
    // arriving at once would both read the record and both act on it; here the
    // loser's commit is rejected and it retries onto an absent document, which
    // is the answer it should have had.
    return this.db.runTransaction(async (tx) => {
      const snapshot = await tx.get(reference);
      const document = snapshot.data();
      if (!document) return null;

      const expiresAt: unknown = document.expires_at;
      if (
        expiresAt instanceof Timestamp &&
        expiresAt.toMillis() <= Date.now()
      ) {
        tx.delete(reference);
        return null;
      }

      const stored: unknown = document.data;
      if (stored === undefined) {
        tx.delete(reference);
        return null;
      }

      // Same contract as `get`: the generic is the caller's own.
      const value = stored as T;
      if (accept && !accept(value)) return null;

      tx.delete(reference);
      return value;
    });
  }

  async delete(collection: CollectionName, id: string): Promise<void> {
    assertSafeId(id);
    await this.db.collection(collection).doc(id).delete();
  }
}

/**
 * In-memory {@link DocumentStore} for tests and for the stdio entry point,
 * where there is one process, one user, and nothing to survive.
 *
 * The single-winner methods are written without an await between the check and
 * the write. An intervening await would hand the event loop to a concurrent
 * caller that has already read the same absent-or-present answer, which is the
 * exact race the Firestore side spends a transaction to avoid.
 */
export class MemoryDocumentStore implements DocumentStore {
  private readonly documents = new Map<
    string,
    { value: unknown; expiresAt: number | null }
  >();

  async get<T>(collection: CollectionName, id: string): Promise<T | null> {
    assertSafeId(id);
    return this.read<T>(collection, id, false);
  }

  async put<T>(
    collection: CollectionName,
    id: string,
    value: T,
    ttlSeconds: number | null
  ): Promise<void> {
    assertSafeId(id);
    this.documents.set(`${collection}\u0000${id}`, {
      value,
      expiresAt: ttlSeconds === null ? null : Date.now() + ttlSeconds * 1000,
    });
  }

  async create<T>(
    collection: CollectionName,
    id: string,
    value: T,
    ttlSeconds: number | null
  ): Promise<boolean> {
    assertSafeId(id);
    if (this.read<T>(collection, id, false) !== null) return false;
    this.documents.set(`${collection}\u0000${id}`, {
      value,
      expiresAt: ttlSeconds === null ? null : Date.now() + ttlSeconds * 1000,
    });
    return true;
  }

  async take<T>(
    collection: CollectionName,
    id: string,
    accept?: (value: T) => boolean
  ): Promise<T | null> {
    assertSafeId(id);
    return this.read<T>(collection, id, accept ?? true);
  }

  async delete(collection: CollectionName, id: string): Promise<void> {
    assertSafeId(id);
    this.documents.delete(`${collection}\u0000${id}`);
  }

  /**
   * Synchronous so that a caller can check and write in one turn.
   *
   * `remove` is false for a plain read, true to remove unconditionally, or a
   * predicate to remove only what it accepts.
   */
  private read<T>(
    collection: CollectionName,
    id: string,
    remove: boolean | ((value: T) => boolean)
  ): T | null {
    const key = `${collection}\u0000${id}`;
    const entry = this.documents.get(key);
    if (!entry) return null;

    if (entry.expiresAt !== null && entry.expiresAt <= Date.now()) {
      this.documents.delete(key);
      return null;
    }

    const value = entry.value as T;
    if (remove === false) return value;
    if (remove !== true && !remove(value)) return null;

    this.documents.delete(key);
    return value;
  }
}

/**
 * The typed view of storage the rest of the server uses.
 *
 * It holds the sealing key so that writing a Reddit refresh token in the clear
 * is not something a caller can do by forgetting a step. Sealing happens here
 * or not at all.
 */
export class OAuthStores {
  constructor(
    private readonly documents: DocumentStore,
    private readonly sealingKey: Buffer
  ) {}

  /**
   * Reads a registration back through the SDK's own schema.
   *
   * Anything that no longer parses is treated as absent rather than passed on
   * half-typed: a record written by an older shape of this server must fail as
   * an unknown client, which sends the agent through registration again.
   */
  async getClient(
    clientId: string
  ): Promise<OAuthClientInformationFull | undefined> {
    const raw = await this.documents.get<unknown>(
      COLLECTIONS.clients,
      clientId
    );
    if (raw === null) return undefined;
    const parsed = OAuthClientInformationFullSchema.safeParse(raw);
    return parsed.success ? parsed.data : undefined;
  }

  async putClient(client: OAuthClientInformationFull): Promise<void> {
    // No TTL. A registration that expired would send an agent back through
    // dynamic registration mid-conversation, holding a client id the server
    // has forgotten. Secret expiry is a separate field the SDK enforces.
    await this.documents.put(
      COLLECTIONS.clients,
      client.client_id,
      client,
      null
    );
  }

  async putTransaction(
    id: string,
    record: TransactionRecord,
    ttlSeconds: number
  ): Promise<void> {
    await this.documents.put(COLLECTIONS.transactions, id, record, ttlSeconds);
  }

  /**
   * Claims a parked request, atomically.
   *
   * A transaction survives exactly one callback. Leaving it readable would let
   * a replayed Reddit callback mint a second authorization code against the
   * same consent.
   */
  async takeTransaction(id: string): Promise<TransactionRecord | null> {
    return this.documents.take<TransactionRecord>(COLLECTIONS.transactions, id);
  }

  /**
   * Records that an authorization code has been redeemed.
   *
   * Returns false when it already had been, which is the single-use check. The
   * ledger holds opaque ids and a spend time, never the code or its payload:
   * the payload travels sealed inside the code itself.
   */
  async spendCode(codeId: string, ttlSeconds: number): Promise<boolean> {
    const record: SpentCodeRecord = { spentAt: Math.floor(Date.now() / 1000) };
    return this.documents.create(COLLECTIONS.codes, codeId, record, ttlSeconds);
  }

  async putAccessToken(
    token: string,
    record: TokenRecord,
    ttlSeconds: number
  ): Promise<void> {
    await this.documents.put(
      COLLECTIONS.accessTokens,
      fingerprint(token),
      record,
      ttlSeconds
    );
  }

  async getAccessToken(token: string): Promise<TokenRecord | null> {
    return this.documents.get<TokenRecord>(
      COLLECTIONS.accessTokens,
      fingerprint(token)
    );
  }

  async putRefreshToken(
    token: string,
    record: TokenRecord,
    ttlSeconds: number
  ): Promise<void> {
    await this.documents.put(
      COLLECTIONS.refreshTokens,
      fingerprint(token),
      record,
      ttlSeconds
    );
  }

  /**
   * Claims a refresh token for the client it was issued to, atomically.
   *
   * Rotation: the token dies here, in the same step that reads it. A refresh
   * token that keeps working after use is a credential with no expiry, and one
   * that two concurrent refreshes can both spend issues two live families.
   *
   * The client binding is checked inside that same step rather than after it.
   * Registration is open, so anybody can hold a client id; if the wrong client
   * could delete the record on its way to being refused, presenting a stolen
   * token would be a reliable way to sign out the agent it belongs to.
   */
  async takeRefreshToken(
    token: string,
    clientId: string
  ): Promise<TokenRecord | null> {
    return this.documents.take<TokenRecord>(
      COLLECTIONS.refreshTokens,
      fingerprint(token),
      (record) => record.clientId === clientId
    );
  }

  /**
   * Drops a token, whichever kind it is, if it belongs to this client.
   *
   * RFC 7009 requires the server to check that the token was issued to the
   * client presenting it, and to answer the same way either way. Both
   * collections are tried because a revocation request need not say which kind
   * it holds, and the fingerprint is the same in both.
   */
  async revoke(token: string, clientId: string): Promise<void> {
    const id = fingerprint(token);
    const ownedByCaller = (record: TokenRecord): boolean =>
      record.clientId === clientId;
    await this.documents.take<TokenRecord>(
      COLLECTIONS.accessTokens,
      id,
      ownedByCaller
    );
    await this.documents.take<TokenRecord>(
      COLLECTIONS.refreshTokens,
      id,
      ownedByCaller
    );
  }

  /**
   * Stores a Reddit account's durable grant, sealed.
   *
   * Keyed by the fingerprint of the username so that signing in again replaces
   * the grant rather than accumulating dead ones, while the id itself does not
   * announce who has connected.
   */
  async putRedditGrant(
    username: string,
    refreshToken: string
  ): Promise<string> {
    const userId = fingerprint(username);
    const record: UserRecord = {
      username,
      sealedRefreshToken: seal(
        this.sealingKey,
        REDDIT_TOKEN_PURPOSE,
        refreshToken
      ),
      updatedAt: Math.floor(Date.now() / 1000),
    };
    await this.documents.put(COLLECTIONS.users, userId, record, null);
    return userId;
  }

  /**
   * Returns a user's Reddit refresh token, or null when there is no usable
   * grant. Null covers a missing record and one this key cannot open, which is
   * what a rotated session secret looks like: the right answer to both is to
   * send the person back through sign-in.
   */
  async getRedditGrant(
    userId: string
  ): Promise<{ username: string; refreshToken: string } | null> {
    const record = await this.documents.get<UserRecord>(
      COLLECTIONS.users,
      userId
    );
    if (!record) return null;

    const refreshToken = open<string>(
      this.sealingKey,
      REDDIT_TOKEN_PURPOSE,
      record.sealedRefreshToken
    );
    if (!refreshToken) return null;

    return { username: record.username, refreshToken };
  }
}

/** Builds the production storage stack against the shared OAuth database. */
export function firestoreStores(
  projectId: string,
  databaseId: string,
  sealingKey: Buffer
): OAuthStores {
  // Firestore throws on an undefined field value unless told otherwise, and
  // the records here legitimately have them: a public client registration has
  // no client_secret, and a token issued without RFC 8707 has no resource.
  // Without this, dynamic registration fails in production and nowhere else.
  const db = new Firestore({
    projectId,
    databaseId,
    ignoreUndefinedProperties: true,
  });
  return new OAuthStores(new FirestoreDocumentStore(db), sealingKey);
}
