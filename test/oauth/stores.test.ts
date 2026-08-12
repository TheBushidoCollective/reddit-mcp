import { beforeEach, describe, expect, test } from 'vitest';

import { deriveSealingKey, fingerprint } from '../../src/oauth/sealing.js';
import {
  COLLECTIONS,
  type CollectionName,
  type DocumentStore,
  MemoryDocumentStore,
  OAuthStores,
  type TokenRecord,
} from '../../src/oauth/stores.js';

const key = deriveSealingKey('a-test-session-secret');

/**
 * Wraps a real store and keeps every write, so a test can assert what did and
 * did not reach storage rather than trusting the shape of the call.
 */
class RecordingStore implements DocumentStore {
  readonly writes: Array<{
    collection: CollectionName;
    id: string;
    value: unknown;
  }> = [];

  private readonly inner = new MemoryDocumentStore();

  async get<T>(collection: CollectionName, id: string): Promise<T | null> {
    return this.inner.get<T>(collection, id);
  }

  async put<T>(
    collection: CollectionName,
    id: string,
    value: T,
    ttlSeconds: number | null
  ): Promise<void> {
    this.writes.push({ collection, id, value });
    await this.inner.put(collection, id, value, ttlSeconds);
  }

  async create<T>(
    collection: CollectionName,
    id: string,
    value: T,
    ttlSeconds: number | null
  ): Promise<boolean> {
    const won = await this.inner.create(collection, id, value, ttlSeconds);
    if (won) this.writes.push({ collection, id, value });
    return won;
  }

  async take<T>(
    collection: CollectionName,
    id: string,
    accept?: (value: T) => boolean
  ): Promise<T | null> {
    return this.inner.take<T>(collection, id, accept);
  }

  async delete(collection: CollectionName, id: string): Promise<void> {
    await this.inner.delete(collection, id);
  }

  /** Everything ever written, as one searchable string. */
  dump(): string {
    return JSON.stringify(this.writes);
  }
}

const tokenRecord: TokenRecord = {
  clientId: 'client-1',
  userId: 'user-1',
  scopes: ['identity'],
  expiresAt: Math.floor(Date.now() / 1000) + 3600,
};

let documents: RecordingStore;
let stores: OAuthStores;

beforeEach(() => {
  documents = new RecordingStore();
  stores = new OAuthStores(documents, key);
});

describe('token storage', () => {
  test('keys an access token by its fingerprint and never writes the token', async () => {
    const token = 'super-secret-access-token';
    await stores.putAccessToken(token, tokenRecord, 3600);

    expect(documents.dump()).not.toContain(token);
    expect(documents.writes[0]?.collection).toBe(COLLECTIONS.accessTokens);
    expect(documents.writes[0]?.id).toBe(fingerprint(token));
    expect(await stores.getAccessToken(token)).toEqual(tokenRecord);
  });

  test('keys a refresh token by its fingerprint and never writes the token', async () => {
    const token = 'super-secret-refresh-token';
    await stores.putRefreshToken(token, tokenRecord, 3600);

    expect(documents.dump()).not.toContain(token);
    expect(documents.writes[0]?.id).toBe(fingerprint(token));
  });

  test('does not answer a token it was never given', async () => {
    await stores.putAccessToken('one-token', tokenRecord, 3600);

    expect(await stores.getAccessToken('another-token')).toBeNull();
  });
});

describe('refresh token rotation', () => {
  test('spends the token for the client it was issued to', async () => {
    await stores.putRefreshToken('rt', tokenRecord, 3600);

    expect(await stores.takeRefreshToken('rt', 'client-1')).toEqual(
      tokenRecord
    );
    expect(await stores.takeRefreshToken('rt', 'client-1')).toBeNull();
  });

  test('refuses another client without destroying the record', async () => {
    await stores.putRefreshToken('rt', tokenRecord, 3600);

    expect(await stores.takeRefreshToken('rt', 'client-2')).toBeNull();
    // The rightful client can still refresh: a refusal must not be a way to
    // sign somebody else out.
    expect(await stores.takeRefreshToken('rt', 'client-1')).toEqual(
      tokenRecord
    );
  });
});

describe('revocation', () => {
  test('drops a token belonging to the calling client', async () => {
    await stores.putAccessToken('at', tokenRecord, 3600);
    await stores.revoke('at', 'client-1');

    expect(await stores.getAccessToken('at')).toBeNull();
  });

  test('leaves a token belonging to somebody else alone', async () => {
    await stores.putAccessToken('at', tokenRecord, 3600);
    await stores.revoke('at', 'client-2');

    expect(await stores.getAccessToken('at')).toEqual(tokenRecord);
  });
});

describe('reddit grants', () => {
  test('seals the upstream refresh token at rest', async () => {
    const upstream = 'reddit-refresh-token-value';
    const userId = await stores.putRedditGrant('some_redditor', upstream);

    expect(documents.dump()).not.toContain(upstream);
    expect(userId).toBe(fingerprint('some_redditor'));
    expect(await stores.getRedditGrant(userId)).toEqual({
      username: 'some_redditor',
      refreshToken: upstream,
    });
  });

  test('replaces the grant when the same person signs in again', async () => {
    const first = await stores.putRedditGrant('some_redditor', 'old-token');
    const second = await stores.putRedditGrant('some_redditor', 'new-token');

    expect(second).toBe(first);
    expect((await stores.getRedditGrant(second))?.refreshToken).toBe(
      'new-token'
    );
  });

  test('reports no grant when the sealing key has changed', async () => {
    const userId = await stores.putRedditGrant('some_redditor', 'a-token');
    const rekeyed = new OAuthStores(documents, deriveSealingKey('rotated'));

    // A rotated session secret reads as "sign in again" rather than as a crash.
    expect(await rekeyed.getRedditGrant(userId)).toBeNull();
  });
});

describe('single use codes', () => {
  test('lets the first spend win and refuses the rest', async () => {
    expect(await stores.spendCode('code-id', 30)).toBe(true);
    expect(await stores.spendCode('code-id', 30)).toBe(false);
  });
});

describe('transactions', () => {
  test('can be claimed exactly once', async () => {
    const parked = {
      clientId: 'client-1',
      redirectUri: 'http://127.0.0.1:9999/callback',
      codeChallenge: 'challenge',
      scopes: ['identity'],
      createdAt: Math.floor(Date.now() / 1000),
    };
    await stores.putTransaction('txn', parked, 600);

    expect(await stores.takeTransaction('txn')).toEqual(parked);
    expect(await stores.takeTransaction('txn')).toBeNull();
  });
});

describe('document ids', () => {
  test('refuse anything that is not opaque and url safe', async () => {
    await expect(
      documents.put(COLLECTIONS.clients, '../escaped', {}, null)
    ).rejects.toThrow();
    await expect(
      documents.get(COLLECTIONS.clients, '__name__')
    ).rejects.toThrow();
  });
});
