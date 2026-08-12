/**
 * Cloud Run entry point.
 *
 * Configuration is read once, here, and every value that has no safe default
 * is required rather than defaulted. Each of these fails in a different quiet
 * way if it is missing: a wrong public URL means clients discover endpoints
 * they cannot reach, no database name means OAuth state has nowhere to live
 * and every cold start asks the person to sign in again, and no session secret
 * means authorization codes and stored Reddit grants cannot be sealed at all.
 * None of them get a default, and the process refuses to start rather than
 * start wrong.
 */

import { createHttpServer, VERSION } from './http-server.js';
import { deriveSealingKey } from './oauth/sealing.js';
import { firestoreStores } from './oauth/stores.js';

/** Cloud Run's own default, and it always sets PORT explicitly anyway. */
const DEFAULT_PORT = 8080;

function required(name: string): string {
  const value = process.env[name]?.trim();
  if (!value) {
    process.stderr.write(`${name} is not set; refusing to start\n`);
    process.exit(1);
  }
  return value;
}

const publicUrl = required('PUBLIC_URL').replace(/\/+$/, '');
const projectId = required('GOOGLE_CLOUD_PROJECT');
const databaseId = required('FIRESTORE_DATABASE');
const redditClientId = required('REDDIT_CLIENT_ID');
const redditClientSecret = required('REDDIT_CLIENT_SECRET');
const sessionSecret = required('MCP_SESSION_SECRET');

const port = Number(process.env.PORT?.trim() || DEFAULT_PORT);
if (!Number.isInteger(port) || port <= 0) {
  process.stderr.write(`PORT is not a usable port number; refusing to start\n`);
  process.exit(1);
}

const sealingKey = deriveSealingKey(sessionSecret);
const stores = firestoreStores(projectId, databaseId, sealingKey);

const app = createHttpServer({
  publicUrl,
  redditClientId,
  redditClientSecret,
  sealingKey,
  stores,
});

// 0.0.0.0 rather than the default, because a container that binds loopback is
// unreachable from outside itself and Cloud Run reports it as a failed start
// with no other explanation.
app.listen(port, '0.0.0.0', () => {
  process.stdout.write(
    `reddit-mcp ${VERSION} listening on ${port}, serving ${publicUrl}\n`
  );
});
