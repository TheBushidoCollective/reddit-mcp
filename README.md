# reddit-mcp

An MCP server for Reddit that runs two ways.

Hosted, it sits behind an OAuth 2.1 authorization server of its own, and the way
you prove you are allowed to use it is by signing in to Reddit. The agent gets a
token this server minted; Reddit gets a normal authorization code grant from a
human in a browser. No Reddit credential is ever pasted into a config file, and
none is shared between users.

Local, it is an ordinary stdio MCP server that reads Reddit credentials from the
environment. That path is for development and for anyone who would rather run it
themselves.

Public tools work either way: frontpage, subreddit listings (hot, new, rising,
top), post content and comments, search, subreddit and user profiles. The user
scoped tools (saved, upvoted, downvoted, hidden, your own posts and comments,
subscriptions, inbox, multireddits) need a signed in Reddit account, and say so
plainly when there is not one rather than failing.

## Hosted endpoint

```
https://reddit-mcp-n5sjtdvmca-uc.a.run.app
```

| Route | What it is for |
| --- | --- |
| `POST /mcp` | The MCP endpoint. Requires a bearer token this server issued. |
| `GET /health` | Liveness, answered by the container, no auth. |
| `GET /.well-known/oauth-authorization-server` | RFC 8414 authorization server metadata. |
| `GET /.well-known/oauth-protected-resource/mcp` | RFC 9728 metadata, the document the `WWW-Authenticate` header on `/mcp` points at. |
| `POST /register` | RFC 7591 dynamic client registration, open on purpose. |
| `GET /authorize` | Starts the handshake and sends the human to Reddit. |
| `POST /token` | Authorization code exchange and refresh. |
| `GET /callback/reddit` | Where Reddit sends the human back. |
| `POST /revoke` | Token revocation. |

Registering is not authorization. Any client may register; it still has to send
its owner through Reddit before it gets a token that `/mcp` will accept.

## Connecting through the han plugin

The plugin is a pointer and nothing else. In
[TheBushidoCollective/han](https://github.com/TheBushidoCollective/han),
`plugins/services/reddit/.mcp.json` is the whole of it:

```json
{
  "mcpServers": {
    "reddit": {
      "type": "http",
      "url": "https://reddit-mcp-n5sjtdvmca-uc.a.run.app/mcp"
    }
  }
}
```

Install it with:

```sh
han plugin install reddit
```

or, without han's CLI:

```sh
claude plugin marketplace add thebushidocollective/han
claude plugin install reddit@han
```

The first tool call is refused with a 401 and a `WWW-Authenticate` header naming
where to go. The client follows it, registers itself, opens Reddit's consent
screen in a browser, and comes back holding a token. After that it is silent:
refresh happens without asking again.

## Environment

The hosted service reads all of these. Terraform sets them on the Cloud Run
service, so this table is documentation of the contract rather than something to
configure by hand.

| Variable | Value | Why |
| --- | --- | --- |
| `PUBLIC_URL` | `https://reddit-mcp-n5sjtdvmca-uc.a.run.app` | Every URL the server advertises is built from this: the metadata documents, and the redirect URI it hands Reddit. It has to match the address clients actually reach or the handshake breaks on the way back. |
| `GOOGLE_CLOUD_PROJECT` | `waldrip-net` | The project holding Firestore. |
| `FIRESTORE_DATABASE` | `monarch-oauth` | Where OAuth state lives, because this runs on a service that scales to zero and in-memory state would not survive a cold start. The name is historical: the database is shared with monarch-mcp, and this server prefixes its collections `reddit_` so the two cannot collide. |
| `REDDIT_CLIENT_ID` | Secret Manager `reddit-oauth-client-id` | The Reddit app this server authenticates users against. |
| `REDDIT_CLIENT_SECRET` | Secret Manager `reddit-oauth-client-secret` | Same app's secret, used only server side in the code exchange. |
| `MCP_SESSION_SECRET` | Secret Manager `reddit-mcp-session-secret` | Signs the artifacts this server issues. Rotating it invalidates every outstanding token, which is the point. |
| `PORT` | injected | Cloud Run sets it. Locally it defaults to 8080. |

Firestore collections: `reddit_clients`, `reddit_transactions`, `reddit_codes`,
`reddit_access_tokens`, `reddit_refresh_tokens`, `reddit_users`.

## Running locally over stdio

The stdio entry point skips the OAuth bridge and Firestore entirely. It talks to
Reddit with credentials from the environment, so there is no sign-in flow and no
shared state.

```sh
npm install
npm run dev:stdio
```

Against the build instead of the sources:

```sh
npm run build
node dist/index.js
```

It reads:

| Variable | Notes |
| --- | --- |
| `REDDIT_CLIENT_ID` | From your own Reddit app. Without it, only the public tools work. |
| `REDDIT_CLIENT_SECRET` | Required for anything beyond public data. |
| `REDDIT_REFRESH_TOKEN` | Reaches your own account. Preferred over a password. |
| `REDDIT_USERNAME`, `REDDIT_PASSWORD` | The alternative, and only valid for a Reddit app of type `script`. |
| `REDDIT_USER_AGENT` | Optional. Reddit rate limits harder on generic ones. |

As an MCP client entry:

```json
{
  "mcpServers": {
    "reddit": {
      "command": "npx",
      "args": ["-y", "@thebushidocollective/reddit-mcp"],
      "env": {
        "REDDIT_CLIENT_ID": "...",
        "REDDIT_CLIENT_SECRET": "...",
        "REDDIT_REFRESH_TOKEN": "..."
      }
    }
  }
}
```

## Operator setup

Everything else is automated. These three things are not, and the service cannot
serve without them.

### 1. Register the Reddit app

At <https://www.reddit.com/prefs/apps>, create another app of type **web app**.

Not `script`, and not `installed app`. The hosted server runs the authorization
code flow on behalf of whichever human signs in, which needs a client secret and
a registered redirect URI, and `web app` is the only type that is both.

The redirect URI has to be exactly:

```
https://reddit-mcp-n5sjtdvmca-uc.a.run.app/callback/reddit
```

Reddit matches it literally. A trailing slash is a different URI and the
handshake fails at the last step, which is the most expensive place to find out.

### 2. Create the secrets, before the service exists

Terraform does not own these three containers. It reads them, the way the
monarch and openings services next door read theirs, and the ordering is the
reason: the Cloud Run service binds all three at `latest`, so an apply that
created the containers and the service together would produce a first revision
that cannot start on a version that does not exist yet. A
`google_secret_manager_secret_version` resource would also write the value into
the state file, in the state bucket, in plaintext, forever.

So the containers and their first versions are provisioned out of band, once,
**before** the cld apply that creates the service:

```sh
cd ~/dev/src/github.com/jwaldrip/cld
./deploy/reddit-secrets.sh
```

It creates `reddit-oauth-client-id`, `reddit-oauth-client-secret` and
`reddit-mcp-session-secret` if they are absent, prompts for the two Reddit app
values without echoing them, and generates the session secret locally. It is
idempotent, so re-running it is safe. Nothing is passed as a command argument,
which would put a secret in argv, in shell history, and in the process list of a
shared machine.

The container binds `latest`, so a new version is picked up the next time an
instance cold starts. To force it, roll a revision by running the deploy
workflow.

### 3. Set the repository variables

The deploy workflow authenticates with workload identity federation and needs to
be told which identity. The cld terraform provisions both, and its output is the
authoritative copy: read the values from there rather than trusting this table,
which is a convenience and can drift.

| Variable | Value |
| --- | --- |
| `WIF_PROVIDER` | `projects/632122948866/locations/global/workloadIdentityPools/reddit-mcp-github/providers/github` |
| `WIF_SERVICE_ACCOUNT` | `reddit-mcp-deployer@waldrip-net.iam.gserviceaccount.com` |

Until `WIF_PROVIDER` is set the deploy job skips rather than fails, because
before the terraform has run there is genuinely no identity to assume and a red
pipeline would read as broken rather than as unfinished setup.

## Where the infrastructure lives

The Cloud Run service, its service account, its IAM and the Firestore database
are all terraform in [jwaldrip/cld](https://github.com/jwaldrip/cld) under
`deploy/terraform`. That apply owns the service's existence and its entire
configuration. The three secret containers are the exception: terraform reads
them and `deploy/reddit-secrets.sh` creates them, for the ordering reason above.

First bring-up runs in this order, and the order is load bearing:

1. `cld/deploy/bootstrap.sh`, which creates the `reddit-mcp-github` workload
   identity pool and provider and sets the two repository variables below. It
   cannot run in CI, because a pipeline cannot create the identity it
   authenticates with. The deployer account itself is not created here: it and
   every role on it are terraform, so they sit next to the rest of what that
   account may do.
2. `cld/deploy/reddit-secrets.sh`, which creates the three secret containers and
   their first versions. Before the apply, not after.
3. Merge the cld pull request. That apply creates the deployer, grants it
   federation from the pool in step 1, and creates the service on a placeholder
   image.
4. Confirm `WIF_PROVIDER` and `WIF_SERVICE_ACCOUNT` are set on this repository.
   Step 1 sets them; this is the check that the deploy job will not skip.
5. Merge here. The deploy workflow builds the real image, rolls it, and probes
   it.
6. Merge the han pull request, which points the plugin at the endpoint.

This repo owns the code and which revision of it serves. The terraform ignores
changes to the container image on purpose, so a deploy from here and an apply
over there do not fight each other. `.github/workflows/deploy.yml` builds the
image, pins Cloud Run to the resulting digest rather than a tag, and then probes
the running service: anonymous callers refused, the discovery documents intact,
registration open, health serving, and the revision it just created holding all
the traffic. Any of those wrong fails the deploy.

Deploys run in CI. Never from a workstation.

## Development

```sh
npm install
npm run dev          # HTTP entry point, with reload
npm run dev:stdio    # stdio entry point
npm run lint         # biome
npm run typecheck    # tsc --noEmit
npm test             # vitest
```

CI runs lint, typecheck and the tests on every pull request. It holds no cloud
credentials, so it stays runnable from a fork.
