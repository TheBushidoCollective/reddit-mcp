#!/usr/bin/env node
/**
 * Local stdio entry point, for one person running this on their own machine.
 *
 * The server always starts. When Reddit credentials are missing it serves the
 * public tools and answers the user scoped ones with setup instructions, which
 * keeps a misconfigured environment diagnosable instead of silently absent.
 * The hosted server cannot work this way, because there the credential belongs
 * to whoever signed in rather than to the process.
 *
 * This path deliberately does not go through the OAuth bridge. One process,
 * one user, and one credential set already in the environment means there is
 * no registration, transaction, authorization code, or issued token to
 * persist, so there is no authorization server and no store here at all.
 *
 * That is also why this file imports nothing from src/oauth: the Firestore
 * client is then never loaded on the stdio path, which is a structural
 * guarantee rather than a claim about what the code happens to call.
 */

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';

import { readCredentials, resolveMode } from './reddit/auth.js';
import { RedditClient } from './reddit/client.js';
import { registerTools } from './reddit/tools.js';

const VERSION = '2.0.0';

/** Starts the stdio MCP server and blocks until the transport closes. */
export async function main(): Promise<void> {
  const credentials = readCredentials();
  const mode = resolveMode(credentials);
  const client = new RedditClient(credentials, mode);

  const server = new McpServer({ name: 'reddit', version: VERSION });
  registerTools(server, client);

  // stdout is the MCP transport, so every diagnostic goes to stderr.
  process.stderr.write(`reddit-mcp ${VERSION} started in ${mode} mode\n`);
  if (mode !== 'user') {
    process.stderr.write(
      'Saved items, profile, and history tools need user auth. ' +
        'Set REDDIT_CLIENT_ID, REDDIT_CLIENT_SECRET, and either ' +
        'REDDIT_REFRESH_TOKEN or REDDIT_USERNAME plus REDDIT_PASSWORD.\n'
    );
  }

  await server.connect(new StdioServerTransport());
}

main().catch((error: unknown) => {
  process.stderr.write(`reddit-mcp failed to start: ${error}\n`);
  process.exit(1);
});
