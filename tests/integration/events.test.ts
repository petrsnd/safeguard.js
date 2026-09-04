/**
 * Integration tests — Event listener (SignalR).
 *
 * Tests the SafeguardEventListener against a live appliance.
 * Uses a short-lived connection to verify handshake and state transitions.
 *
 * NOTE: These tests verify connection establishment and graceful disconnect.
 * Triggering actual events would require changing passwords/running tasks
 * which is too invasive for a smoke-level integration test.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { createRequire } from 'node:module';
import { readFileSync } from 'node:fs';
import * as signalR from '@microsoft/signalr';
import { requireAppliance } from './setup.js';
import { SafeguardEventListener } from '../../src/events/index.js';
import { PasswordAuth } from '../../src/auth/password.js';
import { NodeHttpClient } from '../../src/http/node.js';
import { MemoryStorage } from '../../src/storage/memory.js';
import type { IntegrationEnv } from './setup.js';

const env = requireAppliance();

/** The correct SignalR hub URL for Safeguard event notifications. */
const SIGNALR_HUB_PATH = '/service/event/signalr';

// ws (7.x) ships no bundled types and @types/ws isn't installed; load it via
// require and describe only the construct signature we use.
type WsConstructor = new (
  address: string,
  protocols: undefined,
  options: Record<string, unknown>,
) => object;
const WsWebSocket = createRequire(import.meta.url)('ws') as WsConstructor;

/**
 * Build a SignalR HubConnection to the Safeguard event hub.
 *
 * TLS options are wired directly into the WebSocket transport rather than via
 * the global NODE_TLS_REJECT_UNAUTHORIZED env var: under the serial integration
 * runner a global mutation would leak and silently disable server verification
 * for every test file that runs afterward. Using WebSockets with
 * skipNegotiation avoids the node-fetch negotiate step, so the only TLS
 * connection is the one whose CA / rejectUnauthorized we control here.
 */
function buildSignalRConnection(host: string, accessToken: string): signalR.HubConnection {
  const url = `https://${host}${SIGNALR_HUB_PATH}`;
  const ca = env.caFile ? readFileSync(env.caFile) : undefined;

  class TlsWebSocket extends WsWebSocket {
    constructor(address: string, protocols: undefined, options: Record<string, unknown>) {
      super(address, protocols, {
        ...options,
        rejectUnauthorized: env.verify,
        ...(ca ? { ca } : {}),
      });
    }
  }

  const options = {
    accessTokenFactory: () => accessToken,
    transport: signalR.HttpTransportType.WebSockets,
    skipNegotiation: true,
    WebSocket: TlsWebSocket,
  } as unknown as signalR.IHttpConnectionOptions;

  return new signalR.HubConnectionBuilder()
    .withUrl(url, options)
    .configureLogging(signalR.LogLevel.None)
    .build();
}

async function getAccessToken(e: IntegrationEnv): Promise<string> {
  const auth = new PasswordAuth({
    username: e.username,
    password: e.password,
    provider: e.provider,
  });
  const httpClient = new NodeHttpClient({
    rejectUnauthorized: e.verify,
    ...(e.caFile ? { ca: readFileSync(e.caFile) } : {}),
  });
  const storage = new MemoryStorage();
  const tokenSet = await auth.authenticate(e.host, httpClient, storage);
  httpClient.dispose?.();
  return tokenSet.accessToken.expose();
}

describe('Event Listener', () => {
  let accessToken: string;

  beforeAll(async () => {
    accessToken = await getAccessToken(env);
  });

  it('creates a listener in stopped state', () => {
    const connection = buildSignalRConnection(env.host, accessToken);
    const listener = new SafeguardEventListener(connection);
    expect(listener.state).toBe('stopped');
  });

  it('connects to SignalR and transitions to connected state', async () => {
    const connection = buildSignalRConnection(env.host, accessToken);
    const listener = new SafeguardEventListener(connection);

    await listener.start();
    expect(listener.state).toBe('connected');

    await listener.stop();
    expect(listener.state).toBe('stopped');
  }, 15_000);

  it('stops cleanly after connection', async () => {
    const connection = buildSignalRConnection(env.host, accessToken);
    const listener = new SafeguardEventListener(connection);

    await listener.start();
    expect(listener.state).toBe('connected');

    await listener.stop();
    expect(listener.state).toBe('stopped');
  }, 15_000);
});
