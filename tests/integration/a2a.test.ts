/**
 * Integration tests — live Application-to-Application (A2A) credential retrieval.
 *
 * Bootstraps a full A2A scenario on the appliance: trusted CA chain, a
 * certificate user, an asset with a password account and an SSH-key account, an
 * A2A registration exposing both, and the A2A service enabled. It then drives
 * the {@link A2AClient} over mutually-authenticated TLS to list retrievable
 * accounts and get/set both the password and the SSH private key credential.
 *
 * A2A always uses client-certificate auth, which auto-caps at TLS 1.2 (Node has
 * no client-side TLS 1.3 post-handshake authentication), so these flows work by
 * default on both 8.x and 9.0 appliances.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { readFileSync, mkdtempSync, rmSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { requireAppliance } from './setup.js';
import { createAdminClient, uniqueName, CleanupRegistry } from './fixtures.js';
import { certPaths, CERT_PASSWORD, uploadTrustedCas, createCertUser, createOpsAdminClient } from './certFixtures.js';
import { SafeguardClient } from '../../src/client.js';
import { CertificateAuth } from '../../src/auth/certificate.js';
import { NodeHttpClient } from '../../src/http/node.js';
import { A2AClient } from '../../src/a2a/index.js';
import { Service } from '../../src/types.js';

const env = requireAppliance();

// PlatformId 188 ("Other Managed") requires no real connectivity — ideal for a
// throwaway asset that only exists to host a managed account.
const OTHER_MANAGED_PLATFORM_ID = 188;
const INITIAL_PASSWORD = 'TestA2aPassword123!';

/** Generate a throwaway OpenSSH-format ed25519 private key for A2A key tests. */
function generateSshPrivateKey(): string {
  const dir = mkdtempSync(join(tmpdir(), 'sgjs-ssh-'));
  try {
    const keyPath = join(dir, 'a2a_test_key');
    execFileSync('ssh-keygen', ['-t', 'ed25519', '-f', keyPath, '-N', '', '-q']);
    return readFileSync(keyPath, 'utf8');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

describe('A2A Credential Retrieval', () => {
  let admin: SafeguardClient;
  let ops: SafeguardClient;
  const cleanup = new CleanupRegistry();

  let accountId: number;
  let accountName: string;
  let apiKey: string;
  let sshApiKey: string;
  let originalSshKey: string;

  beforeAll(async () => {
    admin = await createAdminClient(env);

    // The bootstrap Admin lacks AssetAdmin/PolicyAdmin, so mint a fully
    // privileged local admin for the asset/account/registration operations.
    ops = await createOpsAdminClient(admin, env, cleanup);

    // Trust the test CA chain and create the certificate user the A2A
    // registration is bound to.
    await uploadTrustedCas(admin, cleanup);
    const certUser = await createCertUser(admin, cleanup, uniqueName('A2aCertUser'));

    // Preserve and, on teardown, restore the A2A service enabled state.
    let a2aWasEnabled = false;
    try {
      const a2aStatus = await admin.get<{ IsRunning?: boolean; IsEnabled?: boolean }>(
        Service.APPLIANCE,
        'A2AService/Status',
      );
      a2aWasEnabled = (a2aStatus?.IsRunning ?? a2aStatus?.IsEnabled) === true;
    } catch { /* treat unknown state as disabled */ }

    // Create a throwaway asset + account and give the account a known password.
    const asset = await ops.post<{ Id: number }>(Service.CORE, 'Assets', {
      json: {
        Name: uniqueName('A2aAsset'),
        Description: 'Throwaway asset for safeguard.js A2A integration test',
        PlatformId: OTHER_MANAGED_PLATFORM_ID,
        AssetPartitionId: -1,
        NetworkAddress: 'fake.a2a.test.address.local',
      },
    });
    cleanup.register(async () => {
      try { await ops.delete(Service.CORE, `Assets/${asset.Id}`); } catch { /* best effort */ }
    });

    accountName = uniqueName('A2aAccount');
    const account = await ops.post<{ Id: number }>(Service.CORE, 'AssetAccounts', {
      json: { Name: accountName, Asset: { Id: asset.Id } },
    });
    accountId = account.Id;
    cleanup.register(async () => {
      try { await ops.delete(Service.CORE, `AssetAccounts/${account.Id}`); } catch { /* best effort */ }
    });

    await ops.put(Service.CORE, `AssetAccounts/${account.Id}/Password`, {
      json: INITIAL_PASSWORD,
    });

    // Register the account for A2A retrieval by the certificate user.
    const registration = await ops.post<{ Id: number }>(Service.CORE, 'A2ARegistrations', {
      json: {
        AppName: uniqueName('A2aReg'),
        CertificateUserId: certUser.Id,
        VisibleToCertificateUsers: true,
        BidirectionalEnabled: true,
        Description: 'safeguard.js A2A integration test registration',
      },
    });
    cleanup.register(async () => {
      try { await ops.delete(Service.CORE, `A2ARegistrations/${registration.Id}`); } catch { /* best effort */ }
    });

    const retrievable = await ops.post<{ ApiKey: string }>(
      Service.CORE,
      `A2ARegistrations/${registration.Id}/RetrievableAccounts`,
      { json: { AccountId: account.Id, Type: 'Password' } },
    );
    apiKey = retrievable.ApiKey;

    // Second account holding an SSH private key, exposed as a PrivateKey
    // retrievable on the same registration — exercises the A2A SSH-key path.
    const sshAccountName = uniqueName('A2aSshAccount');
    const sshAccount = await ops.post<{ Id: number }>(Service.CORE, 'AssetAccounts', {
      json: { Name: sshAccountName, Asset: { Id: asset.Id } },
    });
    cleanup.register(async () => {
      try { await ops.delete(Service.CORE, `AssetAccounts/${sshAccount.Id}`); } catch { /* best effort */ }
    });

    originalSshKey = generateSshPrivateKey();
    await ops.put(Service.CORE, `AssetAccounts/${sshAccount.Id}/SshKey`, {
      json: { PrivateKey: originalSshKey, Passphrase: '' },
    });

    const sshRetrievable = await ops.post<{ ApiKey: string }>(
      Service.CORE,
      `A2ARegistrations/${registration.Id}/RetrievableAccounts`,
      { json: { AccountId: sshAccount.Id, Type: 'PrivateKey' } },
    );
    sshApiKey = sshRetrievable.ApiKey;

    // Enable the A2A service and restore its prior state on teardown.
    await ops.post(Service.APPLIANCE, 'A2AService/Enable');
    cleanup.register(async () => {
      if (!a2aWasEnabled) {
        try { await ops.post(Service.APPLIANCE, 'A2AService/Disable'); } catch { /* best effort */ }
      }
    });

    // Brief pause for the A2A service to become ready.
    await new Promise((resolve) => setTimeout(resolve, 2000));
  });

  afterAll(async () => {
    await cleanup.runAll();
    await ops?.disconnect();
    await admin?.disconnect();
  });

  /** Build an A2AClient authenticated by the bundled user certificate. */
  function createA2AClient(): A2AClient {
    const pfx = readFileSync(certPaths().userPfx);
    const auth = new CertificateAuth({ pfx, passphrase: CERT_PASSWORD });
    const client = new A2AClient(env.host, { auth, verify: env.verify });
    const httpClient = new NodeHttpClient({
      pfx,
      passphrase: CERT_PASSWORD,
      rejectUnauthorized: env.verify,
      ...(env.caFile ? { ca: readFileSync(env.caFile) } : {}),
    });
    client.setHttpClient(httpClient);
    return client;
  }

  it('lists retrievable accounts for the certificate', async () => {
    const client = createA2AClient();
    const accounts = await client.getRetrievableAccounts();
    const match = accounts.find((a) => a.AccountId === accountId);
    expect(match).toBeDefined();
    expect(match?.AccountName).toBe(accountName);
  });

  it('retrieves the account password via A2A', async () => {
    const client = createA2AClient();
    const secret = await client.retrievePassword(apiKey);
    expect(secret.expose()).toBe(INITIAL_PASSWORD);
  });

  it('sets a new password via A2A and reads it back', async () => {
    const client = createA2AClient();
    const updated = 'UpdatedA2aPass456!@#';
    await client.setPassword(apiKey, updated);
    const secret = await client.retrievePassword(apiKey);
    expect(secret.expose()).toBe(updated);
  });

  it('rejects retrieval with an unknown API key', async () => {
    const client = createA2AClient();
    await expect(
      client.retrievePassword('00000000-0000-0000-0000-000000000000'),
    ).rejects.toThrow();
  });

  it('retrieves the account SSH private key via A2A', async () => {
    const client = createA2AClient();
    const secret = await client.retrievePrivateKey(sshApiKey);
    const key = secret.expose();
    expect(key).toContain('PRIVATE KEY');
    expect(key.length).toBeGreaterThan(20);
  });

  it('sets a new SSH private key via A2A and reads it back', async () => {
    const client = createA2AClient();
    const before = (await client.retrievePrivateKey(sshApiKey)).expose();

    const newKey = generateSshPrivateKey();
    expect(newKey).not.toBe(originalSshKey);
    await client.setPrivateKey(sshApiKey, newKey);

    const after = (await client.retrievePrivateKey(sshApiKey)).expose();
    expect(after).toContain('PRIVATE KEY');
    expect(after.length).toBeGreaterThan(20);
    // The appliance re-serializes the stored key, so compare against the prior
    // retrieved value rather than the raw input: a successful set must change
    // what comes back.
    expect(after).not.toBe(before);
  });
});
