import { beforeEach, describe, expect, it, vi } from 'vitest';

const events: string[] = [];
let headKind: 'notFound' | 'success' = 'notFound';

vi.mock('../operationSigningService', () => ({
  generateDeviceSigningKeyPair: vi.fn(async () => ({
    privateKey: { kind: 'private' } as CryptoKey,
    publicKey: { kind: 'public' } as CryptoKey,
    publicKeyB64Url: 'public-key',
  })),
}));

vi.mock('../recordHashes', () => ({
  sha256Base64Url: vi.fn(async () => 'bootstrap-hash'),
  computeVaultHead: vi.fn(() => 'initial-head'),
}));

vi.mock('../vaultOpLogRepository', () => ({
  getVaultHead: vi.fn(async () => (
    headKind === 'success'
      ? { kind: 'success', head: { vaultHead: 'head-1' } }
      : { kind: 'notFound' }
  )),
  bootstrapVaultTrust: vi.fn(async () => {
    events.push('bootstrap');
    return { kind: 'bootstrapped' };
  }),
}));

vi.mock('../vaultOpLogDeviceSigningKeyStore', () => ({
  loadVaultOpLogDeviceSigningKey: vi.fn(async () => null),
  saveVaultOpLogDeviceSigningKey: vi.fn(async () => {
    events.push('save-signing-key');
  }),
}));

vi.mock('../vaultOpLogDeviceStore', () => ({
  loadVaultOpLogDeviceIdentity: vi.fn(() => null),
  saveVaultOpLogDeviceIdentity: vi.fn(() => {
    events.push('save-device-identity');
  }),
}));

describe('ensureInitialVaultOpLogTrust', () => {
  beforeEach(() => {
    events.length = 0;
    headKind = 'notFound';
    vi.spyOn(crypto, 'randomUUID').mockReturnValue('device-id' as `${string}-${string}-${string}-${string}-${string}`);
  });

  it('stores the local signing identity before bootstrapping remote trust', async () => {
    const { ensureInitialVaultOpLogTrust } = await import('../vaultOpLogInitialTrustService');

    const result = await ensureInitialVaultOpLogTrust({
      userId: 'user-1',
      vaultId: 'vault-1',
      rpcClient: { rpc: vi.fn() },
    });

    expect(result.kind).toBe('bootstrapped');
    expect(events).toEqual(['save-signing-key', 'save-device-identity', 'bootstrap']);
  });

  it('does not create local signing material when the vault already has an OpLog head', async () => {
    headKind = 'success';
    const { ensureInitialVaultOpLogTrust } = await import('../vaultOpLogInitialTrustService');

    const result = await ensureInitialVaultOpLogTrust({
      userId: 'user-1',
      vaultId: 'vault-1',
      rpcClient: { rpc: vi.fn() },
    });

    expect(result.kind).toBe('alreadyInitialized');
    expect(events).toEqual([]);
  });
});
