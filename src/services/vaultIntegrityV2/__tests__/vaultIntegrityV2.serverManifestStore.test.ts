import { describe, expect, it, vi } from 'vitest';
import type { VaultManifestEnvelopeV2 } from '../types';

const supabaseMock = vi.hoisted(() => ({
  rpc: vi.fn(),
}));

vi.mock('@/integrations/supabase/client', () => ({
  supabase: supabaseMock,
}));

const { applyVaultMutationWithManifestV2 } = await import('../serverManifestStore');

function envelope(): VaultManifestEnvelopeV2 {
  return {
    envelopeVersion: 2,
    vaultId: 'vault-1',
    userId: 'user-1',
    keyId: 'legacy-kdf-v1',
    manifestRevision: 2,
    nonce: 'nonce',
    ciphertext: 'ciphertext',
    aad: {
      purpose: 'vault_manifest',
      envelopeVersion: 2,
      vaultId: 'vault-1',
      userId: 'user-1',
      keyId: 'legacy-kdf-v1',
      manifestVersion: 2,
      manifestRevision: 2,
    },
  };
}

describe('Vault Integrity V2 server manifest store', () => {
  it('submits item/category mutations and Manifest V2 metadata to the CAS RPC', async () => {
    supabaseMock.rpc.mockResolvedValueOnce({
      data: {
        applied: true,
        revision: 8,
        manifest_revision: 2,
        conflict_reason: null,
      },
      error: null,
    });

    await expect(applyVaultMutationWithManifestV2({
      baseRevision: 7,
      type: 'delete_item',
      payload: { id: 'item-1', vault_id: 'vault-1' },
      expectedManifestRevision: 1,
      expectedManifestHash: 'old-hash',
      envelope: envelope(),
      manifestHash: 'new-hash',
      previousManifestHash: 'old-hash',
    })).resolves.toEqual({
      applied: true,
      revision: 8,
      manifest_revision: 2,
      conflict_reason: null,
    });

    expect(supabaseMock.rpc).toHaveBeenCalledWith('apply_vault_mutation_v2', expect.objectContaining({
      p_base_revision: 7,
      p_type: 'delete_item',
      p_payload: { id: 'item-1', vault_id: 'vault-1' },
      p_expected_manifest_revision: 1,
      p_expected_manifest_hash: 'old-hash',
      p_manifest_revision: 2,
      p_manifest_hash: 'new-hash',
      p_previous_manifest_hash: 'old-hash',
      p_key_id: 'legacy-kdf-v1',
      p_manifest_envelope: expect.stringMatching(/^sv-vault-manifest-v2:/),
    }));
  });

  it('returns CAS conflicts without converting them to quarantine', async () => {
    supabaseMock.rpc.mockResolvedValueOnce({
      data: {
        applied: false,
        revision: 9,
        manifest_revision: 4,
        conflict_reason: 'stale_manifest_hash',
      },
      error: null,
    });

    await expect(applyVaultMutationWithManifestV2({
      type: 'upsert_category',
      payload: { id: 'cat-1', user_id: 'user-1', name: 'enc:cat:v1:name' },
      expectedManifestRevision: 3,
      expectedManifestHash: 'stale',
      envelope: envelope(),
      manifestHash: 'next',
    })).resolves.toMatchObject({
      applied: false,
      conflict_reason: 'stale_manifest_hash',
    });
  });
});
