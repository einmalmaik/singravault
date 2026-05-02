import { beforeEach, describe, expect, it } from 'vitest';
import {
  loadManifestHighWaterMark,
  ManifestHighWaterMarkError,
  removeManifestHighWaterMark,
  saveManifestHighWaterMark,
} from '../index';

const USER_ID = 'user-hwm';
const VAULT_ID = 'vault-hwm';
const KEY_ID = 'key-hwm';

describe('Manifest V2 high-water mark store', () => {
  beforeEach(async () => {
    await removeManifestHighWaterMark(USER_ID, VAULT_ID).catch(() => undefined);
  });

  it('adopts a first verified manifest and advances monotonically', async () => {
    await expect(saveManifestHighWaterMark({
      userId: USER_ID,
      vaultId: VAULT_ID,
      manifestRevision: 5,
      manifestHash: 'hash-5',
      keyId: KEY_ID,
    })).resolves.toMatchObject({
      manifestRevision: 5,
      manifestHash: 'hash-5',
    });

    await expect(saveManifestHighWaterMark({
      userId: USER_ID,
      vaultId: VAULT_ID,
      manifestRevision: 6,
      manifestHash: 'hash-6',
      keyId: KEY_ID,
    })).resolves.toMatchObject({
      manifestRevision: 6,
      manifestHash: 'hash-6',
    });

    await expect(loadManifestHighWaterMark(USER_ID, VAULT_ID)).resolves.toMatchObject({
      manifestRevision: 6,
      manifestHash: 'hash-6',
    });
  });

  it('keeps idempotent same revision/hash checks but rejects rollback and forks', async () => {
    await saveManifestHighWaterMark({
      userId: USER_ID,
      vaultId: VAULT_ID,
      manifestRevision: 10,
      manifestHash: 'hash-10',
      keyId: KEY_ID,
    });

    await expect(saveManifestHighWaterMark({
      userId: USER_ID,
      vaultId: VAULT_ID,
      manifestRevision: 10,
      manifestHash: 'hash-10',
      keyId: KEY_ID,
    })).resolves.toMatchObject({ manifestRevision: 10 });

    await expect(saveManifestHighWaterMark({
      userId: USER_ID,
      vaultId: VAULT_ID,
      manifestRevision: 9,
      manifestHash: 'hash-9',
      keyId: KEY_ID,
    })).rejects.toMatchObject({ code: 'revision_rollback' } satisfies Partial<ManifestHighWaterMarkError>);

    await expect(saveManifestHighWaterMark({
      userId: USER_ID,
      vaultId: VAULT_ID,
      manifestRevision: 10,
      manifestHash: 'hash-10-fork',
      keyId: KEY_ID,
    })).rejects.toMatchObject({ code: 'same_revision_hash_mismatch' } satisfies Partial<ManifestHighWaterMarkError>);
  });

  it('does not silently rotate key ids without a verified rotation path', async () => {
    await saveManifestHighWaterMark({
      userId: USER_ID,
      vaultId: VAULT_ID,
      manifestRevision: 1,
      manifestHash: 'hash-1',
      keyId: KEY_ID,
    });

    await expect(saveManifestHighWaterMark({
      userId: USER_ID,
      vaultId: VAULT_ID,
      manifestRevision: 2,
      manifestHash: 'hash-2',
      keyId: 'different-key',
    })).rejects.toMatchObject({ code: 'key_id_mismatch' } satisfies Partial<ManifestHighWaterMarkError>);
  });
});
