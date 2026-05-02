import { useCallback } from 'react';
import {
  decrypt,
  decryptBytes,
  encrypt,
  encryptBytes,
  type VaultItemData,
} from '@/services/cryptoService';
import { assertItemDecryptable } from '@/services/vaultQuarantineOrchestrator';
import {
  decryptProductVaultItem,
  decryptProductVaultItemForMigration,
  encryptProductVaultItemV2,
} from '@/services/vaultIntegrityV2/productItemEnvelope';
import { decryptTrustedRecoverySnapshotItem as decryptTrustedRecoverySnapshotItemFromService } from '@/services/vaultIntegrityV2/safeModeDecrypt';
import type { OfflineVaultSnapshot } from '@/services/offlineVaultService';

type VaultProviderState = ReturnType<typeof import('./useVaultProviderState').useVaultProviderState>;
type ActiveUser = { id: string } | null;

export function useVaultCryptoActions(state: VaultProviderState, user: ActiveUser) {
  const encryptData = useCallback(async (plaintext: string, aad?: string): Promise<string> => {
    if (!state.encryptionKey) {
      throw new Error('Vault is locked');
    }
    return encrypt(plaintext, state.encryptionKey, aad);
  }, [state.encryptionKey]);

  const decryptData = useCallback(async (encrypted: string, aad?: string): Promise<string> => {
    if (!state.encryptionKey) {
      throw new Error('Vault is locked');
    }
    return decrypt(encrypted, state.encryptionKey, aad);
  }, [state.encryptionKey]);

  const encryptBinary = useCallback(async (plaintext: Uint8Array, aad?: string): Promise<string> => {
    if (!state.encryptionKey) {
      throw new Error('Vault is locked');
    }
    return encryptBytes(plaintext, state.encryptionKey, aad);
  }, [state.encryptionKey]);

  const decryptBinary = useCallback(async (encrypted: string, aad?: string): Promise<Uint8Array> => {
    if (!state.encryptionKey) {
      throw new Error('Vault is locked');
    }
    return decryptBytes(encrypted, state.encryptionKey, aad);
  }, [state.encryptionKey]);

  const encryptItem = useCallback(async (data: VaultItemData, entryId: string): Promise<string> => {
    if (!state.encryptionKey) {
      throw new Error('Vault is locked');
    }
    if (!user) {
      throw new Error('No active user session');
    }
    return encryptProductVaultItemV2({
      userId: user.id,
      encryptedUserKey: state.encryptedUserKey,
      vaultKey: state.encryptionKey,
      data,
      entryId,
    });
  }, [state.encryptedUserKey, state.encryptionKey, user]);

  const decryptItem = useCallback(async (encryptedData: string, entryId: string): Promise<VaultItemData> => {
    if (!state.encryptionKey) {
      throw new Error('Vault is locked');
    }
    assertItemDecryptable({
      mode: state.integrityMode,
      quarantinedItems: state.quarantinedItems,
      itemId: entryId,
    });
    return decryptProductVaultItem({
      encryptedData,
      vaultKey: state.encryptionKey,
      entryId,
    });
  }, [state.encryptionKey, state.integrityMode, state.quarantinedItems]);

  const decryptItemForLegacyMigration = useCallback(async (
    encryptedData: string,
    entryId: string,
  ): Promise<{ data: VaultItemData; legacyEnvelopeUsed: boolean; legacyNoAadFallbackUsed: boolean }> => {
    if (!state.encryptionKey) {
      throw new Error('Vault is locked');
    }
    assertItemDecryptable({
      mode: state.integrityMode,
      quarantinedItems: state.quarantinedItems,
      itemId: entryId,
    });
    return decryptProductVaultItemForMigration({
      encryptedData,
      vaultKey: state.encryptionKey,
      entryId,
    });
  }, [state.encryptionKey, state.integrityMode, state.quarantinedItems]);

  const decryptTrustedRecoverySnapshotItem = useCallback(async (
    item: OfflineVaultSnapshot['items'][number],
    snapshotId: string,
    vaultId: string,
  ): Promise<VaultItemData> => {
    if (!state.encryptionKey) {
      throw new Error('Vault is locked');
    }
    if (!user) {
      throw new Error('No active user session');
    }
    if (!vaultId) {
      throw new Error('Trusted recovery snapshot is missing vault scope.');
    }

    return decryptTrustedRecoverySnapshotItemFromService({
      item,
      vaultKey: state.encryptionKey,
      context: {
        source: 'trusted_recovery_snapshot',
        reason: 'safe_mode_export',
        snapshotId,
        userId: user.id,
        vaultId,
      },
    });
  }, [state.encryptionKey, user]);

  return {
    encryptData,
    decryptData,
    encryptBinary,
    decryptBinary,
    encryptItem,
    decryptItem,
    decryptItemForLegacyMigration,
    decryptTrustedRecoverySnapshotItem,
  };
}
