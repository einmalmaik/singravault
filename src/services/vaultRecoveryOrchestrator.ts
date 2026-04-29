import { decryptVaultItem } from '@/services/cryptoService';
import { isAppOnline, type OfflineVaultSnapshot } from '@/services/offlineVaultService';
import {
  deleteQuarantinedItemFromVault,
  indexTrustedSnapshotItems,
  restoreQuarantinedItemFromTrustedSnapshot,
  type TrustedSnapshotItemsById,
} from '@/services/vaultQuarantineRecoveryService';
import { getTrustedOfflineSnapshot, saveTrustedOfflineSnapshot } from '@/services/offlineVaultService';
import { resetUserVaultState } from '@/services/vaultRecoveryService';

export interface TrustedRecoverySnapshotState {
  trustedRecoveryAvailable: boolean;
  trustedSnapshotItemsById: TrustedSnapshotItemsById;
  trustedSnapshot: OfflineVaultSnapshot | null;
}

type TrustedSnapshotItem = TrustedSnapshotItemsById[string];

export async function loadTrustedRecoverySnapshotState(
  userId: string,
): Promise<TrustedRecoverySnapshotState> {
  const trustedSnapshot = await getTrustedOfflineSnapshot(userId);
  return {
    trustedRecoveryAvailable: Boolean(trustedSnapshot),
    trustedSnapshotItemsById: indexTrustedSnapshotItems(trustedSnapshot),
    trustedSnapshot,
  };
}

export async function persistTrustedRecoverySnapshot(
  snapshot: OfflineVaultSnapshot,
): Promise<TrustedRecoverySnapshotState> {
  await saveTrustedOfflineSnapshot(snapshot);
  return {
    trustedRecoveryAvailable: true,
    trustedSnapshotItemsById: indexTrustedSnapshotItems(snapshot),
    trustedSnapshot: snapshot,
  };
}

export async function restoreQuarantinedVaultItem(input: {
  userId: string;
  itemId: string;
  activeKey: CryptoKey;
  trustedSnapshotItem: TrustedSnapshotItem;
  verifyIntegrity: () => Promise<{ quarantinedItems: Array<{ id: string }> } | null>;
}): Promise<void> {
  try {
    await decryptVaultItem(input.trustedSnapshotItem.encrypted_data, input.activeKey, input.itemId);
  } catch {
    throw new Error('Die lokale Wiederherstellungskopie für diesen Eintrag ist nicht mehr entschlüsselbar.');
  }

  const { syncedOnline } = await restoreQuarantinedItemFromTrustedSnapshot(
    input.userId,
    input.trustedSnapshotItem,
  );
  if (isAppOnline() && !syncedOnline) {
    throw new Error('Die Wiederherstellung konnte nicht mit dem Server synchronisiert werden.');
  }

  const integrityResult = await input.verifyIntegrity();
  if (integrityResult?.quarantinedItems.some((quarantinedItem) => quarantinedItem.id === input.itemId)) {
    throw new Error('Die Wiederherstellung konnte nicht bestätigt werden. Der Eintrag bleibt in Quarantäne.');
  }
}

export async function deleteQuarantinedVaultItem(input: {
  userId: string;
  itemId: string;
  reason: string;
  verifyIntegrity: () => Promise<unknown>;
  refreshIntegrityBaseline: (mutation: { itemIds: string[] }) => Promise<void>;
}): Promise<void> {
  const { syncedOnline } = await deleteQuarantinedItemFromVault(input.userId, input.itemId);
  if (isAppOnline() && !syncedOnline) {
    throw new Error('Der Quarantäne-Eintrag konnte nicht mit dem Server synchronisiert gelöscht werden.');
  }

  if (input.reason === 'ciphertext_changed') {
    await input.refreshIntegrityBaseline({ itemIds: [input.itemId] });
  } else {
    await input.verifyIntegrity();
  }
}

export async function acceptMissingQuarantinedVaultItem(input: {
  itemId: string;
  refreshIntegrityBaseline: (mutation: { itemIds: string[] }) => Promise<void>;
}): Promise<void> {
  await input.refreshIntegrityBaseline({ itemIds: [input.itemId] });
}

export async function resetVaultAfterIntegrityFailureForUser(
  userId: string,
): Promise<{ error: Error | null }> {
  try {
    await resetUserVaultState(userId);
    return { error: null };
  } catch (error) {
    return {
      error: error instanceof Error ? error : new Error('Vault reset failed.'),
    };
  }
}
