import type { OfflineVaultSnapshot } from '@/services/offlineVaultService';
import {
  indexTrustedSnapshotItems,
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
