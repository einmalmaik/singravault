import { useCallback } from 'react';
import type { VaultItemForIntegrity } from '@/extensions/types';
import {
  acceptMissingQuarantinedVaultItem,
  deleteQuarantinedVaultItem,
  loadTrustedRecoverySnapshotState,
  resetVaultAfterIntegrityFailureForUser,
  restoreQuarantinedVaultItem,
} from '@/services/vaultRecoveryOrchestrator';
import {
  refreshVaultIntegrityBaseline,
  verifyVaultIntegrity,
  type VaultIntegrityRuntimeCallbacks,
} from '@/services/vaultIntegrityRuntimeService';
import type { TrustedVaultMutation } from '@/services/vaultIntegrityDecisionEngine';
import type { VaultIntegrityVerificationResult } from '@/services/vaultIntegrityService';
import type { OfflineVaultSnapshot } from '@/services/offlineVaultService';
import type { VaultSnapshotSource } from './vaultContextTypes';

type VaultProviderState = ReturnType<typeof import('./useVaultProviderState').useVaultProviderState>;
type ActiveUser = { id: string } | null;

interface VaultIntegrityActionsInput {
  state: VaultProviderState;
  user: ActiveUser;
  integrityCallbacks: () => VaultIntegrityRuntimeCallbacks;
}

export function useVaultIntegrityActions({
  state,
  user,
  integrityCallbacks,
}: VaultIntegrityActionsInput) {
  const refreshIntegrityBaseline = useCallback(async (
    trustedMutation?: TrustedVaultMutation,
  ): Promise<void> => {
    if (!user || !state.encryptionKey) {
      return;
    }

    await refreshVaultIntegrityBaseline({
      userId: user.id,
      encryptionKey: state.encryptionKey,
      encryptedUserKey: state.encryptedUserKey,
      trustedMutation,
      callbacks: integrityCallbacks(),
    });
  }, [integrityCallbacks, state.encryptedUserKey, state.encryptionKey, user]);

  const verifyIntegrity = useCallback(async (
    snapshot?: OfflineVaultSnapshot,
    options?: { source?: VaultSnapshotSource },
  ): Promise<VaultIntegrityVerificationResult | null> => {
    if (!user || !state.encryptionKey) {
      return null;
    }

    return verifyVaultIntegrity({
      userId: user.id,
      encryptionKey: state.encryptionKey,
      encryptedUserKey: state.encryptedUserKey,
      snapshot,
      source: options?.source,
      callbacks: integrityCallbacks(),
    });
  }, [integrityCallbacks, state.encryptedUserKey, state.encryptionKey, user]);

  const updateIntegrity = useCallback(async (
    items: VaultItemForIntegrity[],
  ): Promise<void> => {
    await refreshIntegrityBaseline({ itemIds: items.map((item) => item.id) });
  }, [refreshIntegrityBaseline]);

  const restoreQuarantinedItem = useCallback(async (
    itemId: string,
  ): Promise<{ error: Error | null }> => {
    if (!user || !state.encryptionKey) {
      return { error: new Error('No active user session') };
    }

    const resolution = state.quarantineResolutionById[itemId];
    const trustedSnapshotItem = state.trustedSnapshotItemsById[itemId];
    if (!resolution?.canRestore || !trustedSnapshotItem) {
      return { error: new Error('Für diesen Eintrag ist keine vertrauenswürdige lokale Kopie verfügbar.') };
    }

    return state.runQuarantineAction(itemId, async () => {
      await restoreQuarantinedVaultItem({
        userId: user.id,
        itemId,
        activeKey: state.encryptionKey!,
        encryptedUserKey: state.encryptedUserKey,
        trustedSnapshotItem,
        refreshIntegrityBaseline: (mutation) => refreshIntegrityBaseline(mutation),
        verifyIntegrity: () => {
          state.removeRuntimeUnreadableItems([itemId]);
          return verifyIntegrity();
        },
      });
      state.bumpVaultDataVersion();
    });
  }, [
    refreshIntegrityBaseline,
    state,
    user,
    verifyIntegrity,
  ]);

  const deleteQuarantinedItem = useCallback(async (
    itemId: string,
  ): Promise<{ error: Error | null }> => {
    if (!user) {
      return { error: new Error('No active user session') };
    }

    const resolution = state.quarantineResolutionById[itemId];
    if (!resolution?.canDelete) {
      return { error: new Error('Dieser Quarantäne-Eintrag kann nicht gelöscht werden.') };
    }

    return state.runQuarantineAction(itemId, async () => {
      await deleteQuarantinedVaultItem({
        userId: user.id,
        itemId,
        reason: resolution.reason,
        verifyIntegrity,
        refreshIntegrityBaseline,
      });
      state.bumpVaultDataVersion();
    });
  }, [refreshIntegrityBaseline, state, user, verifyIntegrity]);

  const acceptMissingQuarantinedItem = useCallback(async (
    itemId: string,
  ): Promise<{ error: Error | null }> => {
    if (!user) {
      return { error: new Error('No active user session') };
    }

    const resolution = state.quarantineResolutionById[itemId];
    if (!resolution?.canAcceptMissing) {
      return { error: new Error('Dieser Quarantäne-Eintrag kann nicht bestätigt werden.') };
    }

    return state.runQuarantineAction(itemId, async () => {
      await acceptMissingQuarantinedVaultItem({
        itemId,
        refreshIntegrityBaseline,
      });
      state.bumpVaultDataVersion();
    });
  }, [refreshIntegrityBaseline, state, user]);

  const enterSafeMode = useCallback(async (): Promise<{ error: Error | null }> => {
    if (!user || !state.encryptionKey) {
      return { error: new Error('Safe Mode requires an active recovery session.') };
    }

    const trustedState = await loadTrustedRecoverySnapshotState(user.id);
    if (!trustedState.trustedSnapshot) {
      return { error: new Error('No trusted local recovery snapshot is available on this device.') };
    }

    state.applyTrustedRecoveryState(trustedState);
    state.setIntegrityMode('safe');
    state.setPendingSessionRestore(false);
    return { error: null };
  }, [state, user]);

  const exitSafeMode = useCallback(() => {
    state.setIntegrityMode(state.integrityBlockedReason ? 'blocked' : 'healthy');
  }, [state]);

  const resetVaultAfterIntegrityFailure = useCallback(async (): Promise<{ error: Error | null }> => {
    if (!user) {
      return { error: new Error('No active user session') };
    }

    const result = await resetVaultAfterIntegrityFailureForUser(user.id);
    if (result.error) {
      return result;
    }

    state.resetVaultState();
    state.setIsSetupRequired(true);
    state.setIsLoading(false);
    return { error: null };
  }, [state, user]);

  return {
    refreshIntegrityBaseline,
    verifyIntegrity,
    updateIntegrity,
    restoreQuarantinedItem,
    deleteQuarantinedItem,
    acceptMissingQuarantinedItem,
    enterSafeMode,
    exitSafeMode,
    resetVaultAfterIntegrityFailure,
  };
}
