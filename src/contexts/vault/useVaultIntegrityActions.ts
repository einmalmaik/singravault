import { useCallback } from 'react';
import type { VaultItemForIntegrity } from '@/extensions/types';
import {
  loadTrustedRecoverySnapshotState,
  resetVaultAfterIntegrityFailureForUser,
} from '@/services/vaultRecoveryOrchestrator';
import {
  refreshVaultIntegrityBaseline,
  verifyVaultIntegrity,
  type VaultIntegrityRuntimeCallbacks,
} from '@/services/vaultIntegrityRuntimeService';
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
  ): Promise<VaultIntegrityVerificationResult | null> => {
    if (!user || !state.encryptionKey) {
      return null;
    }

    return refreshVaultIntegrityBaseline({
      userId: user.id,
      encryptionKey: state.encryptionKey,
      encryptedUserKey: state.encryptedUserKey,
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
    _items: VaultItemForIntegrity[],
  ): Promise<void> => {
    await refreshIntegrityBaseline();
  }, [refreshIntegrityBaseline]);


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
    enterSafeMode,
    exitSafeMode,
    resetVaultAfterIntegrityFailure,
  };
}
