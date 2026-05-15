import { useCallback } from 'react';
import {
  VAULT_PROTECTION_MODE_DEVICE_KEY_REQUIRED,
  normalizeVaultProtectionMode,
} from '@/services/deviceKeyProtectionPolicy';
import { setupInitialVault } from '@/services/vaultSetupOrchestrator';
import type { useVaultProviderState } from './useVaultProviderState';

type VaultProviderState = ReturnType<typeof useVaultProviderState>;

export function useVaultSetupActions({
  finalizeVaultUnlock,
  state,
  userId,
}: {
  finalizeVaultUnlock: (
    activeKey: CryptoKey,
    vaultEncryptionKey?: Uint8Array,
  ) => Promise<{ error: Error | null }>;
  state: VaultProviderState;
  userId?: string;
}) {
  return useCallback(async (
    masterPassword: string,
  ): Promise<{ error: Error | null }> => {
    if (!userId) {
      return { error: new Error('No user logged in') };
    }

    const result = await setupInitialVault({ userId, masterPassword });
    if (result.credentials) {
      state.applyCredentialsToState(result.credentials);
    }
    if (result.existingProfileSalt) {
      state.setIsSetupRequired(false);
      state.setSalt(result.existingProfileSalt);
    }
    if (result.error) {
      return { error: result.error };
    }

    state.setVaultProtectionMode(VAULT_PROTECTION_MODE_DEVICE_KEY_REQUIRED === result.credentials?.vaultProtectionMode
      ? VAULT_PROTECTION_MODE_DEVICE_KEY_REQUIRED
      : normalizeVaultProtectionMode(result.credentials?.vaultProtectionMode));
    state.setIsSetupRequired(false);
    if (!result.activeUserKey) {
      return { error: null };
    }

    const finalizeResult = await finalizeVaultUnlock(result.activeUserKey, result.vaultEncryptionKey);
    if (!finalizeResult.error && result.vaultEncryptionKey) {
      state.setVaultEncryptionKey(result.vaultEncryptionKey);
    }
    return finalizeResult;
  }, [finalizeVaultUnlock, state, userId]);
}
