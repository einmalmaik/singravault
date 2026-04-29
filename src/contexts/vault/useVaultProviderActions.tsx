import { useCallback, useRef } from 'react';
import {
  decrypt,
  decryptBytes,
  decryptVaultItem,
  encrypt,
  encryptBytes,
  encryptVaultItem,
  type VaultItemData,
} from '@/services/cryptoService';
import {
  getDeviceKey as loadDeviceKey,
  hasDeviceKey as checkHasDeviceKey,
} from '@/services/deviceKeyService';
import { isNativeDeviceKeyBridgeRuntime } from '@/services/deviceKeyNativeBridge';
import {
  VAULT_PROTECTION_MODE_DEVICE_KEY_REQUIRED,
  createUserKeyMigrationRequiredError,
  normalizeVaultProtectionMode,
  type VaultProtectionMode,
} from '@/services/deviceKeyProtectionPolicy';
import { listPasskeys, isWebAuthnAvailable } from '@/services/passkeyService';
import { useAuth } from '../AuthContext';
import {
  resolveRequiredDeviceKey,
  deriveVaultKdfOutputWithDeviceKey,
} from '@/services/deviceKeyUnlockOrchestrator';
import { enforceVaultTwoFactorBeforeKeyRelease as enforceVaultTwoFactorGate } from '@/services/vaultUnlockOrchestrator';
import { markVaultSessionActive, clearVaultSessionMarkers } from '@/services/vaultRuntimeFacade';
import { assertItemDecryptable } from '@/services/vaultQuarantineOrchestrator';
import { setupInitialVault } from '@/services/vaultSetupOrchestrator';
import { activateDeviceKeyProtection } from '@/services/deviceKeyActivationService';
import {
  finalizeVaultUnlockIntegrity,
  refreshVaultIntegrityBaseline,
  verifyVaultIntegrity,
  type VaultIntegrityRuntimeCallbacks,
} from '@/services/vaultIntegrityRuntimeService';
import {
  acceptMissingQuarantinedVaultItem,
  deleteQuarantinedVaultItem,
  loadTrustedRecoverySnapshotState,
  resetVaultAfterIntegrityFailureForUser,
  restoreQuarantinedVaultItem,
} from '@/services/vaultRecoveryOrchestrator';
import {
  getPasskeyWrappingMaterialForVault,
  unlockVaultWithPasskey,
} from '@/services/vaultPasskeyUnlockService';
import { unlockVaultWithMasterPassword } from '@/services/vaultMasterUnlockService';
import type { TrustedVaultMutation } from '@/services/vaultIntegrityDecisionEngine';
import type {
  QuarantinedVaultItem,
  VaultIntegrityBlockedReason,
  VaultIntegrityVerificationResult,
} from '@/services/vaultIntegrityService';
import type { OfflineVaultSnapshot } from '@/services/offlineVaultService';
import type { VaultItemForIntegrity } from '@/extensions/types';
import { buildVaultContextValue } from './buildVaultContextValue';
import { useVaultProviderState } from './useVaultProviderState';
import { useVaultLifecycleEffects } from './useVaultLifecycleEffects';
import type { VaultContextType, VaultSnapshotSource, VaultUnlockOptions } from './vaultContextTypes';

export function useVaultProviderActions(): VaultContextType {
  const { user, authReady } = useAuth();
  const lastUserIdRef = useRef<string | null>(null);
  const state = useVaultProviderState();
  const webAuthnAvailable = isWebAuthnAvailable();
  const {
    applyTrustedRecoveryState, clearActiveVaultSession, currentDeviceKey, encryptedUserKey,
    encryptionKey, kdfVersion, salt, setCurrentDeviceKey, setDeviceKeyActive,
    setEncryptedUserKey, setEncryptionKey, setHasPasskeyUnlock, setIsLoading,
    setKdfVersion, setVaultProtectionMode, setVerificationHash, vaultProtectionMode,
  } = state;

  const refreshPasskeyUnlockStatus = useCallback(async (): Promise<void> => {
    if (!authReady || !user) {
      setHasPasskeyUnlock(false);
      return;
    }

    console.debug('[VaultContext] authReady is true, refreshing passkey unlock status...');

    try {
      const passkeys = await listPasskeys();
      setHasPasskeyUnlock(passkeys.some((passkey) => passkey.prf_enabled));
    } catch {
      setHasPasskeyUnlock(false);
    }
  }, [authReady, setHasPasskeyUnlock, user]);

  const refreshDeviceKeyState = useCallback(async (): Promise<void> => {
    if (!user) {
      setDeviceKeyActive(false);
      setCurrentDeviceKey(null);
      return;
    }

    try {
      const hasDeviceKey = await checkHasDeviceKey(user.id);
      setDeviceKeyActive(hasDeviceKey);
      if (hasDeviceKey && !isNativeDeviceKeyBridgeRuntime()) {
        setCurrentDeviceKey(await loadDeviceKey(user.id));
      } else {
        setCurrentDeviceKey(null);
      }
    } catch {
      setDeviceKeyActive(false);
      setCurrentDeviceKey(null);
    }
  }, [setCurrentDeviceKey, setDeviceKeyActive, user]);

  const getRequiredDeviceKey = useCallback(async () => {
    let loadedDeviceKey: Uint8Array | null = null;
    const result = await resolveRequiredDeviceKey({
      userId: user?.id,
      vaultProtectionMode,
      cachedDeviceKey: currentDeviceKey,
      hasDeviceKey: checkHasDeviceKey,
      loadDeviceKey: async (userId) => {
        loadedDeviceKey = await loadDeviceKey(userId);
        return loadedDeviceKey;
      },
    });

    if (result.deviceKeyAvailable) {
      setDeviceKeyActive(true);
    }
    if (loadedDeviceKey) {
      setCurrentDeviceKey(loadedDeviceKey);
    }

    return result;
  }, [
    currentDeviceKey,
    setCurrentDeviceKey,
    setDeviceKeyActive,
    vaultProtectionMode,
    user?.id,
  ]);

  const deriveVaultKdfOutput = useCallback(async (
    masterPassword: string,
    deviceKey: Uint8Array | null,
    deviceKeyAvailable: boolean,
  ): Promise<Uint8Array> => {
    if (!state.salt) {
      throw new Error('Vault not set up');
    }

    return deriveVaultKdfOutputWithDeviceKey({
      masterPassword,
      salt: state.salt,
      kdfVersion: state.kdfVersion,
      userId: user?.id,
      deviceKey,
      deviceKeyAvailable,
    });
  }, [state.kdfVersion, state.salt, user?.id]);

  const applyCredentialUpdates = useCallback(async (updates: {
    verificationHash?: string;
    kdfVersion?: number;
    encryptedUserKey?: string | null;
  }): Promise<void> => {
    if (updates.verificationHash !== undefined) {
      setVerificationHash(updates.verificationHash);
    }
    if (updates.kdfVersion !== undefined) {
      setKdfVersion(updates.kdfVersion);
    }
    if (updates.encryptedUserKey !== undefined) {
      setEncryptedUserKey(updates.encryptedUserKey);
    }
  }, [setEncryptedUserKey, setKdfVersion, setVerificationHash]);

  const applyTrustedRecoveryStateForUser = useCallback(async (userId: string): Promise<void> => {
    applyTrustedRecoveryState(await loadTrustedRecoverySnapshotState(userId));
  }, [applyTrustedRecoveryState]);

  const setBlockedIntegrityState = useCallback(async (
    activeKey: CryptoKey,
    blockedReason: VaultIntegrityBlockedReason,
    result?: VaultIntegrityVerificationResult | null,
  ) => {
    const displayedResult = state.buildDisplayedIntegrityResult(result ?? null);
    state.setEncryptionKey(activeKey);
    state.setIsLocked(true);
    state.setIsDuressMode(false);
    state.setPendingSessionRestore(false);
    state.setIntegrityVerified(true);
    state.baseIntegrityResultRef.current = result ?? null;
    state.setIntegrityMode('blocked');
    state.setIntegrityBlockedReason(blockedReason);
    state.setQuarantinedItems(displayedResult?.quarantinedItems ?? []);
    state.setLastIntegrityResult(displayedResult);
    state.setLastActivity(Date.now());
    clearVaultSessionMarkers(sessionStorage);
    if (user) {
      await applyTrustedRecoveryStateForUser(user.id);
    }
  }, [applyTrustedRecoveryStateForUser, state, user]);

  const integrityCallbacks = useCallback((): VaultIntegrityRuntimeCallbacks => ({
    applyIntegrityResultState: state.applyIntegrityResultState,
    applyTrustedRecoveryState: state.applyTrustedRecoveryState,
    setBlockedIntegrityState,
    bumpVaultDataVersion: state.bumpVaultDataVersion,
  }), [
    setBlockedIntegrityState,
    state.applyIntegrityResultState,
    state.applyTrustedRecoveryState,
    state.bumpVaultDataVersion,
  ]);

  const finalizeVaultUnlock = useCallback(async (
    activeKey: CryptoKey,
  ): Promise<{ error: Error | null }> => {
    if (!user) {
      return { error: new Error('No active user session') };
    }

    const integrityResult = await finalizeVaultUnlockIntegrity({
      userId: user.id,
      activeKey,
      callbacks: integrityCallbacks(),
    });
    if (integrityResult.error) {
      return integrityResult;
    }

    state.setEncryptionKey(activeKey);
    state.setIsLocked(false);
    state.setIsDuressMode(false);
    state.setIntegrityBlockedReason(null);
    state.setLastActivity(Date.now());
    markVaultSessionActive(sessionStorage);
    state.setPendingSessionRestore(false);
    return { error: null };
  }, [integrityCallbacks, state, user]);

  const enforceVaultTwoFactorBeforeKeyRelease = useCallback(async (
    options?: VaultUnlockOptions,
  ): Promise<{ error: Error | null }> => {
    if (!user) {
      return { error: new Error('No active user session') };
    }

    return enforceVaultTwoFactorGate({ userId: user.id, options });
  }, [user]);

  const openDuressVault = useCallback((activeKey: CryptoKey): void => {
    state.setEncryptionKey(activeKey);
    state.setIsDuressMode(true);
    state.setIsLocked(false);
    state.setIntegrityVerified(false);
    state.baseIntegrityResultRef.current = null;
    state.setLastIntegrityResult(null);
    state.setIntegrityMode('healthy');
    state.setQuarantinedItems([]);
    state.runtimeUnreadableItemsRef.current = [];
    state.setIntegrityBlockedReason(null);
    state.setLastActivity(Date.now());
    markVaultSessionActive(sessionStorage);
    state.setPendingSessionRestore(false);
  }, [state]);

  const setupMasterPassword = useCallback(async (
    masterPassword: string,
  ): Promise<{ error: Error | null }> => {
    if (!user) {
      return { error: new Error('No user logged in') };
    }

    const result = await setupInitialVault({ userId: user.id, masterPassword });
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
    return result.activeUserKey
      ? finalizeVaultUnlock(result.activeUserKey)
      : { error: null };
  }, [finalizeVaultUnlock, state, user]);

  const unlock = useCallback(async (
    masterPassword: string,
    options?: VaultUnlockOptions,
  ): Promise<{ error: Error | null }> => {
    if (!user || !state.salt) {
      return { error: new Error('Vault not set up') };
    }

    return unlockVaultWithMasterPassword({
      userId: user.id,
      masterPassword,
      salt: state.salt,
      verificationHash: state.verificationHash,
      kdfVersion: state.kdfVersion,
      duressConfig: state.duressConfig,
      encryptedUserKey: state.encryptedUserKey,
      vaultProtectionMode: state.vaultProtectionMode,
      options,
      getRequiredDeviceKey,
      deriveVaultKdfOutput,
      enforceVaultTwoFactorBeforeKeyRelease,
      finalizeVaultUnlock,
      openDuressVault,
      applyCredentialUpdates,
    });
  }, [
    applyCredentialUpdates,
    deriveVaultKdfOutput,
    enforceVaultTwoFactorBeforeKeyRelease,
    finalizeVaultUnlock,
    getRequiredDeviceKey,
    openDuressVault,
    state.duressConfig,
    state.encryptedUserKey,
    state.kdfVersion,
    state.salt,
    state.vaultProtectionMode,
    state.verificationHash,
    user,
  ]);

  const unlockWithPasskey = useCallback(async (
    options?: VaultUnlockOptions,
  ): Promise<{ error: Error | null }> => {
    if (!user) {
      console.warn('unlockWithPasskey called without active user session');
      return { error: new Error('User session not ready. Please wait a moment.') };
    }

    return unlockVaultWithPasskey({
      userId: user.id,
      salt: state.salt,
      kdfVersion: state.kdfVersion,
      verificationHash: state.verificationHash,
      encryptedUserKey: state.encryptedUserKey,
      vaultProtectionMode: state.vaultProtectionMode,
      options,
      enforceVaultTwoFactorBeforeKeyRelease,
      finalizeVaultUnlock,
      applyCredentialUpdates,
    });
  }, [
    applyCredentialUpdates,
    enforceVaultTwoFactorBeforeKeyRelease,
    finalizeVaultUnlock,
    state.encryptedUserKey,
    state.kdfVersion,
    state.salt,
    state.vaultProtectionMode,
    state.verificationHash,
    user,
  ]);

  const getPasskeyWrappingMaterial = useCallback(async (
    masterPassword: string,
  ): Promise<Uint8Array | null> => {
    if (!user || !state.salt || state.isLocked) {
      return null;
    }

    return getPasskeyWrappingMaterialForVault({
      userId: user.id,
      masterPassword,
      salt: state.salt,
      kdfVersion: state.kdfVersion,
      verificationHash: state.verificationHash,
      encryptedUserKey: state.encryptedUserKey,
      getRequiredDeviceKey,
      deriveVaultKdfOutput,
    });
  }, [
    deriveVaultKdfOutput,
    getRequiredDeviceKey,
    state.encryptedUserKey,
    state.isLocked,
    state.kdfVersion,
    state.salt,
    state.verificationHash,
    user,
  ]);

  const lock = useCallback(() => {
    clearActiveVaultSession();
    setIsLoading(false);
  }, [clearActiveVaultSession, setIsLoading]);

  useVaultLifecycleEffects({
    user,
    authReady,
    state,
    lastUserIdRef,
    lock,
    refreshPasskeyUnlockStatus,
    refreshDeviceKeyState,
  });

  const enableDeviceKey = useCallback(async (
    masterPassword: string,
  ): Promise<{ error: Error | null }> => {
    if (!user || !salt || !encryptionKey) {
      return { error: new Error('Vault must be unlocked') };
    }
    if (!encryptedUserKey) {
      return { error: createUserKeyMigrationRequiredError() };
    }

    const result = await activateDeviceKeyProtection({
      userId: user.id,
      masterPassword,
      salt,
      kdfVersion,
      encryptionKey,
      encryptedUserKey,
      currentDeviceKey,
    });

    if (result.state) {
      if (result.state.encryptionKey) {
        setEncryptionKey(result.state.encryptionKey);
      }
      setEncryptedUserKey(result.state.encryptedUserKey);
      setVerificationHash(result.state.verificationHash);
      setCurrentDeviceKey(result.state.currentDeviceKey);
      setDeviceKeyActive(result.state.deviceKeyActive);
      setVaultProtectionMode(result.state.vaultProtectionMode);
    }

    return { error: result.error };
  }, [
    currentDeviceKey,
    encryptedUserKey,
    encryptionKey,
    kdfVersion,
    salt,
    setCurrentDeviceKey,
    setDeviceKeyActive,
    setEncryptedUserKey,
    setEncryptionKey,
    setVaultProtectionMode,
    setVerificationHash,
    user,
  ]);

  const refreshIntegrityBaseline = useCallback(async (
    trustedMutation?: TrustedVaultMutation,
  ): Promise<void> => {
    if (!user || !state.encryptionKey) {
      return;
    }

    await refreshVaultIntegrityBaseline({
      userId: user.id,
      encryptionKey: state.encryptionKey,
      trustedMutation,
      callbacks: integrityCallbacks(),
    });
  }, [integrityCallbacks, state.encryptionKey, user]);

  const verifyIntegrity = useCallback(async (
    snapshot?: OfflineVaultSnapshot,
    _options?: { source?: VaultSnapshotSource },
  ): Promise<VaultIntegrityVerificationResult | null> => {
    if (!user || !state.encryptionKey) {
      return null;
    }

    return verifyVaultIntegrity({
      userId: user.id,
      encryptionKey: state.encryptionKey,
      snapshot,
      callbacks: integrityCallbacks(),
    });
  }, [integrityCallbacks, state.encryptionKey, user]);

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
        trustedSnapshotItem,
        verifyIntegrity,
      });
      state.bumpVaultDataVersion();
    });
  }, [
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
    return encryptVaultItem(data, state.encryptionKey, entryId);
  }, [state.encryptionKey]);

  const decryptItem = useCallback(async (encryptedData: string, entryId: string): Promise<VaultItemData> => {
    if (!state.encryptionKey) {
      throw new Error('Vault is locked');
    }
    assertItemDecryptable(state.quarantinedItems, entryId);
    return decryptVaultItem(encryptedData, state.encryptionKey, entryId);
  }, [state.encryptionKey, state.quarantinedItems]);

  return buildVaultContextValue(state, {
    setupMasterPassword,
    unlock,
    unlockWithPasskey,
    lock,
    enableDeviceKey,
    refreshDeviceKeyState,
    webAuthnAvailable,
    refreshPasskeyUnlockStatus,
    getPasskeyWrappingMaterial,
    encryptData,
    decryptData,
    encryptBinary,
    decryptBinary,
    encryptItem,
    decryptItem,
    verifyIntegrity,
    updateIntegrity,
    refreshIntegrityBaseline,
    reportUnreadableItems: state.reportUnreadableItems,
    enterSafeMode,
    restoreQuarantinedItem,
    deleteQuarantinedItem,
    acceptMissingQuarantinedItem,
    exitSafeMode,
    resetVaultAfterIntegrityFailure,
  });
}
