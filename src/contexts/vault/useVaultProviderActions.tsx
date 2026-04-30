import { useCallback, useRef } from 'react';
import {
  decrypt,
  decryptBytes,
  decryptVaultItem,
  decryptVaultItemForMigration,
  encrypt,
  encryptBytes,
  encryptVaultItem,
  type VaultItemData,
} from '@/services/cryptoService';
import {
  deleteDeviceKey,
  getDeviceKey as loadDeviceKey,
  hasDeviceKey as checkHasDeviceKey,
} from '@/services/deviceKeyService';
import { isNativeDeviceKeyBridgeRuntime } from '@/services/deviceKeyNativeBridge';
import {
  VAULT_PROTECTION_MODE_DEVICE_KEY_REQUIRED,
  createUserKeyMigrationRequiredError,
  normalizeVaultProtectionMode,
  requiresDeviceKey,
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
import { deactivateDeviceKeyProtection } from '@/services/deviceKeyDeactivationService';
import {
  finalizeVaultUnlockIntegrity,
  refreshVaultIntegrityBaseline,
  verifyVaultIntegrity,
  type VaultIntegrityRuntimeCallbacks,
} from '@/services/vaultIntegrityRuntimeService';
import { wipeRuntimeDeviceKey } from '@/services/vaultRuntimeCleanupService';
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
import { isAppOnline, saveOfflineCredentials } from '@/services/offlineVaultService';
import { loadRemoteVaultProfile, type VaultRuntimeCredentials } from '@/services/offlineVaultRuntimeService';
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
    applyCredentialsToState,
    applyTrustedRecoveryState, clearActiveVaultSession, currentDeviceKey, encryptedUserKey,
    encryptionKey, isLocked, kdfVersion, salt, setCurrentDeviceKey, setDeviceKeyActive,
    setEncryptedUserKey, setEncryptionKey, setHasPasskeyUnlock, setIsLoading,
    setKdfVersion, setVaultProtectionMode, setVerificationHash, vaultProtectionMode,
  } = state;
  const vaultProtectionModeRef = useRef<VaultProtectionMode>(vaultProtectionMode);
  vaultProtectionModeRef.current = vaultProtectionMode;
  const isLockedRef = useRef(isLocked);
  isLockedRef.current = isLocked;

  const clearCurrentDeviceKey = useCallback((): void => {
    setCurrentDeviceKey((existingKey) => {
      wipeRuntimeDeviceKey(existingKey);
      return null;
    });
  }, [setCurrentDeviceKey]);

  const refreshRemoteCredentials = useCallback(async (): Promise<VaultRuntimeCredentials | null> => {
    if (!authReady || !user || !isAppOnline()) {
      return null;
    }

    const profile = await loadRemoteVaultProfile(user.id);
    if (!profile.credentials) {
      return null;
    }

    applyCredentialsToState(profile.credentials);
    await saveOfflineCredentials(
      user.id,
      profile.credentials.salt,
      profile.credentials.verificationHash,
      profile.credentials.kdfVersion ?? undefined,
      profile.credentials.encryptedUserKey,
      profile.credentials.vaultProtectionMode,
    );
    return profile.credentials;
  }, [applyCredentialsToState, authReady, user]);

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
      clearCurrentDeviceKey();
      return;
    }

    try {
      const remoteCredentials = await refreshRemoteCredentials();
      const effectiveProtectionMode = remoteCredentials?.vaultProtectionMode ?? vaultProtectionModeRef.current;
      if (!requiresDeviceKey(effectiveProtectionMode)) {
        setDeviceKeyActive(false);
        clearCurrentDeviceKey();
        try {
          await deleteDeviceKey(user.id);
        } catch {
          // Best-effort stale local cleanup only. Remote policy remains authoritative.
        }
        return;
      }

      const hasDeviceKey = await checkHasDeviceKey(user.id);
      setDeviceKeyActive(hasDeviceKey);
      if (hasDeviceKey && !isNativeDeviceKeyBridgeRuntime() && isLockedRef.current) {
        setCurrentDeviceKey(await loadDeviceKey(user.id));
      } else if (!hasDeviceKey) {
        clearCurrentDeviceKey();
      } else {
        setCurrentDeviceKey((existingKey) => existingKey);
      }
    } catch {
      setDeviceKeyActive(false);
      clearCurrentDeviceKey();
    }
  }, [
    clearCurrentDeviceKey,
    refreshRemoteCredentials,
    setCurrentDeviceKey,
    setDeviceKeyActive,
    user,
  ]);

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

    const remoteCredentials = await refreshRemoteCredentials();
    const credentials = remoteCredentials ?? {
      salt: state.salt,
      verificationHash: state.verificationHash,
      kdfVersion: state.kdfVersion,
      encryptedUserKey: state.encryptedUserKey,
      vaultProtectionMode: state.vaultProtectionMode,
    };
    if (!requiresDeviceKey(credentials.vaultProtectionMode)) {
      setDeviceKeyActive(false);
      clearCurrentDeviceKey();
    }

    return unlockVaultWithMasterPassword({
      userId: user.id,
      masterPassword,
      salt: credentials.salt,
      verificationHash: credentials.verificationHash,
      kdfVersion: credentials.kdfVersion ?? state.kdfVersion,
      duressConfig: state.duressConfig,
      encryptedUserKey: credentials.encryptedUserKey,
      vaultProtectionMode: credentials.vaultProtectionMode,
      options,
      getRequiredDeviceKey,
      deriveVaultKdfOutput: (password, deviceKey, deviceKeyAvailable) => deriveVaultKdfOutputWithDeviceKey({
        masterPassword: password,
        salt: credentials.salt,
        kdfVersion: credentials.kdfVersion ?? state.kdfVersion,
        userId: user.id,
        deviceKey,
        deviceKeyAvailable,
      }),
      enforceVaultTwoFactorBeforeKeyRelease,
      finalizeVaultUnlock,
      openDuressVault,
      applyCredentialUpdates,
    });
  }, [
    applyCredentialUpdates,
    enforceVaultTwoFactorBeforeKeyRelease,
    finalizeVaultUnlock,
    getRequiredDeviceKey,
    openDuressVault,
    refreshRemoteCredentials,
    setCurrentDeviceKey,
    setDeviceKeyActive,
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

    const remoteCredentials = await refreshRemoteCredentials();
    const credentials = remoteCredentials ?? {
      salt: state.salt,
      verificationHash: state.verificationHash,
      kdfVersion: state.kdfVersion,
      encryptedUserKey: state.encryptedUserKey,
      vaultProtectionMode: state.vaultProtectionMode,
    };

    return unlockVaultWithPasskey({
      userId: user.id,
      salt: credentials.salt,
      kdfVersion: credentials.kdfVersion ?? state.kdfVersion,
      verificationHash: credentials.verificationHash,
      encryptedUserKey: credentials.encryptedUserKey,
      vaultProtectionMode: credentials.vaultProtectionMode,
      options,
      getRequiredDeviceKey,
      enforceVaultTwoFactorBeforeKeyRelease,
      finalizeVaultUnlock,
      applyCredentialUpdates,
    });
  }, [
    applyCredentialUpdates,
    enforceVaultTwoFactorBeforeKeyRelease,
    finalizeVaultUnlock,
    getRequiredDeviceKey,
    refreshRemoteCredentials,
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
      verificationHash: state.verificationHash,
      currentDeviceKey,
    });

    if (result.state) {
      if (result.state.encryptionKey) {
        setEncryptionKey(result.state.encryptionKey);
      }
      setEncryptedUserKey(result.state.encryptedUserKey);
      setVerificationHash(result.state.verificationHash);
      setKdfVersion(result.state.kdfVersion);
      setCurrentDeviceKey(result.state.currentDeviceKey);
      setDeviceKeyActive(result.state.deviceKeyActive);
      setVaultProtectionMode(result.state.vaultProtectionMode);
    }

    return { error: result.error };
  }, [
    currentDeviceKey,
    encryptedUserKey,
    encryptionKey,
    clearCurrentDeviceKey,
    kdfVersion,
    salt,
    setCurrentDeviceKey,
    setDeviceKeyActive,
    setEncryptedUserKey,
    setEncryptionKey,
    setKdfVersion,
    setVaultProtectionMode,
    setVerificationHash,
    user,
  ]);

  const disableDeviceKey = useCallback(async (
    masterPassword: string,
    twoFactorCode?: string,
    confirmationWord?: string,
  ): Promise<{ error: Error | null }> => {
    if (!user || !salt || state.isLocked) {
      return { error: new Error('Vault must be unlocked') };
    }
    if (!encryptedUserKey) {
      return { error: createUserKeyMigrationRequiredError() };
    }

    const result = await deactivateDeviceKeyProtection({
      userId: user.id,
      masterPassword,
      salt,
      kdfVersion,
      encryptedUserKey,
      currentDeviceKey,
      twoFactorCode,
      confirmationWord: confirmationWord ?? '',
    });

    if (result.state) {
      setEncryptedUserKey(result.state.encryptedUserKey);
      setVerificationHash(result.state.verificationHash);
      setKdfVersion(result.state.kdfVersion);
      setCurrentDeviceKey(result.state.currentDeviceKey);
      setDeviceKeyActive(result.state.deviceKeyActive);
      setVaultProtectionMode(result.state.vaultProtectionMode);
    }

    return { error: result.error };
  }, [
    currentDeviceKey,
    encryptedUserKey,
    kdfVersion,
    salt,
    setCurrentDeviceKey,
    setDeviceKeyActive,
    setEncryptedUserKey,
    setKdfVersion,
    setVaultProtectionMode,
    setVerificationHash,
    state.isLocked,
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
    options?: { source?: VaultSnapshotSource },
  ): Promise<VaultIntegrityVerificationResult | null> => {
    if (!user || !state.encryptionKey) {
      return null;
    }

    return verifyVaultIntegrity({
      userId: user.id,
      encryptionKey: state.encryptionKey,
      snapshot,
      source: options?.source,
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

  const decryptItemForLegacyMigration = useCallback(async (
    encryptedData: string,
    entryId: string,
  ): Promise<{ data: VaultItemData; legacyEnvelopeUsed: boolean; legacyNoAadFallbackUsed: boolean }> => {
    if (!state.encryptionKey) {
      throw new Error('Vault is locked');
    }
    return decryptVaultItemForMigration(encryptedData, state.encryptionKey, entryId);
  }, [state.encryptionKey]);

  return buildVaultContextValue(state, {
    setupMasterPassword,
    unlock,
    unlockWithPasskey,
    lock,
    enableDeviceKey,
    disableDeviceKey,
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
    decryptItemForLegacyMigration,
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
