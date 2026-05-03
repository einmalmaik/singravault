import { useCallback, useRef } from 'react';
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
import { setupInitialVault } from '@/services/vaultSetupOrchestrator';
import { activateDeviceKeyProtection } from '@/services/deviceKeyActivationService';
import { deactivateDeviceKeyProtection } from '@/services/deviceKeyDeactivationService';
import {
  finalizeVaultUnlockIntegrity,
  type VaultIntegrityRuntimeCallbacks,
} from '@/services/vaultIntegrityRuntimeService';
import { wipeRuntimeDeviceKey } from '@/services/vaultRuntimeCleanupService';
import {
  getPasskeyWrappingMaterialForVault,
  unlockVaultWithPasskey,
} from '@/services/vaultPasskeyUnlockService';
import { unlockVaultWithMasterPassword } from '@/services/vaultMasterUnlockService';
import { loadTrustedRecoverySnapshotState } from '@/services/vaultRecoveryOrchestrator';
import type {
  VaultIntegrityBlockedReason,
  VaultIntegrityVerificationResult,
} from '@/services/vaultIntegrityService';
import { isAppOnline, saveOfflineCredentials } from '@/services/offlineVaultService';
import { loadRemoteVaultProfile, type VaultRuntimeCredentials } from '@/services/offlineVaultRuntimeService';
import { buildVaultContextValue } from './buildVaultContextValue';
import { useVaultCryptoActions } from './useVaultCryptoActions';
import { useVaultIntegrityActions } from './useVaultIntegrityActions';
import { useVaultProviderState } from './useVaultProviderState';
import { useVaultLifecycleEffects } from './useVaultLifecycleEffects';
import type { VaultContextType, VaultUnlockOptions } from './vaultContextTypes';

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
      encryptedUserKey: state.encryptedUserKey,
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
    clearCurrentDeviceKey,
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
    kdfVersion,
    salt,
    setCurrentDeviceKey,
    setDeviceKeyActive,
    setEncryptedUserKey,
    setEncryptionKey,
    setKdfVersion,
    setVaultProtectionMode,
    setVerificationHash,
    state.verificationHash,
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

  const {
    refreshIntegrityBaseline,
    verifyIntegrity,
    updateIntegrity,
    restoreQuarantinedItem,
    deleteQuarantinedItem,
    acceptMissingQuarantinedItem,
    enterSafeMode,
    exitSafeMode,
    resetVaultAfterIntegrityFailure,
  } = useVaultIntegrityActions({ state, user, integrityCallbacks });

  const {
    encryptData,
    decryptData,
    encryptBinary,
    decryptBinary,
    encryptItem,
    decryptItem,
    decryptItemForLegacyMigration,
    decryptTrustedRecoverySnapshotItem,
  } = useVaultCryptoActions(state, user);

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
    decryptTrustedRecoverySnapshotItem,
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
