import { useCallback, useRef } from 'react';
import {
  deleteDeviceKey,
  getDeviceKey as loadDeviceKey,
  hasDeviceKey as checkHasDeviceKey,
} from '@/services/deviceKeyService';
import { isNativeDeviceKeyBridgeRuntime } from '@/services/deviceKeyNativeBridge';
import {
  createUserKeyMigrationRequiredError,
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
import { useVaultMigrationActions } from './useVaultMigrationActions';
import { useVaultOpLogCrudActions } from './useVaultOpLogCrudActions';
import { useCollectionOpLogActions } from './useCollectionOpLogActions';
import { useVaultProviderState } from './useVaultProviderState';
import { useVaultLifecycleEffects } from './useVaultLifecycleEffects';
import { useVaultOpLogUiState } from './useVaultOpLogUiState';
import { useVaultRevokedDeviceAutoLock } from './useVaultRevokedDeviceAutoLock';
import { useVaultSetupActions } from './useVaultSetupActions';
import type { VaultContextType, VaultUnlockOptions } from './vaultContextTypes';
import { evaluateVaultMigrationGate } from '@/services/vaultOpLog/vaultMigrationRolloutService';
import { loadVaultHealthAnalysisItems } from '@/services/vaultHealthAnalysisItemsService';
import {
  findLegacyDuressDecoyCandidates as findLegacyDuressDecoyCandidatesService,
  purgeLegacyDuressDecoyItems as purgeLegacyDuressDecoyItemsService,
} from '@/services/legacyDuressDecoyCleanupService';
import { synthesizeDuressVaultItems } from '@/services/duressDecoyItemSynthesisService';
import { getServiceHooks } from '@/extensions/registry';

function clearLegacyIntegrityStateAfterOpLogGate(
  state: ReturnType<typeof useVaultProviderState>,
): void {
  state.setIntegrityVerified(true);
  state.baseIntegrityResultRef.current = null;
  state.setLastIntegrityResult(null);
  state.setIntegrityMode('healthy');
  state.setQuarantinedItems([]);
  state.runtimeUnreadableItemsRef.current = [];
  state.setIntegrityBlockedReason(null);
}

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
    setKdfVersion, setVaultEncryptionKey, setVaultProtectionMode, setVerificationHash, vaultProtectionMode,
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
      // `listPasskeys` returns every credential across all RP-IDs so the
      // settings UI can manage them. For "can the user actually unlock
      // on this device?" we must filter by both PRF support AND the
      // current-RP flag — otherwise a PRF passkey registered only on
      // another platform would falsely enable the unlock-with-passkey
      // path here.
      const passkeys = await listPasskeys();
      setHasPasskeyUnlock(passkeys.some((passkey) => (
        passkey.prf_enabled
        && passkey.is_available_on_current_rp !== false
      )));
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
    vaultEncryptionKey?: Uint8Array,
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

    const migrationGate = await evaluateVaultMigrationGate({
      userId: user.id,
      vaultEncryptionKey,
    });
    state.setVaultMigrationStatus(migrationGate.status);
    state.setVaultMigrationError(null);
    if (!migrationGate.allowNormalUnlock) {
      state.setEncryptionKey(null);
      state.setIsLocked(true);
      state.setIsDuressMode(false);
      state.setPendingSessionRestore(false);
      state.setIntegrityMode('migration_required');
      state.setIntegrityBlockedReason(null);
      state.setVaultMigrationCanStart(Boolean(
        migrationGate.status !== 'preflightFailed'
        && migrationGate.vaultId
        && vaultEncryptionKey,
      ));
      state.setVaultMigrationKeyContext({
        activeKey,
        vaultEncryptionKey: vaultEncryptionKey ? new Uint8Array(vaultEncryptionKey) : null,
        vaultId: migrationGate.vaultId,
      });
      state.setLastActivity(Date.now());
      clearVaultSessionMarkers(sessionStorage);
      return { error: null };
    }

    state.setEncryptionKey(activeKey);
    state.setVaultMigrationCanStart(false);
    state.setVaultMigrationKeyContext((existingContext) => {
      existingContext?.vaultEncryptionKey?.fill(0);
      return null;
    });
    clearLegacyIntegrityStateAfterOpLogGate(state);
    state.setIsLocked(false);
    state.setIsDuressMode(false);
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
    // Synthesise a fresh batch of in-memory decoy items for this duress
    // session. The premium hook returns a randomised set on every call so
    // the panic vault looks slightly different each time, matching the
    // user's mental model of a "live" decoy vault. Keeping the items in
    // memory only is a deliberate security property: nothing leaks to
    // `vault_items`, the snapshot cache or the OpLog runtime, so an
    // attacker with direct database access cannot tell that the panic
    // vault was ever opened. See
    // `src/services/duressDecoyItemSynthesisService.ts`.
    state.setDuressDecoyItems(synthesizeDuressVaultItems());
    // Reset OpLog V2 migration status so that `useOpLogVerifiedRuntime`
    // is always false in the duress vault, regardless of any prior real-
    // password unlock in the same session. Without this reset, a user who
    // authenticated with their real password, locked the vault, then
    // immediately entered the panic password could inherit a stale
    // 'verified' status that causes VaultPage to block rendering with
    // `shouldWaitForVerifiedDeviceTrust` (opLogUiView stays null because
    // vaultEncryptionKey is not set in duress mode).
    state.setVaultMigrationStatus(null);
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
  const setupMasterPassword = useVaultSetupActions({
    finalizeVaultUnlock,
    state,
    userId: user?.id,
  });
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

    // Reload the duress configuration straight from the profile before
    // every unlock attempt. `state.duressConfig` is populated by the
    // lifecycle effect on app boot / online events, but it stays `null`
    // when duress was activated mid-session (Premium activation, panic
    // password set in another tab, ...). Without this refresh the very
    // first unlock after activation would fall through to the normal
    // master-password path and silently reject the panic password as
    // invalid. We sync the fresh value back into provider state so any
    // subsequent code paths see the same view.
    const hooks = getServiceHooks();
    let resolvedDuressConfig = state.duressConfig;
    if (hooks.getDuressConfig) {
      try {
        resolvedDuressConfig = await hooks.getDuressConfig(user.id);
        state.setDuressConfig(resolvedDuressConfig);
      } catch (error) {
        console.warn(
          '[Vault] Failed to refresh duress config before unlock; falling back to cached value.',
          error,
        );
      }
    }

    const unlockResult = await unlockVaultWithMasterPassword({
      userId: user.id,
      masterPassword,
      salt: credentials.salt,
      verificationHash: credentials.verificationHash,
      kdfVersion: credentials.kdfVersion ?? state.kdfVersion,
      duressConfig: resolvedDuressConfig,
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

    if (unlockResult.vaultEncryptionKey) {
      setVaultEncryptionKey(unlockResult.vaultEncryptionKey);
    }

    return { error: unlockResult.error };
  }, [
    applyCredentialUpdates,
    enforceVaultTwoFactorBeforeKeyRelease,
    finalizeVaultUnlock,
    getRequiredDeviceKey,
    openDuressVault,
    refreshRemoteCredentials,
    clearCurrentDeviceKey,
    setDeviceKeyActive,
    setVaultEncryptionKey,
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

    const passkeyResult = await unlockVaultWithPasskey({
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

    if (passkeyResult.vaultEncryptionKey) {
      setVaultEncryptionKey(passkeyResult.vaultEncryptionKey);
    }

    return { error: passkeyResult.error };
  }, [
    applyCredentialUpdates,
    enforceVaultTwoFactorBeforeKeyRelease,
    finalizeVaultUnlock,
    getRequiredDeviceKey,
    refreshRemoteCredentials,
    setVaultEncryptionKey,
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
  const opLogUiState = useVaultOpLogUiState(state, user?.id ?? null);
  const getVaultHealthAnalysisItems = useCallback(() => {
    if (!user || state.isDuressMode) {
      return Promise.resolve([]);
    }

    return loadVaultHealthAnalysisItems({
      userId: user.id,
      vaultMigrationStatus: state.vaultMigrationStatus,
      opLogLocalVaultState: opLogUiState.localVaultState,
      decryptItem,
      verifyIntegrity,
    });
  }, [decryptItem, opLogUiState.localVaultState, state.isDuressMode, state.vaultMigrationStatus, user, verifyIntegrity]);
  const findLegacyDuressDecoyCandidates = useCallback(async () => {
    if (!user) {
      return {
        candidates: [],
        inspectedRowCount: 0,
        authenticatedRowCount: 0,
        error: new Error('No active user session.'),
      };
    }

    // The scan must work in TWO states:
    //   (a) the vault is fully unlocked (state.encryptionKey set), or
    //   (b) the migration-gate has blocked normal unlock with
    //       `integrityMode === 'migration_required'`. In that state
    //       state.encryptionKey is null and state.isLocked is true, but
    //       state.vaultMigrationKeyContext.activeKey still holds the
    //       authenticated vault key from finalizeVaultUnlock. We need (b)
    //       so users whose migration gate is blocked by legacy duress
    //       decoys can self-repair from the panel that is shown to them.
    const vaultKey = state.encryptionKey
      ?? state.vaultMigrationKeyContext?.activeKey
      ?? null;
    if (!vaultKey) {
      return {
        candidates: [],
        inspectedRowCount: 0,
        authenticatedRowCount: 0,
        error: new Error('Vault must be unlocked (or in migration-required state) to scan for legacy duress decoys.'),
      };
    }

    const verifiedRecordIds = new Set<string>();
    const localState = opLogUiState.localVaultState;
    if (localState) {
      for (const [recordId, record] of localState.recordsById.entries()) {
        if (record.recordState === 'verified') {
          verifiedRecordIds.add(recordId);
        }
      }
    }

    try {
      const result = await findLegacyDuressDecoyCandidatesService({
        userId: user.id,
        vaultKey,
        opLogVerifiedRecordIds: verifiedRecordIds,
      });
      return { ...result, error: null };
    } catch (error) {
      return {
        candidates: [],
        inspectedRowCount: 0,
        authenticatedRowCount: 0,
        error: error instanceof Error ? error : new Error('Legacy duress decoy scan failed.'),
      };
    }
  }, [opLogUiState.localVaultState, state.encryptionKey, state.vaultMigrationKeyContext, user]);
  const purgeLegacyDuressDecoys = useCallback(async (
    itemIds: ReadonlyArray<string>,
  ): Promise<{ deletedCount: number; error: Error | null }> => {
    if (!user) {
      return { deletedCount: 0, error: new Error('No active user session') };
    }
    if (itemIds.length === 0) {
      return { deletedCount: 0, error: new Error('No items selected for purge.') };
    }
    try {
      const result = await purgeLegacyDuressDecoyItemsService({
        userId: user.id,
        itemIds,
      });
      // Force the migration gate / integrity-v2 evaluator to re-run on the
      // next data refresh by bumping the local data version. The legacy
      // rows are gone, so `hasLegacyRows` should now be false and the
      // vault should leave the orphan_remote / migration_required state.
      state.bumpVaultDataVersion();
      return { deletedCount: result.deletedCount, error: null };
    } catch (error) {
      return {
        deletedCount: 0,
        error: error instanceof Error ? error : new Error('Legacy duress decoy purge failed.'),
      };
    }
  }, [state, user]);
  useVaultRevokedDeviceAutoLock({
    isLocked: state.isLocked,
    localVaultState: opLogUiState.localVaultState,
    lock,
    vaultMigrationStatus: state.vaultMigrationStatus,
  });
  const { startVaultMigration, retryVaultMigration } = useVaultMigrationActions({
    state,
    user,
    decryptItemForLegacyMigration,
  });
  const opLogActions = useVaultOpLogCrudActions({
    state,
    user,
    decryptTrustedRecoverySnapshotItem,
    opLogUiRefresh: opLogUiState.refresh, localVaultState: opLogUiState.localVaultState,
  });
  const collectionOpLogActions = useCollectionOpLogActions(state, user);
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
    exitSafeMode,
    resetVaultAfterIntegrityFailure,
    getVaultHealthAnalysisItems,
    findLegacyDuressDecoyCandidates,
    purgeLegacyDuressDecoys,
    startVaultMigration,
    retryVaultMigration,
    ...opLogActions,
    ...collectionOpLogActions,
  }, opLogUiState);
}
