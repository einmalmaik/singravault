import { useCallback, useMemo, useRef, useState } from 'react';
import {
  VAULT_PROTECTION_MODE_MASTER_ONLY,
  type VaultProtectionMode,
} from '@/services/deviceKeyProtectionPolicy';
import type { DuressConfigHook } from '@/extensions/types';
import {
  buildQuarantineResolutionMap,
  type QuarantineResolutionRuntimeState,
  type TrustedSnapshotItemsById,
} from '@/services/vaultQuarantineRecoveryService';
import type {
  QuarantinedVaultItem,
  VaultIntegrityBlockedReason,
  VaultIntegrityMode,
  VaultIntegrityVerificationResult,
} from '@/services/vaultIntegrityService';
import type { VaultRuntimeCredentials } from '@/services/offlineVaultRuntimeService';
import type { TrustedRecoverySnapshotState } from '@/services/vaultRecoveryOrchestrator';
import {
  clearRuntimeSessionMarkers,
  getInitialAutoLockTimeout,
  isStoredVaultSessionValid,
  persistAutoLockTimeoutIfAllowed,
  wipeRuntimeDeviceKey,
} from '@/services/vaultRuntimeCleanupService';
import { buildDisplayedIntegrityResult as buildDisplayedIntegrityResultFromQuarantine } from '@/services/vaultQuarantineOrchestrator';

function sameQuarantinedItems(left: QuarantinedVaultItem[], right: QuarantinedVaultItem[]): boolean {
  if (left.length !== right.length) {
    return false;
  }

  return left.every((item, index) => {
    const other = right[index];
    return item.id === other.id
      && item.reason === other.reason
      && item.updatedAt === other.updatedAt
      && item.itemType === other.itemType;
  });
}

function sameIntegrityResult(
  left: VaultIntegrityVerificationResult | null,
  right: VaultIntegrityVerificationResult | null,
): boolean {
  if (left === right) {
    return true;
  }
  if (!left || !right) {
    return false;
  }

  return left.valid === right.valid
    && left.isFirstCheck === right.isFirstCheck
    && left.computedRoot === right.computedRoot
    && left.storedRoot === right.storedRoot
    && left.itemCount === right.itemCount
    && left.categoryCount === right.categoryCount
    && left.mode === right.mode
    && left.blockedReason === right.blockedReason
    && sameQuarantinedItems(left.quarantinedItems ?? [], right.quarantinedItems ?? []);
}

export function useVaultProviderState() {
  const [isLocked, setIsLocked] = useState(true);
  const [isSetupRequired, setIsSetupRequired] = useState(false);
  const [isLoading, setIsLoading] = useState(true);
  const [encryptionKey, setEncryptionKey] = useState<CryptoKey | null>(null);
  const [salt, setSalt] = useState<string | null>(null);
  const [verificationHash, setVerificationHash] = useState<string | null>(null);
  const [kdfVersion, setKdfVersion] = useState<number>(1);
  const [autoLockTimeout, setAutoLockTimeoutState] = useState(getInitialAutoLockTimeout);
  const [pendingSessionRestore, setPendingSessionRestore] = useState(() => isStoredVaultSessionValid());
  const [hasPasskeyUnlock, setHasPasskeyUnlock] = useState(false);
  const [isDuressMode, setIsDuressMode] = useState(false);
  const [duressConfig, setDuressConfig] = useState<DuressConfigHook | null>(null);
  const [deviceKeyActive, setDeviceKeyActive] = useState(false);
  const [currentDeviceKey, setCurrentDeviceKey] = useState<Uint8Array | null>(null);
  const [vaultProtectionMode, setVaultProtectionMode] = useState<VaultProtectionMode>(VAULT_PROTECTION_MODE_MASTER_ONLY);
  const [encryptedUserKey, setEncryptedUserKey] = useState<string | null>(null);
  const [integrityVerified, setIntegrityVerified] = useState(false);
  const baseIntegrityResultRef = useRef<VaultIntegrityVerificationResult | null>(null);
  const [lastIntegrityResult, setLastIntegrityResult] = useState<VaultIntegrityVerificationResult | null>(null);
  const [integrityMode, setIntegrityMode] = useState<VaultIntegrityMode | 'safe'>('healthy');
  const [quarantinedItems, setQuarantinedItems] = useState<QuarantinedVaultItem[]>([]);
  const runtimeUnreadableItemsRef = useRef<QuarantinedVaultItem[]>([]);
  const [vaultDataVersion, setVaultDataVersion] = useState(0);
  const [quarantineActionStateById, setQuarantineActionStateById] = useState<
    Record<string, QuarantineResolutionRuntimeState>
  >({});
  const [integrityBlockedReason, setIntegrityBlockedReason] = useState<VaultIntegrityBlockedReason | null>(null);
  const [trustedRecoveryAvailable, setTrustedRecoveryAvailable] = useState(false);
  const [trustedSnapshotItemsById, setTrustedSnapshotItemsById] = useState<TrustedSnapshotItemsById>({});
  const [lastActivity, setLastActivity] = useState(Date.now());
  const [connectivityCheckNonce, setConnectivityCheckNonce] = useState(0);

  const setAutoLockTimeout = useCallback((timeout: number) => {
    persistAutoLockTimeoutIfAllowed(timeout);
    setAutoLockTimeoutState(timeout);
  }, []);

  const bumpVaultDataVersion = useCallback(() => {
    setVaultDataVersion((currentVersion) => currentVersion + 1);
  }, []);

  const applyCredentialsToState = useCallback((credentials: VaultRuntimeCredentials): void => {
    setIsSetupRequired(false);
    setSalt(credentials.salt);
    setVerificationHash(credentials.verificationHash);
    if (credentials.kdfVersion !== null) {
      setKdfVersion(credentials.kdfVersion);
    }
    setEncryptedUserKey(credentials.encryptedUserKey);
    setVaultProtectionMode(credentials.vaultProtectionMode);
  }, []);

  const applyTrustedRecoveryState = useCallback((trustedState: TrustedRecoverySnapshotState): void => {
    setTrustedRecoveryAvailable(trustedState.trustedRecoveryAvailable);
    setTrustedSnapshotItemsById(trustedState.trustedSnapshotItemsById);
  }, []);

  const buildDisplayedIntegrityResult = useCallback((
    result: VaultIntegrityVerificationResult | null,
    runtimeUnreadableItems: QuarantinedVaultItem[] = runtimeUnreadableItemsRef.current,
  ): VaultIntegrityVerificationResult | null => {
    return buildDisplayedIntegrityResultFromQuarantine(result, runtimeUnreadableItems);
  }, []);

  const applyDisplayedIntegrityState = useCallback((
    result: VaultIntegrityVerificationResult | null,
    runtimeUnreadableItems: QuarantinedVaultItem[] = runtimeUnreadableItemsRef.current,
  ): void => {
    const displayedResult = buildDisplayedIntegrityResult(result, runtimeUnreadableItems);
    const nextIntegrityVerified = displayedResult !== null;
    const nextIntegrityMode = displayedResult?.mode ?? 'healthy';
    const nextQuarantinedItems = displayedResult?.quarantinedItems ?? [];
    const nextBlockedReason = displayedResult?.mode === 'blocked'
      ? displayedResult.blockedReason ?? null
      : null;

    setIntegrityVerified((current) => current === nextIntegrityVerified ? current : nextIntegrityVerified);
    setLastIntegrityResult((current) => sameIntegrityResult(current, displayedResult) ? current : displayedResult);
    setIntegrityMode((current) => current === nextIntegrityMode ? current : nextIntegrityMode);
    setQuarantinedItems((current) => sameQuarantinedItems(current, nextQuarantinedItems) ? current : nextQuarantinedItems);
    setIntegrityBlockedReason((current) => current === nextBlockedReason ? current : nextBlockedReason);
  }, [buildDisplayedIntegrityResult]);

  const applyIntegrityResultState = useCallback((result: VaultIntegrityVerificationResult): void => {
    baseIntegrityResultRef.current = result;
    applyDisplayedIntegrityState(result);
  }, [applyDisplayedIntegrityState]);

  const reportUnreadableItems = useCallback((items: QuarantinedVaultItem[]): void => {
    runtimeUnreadableItemsRef.current = items;
    applyDisplayedIntegrityState(baseIntegrityResultRef.current, items);
  }, [applyDisplayedIntegrityState]);

  const clearActiveVaultSession = useCallback(() => {
    setEncryptionKey(null);
    setCurrentDeviceKey((existingKey) => {
      wipeRuntimeDeviceKey(existingKey);
      return null;
    });
    setIsLocked(true);
    setIsDuressMode(false);
    setIntegrityVerified(false);
    baseIntegrityResultRef.current = null;
    setLastIntegrityResult(null);
    setIntegrityMode('healthy');
    setQuarantinedItems([]);
    runtimeUnreadableItemsRef.current = [];
    setVaultDataVersion(0);
    setQuarantineActionStateById({});
    setIntegrityBlockedReason(null);
    setTrustedRecoveryAvailable(false);
    setTrustedSnapshotItemsById({});
    setPendingSessionRestore(false);
    setLastActivity(Date.now());
    clearRuntimeSessionMarkers();
  }, []);

  const resetVaultState = useCallback(() => {
    clearActiveVaultSession();
    setIsSetupRequired(false);
    setSalt(null);
    setVerificationHash(null);
    setKdfVersion(1);
    setHasPasskeyUnlock(false);
    setDuressConfig(null);
    setDeviceKeyActive(false);
    setCurrentDeviceKey(null);
    setVaultProtectionMode(VAULT_PROTECTION_MODE_MASTER_ONLY);
    setEncryptedUserKey(null);
  }, [clearActiveVaultSession]);

  const runQuarantineAction = useCallback(async (
    itemId: string,
    action: () => Promise<void>,
  ): Promise<{ error: Error | null }> => {
    setQuarantineActionStateById((currentState) => ({
      ...currentState,
      [itemId]: { isBusy: true, lastError: null },
    }));

    try {
      await action();
      const nextRuntimeUnreadableItems = runtimeUnreadableItemsRef.current.filter(
        (item) => item.id !== itemId,
      );
      if (nextRuntimeUnreadableItems.length !== runtimeUnreadableItemsRef.current.length) {
        runtimeUnreadableItemsRef.current = nextRuntimeUnreadableItems;
        applyDisplayedIntegrityState(baseIntegrityResultRef.current, nextRuntimeUnreadableItems);
      }
      setQuarantineActionStateById((currentState) => ({
        ...currentState,
        [itemId]: { isBusy: false, lastError: null },
      }));
      return { error: null };
    } catch (error) {
      const resolvedError = error instanceof Error
        ? error
        : new Error('Quarantäne-Aktion fehlgeschlagen.');

      setQuarantineActionStateById((currentState) => ({
        ...currentState,
        [itemId]: { isBusy: false, lastError: resolvedError.message },
      }));
      return { error: resolvedError };
    }
  }, [applyDisplayedIntegrityState]);

  const pruneQuarantineActionState = useCallback(() => {
    setQuarantineActionStateById((currentState) => {
      const activeItemIds = new Set(quarantinedItems.map((item) => item.id));
      const nextState = Object.fromEntries(
        Object.entries(currentState).filter(([itemId]) => activeItemIds.has(itemId)),
      );

      return Object.keys(nextState).length === Object.keys(currentState).length
        ? currentState
        : nextState;
    });
  }, [quarantinedItems]);

  const quarantineResolutionById = useMemo(
    () => buildQuarantineResolutionMap(
      quarantinedItems,
      trustedSnapshotItemsById,
      quarantineActionStateById,
    ),
    [quarantinedItems, quarantineActionStateById, trustedSnapshotItemsById],
  );

  return {
    isLocked,
    setIsLocked,
    isSetupRequired,
    setIsSetupRequired,
    isLoading,
    setIsLoading,
    encryptionKey,
    setEncryptionKey,
    salt,
    setSalt,
    verificationHash,
    setVerificationHash,
    kdfVersion,
    setKdfVersion,
    autoLockTimeout,
    setAutoLockTimeout,
    pendingSessionRestore,
    setPendingSessionRestore,
    hasPasskeyUnlock,
    setHasPasskeyUnlock,
    isDuressMode,
    setIsDuressMode,
    duressConfig,
    setDuressConfig,
    deviceKeyActive,
    setDeviceKeyActive,
    currentDeviceKey,
    setCurrentDeviceKey,
    vaultProtectionMode,
    setVaultProtectionMode,
    encryptedUserKey,
    setEncryptedUserKey,
    integrityVerified,
    setIntegrityVerified,
    baseIntegrityResultRef,
    lastIntegrityResult,
    setLastIntegrityResult,
    integrityMode,
    setIntegrityMode,
    quarantinedItems,
    setQuarantinedItems,
    runtimeUnreadableItemsRef,
    vaultDataVersion,
    bumpVaultDataVersion,
    quarantineResolutionById,
    integrityBlockedReason,
    setIntegrityBlockedReason,
    trustedRecoveryAvailable,
    trustedSnapshotItemsById,
    setTrustedSnapshotItemsById,
    lastActivity,
    setLastActivity,
    connectivityCheckNonce,
    setConnectivityCheckNonce,
    applyCredentialsToState,
    applyTrustedRecoveryState,
    buildDisplayedIntegrityResult,
    applyDisplayedIntegrityState,
    applyIntegrityResultState,
    reportUnreadableItems,
    clearActiveVaultSession,
    resetVaultState,
    runQuarantineAction,
    pruneQuarantineActionState,
  };
}

export type VaultProviderState = ReturnType<typeof useVaultProviderState>;
