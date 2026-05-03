import { useEffect, useRef, type MutableRefObject } from 'react';
import { getServiceHooks } from '@/extensions/registry';
import { saveOfflineCredentials, isAppOnline } from '@/services/offlineVaultService';
import {
  ensureTauriDevVaultSnapshot,
  loadCachedVaultCredentials,
  loadRemoteVaultProfile,
} from '@/services/offlineVaultRuntimeService';
import { isTauriDevUserId } from '@/platform/tauriDevMode';
import { isNativeDeviceKeyBridgeRuntime } from '@/services/deviceKeyNativeBridge';
import type { VaultProviderState } from './useVaultProviderState';

export interface VaultLifecycleEffectsInput {
  user: { id: string } | null | undefined;
  authReady: boolean;
  state: VaultProviderState;
  lastUserIdRef: MutableRefObject<string | null>;
  lock: () => void;
  refreshPasskeyUnlockStatus: () => Promise<void>;
  refreshDeviceKeyState: () => Promise<void>;
}

export function useVaultLifecycleEffects(input: VaultLifecycleEffectsInput): void {
  const {
    user,
    authReady,
    state,
    lastUserIdRef,
    lock,
    refreshPasskeyUnlockStatus,
    refreshDeviceKeyState,
  } = input;
  const {
    applyCredentialsToState,
    autoLockTimeout,
    connectivityCheckNonce,
    encryptionKey,
    isLocked,
    lastActivity,
    pruneQuarantineActionState,
    resetVaultState,
    setConnectivityCheckNonce,
    setCurrentDeviceKey,
    setDeviceKeyActive,
    setDuressConfig,
    setHasPasskeyUnlock,
    setIsLoading,
    setIsLocked,
    setIsSetupRequired,
    setLastActivity,
  } = state;
  const encryptionKeyRef = useRef(encryptionKey);
  const isLockedRef = useRef(isLocked);
  encryptionKeyRef.current = encryptionKey;
  isLockedRef.current = isLocked;

  useEffect(() => {
    const currentUserId = user?.id ?? null;
    if (lastUserIdRef.current === currentUserId) {
      return;
    }

    lastUserIdRef.current = currentUserId;
    resetVaultState();
    setIsLoading(Boolean(currentUserId));
  }, [lastUserIdRef, resetVaultState, setIsLoading, user?.id]);

  useEffect(() => {
    const refreshSetupState = () => setConnectivityCheckNonce((value) => value + 1);
    const refreshVisibleSetupState = () => {
      if (document.visibilityState === 'visible') {
        refreshSetupState();
      }
    };

    window.addEventListener('online', refreshSetupState);
    window.addEventListener('focus', refreshSetupState);
    document.addEventListener('visibilitychange', refreshVisibleSetupState);
    return () => {
      window.removeEventListener('online', refreshSetupState);
      window.removeEventListener('focus', refreshSetupState);
      document.removeEventListener('visibilitychange', refreshVisibleSetupState);
    };
  }, [setConnectivityCheckNonce]);

  useEffect(() => {
    async function checkSetup() {
      if (!user) {
        setHasPasskeyUnlock(false);
        setIsLoading(false);
        return;
      }

      if (!authReady) {
        return;
      }

      console.debug('[VaultContext] authReady is true, fetching user profiles...');

      if (isTauriDevUserId(user.id)) {
        const cached = await loadCachedVaultCredentials(user.id);
        if (cached) {
          applyCredentialsToState(cached);
          await ensureTauriDevVaultSnapshot(user.id);
        } else {
          setIsSetupRequired(true);
          setIsLocked(true);
        }
        setDeviceKeyActive(false);
        setCurrentDeviceKey(null);
        setIsLoading(false);
        return;
      }

      if (!isAppOnline()) {
        console.debug('[VaultContext] App is offline, loading cached credentials...');
        const cached = await loadCachedVaultCredentials(user.id);
        if (cached) {
          applyCredentialsToState(cached);
          setIsLoading(false);
          return;
        }
        setIsSetupRequired(false);
        setIsLocked(true);
        setIsLoading(false);
        return;
      }

      try {
        const profile = await loadRemoteVaultProfile(user.id);
        if (!profile.credentials) {
          if (encryptionKeyRef.current && !isLockedRef.current) {
            setIsLoading(false);
            return;
          }
          const cached = await loadCachedVaultCredentials(user.id);
          if (cached) {
            applyCredentialsToState(cached);
            setIsLoading(false);
            return;
          }
          if (profile.setupCheckFailed) {
            console.warn('[VaultContext] Vault setup check failed; keeping setup flow hidden until state is known.');
            setIsSetupRequired(false);
          } else {
            setIsSetupRequired(profile.setupRequired);
          }
          setIsLocked(true);
        } else {
          applyCredentialsToState(profile.credentials);
          await saveOfflineCredentials(
            user.id,
            profile.credentials.salt,
            profile.credentials.verificationHash,
            profile.credentials.kdfVersion ?? undefined,
            profile.credentials.encryptedUserKey,
            profile.credentials.vaultProtectionMode,
          );

          await refreshPasskeyUnlockStatus();

          const hooks = getServiceHooks();
          if (hooks.getDuressConfig) {
            try {
              const duress = await hooks.getDuressConfig(user.id);
              setDuressConfig(duress);
            } catch {
              // Non-fatal: duress config can fail silently.
            }
          }

          await refreshDeviceKeyState();
        }
      } catch (error) {
        console.error('Error checking vault setup:', error);
        if (encryptionKeyRef.current && !isLockedRef.current) {
          setIsLoading(false);
          return;
        }
        const cached = await loadCachedVaultCredentials(user.id);
        if (cached) {
          applyCredentialsToState(cached);
          setIsLoading(false);
          return;
        }
        setIsSetupRequired(false);
        setIsLocked(true);
      } finally {
        setIsLoading(false);
      }
    }

    void checkSetup();
  }, [
    authReady,
    applyCredentialsToState,
    connectivityCheckNonce,
    refreshDeviceKeyState,
    refreshPasskeyUnlockStatus,
    setCurrentDeviceKey,
    setDeviceKeyActive,
    setDuressConfig,
    setHasPasskeyUnlock,
    setIsLoading,
    setIsLocked,
    setIsSetupRequired,
    user,
  ]);

  useEffect(() => {
    if (isLocked || !encryptionKey) {
      return;
    }

    const checkInactivity = setInterval(() => {
      const timeSinceActivity = Date.now() - lastActivity;
      if (timeSinceActivity >= autoLockTimeout) {
        lock();
      }
    }, 10000);

    return () => clearInterval(checkInactivity);
  }, [autoLockTimeout, encryptionKey, isLocked, lastActivity, lock]);

  useEffect(() => {
    if (isLocked) {
      return;
    }

    const updateActivity = () => setLastActivity(Date.now());
    const events = ['mousedown', 'keydown', 'scroll', 'touchstart'];
    events.forEach((event) => {
      document.addEventListener(event, updateActivity, { passive: true });
    });

    return () => {
      events.forEach((event) => {
        document.removeEventListener(event, updateActivity);
      });
    };
  }, [isLocked, setLastActivity]);

  useEffect(() => {
    pruneQuarantineActionState();
  }, [pruneQuarantineActionState]);

  useEffect(() => {
    if (!user || isNativeDeviceKeyBridgeRuntime()) {
      setCurrentDeviceKey(null);
    }
  }, [setCurrentDeviceKey, user]);
}
