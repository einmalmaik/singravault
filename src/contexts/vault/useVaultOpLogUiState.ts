// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE
/**
 * `useVaultOpLogUiState` — Phase 9 UI state hook.
 *
 * Manages the vault operation-log-based UI view (security modes,
 * quarantine, conflicts) behind the `VITE_VAULT_OP_LOG_PHASE_9_UI_ENABLED`
 * feature flag.
 *
 * When the flag is off this hook returns `null` for everything and
 * performs no RPC calls.
 *
 * When the flag is on but required credentials (device identity,
 * vault encryption key) are missing, it also returns `null` so the
 * old productive vault path remains unchanged.
 */

import { useCallback, useEffect, useRef, useState } from 'react';
import { supabase } from '@/integrations/supabase/client';
import {
  isVaultOpLogPhase9UIEnabled,
} from '@/services/vaultOpLog/vaultOpLogFeatureFlags';
import {
  loadVaultOpLogUiState,
} from '@/services/vaultOpLog/vaultOpLogUiOrchestrator';
import type {
  VaultOpLogUiView,
} from '@/services/vaultOpLog/vaultOpLogUiAdapter';
import {
  loadVaultOpLogDeviceIdentity,
} from '@/services/vaultOpLog/vaultOpLogDeviceStore';
import type { VaultProviderState } from './useVaultProviderState';

export interface VaultOpLogUiState {
  readonly uiView: VaultOpLogUiView | null;
  readonly isLoading: boolean;
  readonly lastError: string | null;
  readonly refresh: () => Promise<void>;
}

export function useVaultOpLogUiState(
  vaultProviderState: VaultProviderState,
  userId: string | null,
): VaultOpLogUiState {
  const isEnabled = isVaultOpLogPhase9UIEnabled();
  const [uiView, setUiView] = useState<VaultOpLogUiView | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [lastError, setLastError] = useState<string | null>(null);
  const isRunningRef = useRef(false);

  const refresh = useCallback(async (): Promise<void> => {
    if (!isEnabled) {
      setUiView(null);
      setLastError(null);
      return;
    }

    if (isRunningRef.current) {
      return;
    }

    const deviceIdentity = loadVaultOpLogDeviceIdentity();
    const vaultEncryptionKey = vaultProviderState.vaultEncryptionKey;

    if (!deviceIdentity || !vaultEncryptionKey || !userId) {
      // Required Phase 9 credentials not available — fall back to old path.
      setUiView(null);
      setLastError(null);
      return;
    }

    isRunningRef.current = true;
    setIsLoading(true);
    setLastError(null);

    try {
      const result = await loadVaultOpLogUiState({
        rpcClient: supabase as unknown as import('@/services/vaultOpLog/vaultOpLogRepository').SupabaseRpcClient,
        vaultId: userId,
        deviceId: deviceIdentity.deviceId,
        publicSigningKeyB64Url: deviceIdentity.publicSigningKeyB64Url,
        vaultEncryptionKey,
      });

      if (result.error) {
        setLastError(result.error);
        setUiView(null);
      } else {
        setUiView(result.uiView);
      }
    } catch (err) {
      setLastError(err instanceof Error ? err.message : 'unknown_ui_state_error');
      setUiView(null);
    } finally {
      setIsLoading(false);
      isRunningRef.current = false;
    }
  }, [isEnabled, vaultProviderState.vaultEncryptionKey, userId]);

  useEffect(() => {
    if (!isEnabled) {
      return;
    }

    if (!vaultProviderState.isLocked && vaultProviderState.vaultEncryptionKey && userId) {
      void refresh();
    } else {
      setUiView(null);
      setLastError(null);
    }
  }, [isEnabled, vaultProviderState.isLocked, vaultProviderState.vaultEncryptionKey, userId, refresh]);

  return {
    uiView,
    isLoading,
    lastError,
    refresh,
  };
}
