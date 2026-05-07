// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE
/**
 * `useVaultOpLogUiState` - Phase 9 UI state hook.
 *
 * Manages the vault operation-log-based UI view (security modes,
 * quarantine, conflicts) behind the `VITE_VAULT_OP_LOG_PHASE_9_UI_ENABLED`
 * feature flag.
 */

import { useCallback, useEffect, useRef, useState } from 'react';
import { supabase } from '@/integrations/supabase/client';
import {
  isVaultOpLogPhase9UIEnabled,
} from '@/services/vaultOpLog/vaultOpLogFeatureFlags';
import {
  loadVaultOpLogUiState,
  type VaultOpLogTrustReadClient,
} from '@/services/vaultOpLog/vaultOpLogUiOrchestrator';
import type { SupabaseRpcClient } from '@/services/vaultOpLog/vaultOpLogRepository';
import type {
  VaultOpLogUiView,
} from '@/services/vaultOpLog/vaultOpLogUiAdapter';
import {
  loadVaultOpLogDeviceIdentity,
} from '@/services/vaultOpLog/vaultOpLogDeviceStore';
import {
  recoverVaultOpLogDeviceIdentity,
} from '@/services/vaultOpLog/vaultOpLogDeviceIdentityRecovery';
import type { LocalVaultState } from '@/services/vaultOpLog/vaultStateMachine';
import type { VaultProviderState } from './useVaultProviderState';

export interface VaultOpLogUiState {
  readonly uiView: VaultOpLogUiView | null;
  readonly localVaultState: LocalVaultState | null;
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
  const [localVaultState, setLocalVaultState] = useState<LocalVaultState | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [lastError, setLastError] = useState<string | null>(null);
  const isRunningRef = useRef(false);

  const clearState = useCallback(() => {
    setUiView(null);
    setLocalVaultState(null);
    setLastError(null);
  }, []);

  const refresh = useCallback(async (): Promise<void> => {
    if (!isEnabled) {
      clearState();
      return;
    }

    if (isRunningRef.current) {
      return;
    }

    const vaultEncryptionKey = vaultProviderState.vaultEncryptionKey;
    if (!vaultEncryptionKey || !userId) {
      clearState();
      return;
    }

    isRunningRef.current = true;
    setIsLoading(true);
    setLastError(null);

    try {
      const vaultId = vaultProviderState.vaultMigrationKeyContext?.vaultId
        ?? await loadDefaultVaultId(userId);
      if (!vaultId) {
        setUiView(null);
        setLocalVaultState(null);
        setLastError('vault_id_load_failed');
        return;
      }

      const deviceIdentity = loadVaultOpLogDeviceIdentity()
        ?? await recoverVaultOpLogDeviceIdentity({
          userId,
          vaultId,
          trustClient: supabase,
        });
      if (!deviceIdentity) {
        clearState();
        return;
      }

      const result = await loadVaultOpLogUiState({
        rpcClient: supabase as unknown as SupabaseRpcClient,
        trustClient: supabase as unknown as VaultOpLogTrustReadClient,
        vaultId,
        deviceId: deviceIdentity.deviceId,
        publicSigningKeyB64Url: deviceIdentity.publicSigningKeyB64Url,
        vaultEncryptionKey,
      });

      if (result.error) {
        setLastError(result.error);
        setUiView(null);
        setLocalVaultState(null);
      } else {
        setUiView(result.uiView);
        setLocalVaultState(result.localVaultState);
      }
    } catch (err) {
      setLastError(err instanceof Error ? err.message : 'unknown_ui_state_error');
      setUiView(null);
      setLocalVaultState(null);
    } finally {
      setIsLoading(false);
      isRunningRef.current = false;
    }
  }, [
    clearState,
    isEnabled,
    vaultProviderState.vaultEncryptionKey,
    vaultProviderState.vaultMigrationKeyContext?.vaultId,
    userId,
  ]);

  useEffect(() => {
    if (!isEnabled) {
      return;
    }

    if (!vaultProviderState.isLocked && vaultProviderState.vaultEncryptionKey && userId) {
      void refresh();
    } else {
      clearState();
    }
  }, [
    clearState,
    isEnabled,
    vaultProviderState.isLocked,
    vaultProviderState.vaultEncryptionKey,
    userId,
    refresh,
  ]);

  return {
    uiView,
    localVaultState,
    isLoading,
    lastError,
    refresh,
  };
}

async function loadDefaultVaultId(userId: string): Promise<string | null> {
  const { data, error } = await supabase
    .from('vaults')
    .select('id')
    .eq('user_id', userId)
    .eq('is_default', true)
    .maybeSingle();

  if (error || typeof data?.id !== 'string') {
    return null;
  }

  return data.id;
}
