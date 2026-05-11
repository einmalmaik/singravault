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
  readonly vaultId: string | null;
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
  const [vaultId, setVaultId] = useState<string | null>(null);
  const [uiView, setUiView] = useState<VaultOpLogUiView | null>(null);
  const [localVaultState, setLocalVaultState] = useState<LocalVaultState | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [lastError, setLastError] = useState<string | null>(null);
  const isRunningRef = useRef(false);

  const clearState = useCallback(() => {
    setVaultId(null);
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
        setVaultId(null);
        setUiView(null);
        setLocalVaultState(null);
        setLastError('vault_id_load_failed');
        return;
      }
      setVaultId(vaultId);

      const deviceIdentity = loadVaultOpLogDeviceIdentity()
        ?? await recoverVaultOpLogDeviceIdentity({
          userId,
          vaultId,
          trustClient: supabase,
        });

      const result = await loadVaultOpLogUiState({
        rpcClient: supabase as unknown as SupabaseRpcClient,
        trustClient: supabase as unknown as VaultOpLogTrustReadClient,
        vaultId,
        deviceId: deviceIdentity?.deviceId,
        publicSigningKeyB64Url: deviceIdentity?.publicSigningKeyB64Url,
        vaultEncryptionKey,
        requireLocalDeviceTrust: true,
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

  useEffect(() => {
    if (
      !isEnabled
      || vaultProviderState.isLocked
      || !vaultProviderState.vaultEncryptionKey
      || !userId
      || !vaultId
    ) {
      return;
    }

    let debounceTimer: ReturnType<typeof setTimeout> | null = null;
    const scheduleRefresh = (options?: { readonly clearBeforeRefresh?: boolean }) => {
      if (options?.clearBeforeRefresh) {
        setUiView(null);
        setLocalVaultState(null);
        setLastError(null);
      }
      if (debounceTimer) {
        return;
      }
      debounceTimer = setTimeout(() => {
        debounceTimer = null;
        void refresh();
      }, 250);
    };

    const channel = supabase
      .channel(`vault-oplog-live-${vaultId}`)
      .on(
        'postgres_changes',
        {
          event: 'INSERT',
          schema: 'public',
          table: 'vault_operations',
          filter: `vault_id=eq.${vaultId}`,
        },
        () => scheduleRefresh(),
      )
      .on(
        'postgres_changes',
        {
          event: 'UPDATE',
          schema: 'public',
          table: 'vault_device_trust_records',
          filter: `vault_id=eq.${vaultId}`,
        },
        () => scheduleRefresh({ clearBeforeRefresh: true }),
      )
      .subscribe();

    const pollingTimer = window.setInterval(scheduleRefresh, 5000);

    return () => {
      if (debounceTimer) {
        window.clearTimeout(debounceTimer);
      }
      window.clearInterval(pollingTimer);
      void channel.unsubscribe();
    };
  }, [
    isEnabled,
    refresh,
    userId,
    vaultId,
    vaultProviderState.isLocked,
    vaultProviderState.vaultEncryptionKey,
  ]);

  return {
    vaultId,
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
