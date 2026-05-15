// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE
/**
 * @fileoverview Vault Bulk Restore Hook
 *
 * Owns the multi-step "restore all visible quarantined items" flow that the
 * list panel triggers. The restoration is sequential: each item flows
 * through the central `opLogRestoreRecord`, which performs the security
 * checks. This hook only tracks completion/failure counts so the progress
 * dialog can render them — it does not bypass the orchestrator.
 */

import { useCallback, useState } from 'react';

import type { QuarantinedVaultItem } from '@/services/vaultIntegrityService';

import type { BulkRestoreProgress } from './VaultItemListBulkRestoreDialogs';

interface RestoreResult {
  readonly error: { readonly message: string } | null;
}

export interface UseVaultBulkRestoreInput {
  readonly opLogRestoreRecord: (itemId: string) => Promise<RestoreResult>;
}

export interface UseVaultBulkRestoreResult {
  readonly confirmOpen: boolean;
  readonly setConfirmOpen: (open: boolean) => void;
  readonly progress: BulkRestoreProgress;
  readonly closeProgress: () => void;
  readonly restoreAll: (items: readonly QuarantinedVaultItem[]) => Promise<void>;
}

const INITIAL_PROGRESS: BulkRestoreProgress = {
  open: false,
  status: 'running',
  total: 0,
  completed: 0,
  failed: 0,
  currentItemId: null,
  lastError: null,
};

export function useVaultBulkRestore({
  opLogRestoreRecord,
}: UseVaultBulkRestoreInput): UseVaultBulkRestoreResult {
  const [confirmOpen, setConfirmOpen] = useState(false);
  const [progress, setProgress] = useState<BulkRestoreProgress>(INITIAL_PROGRESS);

  const restoreAll = useCallback(async (itemsToRestore: readonly QuarantinedVaultItem[]) => {
    if (itemsToRestore.length === 0) {
      setConfirmOpen(false);
      return;
    }

    setConfirmOpen(false);
    setProgress({
      open: true,
      status: 'running',
      total: itemsToRestore.length,
      completed: 0,
      failed: 0,
      currentItemId: itemsToRestore[0].id,
      lastError: null,
    });

    let completed = 0;
    let failed = 0;
    let lastError: string | null = null;

    for (const item of itemsToRestore) {
      setProgress((current) => ({ ...current, currentItemId: item.id }));

      const result = await opLogRestoreRecord(item.id);
      if (result.error) {
        failed += 1;
        lastError = result.error.message;
      } else {
        completed += 1;
      }

      setProgress((current) => ({ ...current, completed, failed, lastError }));
    }

    setProgress((current) => ({
      ...current,
      status: failed > 0 ? 'failed' : 'success',
      currentItemId: null,
      lastError,
    }));
  }, [opLogRestoreRecord]);

  const closeProgress = useCallback(() => {
    setProgress((current) => ({ ...current, open: false }));
  }, []);

  return {
    confirmOpen,
    setConfirmOpen,
    progress,
    closeProgress,
    restoreAll,
  };
}
