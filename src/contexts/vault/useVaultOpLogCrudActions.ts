import { useCallback } from 'react';
import { supabase } from '@/integrations/supabase/client';
import type { User } from '@supabase/supabase-js';
import type { VaultItemData } from '@/services/cryptoService';
import { loadTrustedRecoverySnapshotState } from '@/services/vaultRecoveryOrchestrator';
import {
  createCategory,
  createItem,
  deleteCategory,
  deleteCategoryAndReferencedItems,
  deleteCategoryAndUnlinkItems,
  deleteItem,
  getReferencedVerifiedItemIdsForCategory,
  getVerifiedRecordBase,
  resolveConflict,
  restoreRecord,
  updateCategory,
  updateItem,
  type CategoryPlaintext,
  type ItemPlaintext,
  type OpLogCategoryDeleteMode,
  type VaultOpLogCrudServiceDependencies,
  type VerifiedRecordBase,
} from '@/services/vaultOpLog/vaultOpLogCrudService';
import { approvePendingDeviceRequest, rejectPendingDeviceRequest, submitVaultOperation } from '@/services/vaultOpLog/vaultOpLogRepository';
import { buildAddDeviceOperation } from '@/services/vaultOpLog/vaultOpLogOperationBuilder';
import { loadVerifiedVaultOpLogDeviceContext } from '@/services/vaultOpLog/vaultOpLogDeviceIdentityRecovery';
import { loadVaultOpLogDeviceSigningKey } from '@/services/vaultOpLog/vaultOpLogDeviceSigningKeyStore';
import { loadVaultOpLogUiState } from '@/services/vaultOpLog/vaultOpLogUiOrchestrator';
import type { VaultOpLogTrustReadClient } from '@/services/vaultOpLog/vaultOpLogUiOrchestrator';
import type { SupabaseRpcClient } from '@/services/vaultOpLog/vaultOpLogRepository';
import type { LocalVaultState, LocalVerifiedRecord } from '@/services/vaultOpLog/vaultStateMachine';
import type { RecordType } from '@/services/vaultOpLog/types';
import type { VaultContextType } from './vaultContextTypes';
import type { VaultProviderState } from './useVaultProviderState';

interface UseVaultOpLogCrudActionsInput {
  readonly state: VaultProviderState;
  readonly user: User | null;
  readonly decryptTrustedRecoverySnapshotItem: VaultContextType['decryptTrustedRecoverySnapshotItem'];
  readonly opLogUiRefresh: () => Promise<void>;
}

interface VerifiedOpLogRuntimeContext {
  readonly deps: VaultOpLogCrudServiceDependencies;
  readonly localVaultState: LocalVaultState;
}

class VaultOpLogUiActionBlockedError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'VaultOpLogUiActionBlockedError';
  }
}

const textEncoder = new TextEncoder();

function itemPlaintextFromVaultItemData(data: VaultItemData): ItemPlaintext {
  return {
    title: data.title ?? '',
    websiteUrl: data.websiteUrl ?? null,
    username: data.username ?? null,
    password: data.password ?? null,
    notes: data.notes ?? null,
    itemType: data.itemType === 'note'
      ? 'note'
      : data.itemType === 'totp'
        ? 'totp'
        : data.itemType === 'card'
          ? 'card'
          : 'password',
    categoryRecordId: data.categoryId ?? null,
    isFavorite: data.isFavorite ?? false,
    sortOrder: null,
    totpSecret: data.totpSecret ?? null,
    totpIssuer: data.totpIssuer ?? null,
    totpLabel: data.totpLabel ?? null,
    totpAlgorithm: data.totpAlgorithm ?? null,
    totpDigits: data.totpDigits ?? null,
    totpPeriod: data.totpPeriod ?? null,
    customFields: null,
  };
}

function encodeResolvedPlaintext(record: LocalVerifiedRecord): Uint8Array {
  if (!record.plaintext || record.plaintext.length === 0) {
    throw new VaultOpLogUiActionBlockedError('Kein verifizierter Plaintext für die Konfliktlösung verfügbar.');
  }
  return new Uint8Array(record.plaintext);
}

function recordBase(state: LocalVaultState, recordId: string): VerifiedRecordBase {
  return getVerifiedRecordBase(
    state.recordsById.get(recordId) ?? null,
    state.lastVerifiedVaultHead,
  );
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

export function useVaultOpLogCrudActions(input: UseVaultOpLogCrudActionsInput) {
  const loadRuntimeContext = useCallback(async (): Promise<VerifiedOpLogRuntimeContext> => {
    const { state, user } = input;
    if (!user) {
      throw new VaultOpLogUiActionBlockedError('Keine aktive Sitzung.');
    }
    if (!state.vaultEncryptionKey) {
      throw new VaultOpLogUiActionBlockedError('Vault-Key ist nicht im Runtime-State verfügbar.');
    }

    const vaultId = state.vaultMigrationKeyContext?.vaultId ?? await loadDefaultVaultId(user.id);
    if (!vaultId) {
      throw new VaultOpLogUiActionBlockedError('Vault-ID konnte nicht verifiziert geladen werden.');
    }

    const deviceContext = await loadVerifiedVaultOpLogDeviceContext({
      userId: user.id,
      vaultId,
      trustClient: supabase,
    });
    const identity = deviceContext?.identity ?? null;
    if (!identity) {
      throw new VaultOpLogUiActionBlockedError('OpLog-Device-Identität fehlt oder ist auf diesem Gerät nicht verfügbar.');
    }

    const deviceSigningKey = await loadVaultOpLogDeviceSigningKey({
      userId: user.id,
      vaultId,
      deviceId: identity.deviceId,
    });
    if (!deviceSigningKey) {
      throw new VaultOpLogUiActionBlockedError('Device-Signing-Key fehlt.');
    }

    const deps: VaultOpLogCrudServiceDependencies = {
      vaultId,
      userId: user.id,
      deviceId: identity.deviceId,
      deviceSigningKey,
      publicSigningKeyB64Url: identity.publicSigningKeyB64Url,
      vaultEncryptionKey: state.vaultEncryptionKey,
      trustEpoch: deviceContext.trustEpoch,
      keyVersion: 1,
      rpcClient: supabase as unknown as SupabaseRpcClient,
      trustClient: supabase as unknown as VaultOpLogTrustReadClient,
    };

    const loaded = await loadVaultOpLogUiState({
      rpcClient: deps.rpcClient,
      trustClient: deps.trustClient,
      vaultId,
      deviceId: identity.deviceId,
      publicSigningKeyB64Url: identity.publicSigningKeyB64Url,
      vaultEncryptionKey: state.vaultEncryptionKey,
    });

    if (loaded.error || !loaded.localVaultState) {
      throw new VaultOpLogUiActionBlockedError(
        loaded.error ?? 'OpLog-State konnte nicht verifiziert geladen werden.',
      );
    }

    return { deps, localVaultState: loaded.localVaultState };
  }, [input]);

  const afterVerifiedCommit = useCallback(async (): Promise<void> => {
    await input.opLogUiRefresh();
    input.state.bumpVaultDataVersion();
  }, [input]);

  const wrap = useCallback(async (
    action: () => Promise<void>,
  ): Promise<{ error: Error | null }> => {
    try {
      await action();
      await afterVerifiedCommit();
      return { error: null };
    } catch (error) {
      return { error: error instanceof Error ? error : new Error('OpLog-Aktion fehlgeschlagen.') };
    }
  }, [afterVerifiedCommit]);

  const opLogCreateItem = useCallback(async (
    plaintext: ItemPlaintext,
  ): Promise<{ error: Error | null; recordId: string | null }> => {
    try {
      const { deps, localVaultState } = await loadRuntimeContext();
      const result = await createItem(deps, { baseVaultHead: localVaultState.lastVerifiedVaultHead }, plaintext);
      await afterVerifiedCommit();
      return { error: null, recordId: result.recordId };
    } catch (error) {
      return {
        error: error instanceof Error ? error : new Error('OpLog-Create fehlgeschlagen.'),
        recordId: null,
      };
    }
  }, [afterVerifiedCommit, loadRuntimeContext]);

  const opLogUpdateItem = useCallback((recordId: string, plaintext: ItemPlaintext) => wrap(async () => {
    const { deps, localVaultState } = await loadRuntimeContext();
    await updateItem(deps, recordId, recordBase(localVaultState, recordId), plaintext);
  }), [loadRuntimeContext, wrap]);

  const opLogDeleteItem = useCallback((recordId: string) => wrap(async () => {
    const { deps, localVaultState } = await loadRuntimeContext();
    await deleteItem(deps, recordId, recordBase(localVaultState, recordId));
  }), [loadRuntimeContext, wrap]);

  const opLogCreateCategory = useCallback(async (
    plaintext: CategoryPlaintext,
  ): Promise<{ error: Error | null; recordId: string | null }> => {
    try {
      const { deps, localVaultState } = await loadRuntimeContext();
      const result = await createCategory(deps, { baseVaultHead: localVaultState.lastVerifiedVaultHead }, plaintext);
      await afterVerifiedCommit();
      return { error: null, recordId: result.recordId };
    } catch (error) {
      return {
        error: error instanceof Error ? error : new Error('OpLog-Create fehlgeschlagen.'),
        recordId: null,
      };
    }
  }, [afterVerifiedCommit, loadRuntimeContext]);

  const opLogUpdateCategory = useCallback((recordId: string, plaintext: CategoryPlaintext) => wrap(async () => {
    const { deps, localVaultState } = await loadRuntimeContext();
    await updateCategory(deps, recordId, recordBase(localVaultState, recordId), plaintext);
  }), [loadRuntimeContext, wrap]);

  const opLogDeleteCategory = useCallback((
    recordId: string,
    mode: OpLogCategoryDeleteMode = 'blockIfReferenced',
  ) => wrap(async () => {
    const { deps, localVaultState } = await loadRuntimeContext();
    if (mode === 'unlinkItems') {
      await deleteCategoryAndUnlinkItems(deps, recordId, localVaultState);
      return;
    }
    if (mode === 'deleteItems') {
      await deleteCategoryAndReferencedItems(deps, recordId, localVaultState);
      return;
    }

    await deleteCategory(
      deps,
      recordId,
      recordBase(localVaultState, recordId),
      getReferencedVerifiedItemIdsForCategory(localVaultState, recordId),
    );
  }), [loadRuntimeContext, wrap]);

  const opLogRestoreRecord = useCallback((recordId: string) => input.state.runQuarantineAction(recordId, async () => {
    const { deps, localVaultState } = await loadRuntimeContext();
    const record = localVaultState.recordsById.get(recordId) ?? null;
    if (!record || record.recordState !== 'deletedByTrustedDevice') {
      throw new VaultOpLogUiActionBlockedError('Restore benötigt einen verifizierten Tombstone-Kontext.');
    }

    const trustedState = await loadTrustedRecoverySnapshotState(deps.userId);
    const trustedSnapshot = trustedState.trustedSnapshot;
    const trustedItem = trustedSnapshot?.items.find((item) => item.id === recordId) ?? null;
    if (!trustedSnapshot || !trustedItem || !trustedSnapshot.vaultId) {
      throw new VaultOpLogUiActionBlockedError('Kein verifizierter Trusted-Snapshot-Kontext für Restore verfügbar.');
    }

    const snapshotId = `trusted-recovery:${trustedSnapshot.updatedAt}`;
    const restoredData = await input.decryptTrustedRecoverySnapshotItem(
      trustedItem,
      snapshotId,
      trustedSnapshot.vaultId,
    );
    await restoreRecord(
      deps,
      recordId,
      'item',
      recordBase(localVaultState, recordId),
      textEncoder.encode(JSON.stringify(itemPlaintextFromVaultItemData(restoredData))),
    );
    await afterVerifiedCommit();
  }), [afterVerifiedCommit, input, loadRuntimeContext]);

  const opLogDeleteUntrustedRecord = useCallback((recordId: string) => input.state.runQuarantineAction(recordId, async () => {
    const { deps, localVaultState } = await loadRuntimeContext();
    const record = localVaultState.recordsById.get(recordId) ?? null;
    if (!record || (record.recordState !== 'verified' && record.recordState !== 'restoredFromSnapshot')) {
      throw new VaultOpLogUiActionBlockedError('Delete benötigt verifizierte Record-Basisdaten.');
    }
    if (record.record.recordType === 'category') {
      await deleteCategory(
        deps,
        recordId,
        recordBase(localVaultState, recordId),
        getReferencedVerifiedItemIdsForCategory(localVaultState, recordId),
      );
    } else {
      await deleteItem(deps, recordId, recordBase(localVaultState, recordId));
    }
    await afterVerifiedCommit();
  }), [afterVerifiedCommit, input, loadRuntimeContext]);

  const opLogResolveConflict = useCallback((recordId: string) => input.state.runQuarantineAction(recordId, async () => {
    const { deps, localVaultState } = await loadRuntimeContext();
    const conflict = localVaultState.conflictsByRecordId.get(recordId);
    const record = localVaultState.recordsById.get(recordId) ?? null;
    if (!conflict || !record || (record.recordState !== 'verified' && record.recordState !== 'restoredFromSnapshot')) {
      throw new VaultOpLogUiActionBlockedError('Resolve benötigt einen verifizierten lokalen Konflikt-Kontext.');
    }
    await resolveConflict(
      deps,
      recordId,
      record.record.recordType as Extract<RecordType, 'item' | 'category'>,
      recordBase(localVaultState, recordId),
      encodeResolvedPlaintext(record),
    );
    await afterVerifiedCommit();
  }), [afterVerifiedCommit, input, loadRuntimeContext]);

  const opLogApproveDeviceRequest = useCallback(async (requestId: string): Promise<{ error: Error | null }> => {
    try {
      const { deps, localVaultState } = await loadRuntimeContext();
      
      const approveResult = await approvePendingDeviceRequest(deps.rpcClient, {
        vaultId: deps.vaultId,
        requestId,
      });

      if (approveResult.kind !== 'approved') {
        throw new Error(`Konnte Anfrage nicht genehmigen: ${approveResult.kind}`);
      }

      const builtOp = await buildAddDeviceOperation({
        opId: crypto.randomUUID(),
        intentId: crypto.randomUUID(),
        rebasedFromOpId: localVaultState.lastVerifiedVaultHead,
        vaultId: deps.vaultId,
        deviceId: deps.deviceId,
        deviceSigningKey: deps.deviceSigningKey,
        targetDeviceId: approveResult.requestedDeviceId,
        targetPublicSigningKey: approveResult.requestedPublicKey,
        baseVaultHead: localVaultState.lastVerifiedVaultHead,
        trustEpoch: deps.trustEpoch,
      });

      const submitResult = await submitVaultOperation(deps.rpcClient, {
        operationParams: builtOp.signedOperation,
        expectedPreviousHead: builtOp.signedOperation.rebasedFromOpId,
        resultingVaultHead: builtOp.resultingVaultHead,
      });

      if (submitResult.kind !== 'success') {
        throw new Error(`Fehler beim Speichern der Operation: ${submitResult.kind}`);
      }

      await afterVerifiedCommit();
      return { error: null };
    } catch (error) {
      return { error: error instanceof Error ? error : new Error('Geräte-Genehmigung fehlgeschlagen.') };
    }
  }, [afterVerifiedCommit, loadRuntimeContext]);

  const opLogRejectDeviceRequest = useCallback(async (requestId: string): Promise<{ error: Error | null }> => {
    try {
      const { deps } = await loadRuntimeContext();
      const rejectResult = await rejectPendingDeviceRequest(deps.rpcClient, {
        vaultId: deps.vaultId,
        requestId,
      });

      if (rejectResult.kind !== 'rejected') {
        throw new Error(`Konnte Anfrage nicht ablehnen: ${rejectResult.kind}`);
      }

      return { error: null };
    } catch (error) {
      return { error: error instanceof Error ? error : new Error('Geräte-Ablehnung fehlgeschlagen.') };
    }
  }, [loadRuntimeContext]);

  return {
    opLogCreateItem,
    opLogUpdateItem,
    opLogDeleteItem,
    opLogCreateCategory,
    opLogUpdateCategory,
    opLogDeleteCategory,
    opLogRestoreRecord,
    opLogDeleteUntrustedRecord,
    opLogResolveConflict,
    opLogApproveDeviceRequest,
    opLogRejectDeviceRequest,
  };
}
