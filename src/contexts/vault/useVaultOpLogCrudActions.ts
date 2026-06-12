import { randomUuid } from '@dis/shield/random';
import { useCallback, useRef, type MutableRefObject } from 'react';
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
import {
  buildAddDeviceOperation,
  buildAddDeviceTrustPayload,
  buildRevokeDeviceOperation,
  buildRevokeDeviceTrustPayload,
  toVaultOperationRowFromSigned,
} from '@/services/vaultOpLog/vaultOpLogOperationBuilder';
import {
  loadVerifiedVaultOpLogDeviceContext,
  type VerifiedVaultOpLogDeviceContext,
} from '@/services/vaultOpLog/vaultOpLogDeviceIdentityRecovery';
import { loadVaultOpLogDeviceSigningKey } from '@/services/vaultOpLog/vaultOpLogDeviceSigningKeyStore';
import { loadVaultOpLogDeviceIdentity } from '@/services/vaultOpLog/vaultOpLogDeviceStore';
import { loadVaultOpLogUiState } from '@/services/vaultOpLog/vaultOpLogUiOrchestrator';
import { isAppOnline } from '@/services/offlineVaultService';
import { getVaultRecoveryCodeStatus } from '@/services/vaultOpLog/vaultRecoveryCodeService';
import { resolveVaultOpLogDefaultVaultId } from '@/services/vaultOpLog/vaultOpLogDefaultVaultResolver';
import { ensureInitialVaultOpLogTrust } from '@/services/vaultOpLog/vaultOpLogInitialTrustService';
import type { VaultOpLogTrustReadClient } from '@/services/vaultOpLog/vaultOpLogUiOrchestrator';
import type { SupabaseRpcClient } from '@/services/vaultOpLog/vaultOpLogRepository';
import type { SubmitVaultOperationResult } from '@/services/vaultOpLog/vaultOpLogRpcTypes';
import type { LocalVaultState, LocalVerifiedRecord } from '@/services/vaultOpLog/vaultStateMachine';
import type { RecordType } from '@/services/vaultOpLog/types';
import type { VaultContextType } from './vaultContextTypes';
import type { VaultProviderState } from './useVaultProviderState';
import { createOpLogActionQueue, type OpLogActionQueue } from './opLogActionQueue';

interface UseVaultOpLogCrudActionsInput {
  readonly state: VaultProviderState;
  readonly user: User | null;
  readonly decryptTrustedRecoverySnapshotItem: VaultContextType['decryptTrustedRecoverySnapshotItem'];
  readonly opLogUiRefresh: () => Promise<void>;
  readonly localVaultState: LocalVaultState | null;
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

function describeDeviceTrustSubmitFailure(
  result: Exclude<SubmitVaultOperationResult, { readonly kind: 'applied' }>,
  operationLabel: string,
): string {
  if (result.kind === 'rpcError') {
    return `RPC-Fehler beim Speichern der ${operationLabel}: ${result.message}`;
  }
  if (result.kind === 'rebaseNeeded') {
    return 'Vault-Stand ist veraltet. Bitte erneut synchronisieren und die Anfrage noch einmal bestätigen.';
  }
  if (result.kind === 'duplicateOpIdDifferentHash') {
    return 'Operation-ID wurde mit anderem Inhalt wiederverwendet.';
  }
  if (result.kind === 'unauthorized') {
    return `Keine gültige Sitzung für die ${operationLabel}.`;
  }
  if (result.kind === 'vaultOwnershipError') {
    return `Vault-Zugriff konnte für diese ${operationLabel} nicht bestätigt werden.`;
  }
  if (result.kind === 'malformedResponse') {
    return `Unerwartete RPC-Antwort beim Speichern der ${operationLabel}: ${result.reason}`;
  }
  return `${operationLabel} wurde nicht gespeichert: ${result.kind}`;
}

function getOpLogActionQueue(
  ref: MutableRefObject<OpLogActionQueue | null>,
): OpLogActionQueue {
  if (ref.current && typeof ref.current.run === 'function') {
    return ref.current;
  }

  const queue = createOpLogActionQueue();
  ref.current = queue;
  return queue;
}

export function useVaultOpLogCrudActions(input: UseVaultOpLogCrudActionsInput) {
  const opLogActionQueueRef = useRef<OpLogActionQueue | null>(null);

  const runSerializedAction = useCallback(<T,>(action: () => Promise<T>): Promise<T> => (
    getOpLogActionQueue(opLogActionQueueRef).run(action)
  ), []);

  const loadRuntimeContext = useCallback(async (): Promise<VerifiedOpLogRuntimeContext> => {
    const { state, user } = input;
    if (!user) {
      throw new VaultOpLogUiActionBlockedError('Keine aktive Sitzung.');
    }
    if (!state.vaultEncryptionKey) {
      throw new VaultOpLogUiActionBlockedError('Vault-Key ist nicht im Runtime-State verfügbar.');
    }

    const vaultId = state.vaultMigrationKeyContext?.vaultId ?? await resolveVaultOpLogDefaultVaultId(user.id);
    if (!vaultId) {
      throw new VaultOpLogUiActionBlockedError('Vault-ID konnte nicht verifiziert geladen werden.');
    }

    const online = isAppOnline();
    let deviceContext = online
      ? await loadVerifiedVaultOpLogDeviceContext({
          userId: user.id,
          vaultId,
          trustClient: supabase,
        })
      : loadVerifiedVaultOpLogDeviceContextFromLocalState(input.localVaultState);

    if (!deviceContext && online) {
      const bootstrapResult = await ensureInitialVaultOpLogTrust({
        userId: user.id,
        vaultId,
        rpcClient: supabase as unknown as SupabaseRpcClient,
      });
      if (bootstrapResult.kind === 'bootstrapped') {
        await input.opLogUiRefresh();
        deviceContext = await loadVerifiedVaultOpLogDeviceContext({
          userId: user.id,
          vaultId,
          trustClient: supabase,
        });
      }
    }

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

    const loaded = isAppOnline()
      ? await loadVaultOpLogUiState({
          rpcClient: deps.rpcClient,
          trustClient: deps.trustClient,
          userId: user.id,
          vaultId,
          deviceId: identity.deviceId,
          publicSigningKeyB64Url: identity.publicSigningKeyB64Url,
          vaultEncryptionKey: state.vaultEncryptionKey,
        })
      : { error: null, localVaultState: input.localVaultState };

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
    return runSerializedAction(async () => {
      try {
        await action();
        await afterVerifiedCommit();
        return { error: null };
      } catch (error) {
        return { error: error instanceof Error ? error : new Error('OpLog-Aktion fehlgeschlagen.') };
      }
    });
  }, [afterVerifiedCommit, runSerializedAction]);

  const opLogCreateItem = useCallback(async (
    plaintext: ItemPlaintext,
  ): Promise<{ error: Error | null; recordId: string | null }> => {
    return runSerializedAction(async () => {
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
    });
  }, [afterVerifiedCommit, loadRuntimeContext, runSerializedAction]);

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
    return runSerializedAction(async () => {
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
    });
  }, [afterVerifiedCommit, loadRuntimeContext, runSerializedAction]);

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

  const opLogRestoreRecord = useCallback((recordId: string) => runSerializedAction(() =>
    input.state.runQuarantineAction(recordId, async () => {
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
    }),
  ), [afterVerifiedCommit, input, loadRuntimeContext, runSerializedAction]);

  const opLogDeleteUntrustedRecord = useCallback((recordId: string) => runSerializedAction(() =>
    input.state.runQuarantineAction(recordId, async () => {
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
    }),
  ), [afterVerifiedCommit, input, loadRuntimeContext, runSerializedAction]);

  const opLogResolveConflict = useCallback((recordId: string) => runSerializedAction(() =>
    input.state.runQuarantineAction(recordId, async () => {
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
    }),
  ), [afterVerifiedCommit, input, loadRuntimeContext, runSerializedAction]);

  const opLogApproveDeviceRequest = useCallback(async (requestId: string): Promise<{ error: Error | null }> => {
    return runSerializedAction(async () => {
      try {
        const { deps, localVaultState } = await loadRuntimeContext();

        const approveResult = await approvePendingDeviceRequest(deps.rpcClient, requestId, deps.deviceId);

        if (approveResult.kind !== 'approved') {
          throw new Error(`Konnte Anfrage nicht genehmigen: ${approveResult.kind}`);
        }

        const builtOp = await buildAddDeviceOperation({
          opId: randomUuid(),
          intentId: randomUuid(),
          rebasedFromOpId: null,
          vaultId: deps.vaultId,
          deviceId: deps.deviceId,
          deviceSigningKey: deps.deviceSigningKey,
          targetDeviceId: approveResult.requestedDeviceId,
          targetPublicSigningKey: approveResult.requestedPublicSigningKey,
          targetDeviceName: approveResult.requestedDeviceName,
          baseVaultHead: localVaultState.lastVerifiedVaultHead,
          trustEpoch: deps.trustEpoch,
        });

        const submitResult = await submitVaultOperation(
          deps.rpcClient,
          toVaultOperationRowFromSigned(builtOp.signedOperation, builtOp.resultingVaultHead),
          null,
          buildAddDeviceTrustPayload(builtOp, deps.deviceId),
        );

        if (submitResult.kind !== 'applied') {
          throw new Error(describeDeviceTrustSubmitFailure(submitResult, 'Add-Device-Operation'));
        }

        await afterVerifiedCommit();
        return { error: null };
      } catch (error) {
        return { error: error instanceof Error ? error : new Error('Geräte-Genehmigung fehlgeschlagen.') };
      }
    });
  }, [afterVerifiedCommit, loadRuntimeContext, runSerializedAction]);

  const opLogRejectDeviceRequest = useCallback(async (requestId: string): Promise<{ error: Error | null }> => {
    return runSerializedAction(async () => {
      try {
        const { deps } = await loadRuntimeContext();
        const rejectResult = await rejectPendingDeviceRequest(deps.rpcClient, requestId, deps.deviceId);

        if (rejectResult.kind !== 'rejected') {
          throw new Error(`Konnte Anfrage nicht ablehnen: ${rejectResult.kind}`);
        }

        return { error: null };
      } catch (error) {
        return { error: error instanceof Error ? error : new Error('Geräte-Ablehnung fehlgeschlagen.') };
      }
    });
  }, [loadRuntimeContext, runSerializedAction]);

  const opLogRevokeDevice = useCallback(async (targetDeviceId: string): Promise<{ error: Error | null }> => {
    return runSerializedAction(async () => {
      try {
        const { deps, localVaultState } = await loadRuntimeContext();
        const trustedDevices = Array.from(localVaultState.trustedDevicesById.values())
          .filter((device) => device.status === 'trusted');
        if (trustedDevices.length <= 1) {
          const recoveryStatus = await getVaultRecoveryCodeStatus(deps.vaultId);
          if (!recoveryStatus.hasActiveSet || recoveryStatus.remainingCodes < 1) {
            throw new VaultOpLogUiActionBlockedError('Das letzte vertrauenswürdige Gerät kann erst entfernt werden, wenn mindestens ein aktiver Recovery-Code verfügbar ist.');
          }
        }
        if (!trustedDevices.some((device) => device.deviceId === targetDeviceId)) {
          throw new VaultOpLogUiActionBlockedError('Dieses Gerät ist nicht als vertrauenswürdig registriert.');
        }

        const builtOp = await buildRevokeDeviceOperation({
          opId: randomUuid(),
          intentId: randomUuid(),
          rebasedFromOpId: null,
          vaultId: deps.vaultId,
          deviceId: deps.deviceId,
          deviceSigningKey: deps.deviceSigningKey,
          targetDeviceId,
          baseVaultHead: localVaultState.lastVerifiedVaultHead,
          trustEpoch: deps.trustEpoch,
        });

        const submitResult = await submitVaultOperation(
          deps.rpcClient,
          toVaultOperationRowFromSigned(builtOp.signedOperation, builtOp.resultingVaultHead),
          null,
          buildRevokeDeviceTrustPayload(builtOp),
        );

        if (submitResult.kind !== 'applied') {
          throw new Error(describeDeviceTrustSubmitFailure(submitResult, 'Revoke-Device-Operation'));
        }

        await afterVerifiedCommit();
        return { error: null };
      } catch (error) {
        return { error: error instanceof Error ? error : new Error('Gerät konnte nicht entfernt werden.') };
      }
    });
  }, [afterVerifiedCommit, loadRuntimeContext, runSerializedAction]);

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
    opLogRevokeDevice,
  };
}

function loadVerifiedVaultOpLogDeviceContextFromLocalState(
  localVaultState: LocalVaultState | null,
): VerifiedVaultOpLogDeviceContext | null {
  const identity = loadVaultOpLogDeviceIdentity();
  if (!identity || !localVaultState) {
    return null;
  }

  const trusted = localVaultState.trustedDevicesById.get(identity.deviceId);
  if (
    !trusted
    || trusted.status !== 'trusted'
    || trusted.publicSigningKey !== identity.publicSigningKeyB64Url
  ) {
    return null;
  }

  return {
    identity,
    trustEpoch: trusted.trustEpoch,
  };
}
