// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE
/**
 * `vaultOpLogUiOrchestrator` — Phase 9 UI orchestrator.
 *
 * Fetches the operation-log-based vault state via RPC, runs the
 * Phase 5 state machine, and produces a `VaultOpLogUiView` for the
 * React layer.
 *
 * Design principles:
 * - This is a READ-ONLY orchestrator for UI representation.
 * - It does NOT modify the old productive vault path.
 * - It does NOT decrypt or persist plaintexts beyond the state machine
 *   invocation.
 * - If RPC or state-machine failures occur, it returns `null` so the
 *   UI can keep normal egress blocked or show migration/quarantine state.
 * - It reuses the existing repository RPCs (Phase 3) and state machine
 *   (Phase 5) — no second state machine, no direct table writes.
 *
 * Security invariants:
 * - No plaintext secrets are returned.
 * - No vault keys are stored in the output.
 * - Failure is graceful (returns `null`); the UI must handle the
 *   fallback path.
 */

import {
  getVaultHead,
  getVaultChangesSince,
  getVaultRecordsByIds,
} from './vaultOpLogRepository';
import {
  applyTrustedDelete,
  applyRemoteOperation,
  determineVaultSecurityMode,
  type LocalVaultState,
  type VerifiedBaseRecordState,
} from './vaultStateMachine';
import { verifyOperation } from './verifyOperation';
import { computeVaultHead } from './recordHashes';
import {
  buildVaultOpLogUiView,
  type VaultOpLogUiView,
} from './vaultOpLogUiAdapter';
import {
  applyDeviceTrustOperation,
  TrustListInput,
} from './deviceTrustService';
import {
  applyRecoveryCodeRotationOperation,
  markRecoveryCodeCommitmentUsed,
  type RecoveryCodeSetState,
} from './recoveryCodeTrustService';
import {
  loadVerifiedVaultOpLogOfflineCache,
  saveVerifiedVaultOpLogOfflineCache,
  type VaultOpLogOfflineCacheEntry,
} from './vaultOpLogOfflineStore';
import { VaultOpLogPendingQueue } from './vaultOpLogPendingQueue';
import { IndexedDbQueuePersistence } from './vaultOpLogQueuePersistence';
import type { PendingLocalOperation } from './vaultOpLogPendingQueueTypes';
import type {
  VaultOperationRow,
  VaultRecordRow,
} from './vaultOpLogRpcTypes';
import type { SignedVaultOperationV1, TrustedDeviceRecordV1 } from './types';
import type { SupabaseRpcClient } from './vaultOpLogRepository';

// ---------------------------------------------------------------------------
// Input / Output
// ---------------------------------------------------------------------------

export interface VaultOpLogUiOrchestratorInput {
  readonly rpcClient: SupabaseRpcClient;
  readonly trustClient?: VaultOpLogTrustReadClient;
  readonly userId?: string;
  readonly vaultId: string;
  readonly deviceId?: string;
  readonly publicSigningKeyB64Url?: string;
  readonly vaultEncryptionKey: Uint8Array;
  readonly requireLocalDeviceTrust?: boolean;
}

export interface VaultOpLogUiOrchestratorResult {
  readonly uiView: VaultOpLogUiView | null;
  readonly localVaultState: LocalVaultState | null;
  readonly error: string | null;
}

export interface VaultOpLogTrustReadClient {
  readonly from: (table: 'vault_device_trust_records') => {
    readonly select: (columns: string) => {
      readonly eq: (
        column: 'vault_id',
        value: string,
      ) => Promise<{
        readonly data: unknown[] | null;
        readonly error: { readonly message?: string; readonly code?: string } | null;
      }>;
    };
  };
}

type TrustLoadResult =
  | { readonly kind: 'success'; readonly trust: TrustListInput }
  | { readonly kind: 'error' };

type OperationChainVerificationResult =
  | {
      readonly kind: 'success';
      readonly latestOperationByRecordId: ReadonlyMap<string, VaultOperationRow>;
      readonly trustByOperationId: ReadonlyMap<string, TrustListInput>;
      readonly verifiedTrust: TrustListInput;
      readonly verifiedHead: string | null;
    }
  | {
      readonly kind: 'error';
      readonly error: string;
    };

// ---------------------------------------------------------------------------
// Public orchestrator
// ---------------------------------------------------------------------------

export async function loadVaultOpLogUiState(
  input: VaultOpLogUiOrchestratorInput,
): Promise<VaultOpLogUiOrchestratorResult> {
  try {
    // Step 1: Load vault head
    const headResult = await getVaultHead(input.rpcClient, input.vaultId);
    if (headResult.kind !== 'success') {
      const cached = await loadCachedVaultOpLogUiState(input);
      if (cached) {
        return cached;
      }
      return {
        uiView: null,
        localVaultState: null,
        error: 'vault_head_load_failed',
      };
    }

    // Step 2: Load all operations with pagination (batch size 500)
    const PAGE_SIZE = 500;
    const allOperations: VaultOperationRow[] = [];
    let sinceSequence = 0;
    let page: VaultOperationRow[] = [];

    do {
      const changesResult = await getVaultChangesSince(
        input.rpcClient,
        input.vaultId,
        sinceSequence,
        PAGE_SIZE,
      );
      if (changesResult.kind !== 'success') {
        return {
          uiView: null,
          localVaultState: null,
          error: 'vault_changes_load_failed',
        };
      }
      page = [...changesResult.operations];
      allOperations.push(...page);
      if (page.length > 0) {
        const lastSeq = page[page.length - 1].sequenceNumber;
        sinceSequence = lastSeq;
      }
    } while (page.length === PAGE_SIZE);

    // Remove duplicates by opId and sort by sequenceNumber for deterministic ordering
    const seenOpIds = new Set<string>();
    const deduplicatedOps: VaultOperationRow[] = [];
    for (const op of allOperations) {
      if (!seenOpIds.has(op.opId)) {
        seenOpIds.add(op.opId);
        deduplicatedOps.push(op);
      }
    }
    deduplicatedOps.sort((a, b) => a.sequenceNumber - b.sequenceNumber);

    const trustResult = await loadTrustList(input);
    if (trustResult.kind !== 'success') {
      return {
        uiView: null,
        localVaultState: null,
        error: 'vault_trust_load_failed',
      };
    }
    const trust = trustResult.trust;

    if (input.requireLocalDeviceTrust && !isLocalDeviceTrusted(input, trust)) {
      const untrustedState = buildEmptyLocalVaultState({
        trust,
        lastVerifiedVaultHead: headResult.head.currentHead,
      });
      return {
        uiView: buildVaultOpLogUiView(untrustedState),
        localVaultState: untrustedState,
        error: null,
      };
    }

    const chainResult = deduplicatedOps.length === 0
      ? {
          kind: 'success' as const,
          latestOperationByRecordId: new Map<string, VaultOperationRow>(),
          trustByOperationId: new Map<string, TrustListInput>(),
          verifiedTrust: trust,
          verifiedHead: headResult.head.currentHead,
        }
      : await verifyOperationChain({
          operations: deduplicatedOps,
          trust,
          expectedHead: headResult.head.currentHead,
        });
    if (chainResult.kind !== 'success') {
      return {
        uiView: null,
        localVaultState: null,
        error: chainResult.error,
      };
    }

    // Step 3: Load records referenced by verified record operations
    const recordIds = [
      ...new Set(
        Array.from(chainResult.latestOperationByRecordId.values())
          .map((op) => op.recordId),
      ),
    ];

    if (recordIds.length === 0) {
      // No operations → empty vault. Build UI view from empty state.
      const emptyState = buildEmptyLocalVaultState({
        trust: chainResult.verifiedTrust,
        lastVerifiedVaultHead: chainResult.verifiedHead,
      });
      await persistOfflineCacheIfPossible(input, {
        currentHead: headResult.head.currentHead,
        currentSequenceNumber: headResult.head.currentSequenceNumber,
        operations: deduplicatedOps,
        records: [],
        trust: chainResult.verifiedTrust,
      });
      const withPending = await applyPendingLocalOperationsToState({
        state: emptyState,
        trust: chainResult.verifiedTrust,
        vaultEncryptionKey: input.vaultEncryptionKey,
        vaultId: input.vaultId,
      });
      return {
        uiView: buildVaultOpLogUiView(withPending),
        localVaultState: withPending,
        error: null,
      };
    }

    const recordsResult = await getVaultRecordsByIds(
      input.rpcClient,
      input.vaultId,
      recordIds,
    );
    if (recordsResult.kind !== 'success') {
      return {
        uiView: null,
        localVaultState: null,
        error: 'vault_records_load_failed',
      };
    }

    const recordsById = new Map<string, VaultRecordRow>();
    for (const record of recordsResult.records) {
      recordsById.set(record.recordId, record);
    }

    let localState: LocalVaultState = {
      recordsById: new Map(),
      quarantinedRecordsById: new Map(),
      conflictsByRecordId: new Map(),
      trustedDevicesById: chainResult.verifiedTrust.trustedDevicesById,
      lastVerifiedVaultHead: chainResult.verifiedHead,
    };

    for (const operation of chainResult.latestOperationByRecordId.values()) {
      const record = recordsById.get(operation.recordId) ?? null;
      if (!record) {
        // Missing record without a valid delete operation → quarantine
        const nextQuarantined = new Map(localState.quarantinedRecordsById);
        nextQuarantined.set(operation.recordId, {
          record: null,
          recordState: 'quarantinedMissingWithoutDelete',
          reason: 'missing_record_without_delete',
        });
        localState = {
          ...localState,
          quarantinedRecordsById: nextQuarantined,
        };
        continue;
      }

      try {
        const verifiedBaseRecordState = buildVerifiedBaseRecordState(operation);
        if (operation.opType !== 'create' && !verifiedBaseRecordState) {
          const nextQuarantined = new Map(localState.quarantinedRecordsById);
          nextQuarantined.set(operation.recordId, {
            record,
            recordState: 'quarantinedTampered',
            reason: 'operation_missing_verified_base_record_state',
          });
          localState = {
            ...localState,
            quarantinedRecordsById: nextQuarantined,
          };
          continue;
        }

        const applyResult = operation.opType === 'delete'
          ? await applyTrustedDelete({
              state: localState,
              operation,
              record,
              trust: chainResult.trustByOperationId.get(operation.opId) ?? trust,
              verifiedBaseRecordState,
              vaultHeadTransitionVerified: true,
            })
          : await applyRemoteOperation({
              state: localState,
              operation,
              record,
              trust: chainResult.trustByOperationId.get(operation.opId) ?? trust,
              vaultEncryptionKey: input.vaultEncryptionKey,
              verifiedBaseRecordState,
              vaultHeadTransitionVerified: true,
            });

        localState = {
          ...applyResult.nextState,
          lastVerifiedVaultHead: headResult.head.currentHead,
        };
      } catch {
        // State machine threw — quarantine the record and continue
        const nextQuarantined = new Map(localState.quarantinedRecordsById);
        nextQuarantined.set(record.recordId, {
          record,
          recordState: 'quarantinedUnreadable',
          reason: 'state_machine_exception',
        });
        localState = {
          ...localState,
          quarantinedRecordsById: nextQuarantined,
        };
      }
    }

    await persistOfflineCacheIfPossible(input, {
      currentHead: headResult.head.currentHead,
      currentSequenceNumber: headResult.head.currentSequenceNumber,
      operations: deduplicatedOps,
      records: recordsResult.records,
      trust: chainResult.verifiedTrust,
    });

    localState = await applyPendingLocalOperationsToState({
      state: localState,
      trust: chainResult.verifiedTrust,
      vaultEncryptionKey: input.vaultEncryptionKey,
      vaultId: input.vaultId,
    });

    // Step 6: Build UI view (no secrets)
    const uiView = buildVaultOpLogUiView(localState);

    return {
      uiView,
      localVaultState: localState,
      error: null,
    };
  } catch (err) {
    return {
      uiView: null,
      localVaultState: null,
      error: err instanceof Error ? err.message : 'unknown_orchestrator_error',
    };
  }
}

async function loadCachedVaultOpLogUiState(
  input: VaultOpLogUiOrchestratorInput,
): Promise<VaultOpLogUiOrchestratorResult | null> {
  if (!input.userId || !isRuntimeOffline()) {
    return null;
  }

  const cache = await loadVerifiedVaultOpLogOfflineCache({
    userId: input.userId,
    vaultId: input.vaultId,
  }).catch(() => null);
  if (!cache) {
    return null;
  }

  const trust = trustFromOfflineCache(cache);
  if (input.requireLocalDeviceTrust && !isLocalDeviceTrusted(input, trust)) {
    const untrustedState = buildEmptyLocalVaultState({
      trust,
      lastVerifiedVaultHead: cache.currentHead,
    });
    return {
      uiView: buildVaultOpLogUiView(untrustedState),
      localVaultState: untrustedState,
      error: null,
    };
  }

  const chainResult = cache.operations.length === 0
    ? {
        kind: 'success' as const,
        latestOperationByRecordId: new Map<string, VaultOperationRow>(),
        trustByOperationId: new Map<string, TrustListInput>(),
        verifiedTrust: trust,
        verifiedHead: cache.currentHead,
      }
    : await verifyOperationChain({
        operations: [...cache.operations].sort((a, b) => a.sequenceNumber - b.sequenceNumber),
        trust,
        expectedHead: cache.currentHead,
      });
  if (chainResult.kind !== 'success') {
    return {
      uiView: null,
      localVaultState: null,
      error: chainResult.error,
    };
  }

  const recordsById = new Map(cache.records.map((record) => [record.recordId, record]));
  let localState: LocalVaultState = {
    recordsById: new Map(),
    quarantinedRecordsById: new Map(),
    conflictsByRecordId: new Map(),
    trustedDevicesById: chainResult.verifiedTrust.trustedDevicesById,
    lastVerifiedVaultHead: chainResult.verifiedHead,
  };

  for (const operation of chainResult.latestOperationByRecordId.values()) {
    const record = recordsById.get(operation.recordId) ?? null;
    if (!record) {
      const nextQuarantined = new Map(localState.quarantinedRecordsById);
      nextQuarantined.set(operation.recordId, {
        record: null,
        recordState: 'quarantinedMissingWithoutDelete',
        reason: 'offline_cache_missing_record_without_delete',
      });
      localState = {
        ...localState,
        quarantinedRecordsById: nextQuarantined,
      };
      continue;
    }

    const verifiedBaseRecordState = buildVerifiedBaseRecordState(operation);
    if (operation.opType !== 'create' && !verifiedBaseRecordState) {
      const nextQuarantined = new Map(localState.quarantinedRecordsById);
      nextQuarantined.set(operation.recordId, {
        record,
        recordState: 'quarantinedTampered',
        reason: 'offline_cache_operation_missing_verified_base_record_state',
      });
      localState = {
        ...localState,
        quarantinedRecordsById: nextQuarantined,
      };
      continue;
    }

    const applyResult = operation.opType === 'delete'
      ? await applyTrustedDelete({
          state: localState,
          operation,
          record,
          trust: chainResult.trustByOperationId.get(operation.opId) ?? trust,
          verifiedBaseRecordState,
          vaultHeadTransitionVerified: true,
        })
      : await applyRemoteOperation({
          state: localState,
          operation,
          record,
          trust: chainResult.trustByOperationId.get(operation.opId) ?? trust,
          vaultEncryptionKey: input.vaultEncryptionKey,
          verifiedBaseRecordState,
          vaultHeadTransitionVerified: true,
        });

    localState = {
      ...applyResult.nextState,
      lastVerifiedVaultHead: cache.currentHead,
    };
  }

  localState = await applyPendingLocalOperationsToState({
    state: localState,
    trust: chainResult.verifiedTrust,
    vaultEncryptionKey: input.vaultEncryptionKey,
    vaultId: input.vaultId,
  });

  return {
    uiView: buildVaultOpLogUiView(localState),
    localVaultState: localState,
    error: null,
  };
}

async function persistOfflineCacheIfPossible(
  input: VaultOpLogUiOrchestratorInput,
  verified: {
    readonly currentHead: string | null;
    readonly currentSequenceNumber: number;
    readonly operations: readonly VaultOperationRow[];
    readonly records: readonly VaultRecordRow[];
    readonly trust: TrustListInput;
  },
): Promise<void> {
  if (!input.userId) {
    return;
  }

  await saveVerifiedVaultOpLogOfflineCache({
    userId: input.userId,
    vaultId: input.vaultId,
    currentHead: verified.currentHead,
    currentSequenceNumber: verified.currentSequenceNumber,
    operations: verified.operations,
    records: verified.records,
    trustedDevices: Array.from(verified.trust.trustedDevicesById.values()),
  }).catch(() => undefined);
}

async function applyPendingLocalOperationsToState(input: {
  readonly state: LocalVaultState;
  readonly trust: TrustListInput;
  readonly vaultEncryptionKey: Uint8Array;
  readonly vaultId: string;
}): Promise<LocalVaultState> {
  const queue = new VaultOpLogPendingQueue(input.vaultId, new IndexedDbQueuePersistence());
  await queue.load().catch(() => undefined);
  await queue.recoverAfterCrash().catch(() => undefined);

  let localState = input.state;
  const pending = queue.getPending();
  for (const entry of pending) {
    localState = await applyPendingEntryToState(localState, entry, input).catch(() => localState);
  }
  return localState;
}

async function applyPendingEntryToState(
  state: LocalVaultState,
  entry: PendingLocalOperation,
  input: {
    readonly trust: TrustListInput;
    readonly vaultEncryptionKey: Uint8Array;
  },
): Promise<LocalVaultState> {
  if (!entry.record) {
    return state;
  }
  const verifiedBaseRecordState = buildVerifiedBaseRecordState(entry.op);
  if (entry.op.opType !== 'create' && !verifiedBaseRecordState) {
    return state;
  }

  const result = entry.op.opType === 'delete'
    ? await applyTrustedDelete({
        state,
        operation: entry.op,
        record: entry.record,
        trust: input.trust,
        verifiedBaseRecordState,
      })
    : await applyRemoteOperation({
        state,
        operation: entry.op,
        record: entry.record,
        trust: input.trust,
        vaultEncryptionKey: input.vaultEncryptionKey,
        verifiedBaseRecordState,
      });

  return result.nextState;
}

function trustFromOfflineCache(cache: VaultOpLogOfflineCacheEntry): TrustListInput {
  return {
    vaultId: cache.vaultId,
    trustedDevicesById: new Map(cache.trustedDevices.map((device) => [device.deviceId, device])),
  };
}

function isRuntimeOffline(): boolean {
  return typeof navigator !== 'undefined' && navigator.onLine === false;
}

async function verifyOperationChain(input: {
  readonly operations: readonly VaultOperationRow[];
  readonly trust: TrustListInput;
  readonly expectedHead: string | null;
}): Promise<OperationChainVerificationResult> {
  const { operations, trust, expectedHead } = input;
  let verifiedHead = operations[0]?.baseVaultHead ?? null;
  const latestOperationByRecordId = new Map<string, VaultOperationRow>();
  const trustByOperationId = new Map<string, TrustListInput>();
  let historicalTrust: TrustListInput = {
    vaultId: trust.vaultId,
    trustedDevicesById: buildBootstrapTrustList(trust.trustedDevicesById, operations),
  };
  let historicalRecoveryCodeSets = new Map<string, RecoveryCodeSetState>();

  for (const operation of operations) {
    trustByOperationId.set(operation.opId, cloneTrustList(historicalTrust));
    const operationResult = await verifyOperation({
      operation,
      trust: historicalTrust,
      recoveryTrust: {
        vaultId: trust.vaultId,
        recoveryCodeSetsById: historicalRecoveryCodeSets,
      },
    });
    if (operationResult.kind !== 'validTrustedOperation') {
      return {
        kind: 'error',
        error: `operation_verification_failed:${operationResult.kind}`,
      };
    }

    if (operation.baseVaultHead !== verifiedHead) {
      return {
        kind: 'error',
        error: 'vault_head_mismatch',
      };
    }

    const expectedResultingHead = await computeVaultHead({
      previousVaultHead: verifiedHead,
      opHash: operation.opHash,
      recordId: operation.recordId,
      recordType: operation.recordType,
      newRecordHash: operation.newRecordHash,
      opType: operation.opType,
    });
    if (expectedResultingHead !== operation.resultingVaultHead) {
      return {
        kind: 'error',
        error: 'vault_head_mismatch',
      };
    }

    verifiedHead = operation.resultingVaultHead;
    if (isRecoveryCodeRotationOperation(operation)) {
      try {
        historicalRecoveryCodeSets = applyRecoveryCodeRotationOperation(
          historicalRecoveryCodeSets,
          operationResult.signedOperation,
        );
      } catch {
        return {
          kind: 'error',
          error: 'recovery_code_rotation_invalid',
        };
      }
    } else if (isDeviceTrustOperation(operation)) {
      try {
        historicalTrust = {
          vaultId: historicalTrust.vaultId,
          trustedDevicesById: applyDeviceTrustOperation(
            historicalTrust.trustedDevicesById,
            operationResult.signedOperation,
            buildDeviceTrustPayloadFromSignedOperation(operationResult.signedOperation),
          ),
        };
        if (operation.opType === 'recover_device') {
          historicalRecoveryCodeSets = markRecoveryCodeCommitmentUsed(
            historicalRecoveryCodeSets,
            operationResult.signedOperation,
          );
        }
      } catch {
        return {
          kind: 'error',
          error: 'device_trust_operation_invalid',
        };
      }
    } else {
      latestOperationByRecordId.set(operation.recordId, operation);
    }
  }

  if (verifiedHead !== expectedHead) {
    return {
      kind: 'error',
      error: 'vault_head_mismatch',
    };
  }

  return {
    kind: 'success',
    latestOperationByRecordId,
    trustByOperationId,
    verifiedTrust: historicalTrust,
    verifiedHead,
  };
}

function cloneTrustList(trust: TrustListInput): TrustListInput {
  return {
    vaultId: trust.vaultId,
    trustedDevicesById: new Map(trust.trustedDevicesById),
  };
}

function buildBootstrapTrustList(
  devices: ReadonlyMap<string, TrustedDeviceRecordV1>,
  operations: readonly VaultOperationRow[],
): Map<string, TrustedDeviceRecordV1> {
  const operationAddedDeviceIds = new Set(
    operations
      .filter((operation) => operation.opType === 'add_device' || operation.opType === 'recover_device')
      .map((operation) => operation.recordId),
  );
  const bootstrapDevices = new Map<string, TrustedDeviceRecordV1>();
  for (const device of devices.values()) {
    if (operationAddedDeviceIds.has(device.deviceId)) {
      continue;
    }

    const isBootstrapDevice = (device.addedOpId ?? null) === null
      && (device.addedByDeviceId === null || device.addedByDeviceId === device.deviceId);
    if (!isBootstrapDevice) {
      continue;
    }

    bootstrapDevices.set(device.deviceId, {
      ...device,
      status: 'trusted',
      revokedAt: null,
      revokedByDeviceId: null,
      trustEpoch: device.status === 'revoked'
        ? Math.max(0, device.trustEpoch - 1)
        : device.trustEpoch,
    });
  }
  return bootstrapDevices;
}

function buildDeviceTrustPayloadFromSignedOperation(
  operation: SignedVaultOperationV1,
): Parameters<typeof applyDeviceTrustOperation>[2] {
  if (operation.body.opType === 'add_device') {
    const targetPublicSigningKey = operation.body.targetPublicSigningKey ?? null;
    if (!targetPublicSigningKey) {
      throw new Error('add_device_missing_target_key');
    }
    return {
      kind: 'add',
        device: {
          vaultId: operation.body.vaultId,
          deviceId: operation.body.recordId,
          publicSigningKey: targetPublicSigningKey,
          deviceNameEncrypted: '',
          addedByDeviceId: operation.body.authorDeviceId,
          addedOpId: operation.body.opId,
          addedAt: operation.body.createdAtClient,
          trustEpoch: 0,
          status: 'trusted',
        revokedAt: null,
        revokedByDeviceId: null,
      },
    };
  }

  if (operation.body.opType === 'recover_device') {
    const targetPublicSigningKey = operation.body.targetPublicSigningKey ?? null;
    if (!targetPublicSigningKey) {
      throw new Error('recover_device_missing_target_key');
    }
    return {
      kind: 'recover',
        device: {
          vaultId: operation.body.vaultId,
          deviceId: operation.body.recordId,
          publicSigningKey: targetPublicSigningKey,
          deviceNameEncrypted: '',
          addedByDeviceId: null,
          addedOpId: operation.body.opId,
          addedAt: operation.body.createdAtClient,
          trustEpoch: 0,
          status: 'trusted',
        revokedAt: null,
        revokedByDeviceId: null,
      },
    };
  }

  if (operation.body.opType === 'revoke_device') {
    return {
      kind: 'revoke',
      deviceId: operation.body.recordId,
      revokedAt: operation.body.createdAtClient,
    };
  }

  throw new Error('not_device_trust_operation');
}

function isDeviceTrustOperation(operation: VaultOperationRow): boolean {
  return operation.opType === 'add_device'
    || operation.opType === 'revoke_device'
    || operation.opType === 'recover_device';
}

function isRecoveryCodeRotationOperation(operation: VaultOperationRow): boolean {
  return operation.opType === 'recovery_codes_rotate';
}

function isLocalDeviceTrusted(
  input: Pick<VaultOpLogUiOrchestratorInput, 'deviceId' | 'publicSigningKeyB64Url'>,
  trust: TrustListInput,
): boolean {
  if (!input.deviceId || !input.publicSigningKeyB64Url) {
    return false;
  }

  const trustedDevice = trust.trustedDevicesById.get(input.deviceId);
  return trustedDevice?.status === 'trusted'
    && trustedDevice.publicSigningKey === input.publicSigningKeyB64Url;
}

function buildEmptyLocalVaultState(input: {
  readonly trust: TrustListInput;
  readonly lastVerifiedVaultHead: string | null;
}): LocalVaultState {
  return {
    recordsById: new Map(),
    quarantinedRecordsById: new Map(),
    conflictsByRecordId: new Map(),
    trustedDevicesById: input.trust.trustedDevicesById,
    lastVerifiedVaultHead: input.lastVerifiedVaultHead,
  };
}

function buildVerifiedBaseRecordState(
  operation: VaultOperationRow,
): VerifiedBaseRecordState | undefined {
  if (operation.opType === 'create') {
    return undefined;
  }
  if (
    operation.baseRecordVersion === null
    || operation.previousCiphertextHash === null
  ) {
    return undefined;
  }
  return {
    recordVersion: operation.baseRecordVersion,
    ciphertextHash: operation.previousCiphertextHash,
  };
}

async function loadTrustList(
  input: VaultOpLogUiOrchestratorInput,
): Promise<TrustLoadResult> {
  if (!input.trustClient) {
    if (!input.deviceId || !input.publicSigningKeyB64Url) {
      return { kind: 'error' };
    }

    return {
      kind: 'success',
      trust: buildLocalDeviceOnlyTrust({
        vaultId: input.vaultId,
        deviceId: input.deviceId,
        publicSigningKeyB64Url: input.publicSigningKeyB64Url,
      }),
    };
  }

  try {
    const { data, error } = await input.trustClient
      .from('vault_device_trust_records')
      .select('vault_id,device_id,public_signing_key,device_name_encrypted,added_by_device_id,added_op_id,added_at,trust_epoch,status,revoked_at,revoked_by_device_id')
      .eq('vault_id', input.vaultId);

    if (error || !Array.isArray(data) || data.length === 0) {
      return { kind: 'error' };
    }

    const trustedDevicesById = new Map<string, TrustedDeviceRecordV1>();
    for (const row of data) {
      const device = mapTrustRow(row, input.vaultId);
      if (!device) {
        return { kind: 'error' };
      }
      trustedDevicesById.set(device.deviceId, device);
    }

    return {
      kind: 'success',
      trust: { vaultId: input.vaultId, trustedDevicesById },
    };
  } catch {
    return { kind: 'error' };
  }
}

function buildLocalDeviceOnlyTrust(
  input: Pick<VaultOpLogUiOrchestratorInput, 'vaultId' | 'deviceId' | 'publicSigningKeyB64Url'>,
): TrustListInput {
  const trustedDevice: TrustedDeviceRecordV1 = {
    vaultId: input.vaultId,
    deviceId: input.deviceId,
    publicSigningKey: input.publicSigningKeyB64Url,
    deviceNameEncrypted: '',
    addedByDeviceId: null,
    addedAt: new Date().toISOString(),
    trustEpoch: 0,
    status: 'trusted',
    revokedAt: null,
    revokedByDeviceId: null,
  };

  return {
    vaultId: input.vaultId,
    trustedDevicesById: new Map([[input.deviceId, trustedDevice]]),
  };
}

function mapTrustRow(row: unknown, vaultId: string): TrustedDeviceRecordV1 | null {
  if (!row || typeof row !== 'object') {
    return null;
  }

  const value = row as Record<string, unknown>;
  const rowVaultId = readString(value, 'vault_id');
  const deviceId = readString(value, 'device_id');
  const publicSigningKey = readString(value, 'public_signing_key');
  const deviceNameEncrypted = readString(value, 'device_name_encrypted');
  const addedAt = readString(value, 'added_at');
  const trustEpoch = readNumber(value, 'trust_epoch');
  const status = readString(value, 'status');

  if (
    rowVaultId !== vaultId
    || !deviceId
    || !publicSigningKey
    || deviceNameEncrypted === null
    || !addedAt
    || trustEpoch === null
    || (status !== 'trusted' && status !== 'revoked')
  ) {
    return null;
  }

  return {
    vaultId,
    deviceId,
    publicSigningKey,
    deviceNameEncrypted,
    addedByDeviceId: readNullableString(value, 'added_by_device_id'),
    addedOpId: readNullableString(value, 'added_op_id'),
    addedAt,
    trustEpoch,
    status,
    revokedAt: readNullableString(value, 'revoked_at'),
    revokedByDeviceId: readNullableString(value, 'revoked_by_device_id'),
  };
}

function readString(row: Record<string, unknown>, key: string): string | null {
  const value = row[key];
  return typeof value === 'string' ? value : null;
}

function readNullableString(row: Record<string, unknown>, key: string): string | null {
  const value = row[key];
  if (value === null || value === undefined) {
    return null;
  }
  return typeof value === 'string' ? value : null;
}

function readNumber(row: Record<string, unknown>, key: string): number | null {
  const value = row[key];
  return typeof value === 'number' && Number.isSafeInteger(value) ? value : null;
}
