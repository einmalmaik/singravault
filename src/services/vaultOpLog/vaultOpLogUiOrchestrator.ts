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
 *   UI can fall back to the old integrity path.
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
  applyRemoteOperation,
  determineVaultSecurityMode,
  type LocalVaultState,
} from './vaultStateMachine';
import {
  buildVaultOpLogUiView,
  type VaultOpLogUiView,
} from './vaultOpLogUiAdapter';
import type {
  TrustListInput,
} from './deviceTrustService';
import type {
  VaultOperationRow,
  VaultRecordRow,
} from './vaultOpLogRpcTypes';
import type { TrustedDeviceRecordV1 } from './types';
import type { SupabaseRpcClient } from './vaultOpLogRepository';

// ---------------------------------------------------------------------------
// Input / Output
// ---------------------------------------------------------------------------

export interface VaultOpLogUiOrchestratorInput {
  readonly rpcClient: SupabaseRpcClient;
  readonly trustClient?: VaultOpLogTrustReadClient;
  readonly vaultId: string;
  readonly deviceId: string;
  readonly publicSigningKeyB64Url: string;
  readonly vaultEncryptionKey: Uint8Array;
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

    // Step 3: Load records referenced by those operations
    const recordIds = [...new Set(deduplicatedOps.map((op) => op.recordId))];

    if (recordIds.length === 0) {
      // No operations → empty vault. Build UI view from empty state.
      const emptyState: LocalVaultState = {
        recordsById: new Map(),
        quarantinedRecordsById: new Map(),
        conflictsByRecordId: new Map(),
        trustedDevicesById: trust.trustedDevicesById,
        lastVerifiedVaultHead: null,
      };
      return {
        uiView: buildVaultOpLogUiView(emptyState),
        localVaultState: emptyState,
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

    // Step 5: Run the state machine over every operation
    let localState: LocalVaultState = {
      recordsById: new Map(),
      quarantinedRecordsById: new Map(),
      conflictsByRecordId: new Map(),
      trustedDevicesById: trust.trustedDevicesById,
      lastVerifiedVaultHead: null,
    };

    for (const operation of deduplicatedOps) {
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
        const applyResult = await applyRemoteOperation({
          state: localState,
          operation,
          record,
          trust,
          vaultEncryptionKey: input.vaultEncryptionKey,
        });

        localState = applyResult.nextState;
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

async function loadTrustList(
  input: VaultOpLogUiOrchestratorInput,
): Promise<TrustLoadResult> {
  if (!input.trustClient) {
    return {
      kind: 'success',
      trust: buildLocalDeviceOnlyTrust(input),
    };
  }

  try {
    const { data, error } = await input.trustClient
      .from('vault_device_trust_records')
      .select('vault_id,device_id,public_signing_key,device_name_encrypted,added_by_device_id,added_at,trust_epoch,status,revoked_at,revoked_by_device_id')
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
