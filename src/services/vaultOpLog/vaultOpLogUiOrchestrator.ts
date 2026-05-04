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
import {
  decodeBase64Url,
} from './canonicalJson';
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

    // Step 3: Load records referenced by those operations
    const recordIds = [...new Set(deduplicatedOps.map((op) => op.recordId))];

    if (recordIds.length === 0) {
      // No operations → empty vault. Build UI view from empty state.
      const emptyState: LocalVaultState = {
        recordsById: new Map(),
        quarantinedRecordsById: new Map(),
        conflictsByRecordId: new Map(),
        trustedDevicesById: new Map(),
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

    // Step 4: Build a minimal trust list containing only the current device.
    // In a full deployment this would load the remote trust list.
    const now = new Date().toISOString();
    const trustedDevice: TrustedDeviceRecordV1 = {
      vaultId: input.vaultId,
      deviceId: input.deviceId,
      publicSigningKey: input.publicSigningKeyB64Url,
      deviceNameEncrypted: '',
      addedByDeviceId: null,
      addedAt: now,
      trustEpoch: 0,
      status: 'trusted',
      revokedAt: null,
      revokedByDeviceId: null,
    };

    const trust: TrustListInput = {
      vaultId: input.vaultId,
      trustedDevicesById: new Map([[input.deviceId, trustedDevice]]),
    };

    const publicKey = await crypto.subtle.importKey(
      'spki',
      decodeBase64Url(input.publicSigningKeyB64Url).buffer as ArrayBuffer,
      { name: 'ECDSA', namedCurve: 'P-256' },
      false,
      ['verify'],
    );

    // Step 5: Run the state machine over every operation
    let localState: LocalVaultState = {
      recordsById: new Map(),
      quarantinedRecordsById: new Map(),
      conflictsByRecordId: new Map(),
      trustedDevicesById: new Map([[input.deviceId, trustedDevice]]),
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
          publicKey,
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
