// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE
/**
 * `vaultOpLogShadowMode` — Phase 8 orchestrator for background,
 * non-blocking, read-only verification of the operation-log-based
 * vault state.
 *
 * What it does:
 *   - Fetches the current vault head and recent changes via RPC.
 *   - Applies the new state machine (Phase 5) to every operation.
 *   - Builds a structural diagnosis (counts, classifications,
 *     hash prefixes, status codes).
 *   - Stores the diagnosis in a transient, in-memory buffer.
 *
 * What it does NOT do:
 *   - It does NOT modify the old productive vault path.
 *   - It does NOT switch UI, Autofill, Export, Search or Clipboard.
 *   - It does NOT decrypt or store plaintext vault items.
 *   - It does NOT write to vault tables outside the operation layer.
 *   - It does NOT set baselines, repair data, or delete records.
 *   - It does NOT lock the vault when shadow verification fails.
 *   - It does NOT log secrets, ciphertexts, keys, or user content.
 *
 * Threat model:
 *   - Assets: vault metadata, operation integrity, diagnosis buffers.
 *   - Trust boundaries: the shadow runs inside the same process as
 *     the productive vault, but must not leak keys into its buffers.
 *   - Data lifecycle: RPC read → verify → classify → sanitise →
 *     store diagnosis → discard all decrypted material.
 */

import { importEcdsaP256PublicKeySpki } from '@msdis/shield/signing';
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
  type TrustListInput,
} from './deviceTrustService';
import {
  decodeBase64Url,
} from './canonicalJson';
import {
  isVaultOpLogShadowModeEnabled,
} from './vaultOpLogFeatureFlags';
import type {
  ShadowModeRunInput,
  ShadowModeRunResult,
  ShadowModeVaultDiagnosis,
  ShadowModeRecordDiagnosis,
  ShadowModeRecordClassification,
  ShadowModeErrorKind,
} from './vaultOpLogShadowModeTypes';
import type {
  VaultRecordRow,
} from './vaultOpLogRpcTypes';
import type { TrustedDeviceRecordV1 } from './types';

// ---------------------------------------------------------------------------
// Transient diagnosis buffer (module-level, not persisted, cleared on reload)
// ---------------------------------------------------------------------------

const diagnosisBuffer: ShadowModeVaultDiagnosis[] = [];
const MAX_DIAGNOSIS_BUFFER_SIZE = 20;

export function getShadowModeDiagnoses(): readonly ShadowModeVaultDiagnosis[] {
  return Object.freeze([...diagnosisBuffer]);
}

export function clearShadowModeDiagnoses(): void {
  diagnosisBuffer.length = 0;
}

function pushDiagnosis(diagnosis: ShadowModeVaultDiagnosis): void {
  diagnosisBuffer.push(diagnosis);
  if (diagnosisBuffer.length > MAX_DIAGNOSIS_BUFFER_SIZE) {
    diagnosisBuffer.shift();
  }
}

// ---------------------------------------------------------------------------
// Public orchestrator
// ---------------------------------------------------------------------------

export async function runShadowModeVerification(
  input: ShadowModeRunInput,
): Promise<ShadowModeRunResult> {
  const startAt = new Date().toISOString();

  if (!isVaultOpLogShadowModeEnabled()) {
    const diagnosis: ShadowModeVaultDiagnosis = {
      vaultId: input.vaultId,
      runAt: startAt,
      status: 'skippedFlagDisabled',
      errorKind: 'featureFlagDisabled',
      verifiedCount: 0,
      quarantinedCount: 0,
      conflictCount: 0,
      deletedCount: 0,
      unreadableCount: 0,
      vaultSecurityMode: 'unknown',
      recordDiagnoses: [],
    };
    pushDiagnosis(diagnosis);
    return { success: false, diagnosis };
  }

  // Build an empty diagnosis skeleton so we always return something.
  const baseDiagnosis: ShadowModeVaultDiagnosis = {
    vaultId: input.vaultId,
    runAt: startAt,
    status: 'inProgress',
    errorKind: null,
    verifiedCount: 0,
    quarantinedCount: 0,
    conflictCount: 0,
    deletedCount: 0,
    unreadableCount: 0,
    vaultSecurityMode: 'unknown',
    recordDiagnoses: [],
  };

  try {
    // Step 1: Load vault head
    const headResult = await getVaultHead(input.rpcClient, input.vaultId);
    if (headResult.kind !== 'success') {
      const diagnosis: ShadowModeVaultDiagnosis = {
        ...baseDiagnosis,
        status: 'failed',
        errorKind: 'rpcError',
        vaultSecurityMode: 'unknown',
      };
      pushDiagnosis(diagnosis);
      return { success: false, diagnosis };
    }

    // Step 2: Load recent operations (since sequence 0 for a full check)
    const changesResult = await getVaultChangesSince(
      input.rpcClient,
      input.vaultId,
      0,
      500,
    );
    if (changesResult.kind !== 'success') {
      const diagnosis: ShadowModeVaultDiagnosis = {
        ...baseDiagnosis,
        status: 'failed',
        errorKind: 'rpcError',
        vaultSecurityMode: 'unknown',
      };
      pushDiagnosis(diagnosis);
      return { success: false, diagnosis };
    }

    const operations = changesResult.operations;

    // Step 3: Load records referenced by those operations
    const recordIds = [...new Set(operations.map((op) => op.recordId))];

    const recordsResult = await getVaultRecordsByIds(
      input.rpcClient,
      input.vaultId,
      recordIds,
    );
    if (recordsResult.kind !== 'success') {
      const diagnosis: ShadowModeVaultDiagnosis = {
        ...baseDiagnosis,
        status: 'failed',
        errorKind: 'rpcError',
        vaultSecurityMode: 'unknown',
      };
      pushDiagnosis(diagnosis);
      return { success: false, diagnosis };
    }

    const recordsById = new Map<string, VaultRecordRow>();
    for (const record of recordsResult.records) {
      recordsById.set(record.recordId, record);
    }

    // Step 4: Build a minimal trust list containing only the current device.
    // In a full deployment this would load the remote trust list; for Phase 8
    // we verify only operations signed by the device that performed the
    // migration, because that is the only device we currently have a public key
    // for in the caller context.
    const trustedDevice: TrustedDeviceRecordV1 = {
      vaultId: input.vaultId,
      deviceId: input.deviceId,
      publicSigningKey: input.publicSigningKeyB64Url,
      deviceNameEncrypted: '',
      addedByDeviceId: null,
      addedAt: startAt,
      trustEpoch: 0,
      status: 'trusted',
      revokedAt: null,
      revokedByDeviceId: null,
    };

    const trust: TrustListInput = {
      vaultId: input.vaultId,
      trustedDevicesById: new Map([[input.deviceId, trustedDevice]]),
    };

    const publicKey = await importEcdsaP256PublicKeySpki(
      decodeBase64Url(input.publicSigningKeyB64Url),
    );

    // Step 5: Run the state machine over every operation
    let localState: LocalVaultState = {
      recordsById: new Map(),
      quarantinedRecordsById: new Map(),
      conflictsByRecordId: new Map(),
      trustedDevicesById: new Map([[input.deviceId, trustedDevice]]),
      lastVerifiedVaultHead: null,
    };

    const recordDiagnoses: ShadowModeRecordDiagnosis[] = [];

    for (const operation of operations) {
      const record = recordsById.get(operation.recordId) ?? null;
      if (!record) {
        // Missing record without a valid delete operation is suspicious.
        recordDiagnoses.push({
          recordId: operation.recordId,
          recordType: operation.recordType,
          recordVersion: operation.baseRecordVersion ?? 0,
          classification: 'quarantined',
          reasonCode: 'missing_record_without_delete',
          hashPrefix: '00000000',
        });
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

        const classification = classifyRecordState(applyResult.recordState);
        recordDiagnoses.push({
          recordId: record.recordId,
          recordType: record.recordType,
          recordVersion: record.recordVersion,
          classification,
          reasonCode: applyResult.recordState,
          hashPrefix: record.ciphertextHash.slice(0, 8),
        });
      } catch (err) {
        // State machine threw — do not crash the shadow run.
        recordDiagnoses.push({
          recordId: record.recordId,
          recordType: record.recordType,
          recordVersion: record.recordVersion,
          classification: 'unreadable',
          reasonCode: 'state_machine_exception',
          hashPrefix: record.ciphertextHash.slice(0, 8),
        });
      }
    }

    // Step 6: Aggregate diagnosis without secrets
    const vaultMode = determineVaultSecurityMode(localState);
    let verifiedCount = 0;
    let quarantinedCount = 0;
    let conflictCount = 0;
    let deletedCount = 0;
    let unreadableCount = 0;

    for (const d of recordDiagnoses) {
      switch (d.classification) {
        case 'verified':
          verifiedCount += 1;
          break;
        case 'quarantined':
          quarantinedCount += 1;
          break;
        case 'conflict':
          conflictCount += 1;
          break;
        case 'deleted':
          deletedCount += 1;
          break;
        case 'unreadable':
        case 'pending':
          unreadableCount += 1;
          break;
      }
    }

    const diagnosis: ShadowModeVaultDiagnosis = {
      vaultId: input.vaultId,
      runAt: startAt,
      status: 'completed',
      errorKind: null,
      verifiedCount,
      quarantinedCount,
      conflictCount,
      deletedCount,
      unreadableCount,
      vaultSecurityMode: vaultMode,
      recordDiagnoses: Object.freeze([...recordDiagnoses]),
    };

    pushDiagnosis(diagnosis);
    return { success: true, diagnosis };
  } catch (err) {
    const errorKind: ShadowModeErrorKind = 'unexpectedError';
    const diagnosis: ShadowModeVaultDiagnosis = {
      ...baseDiagnosis,
      status: 'failed',
      errorKind,
      vaultSecurityMode: 'unknown',
    };
    pushDiagnosis(diagnosis);
    return { success: false, diagnosis };
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function classifyRecordState(
  recordState: import('./vaultSecurityStates').RecordSecurityState,
): ShadowModeRecordClassification {
  switch (recordState) {
    case 'verified':
    case 'restoredFromSnapshot':
      return 'verified';
    case 'deletedByTrustedDevice':
      return 'deleted';
    case 'conflict':
      return 'conflict';
    case 'quarantinedTampered':
    case 'quarantinedUnknownAuthor':
    case 'quarantinedMissingWithoutDelete':
    case 'quarantinedInvalidSchema':
      return 'quarantined';
    case 'quarantinedUnreadable':
      return 'unreadable';
    case 'pendingVerification':
    case 'containerQuarantined':
      return 'pending';
    default:
      return 'quarantined';
  }
}
