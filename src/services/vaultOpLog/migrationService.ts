// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE
/**
 * `migrationService` — Phase 7 orchestrator for migrating legacy vault
 * items and categories into the operation-log record model.
 *
 * Architecture:
 * - The service is a state machine, not a monolithic block.
 * - Every state transition is a small, named, testable function.
 * - The orchestrator composes these functions into the full flow.
 * - No direct table writes; everything goes through `vaultOpLogRepository`.
 * - No plaintext secrets in logs, errors, or persisted state.
 * - Retry is idempotent because record IDs are deterministically derived
 *   from legacy IDs and operations use stable `opId`s derived from the
 *   same source.
 *
 * Threat model (reiterated from migrationTypes):
 * - Assets: passwords, vault entries, categories, vault encryption key,
 *   device signing key, recovery/snapshot data, tokens, metadata, logs.
 * - Trust boundaries: Web-Client, Tauri-Client, Supabase/Auth, DB,
 *   RPC-layer, local storage, snapshot store.
 * - Data lifecycle: legacy-read → decrypt → validate → quarantine →
 *   re-encrypt → sign → commit → verify → snapshot → retry/rollback.
 * - Risks: secret leaks, metadata leaks, replay, rollback, downgrade,
 *   partial migration, double commit, weak recovery, wrong device trust,
 *   faulty category mapping.
 */

import {
  buildCreateRecordOperation,
  toVaultOperationRow,
  toVaultRecordRow,
} from './vaultOpLogOperationBuilder';
import {
  submitVaultOperation,
  bootstrapVaultTrust,
  type SupabaseRpcClient,
} from './vaultOpLogRepository';
import {
  generateDeviceSigningKeyPair,
} from './operationSigningService';
import {
  computeVaultHead,
  sha256Base64Url,
} from './recordHashes';
import {
  canonicalizeVaultStructure,
  decodeBase64Url,
} from './canonicalJson';
import {
  createTrustedSnapshot,
  type CreateTrustedSnapshotInput,
} from './trustedSnapshotService';
import {
  applyRemoteOperation,
  determineVaultSecurityMode,
  type LocalVaultState,
} from './vaultStateMachine';
import {
  verifyOperation,
} from './verifyOperation';
import {
  verifyRecordContext,
} from './verifyRecordContext';
import {
  classifyOperationAuthor,
  isDeviceCurrentlyTrusted,
} from './deviceTrustService';
import {
  buildRecordAad,
} from './recordAad';
import {
  openRecord,
  deriveRecordKey,
} from './cryptoRecordService';
import {
  type MigrationState,
  type MigrationError,
  type MigrationErrorKind,
  type MigrationProgress,
  type MigrationCheckpoint,
  type LegacyVaultItemRow,
  type LegacyCategoryRow,
  type LegacyItemValidationFailure,
  type LegacyCategoryValidationFailure,
  type ValidatedLegacyItem,
  type ValidatedLegacyCategory,
  type PreparedItemMigration,
  type PreparedCategoryMigration,
} from './migrationTypes';
import {
  validateLegacyItem,
  validateLegacyCategory,
} from './legacyMigrationValidator';
import {
  buildMigratedItemPlaintext,
  buildMigratedCategoryPlaintext,
  legacyToNewRecordId,
} from './legacyMigrationMapper';
import {
  saveMigrationCheckpoint,
  loadMigrationCheckpoint,
  clearMigrationCheckpoint,
  saveMigrationCompletionMarker,
  type MigrationStorage,
} from './legacyMigrationStateStore';
import {
  isVaultOpLogRepositoryEnabled,
} from './vaultOpLogFeatureFlags';
import {
  type VaultOperationRow,
  type VaultRecordRow,
  type BootstrapVaultTrustResult,
  type SubmitVaultOperationResult,
} from './vaultOpLogRpcTypes';
import {
  type SignedVaultOperationV1,
  type TrustedDeviceRecordV1,
} from './types';

// ---------------------------------------------------------------------------
// Public orchestrator input / output
// ---------------------------------------------------------------------------

export interface MigrateVaultInput {
  readonly vaultId: string;
  readonly userId: string;
  readonly deviceId: string;
  readonly deviceSigningKey: CryptoKey;
  readonly publicSigningKeyB64Url: string;
  readonly vaultEncryptionKey: Uint8Array;
  readonly legacyItems: readonly LegacyVaultItemRow[];
  readonly legacyCategories: readonly LegacyCategoryRow[];
  /**
   * Decrypt a single legacy item.  Returns the decrypted plaintext
   * object (caller must cast to VaultItemData) or throws on failure.
   */
  readonly decryptItem: (legacyItem: LegacyVaultItemRow) => Promise<unknown>;
  readonly rpcClient: SupabaseRpcClient;
  readonly now?: string;
  readonly checkpointStorage?: MigrationStorage;
}

export interface MigrateVaultResult {
  readonly success: boolean;
  readonly finalState: MigrationState;
  readonly progress: MigrationProgress;
  readonly error: MigrationError | null;
}

// ---------------------------------------------------------------------------
// Orchestrator
// ---------------------------------------------------------------------------

/**
 * Run the full migration flow.
 *
 * The function is designed to be resumable: if a previous checkpoint
 * exists, it picks up from the last successful state.  Every major
 * step writes a checkpoint before proceeding to the next step.
 */
export async function migrateVault(input: MigrateVaultInput): Promise<MigrateVaultResult> {
  const checkpoint = loadMigrationCheckpoint(input.vaultId, input.checkpointStorage);
  const state: MigrationOrchestratorState = {
    vaultId: input.vaultId,
    userId: input.userId,
    deviceId: input.deviceId,
    deviceSigningKey: input.deviceSigningKey,
    publicSigningKeyB64Url: input.publicSigningKeyB64Url,
    vaultEncryptionKey: input.vaultEncryptionKey,
    rpcClient: input.rpcClient,
    checkpointStorage: input.checkpointStorage,
    now: input.now ?? new Date().toISOString(),
    // Runtime accumulators (not persisted; rebuilt on resume)
    validatedItems: [],
    validatedCategories: [],
    quarantinedItems: [],
    quarantinedCategories: [],
    preparedItems: [],
    preparedCategories: [],
    builtOperations: [],
    // Loaded from checkpoint if resuming
    currentState: checkpoint?.state ?? 'notStarted',
    snapshotId: checkpoint?.snapshotId ?? null,
    legacyToNewRecordIdMap: checkpoint ? new Map(Object.entries(checkpoint.legacyToNewRecordIdMap)) : new Map(),
    committedOpIds: checkpoint ? new Set(checkpoint.committedOpIds) : new Set(),
  };

  try {
    // Step 1: Preflight
    if (isBefore(state.currentState, 'preflightChecked')) {
      runPreflight(state, input.legacyItems, input.legacyCategories);
      await writeCheckpoint(state, null, input.checkpointStorage);
    }

    // Step 2: Pre-migration snapshot. This must be the first step after
    // preflight/checkpoint validation that can have an irreversible security
    // meaning for support and recovery. No server-side trust/head/op-log write
    // is allowed before this checkpoint exists.
    if (isBefore(state.currentState, 'preMigrationSnapshotCreated')) {
      await createPreMigrationSnapshot(state);
      await writeCheckpoint(state, null, input.checkpointStorage);
    }

    // Step 3: Device trust bootstrap. Bootstrap is still required before
    // operation commits, but Phase 12 preflight forbids running it before the
    // pre-migration snapshot.
    if (isBefore(state.currentState, 'deviceTrustPrepared')) {
      await bootstrapDeviceTrust(state);
      await writeCheckpoint(state, null, input.checkpointStorage);
    }

    // Step 4: Read & decrypt legacy (caller already read them; we decrypt)
    if (isBefore(state.currentState, 'legacyValidated')) {
      await readAndValidateLegacy(state, input.legacyItems, input.legacyCategories, input.decryptItem);
      await writeCheckpoint(state, null, input.checkpointStorage);
    }

    // Step 5: Prepare new records
    if (isBefore(state.currentState, 'newRecordsPrepared')) {
      prepareNewRecords(state);
      await writeCheckpoint(state, null, input.checkpointStorage);
    }

    // Step 6: Build initial operations
    if (isBefore(state.currentState, 'initialOperationsPrepared')) {
      await buildInitialOperations(state);
      await writeCheckpoint(state, null, input.checkpointStorage);
    }

    // Step 7: Commit operations via RPC
    if (isBefore(state.currentState, 'commitCompleted')) {
      await commitMigrationBatch(state);
      await writeCheckpoint(state, null, input.checkpointStorage);
    }

    // Step 8: Verify committed state
    if (isBefore(state.currentState, 'verified')) {
      await verifyCommittedState(state);
      await writeCheckpoint(state, null, input.checkpointStorage);
    }

    // Step 9: Mark legacy as migrated (not deleting legacy data)
    if (isBefore(state.currentState, 'legacyMarkedMigrated')) {
      markLegacyMigrated(state);
      await writeCheckpoint(state, null, input.checkpointStorage);
      saveMigrationCompletionMarker({
        version: 1,
        vaultId: state.vaultId,
        state: 'verified',
        completedAt: state.now,
      }, input.checkpointStorage);
      clearMigrationCheckpoint(state.vaultId, input.checkpointStorage);
    }

    return buildResult(state, null);
  } catch (err) {
    const migrationError = classifyOrchestratorError(err, state.currentState);
    state.currentState = migrationError.retryable ? 'failedRetryable' : 'failedBlocked';
    await writeCheckpoint(state, migrationError, input.checkpointStorage);
    return buildResult(state, migrationError);
  }
}

// ---------------------------------------------------------------------------
// Internal state container (transient, not exported)
// ---------------------------------------------------------------------------

interface MigrationOrchestratorState {
  vaultId: string;
  userId: string;
  deviceId: string;
  deviceSigningKey: CryptoKey;
  publicSigningKeyB64Url: string;
  vaultEncryptionKey: Uint8Array;
  rpcClient: SupabaseRpcClient;
  checkpointStorage?: MigrationStorage;
  now: string;

  currentState: MigrationState;
  snapshotId: string | null;
  legacyToNewRecordIdMap: Map<string, string>;
  committedOpIds: Set<string>;

  validatedItems: ValidatedLegacyItem[];
  validatedCategories: ValidatedLegacyCategory[];
  quarantinedItems: LegacyItemValidationFailure[];
  quarantinedCategories: LegacyCategoryValidationFailure[];

  preparedItems: PreparedItemMigration[];
  preparedCategories: PreparedCategoryMigration[];

  builtOperations: BuiltMigrationOperation[];
}

interface BuiltMigrationOperation {
  readonly opRow: VaultOperationRow;
  readonly recordRow: VaultRecordRow;
}

// ---------------------------------------------------------------------------
// Step 1 — Preflight
// ---------------------------------------------------------------------------

function runPreflight(
  state: MigrationOrchestratorState,
  legacyItems: readonly LegacyVaultItemRow[],
  legacyCategories: readonly LegacyCategoryRow[],
): void {
  // Feature flag must be enabled
  if (!isVaultOpLogRepositoryEnabled()) {
    throw migrationError('preflightFailed', 'vault op log repository feature flag is not enabled', false);
  }

  // Device signing key must be present
  if (!state.deviceSigningKey) {
    throw migrationError('preflightFailed', 'device signing key is required', false);
  }

  // Vault encryption key must be present
  if (!state.vaultEncryptionKey || state.vaultEncryptionKey.length < 16) {
    throw migrationError('preflightFailed', 'vault encryption key is missing or too short', false);
  }

  // RPC client must be present
  if (!state.rpcClient) {
    throw migrationError('preflightFailed', 'rpc client is required', false);
  }

  // Safety freeze: no parallel writes. We simulate this by ensuring
  // no other migration checkpoint exists for this vault in a
  // non-terminal state. (In a real UI integration this would be a
  // stronger lock.)
  const existing = loadMigrationCheckpoint(state.vaultId, state.checkpointStorage);
  if (existing && !isTerminalState(existing.state)) {
    throw migrationError(
      'preflightFailed',
      'another migration is already in progress for this vault',
      false,
    );
  }

  // Basic sanity on legacy data
  if (legacyItems.length === 0 && legacyCategories.length === 0) {
    // Empty vault is allowed but unusual; log for diagnosis only.
    // No secrets logged.
  }

  state.currentState = 'preflightChecked';
}

// ---------------------------------------------------------------------------
// Step 2 — Device trust bootstrap
// ---------------------------------------------------------------------------

async function bootstrapDeviceTrust(state: MigrationOrchestratorState): Promise<void> {
  const initialHead = await computeVaultHead({
    previousVaultHead: null,
    opHash: await sha256Base64Url(new TextEncoder().encode(`migration-bootstrap-${state.vaultId}`)),
    recordId: 'bootstrap',
    recordType: 'manifest',
    newRecordHash: null,
    opType: 'create',
  });

  const initialOpId = crypto.randomUUID();

  const result = await bootstrapVaultTrust(
    state.rpcClient,
    state.vaultId,
    state.deviceId,
    state.publicSigningKeyB64Url,
    '', // deviceNameEncrypted — minimal, no secret
    initialHead,
    initialOpId,
  );

  if (result.kind !== 'bootstrapped') {
    if (result.kind === 'trustListAlreadyExists' || result.kind === 'headAlreadyExists') {
      // Already bootstrapped — this is acceptable on retry.
      // We do not treat it as an error.
    } else {
      throw migrationError(
        'deviceTrustBootstrapFailed',
        `bootstrap_vault_trust failed: ${result.kind}`,
        result.kind === 'rpcError' || result.kind === 'malformedResponse',
      );
    }
  }

  state.currentState = 'deviceTrustPrepared';
}

// ---------------------------------------------------------------------------
// Step 3 — Pre-migration snapshot
// ---------------------------------------------------------------------------

async function createPreMigrationSnapshot(state: MigrationOrchestratorState): Promise<void> {
  const snapshotId = `pre-migration-${state.vaultId}-${state.now}`;

  // Build a minimal local vault state with only the bootstrapped device.
  const trustedDevice: TrustedDeviceRecordV1 = {
    vaultId: state.vaultId,
    deviceId: state.deviceId,
    publicSigningKey: state.publicSigningKeyB64Url,
    deviceNameEncrypted: '',
    addedByDeviceId: null,
    addedAt: state.now,
    trustEpoch: 0,
    status: 'trusted',
    revokedAt: null,
    revokedByDeviceId: null,
  };

  const localState: LocalVaultState = {
    recordsById: new Map(),
    quarantinedRecordsById: new Map(),
    conflictsByRecordId: new Map(),
    trustedDevicesById: new Map([[state.deviceId, trustedDevice]]),
    lastVerifiedVaultHead: null,
  };

  const trustedDevicesHash = await sha256Base64Url(
    canonicalizeVaultStructure({ devices: [trustedDevice] }),
  );

  // No manifest exists yet; use a deterministic placeholder hash.
  const manifestHash = await sha256Base64Url(
    canonicalizeVaultStructure({ placeholder: true, vaultId: state.vaultId }),
  );

  const snapshotInput: CreateTrustedSnapshotInput = {
    snapshotId,
    vaultId: state.vaultId,
    createdByDeviceId: state.deviceId,
    deviceSigningKey: state.deviceSigningKey,
    vaultEncryptionKey: state.vaultEncryptionKey,
    trustEpoch: 0,
    verifiedVaultHead: null,
    state: localState,
    trustedDevicesHash,
    manifestHash,
    now: state.now,
  };

  try {
    await createTrustedSnapshot(snapshotInput);
  } catch (err) {
    const msg = err instanceof Error ? err.message : 'unknown snapshot error';
    throw migrationError('snapshotFailed', msg, true);
  }

  state.snapshotId = snapshotId;
  state.currentState = 'preMigrationSnapshotCreated';
}

// ---------------------------------------------------------------------------
// Step 4 — Read and validate legacy data
// ---------------------------------------------------------------------------

async function readAndValidateLegacy(
  state: MigrationOrchestratorState,
  legacyItems: readonly LegacyVaultItemRow[],
  legacyCategories: readonly LegacyCategoryRow[],
  decryptItem: (item: LegacyVaultItemRow) => Promise<unknown>,
): Promise<void> {
  const validatedItems: ValidatedLegacyItem[] = [];
  const validatedCategories: ValidatedLegacyCategory[] = [];
  const quarantinedItems: LegacyItemValidationFailure[] = [];
  const quarantinedCategories: LegacyCategoryValidationFailure[] = [];

  // Categories first — items need their mapped category IDs later.
  for (const cat of legacyCategories) {
    const result = validateLegacyCategory({ legacyCategory: cat });
    if (result.ok === true) {
      validatedCategories.push(result.validated);
    } else {
      quarantinedCategories.push(result.failure);
    }
  }

  for (const item of legacyItems) {
    let decryptedData: unknown;
    try {
      decryptedData = await decryptItem(item);
    } catch {
      quarantinedItems.push({
        legacyId: item.id,
        reason: 'legacyDecryptFailed',
        detail: 'item could not be decrypted',
      });
      continue;
    }

    const result = validateLegacyItem({ legacyItem: item, decryptedData });
    if (result.ok === true) {
      validatedItems.push(result.validated);
    } else {
      quarantinedItems.push(result.failure);
    }
  }

  state.validatedItems = validatedItems;
  state.validatedCategories = validatedCategories;
  state.quarantinedItems = quarantinedItems;
  state.quarantinedCategories = quarantinedCategories;
  state.currentState = 'legacyValidated';
}

// ---------------------------------------------------------------------------
// Step 5 — Prepare new records
// ---------------------------------------------------------------------------

function prepareNewRecords(state: MigrationOrchestratorState): void {
  // Build deterministic new record IDs for every validated category.
  for (const cat of state.validatedCategories) {
    const newRecordId = legacyToNewRecordId(cat.legacyId);
    state.legacyToNewRecordIdMap.set(cat.legacyId, newRecordId);
  }

  const preparedCategories: PreparedCategoryMigration[] = [];
  for (const cat of state.validatedCategories) {
    const newRecordId = state.legacyToNewRecordIdMap.get(cat.legacyId)!;
    const prepared = buildMigratedCategoryPlaintext({
      validatedCategory: cat,
      newRecordId,
    });
    preparedCategories.push(prepared);
  }

  const preparedItems: PreparedItemMigration[] = [];
  for (const item of state.validatedItems) {
    const newRecordId = legacyToNewRecordId(item.legacyId);
    state.legacyToNewRecordIdMap.set(item.legacyId, newRecordId);

    // Map legacy category ID to new category record ID, if possible.
    let mappedCategoryRecordId: string | null = null;
    if (item.categoryId !== null) {
      mappedCategoryRecordId = state.legacyToNewRecordIdMap.get(item.categoryId) ?? null;
      // If the category was quarantined and therefore has no new record ID,
      // the item ends up with null categoryRecordId.  This is safe: the
      // item itself is still migratable, but its category link is broken.
    }

    const prepared = buildMigratedItemPlaintext({
      validatedItem: item,
      newRecordId,
      mappedCategoryRecordId,
    });
    preparedItems.push(prepared);
  }

  state.preparedCategories = preparedCategories;
  state.preparedItems = preparedItems;
  state.currentState = 'newRecordsPrepared';
}

// ---------------------------------------------------------------------------
// Step 6 — Build initial operations
// ---------------------------------------------------------------------------

async function buildInitialOperations(state: MigrationOrchestratorState): Promise<void> {
  const operations: BuiltMigrationOperation[] = [];

  // Build a manifest create operation first so the vault has a manifest.
  const manifestRecordId = legacyToNewRecordId(`manifest-${state.vaultId}`);
  const manifestPlaintext = canonicalizeVaultStructure({
    vaultId: state.vaultId,
    manifestVersion: 1,
    createdAt: state.now,
    createdByDeviceId: state.deviceId,
    currentKeyVersion: 1,
    cryptoPolicy: {
      recordEncryption: 'record-aead-v1',
      kdfVersion: 1,
      operationSignature: 'device-signature-v1',
    },
    features: {
      categories: true,
      attachments: false,
      sharing: false,
      passkeys: false,
    },
  });

  const manifestBuilt = await buildCreateRecordOperation({
    opId: legacyToNewRecordId(`op-manifest-${state.vaultId}`),
    intentId: legacyToNewRecordId(`intent-manifest-${state.vaultId}`),
    rebasedFromOpId: null,
    vaultId: state.vaultId,
    recordId: manifestRecordId,
    deviceId: state.deviceId,
    deviceSigningKey: state.deviceSigningKey,
    trustEpoch: 0,
    baseVaultHead: null,
    recordType: 'manifest',
    vaultEncryptionKey: state.vaultEncryptionKey,
    plaintext: manifestPlaintext,
    keyVersion: 1,
    createdAtClient: state.now,
  });

  const manifestOpRow = toVaultOperationRow(manifestBuilt);
  const manifestRecRow = toVaultRecordRow(manifestBuilt.sealedRecord, manifestOpRow, false);
  operations.push({ opRow: manifestOpRow, recordRow: manifestRecRow });

  // Categories next
  for (const cat of state.preparedCategories) {
    const built = await buildCreateRecordOperation({
      opId: legacyToNewRecordId(`op-cat-${cat.legacyId}`),
      intentId: legacyToNewRecordId(`intent-cat-${cat.legacyId}`),
      rebasedFromOpId: null,
      vaultId: state.vaultId,
      recordId: cat.newRecordId,
      deviceId: state.deviceId,
      deviceSigningKey: state.deviceSigningKey,
      trustEpoch: 0,
      baseVaultHead: manifestBuilt.resultingVaultHead,
      recordType: 'category',
      vaultEncryptionKey: state.vaultEncryptionKey,
      plaintext: cat.plaintext,
      keyVersion: 1,
      createdAtClient: state.now,
    });

    const opRow = toVaultOperationRow(built);
    const recRow = toVaultRecordRow(built.sealedRecord, opRow, false);
    operations.push({ opRow, recordRow: recRow });
  }

  // Items last
  for (const item of state.preparedItems) {
    const built = await buildCreateRecordOperation({
      opId: legacyToNewRecordId(`op-item-${item.legacyId}`),
      intentId: legacyToNewRecordId(`intent-item-${item.legacyId}`),
      rebasedFromOpId: null,
      vaultId: state.vaultId,
      recordId: item.newRecordId,
      deviceId: state.deviceId,
      deviceSigningKey: state.deviceSigningKey,
      trustEpoch: 0,
      baseVaultHead: operations[operations.length - 1].opRow.resultingVaultHead,
      recordType: 'item',
      vaultEncryptionKey: state.vaultEncryptionKey,
      plaintext: item.plaintext,
      keyVersion: 1,
      createdAtClient: state.now,
    });

    const opRow = toVaultOperationRow(built);
    const recRow = toVaultRecordRow(built.sealedRecord, opRow, false);
    operations.push({ opRow, recordRow: recRow });
  }

  state.builtOperations = operations;
  state.currentState = 'initialOperationsPrepared';
}

// ---------------------------------------------------------------------------
// Step 7 — Commit migration batch via repository
// ---------------------------------------------------------------------------

async function commitMigrationBatch(state: MigrationOrchestratorState): Promise<void> {
  state.currentState = 'commitStarted';

  for (const built of state.builtOperations) {
    // Skip already-committed operations (idempotent retry)
    if (state.committedOpIds.has(built.opRow.opId)) {
      continue;
    }

    const recordPayload = {
      aadHash: built.recordRow.aadHash,
      ciphertextHash: built.recordRow.ciphertextHash,
      nonce: built.recordRow.nonce,
      ciphertext: built.recordRow.ciphertext,
      keyVersion: built.recordRow.keyVersion,
    };

    const result = await submitVaultOperation(
      state.rpcClient,
      built.opRow,
      recordPayload,
      null, // no device trust payload for create
    );

    if (result.kind === 'applied') {
      state.committedOpIds.add(built.opRow.opId);
    } else if (result.kind === 'recordAlreadyExists') {
      // Idempotent: record already created in a previous attempt.
      state.committedOpIds.add(built.opRow.opId);
    } else {
      throw migrationError(
        'commitFailed',
        `submit_vault_operation failed for ${built.opRow.recordType} ${built.opRow.recordId}: ${result.kind}`,
        true,
      );
    }
  }

  state.currentState = 'commitCompleted';
}

// ---------------------------------------------------------------------------
// Step 8 — Verify committed state
// ---------------------------------------------------------------------------

async function verifyCommittedState(state: MigrationOrchestratorState): Promise<void> {
  state.currentState = 'verificationStarted';

  // Re-fetch all committed records by their IDs via the repository.
  const recordIds = state.builtOperations.map((b) => b.recordRow.recordId);

  // We cannot use getVaultRecordsByIds because it returns only records
  // that exist on the server, but we also need to verify the operations.
  // For a minimal verification we verify each operation signature and
  // record context locally using the state machine helpers.

  const trustedDevice: TrustedDeviceRecordV1 = {
    vaultId: state.vaultId,
    deviceId: state.deviceId,
    publicSigningKey: state.publicSigningKeyB64Url,
    deviceNameEncrypted: '',
    addedByDeviceId: null,
    addedAt: state.now,
    trustEpoch: 0,
    status: 'trusted',
    revokedAt: null,
    revokedByDeviceId: null,
  };

  const trustList = {
    vaultId: state.vaultId,
    trustedDevicesById: new Map([[state.deviceId, trustedDevice]]),
  };

  let localVaultState: LocalVaultState = {
    recordsById: new Map(),
    quarantinedRecordsById: new Map(),
    conflictsByRecordId: new Map(),
    trustedDevicesById: new Map([[state.deviceId, trustedDevice]]),
    lastVerifiedVaultHead: null,
  };

  const publicKey = await crypto.subtle.importKey(
    'spki',
    decodeBase64Url(state.publicSigningKeyB64Url) as unknown as ArrayBuffer,
    { name: 'ECDSA', namedCurve: 'P-256' },
    false,
    ['verify'],
  );

  for (const built of state.builtOperations) {
    // Verify operation signature locally
    const opResult = await verifyOperation({
      operation: built.opRow,
      trust: trustList,
      publicKey,
      localRecordState: null,
    });

    if (opResult.kind !== 'validTrustedOperation') {
      throw migrationError(
        'verificationFailed',
        `operation verification failed for ${built.opRow.recordId}: ${opResult.kind}`,
        false,
      );
    }

    // Verify record context
    const ctxResult = await verifyRecordContext({
      record: built.recordRow,
      operation: built.opRow,
    });

    if (ctxResult.kind !== 'validContext') {
      throw migrationError(
        'verificationFailed',
        `record context verification failed for ${built.recordRow.recordId}: ${ctxResult.kind}`,
        false,
      );
    }

    // Decrypt gate: ensure the record is openable with the vault key
    const recordKey = await deriveRecordKey({
      vaultEncryptionKey: state.vaultEncryptionKey,
      vaultId: state.vaultId,
      recordId: built.recordRow.recordId,
      recordType: built.recordRow.recordType,
      keyVersion: built.recordRow.keyVersion,
    });

    try {
      await openRecord({
        sealed: {
          aad: buildRecordAad({
            vaultId: state.vaultId,
            recordId: built.recordRow.recordId,
            recordType: built.recordRow.recordType,
            recordVersion: built.recordRow.recordVersion,
            keyVersion: built.recordRow.keyVersion,
          }),
          aadHash: built.recordRow.aadHash,
          nonceB64Url: built.recordRow.nonce,
          ciphertextB64Url: built.recordRow.ciphertext,
          ciphertextHash: built.recordRow.ciphertextHash,
        },
        recordKey,
        expectedAadInput: {
          vaultId: state.vaultId,
          recordId: built.recordRow.recordId,
          recordType: built.recordRow.recordType,
          recordVersion: built.recordRow.recordVersion,
          keyVersion: built.recordRow.keyVersion,
        },
        expectedAadHash: built.recordRow.aadHash,
        expectedCiphertextHash: built.recordRow.ciphertextHash,
      });
    } catch {
      recordKey.fill(0);
      throw migrationError(
        'verificationFailed',
        `record decryption failed for ${built.recordRow.recordId}`,
        false,
      );
    } finally {
      recordKey.fill(0);
    }

    // Apply to local state so the vault security mode can be determined
    const applyResult = await applyRemoteOperation({
      state: localVaultState,
      operation: built.opRow,
      record: built.recordRow,
      trust: trustList,
      publicKey,
      vaultEncryptionKey: state.vaultEncryptionKey,
    });

    localVaultState = applyResult.nextState;
  }

  const vaultMode = determineVaultSecurityMode(localVaultState);
  if (vaultMode === 'lockedCritical') {
    throw migrationError('verificationFailed', 'vault entered lockedCritical after migration', false);
  }

  state.currentState = 'verified';
}

// ---------------------------------------------------------------------------
// Step 9 — Mark legacy migrated
// ---------------------------------------------------------------------------

function markLegacyMigrated(state: MigrationOrchestratorState): void {
  // We do NOT delete legacy data.  We only mark the migration as
  // complete.  The actual removal of legacy reads from the UI is
  // handled by Phase 11.
  state.currentState = 'legacyMarkedMigrated';
}

// ---------------------------------------------------------------------------
// Checkpoint helpers
// ---------------------------------------------------------------------------

async function writeCheckpoint(
  state: MigrationOrchestratorState,
  error: MigrationError | null = null,
  storage?: MigrationStorage,
): Promise<void> {
  const checkpoint: MigrationCheckpoint = {
    version: 1,
    vaultId: state.vaultId,
    state: state.currentState,
    snapshotId: state.snapshotId,
    legacyToNewRecordIdMap: Object.fromEntries(state.legacyToNewRecordIdMap),
    quarantinedLegacyIds: [
      ...state.quarantinedItems.map((q) => q.legacyId),
      ...state.quarantinedCategories.map((q) => q.legacyId),
    ],
    committedOpIds: [...state.committedOpIds],
    error,
    updatedAt: state.now,
  };

  saveMigrationCheckpoint(checkpoint, storage);
}

// ---------------------------------------------------------------------------
// Error helpers
// ---------------------------------------------------------------------------

function migrationError(
  kind: MigrationErrorKind,
  message: string,
  retryable: boolean,
): MigrationServiceError {
  return new MigrationServiceError(kind, message, retryable);
}

class MigrationServiceError extends Error {
  public readonly kind: MigrationErrorKind;
  public readonly retryable: boolean;
  constructor(kind: MigrationErrorKind, message: string, retryable: boolean) {
    super(message);
    this.name = 'MigrationServiceError';
    this.kind = kind;
    this.retryable = retryable;
  }
}

function classifyOrchestratorError(err: unknown, currentState: MigrationState): MigrationError {
  if (err instanceof MigrationServiceError) {
    return {
      kind: err.kind,
      message: err.message,
      stateAtError: currentState,
      retryable: err.retryable,
    };
  }
  // Never include stack traces or raw error messages from untrusted sources;
  // they may contain secrets, ciphertext fragments, or key material.
  const msg = err instanceof Error
    ? `unexpected error during migration: ${err.name}`
    : 'unknown error during migration';
  return {
    kind: 'commitFailed',
    message: msg,
    stateAtError: currentState,
    retryable: true,
  };
}

// ---------------------------------------------------------------------------
// Result builder
// ---------------------------------------------------------------------------

function buildResult(state: MigrationOrchestratorState, error: MigrationError | null): MigrateVaultResult {
  const progress: MigrationProgress = {
    state: state.currentState,
    vaultId: state.vaultId,
    deviceId: state.deviceId,
    snapshotId: state.snapshotId,
    legacyItemCount: state.validatedItems.length + state.quarantinedItems.length,
    legacyCategoryCount: state.validatedCategories.length + state.quarantinedCategories.length,
    quarantinedItemCount: state.quarantinedItems.length,
    quarantinedCategoryCount: state.quarantinedCategories.length,
    preparedItemCount: state.preparedItems.length,
    preparedCategoryCount: state.preparedCategories.length,
    committedOperationCount: state.committedOpIds.size,
    error,
    startedAt: state.now,
    completedAt: state.currentState === 'legacyMarkedMigrated' ? state.now : null,
  };

  return {
    success: state.currentState === 'legacyMarkedMigrated',
    finalState: state.currentState,
    progress,
    error,
  };
}

// ---------------------------------------------------------------------------
// State ordering helpers
// ---------------------------------------------------------------------------

const STATE_ORDER: readonly MigrationState[] = [
  'notStarted',
  'failedRetryable',
  'preflightChecked',
  'safetyFreezeActive',
  'preMigrationSnapshotCreated',
  'deviceTrustPrepared',
  'legacyRead',
  'legacyValidated',
  'legacyQuarantinePrepared',
  'newRecordsPrepared',
  'initialOperationsPrepared',
  'commitStarted',
  'commitCompleted',
  'verificationStarted',
  'verified',
  'legacyMarkedMigrated',
];

function stateIndex(state: MigrationState): number {
  const idx = STATE_ORDER.indexOf(state);
  return idx === -1 ? Number.MAX_SAFE_INTEGER : idx;
}

function isBefore(current: MigrationState, target: MigrationState): boolean {
  return stateIndex(current) < stateIndex(target);
}

function isTerminalState(state: MigrationState): boolean {
  return state === 'legacyMarkedMigrated' || state === 'failedRetryable' || state === 'failedBlocked' || state === 'rolledBack';
}
