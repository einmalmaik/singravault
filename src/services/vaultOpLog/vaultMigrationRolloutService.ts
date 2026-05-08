// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE
/**
 * Conservative Phase-12 blocker gate for legacy-to-op-log migration.
 *
 * This service does not run migration. It only decides whether a normal vault
 * unlock may become usable. Any ambiguous migration signal blocks normal
 * operation so a partially migrated vault is never shown as verified.
 */

import { supabase } from '@/integrations/supabase/client';
import {
  loadMigrationCheckpoint,
  loadMigrationCompletionMarker,
  type MigrationStorage,
} from './legacyMigrationStateStore';
import type { MigrationState } from './migrationTypes';
import { getVaultHead, type SupabaseRpcClient } from './vaultOpLogRepository';
import {
  loadVaultOpLogUiState,
  type VaultOpLogTrustReadClient,
} from './vaultOpLogUiOrchestrator';

export type VaultMigrationRolloutStatus =
  | 'notNeeded'
  | 'required'
  | 'preflightFailed'
  | 'ready'
  | 'running'
  | 'committed'
  | 'verified'
  | 'failed';

export interface VaultMigrationGateResult {
  readonly allowNormalUnlock: boolean;
  readonly status: VaultMigrationRolloutStatus;
  readonly vaultId: string | null;
  readonly reason: string | null;
}

export type RemoteOpLogMigrationVerifier = (input: {
  readonly rpcClient: SupabaseRpcClient;
  readonly trustClient: VaultOpLogTrustReadClient;
  readonly vaultId: string;
  readonly vaultEncryptionKey: Uint8Array;
}) => Promise<{ readonly verified: boolean; readonly error: string | null }>;

interface VaultMigrationRolloutClient {
  readonly from: typeof supabase.from;
}

export interface EvaluateVaultMigrationGateInput {
  readonly userId: string;
  readonly client?: VaultMigrationRolloutClient;
  readonly rpcClient?: SupabaseRpcClient;
  readonly trustClient?: VaultOpLogTrustReadClient;
  readonly checkpointStorage?: MigrationStorage;
  readonly vaultEncryptionKey?: Uint8Array;
  readonly remoteOpLogVerifier?: RemoteOpLogMigrationVerifier;
}

export async function evaluateVaultMigrationGate(
  input: EvaluateVaultMigrationGateInput,
): Promise<VaultMigrationGateResult> {
  const client = input.client ?? supabase;
  const rpcClient = input.rpcClient ?? supabase;

  try {
    const legacySignals = await loadLegacyVaultSignals(client, input.userId);
    if (!legacySignals.vaultId) {
      return legacySignals.hasLegacyRows
        ? block('preflightFailed', null, 'legacy rows exist but no default vault could be resolved')
        : allow('notNeeded', null);
    }

    const completionMarker = loadMigrationCompletionMarker(legacySignals.vaultId, input.checkpointStorage);
    if (completionMarker) {
      return allow('verified', legacySignals.vaultId);
    }

    const checkpoint = loadMigrationCheckpoint(legacySignals.vaultId, input.checkpointStorage);
    if (checkpoint) {
      return gateFromCheckpoint(checkpoint.state, legacySignals.vaultId);
    }

    const opLogHead = await getVaultHead(rpcClient, legacySignals.vaultId);
    const hasOpLogHead = opLogHead.kind === 'success';
    if (opLogHead.kind === 'rpcError' || opLogHead.kind === 'malformedResponse') {
      return block('preflightFailed', legacySignals.vaultId, `op-log head preflight failed: ${opLogHead.kind}`);
    }

    if (legacySignals.hasLegacyRows && hasOpLogHead) {
      // If we have a vault key, verify the remote OpLog properly
      if (input.vaultEncryptionKey) {
        const verifier = input.remoteOpLogVerifier ?? verifyRemoteOpLogMigration;
        const verified = await verifier({
          rpcClient,
          trustClient: input.trustClient ?? (client as unknown as VaultOpLogTrustReadClient),
          vaultId: legacySignals.vaultId,
          vaultEncryptionKey: input.vaultEncryptionKey,
        });

        if (verified.verified) {
          return allow('verified', legacySignals.vaultId);
        }

        return block(
          'preflightFailed',
          legacySignals.vaultId,
          verified.error ?? 'legacy rows and op-log head both exist but remote op-log verification failed',
        );
      }

      return block(
        'preflightFailed',
        legacySignals.vaultId,
        'legacy rows and op-log head both exist; vault key is required to verify remote migration',
      );
    }

    if (legacySignals.hasLegacyRows) {
      return block('required', legacySignals.vaultId, 'legacy vault requires controlled migration');
    }

    return allow('notNeeded', legacySignals.vaultId);
  } catch {
    return block('preflightFailed', null, 'migration preflight could not be evaluated');
  }
}

async function verifyRemoteOpLogMigration(input: {
  readonly rpcClient: SupabaseRpcClient;
  readonly trustClient: VaultOpLogTrustReadClient;
  readonly vaultId: string;
  readonly vaultEncryptionKey: Uint8Array;
}): Promise<{ readonly verified: boolean; readonly error: string | null }> {
  const result = await loadVaultOpLogUiState({
    rpcClient: input.rpcClient,
    trustClient: input.trustClient,
    vaultId: input.vaultId,
    vaultEncryptionKey: input.vaultEncryptionKey,
  });

  if (result.error || !result.localVaultState) {
    return { verified: false, error: result.error ?? 'remote_op_log_state_missing' };
  }

  // A completed migration always creates a verified manifest record. A head
  // without that record can be a trust bootstrap or partial commit, not a
  // migrated vault, so it must not unlock the legacy rows by itself.
  const hasVerifiedManifest = Array.from(result.localVaultState.recordsById.values()).some((record) => (
    record.recordState === 'verified' && record.record.recordType === 'manifest'
  ));

  return hasVerifiedManifest
    ? { verified: true, error: null }
    : { verified: false, error: 'remote_op_log_manifest_missing' };
}

function gateFromCheckpoint(
  state: MigrationState,
  vaultId: string,
): VaultMigrationGateResult {
  switch (state) {
    case 'legacyMarkedMigrated':
    case 'verified':
      return allow('verified', vaultId);
    case 'notStarted':
      return block('required', vaultId, 'migration checkpoint has not started');
    case 'preflightChecked':
    case 'safetyFreezeActive':
    case 'preMigrationSnapshotCreated':
      return block('ready', vaultId, `migration checkpoint is ${state}`);
    case 'deviceTrustPrepared':
    case 'legacyRead':
    case 'legacyValidated':
    case 'legacyQuarantinePrepared':
    case 'newRecordsPrepared':
    case 'initialOperationsPrepared':
    case 'commitStarted':
      return block('running', vaultId, `migration checkpoint is ${state}`);
    case 'commitCompleted':
    case 'verificationStarted':
      return block('committed', vaultId, `migration checkpoint is ${state}`);
    case 'failedRetryable':
    case 'failedBlocked':
    case 'rolledBack':
      return block('failed', vaultId, `migration checkpoint is ${state}`);
    default:
      return block('preflightFailed', vaultId, 'migration checkpoint state is not recognized');
  }
}

async function loadLegacyVaultSignals(
  client: VaultMigrationRolloutClient,
  userId: string,
): Promise<{ vaultId: string | null; hasLegacyRows: boolean }> {
  const { data: vault, error: vaultError } = await client
    .from('vaults')
    .select('id')
    .eq('user_id', userId)
    .eq('is_default', true)
    .maybeSingle();
  if (vaultError) {
    throw vaultError;
  }

  const itemCount = await countLegacyRows(client, 'vault_items', userId);
  const categoryCount = await countLegacyRows(client, 'categories', userId);

  return {
    vaultId: typeof vault?.id === 'string' ? vault.id : null,
    hasLegacyRows: itemCount > 0 || categoryCount > 0,
  };
}

async function countLegacyRows(
  client: VaultMigrationRolloutClient,
  table: 'vault_items' | 'categories',
  userId: string,
): Promise<number> {
  const { count, error } = await client
    .from(table)
    .select('id', { count: 'exact', head: true })
    .eq('user_id', userId);
  if (error) {
    throw error;
  }
  return count ?? 0;
}

function allow(status: VaultMigrationRolloutStatus, vaultId: string | null): VaultMigrationGateResult {
  return {
    allowNormalUnlock: true,
    status,
    vaultId,
    reason: null,
  };
}

function block(
  status: VaultMigrationRolloutStatus,
  vaultId: string | null,
  reason: string,
): VaultMigrationGateResult {
  return {
    allowNormalUnlock: false,
    status,
    vaultId,
    reason,
  };
}
