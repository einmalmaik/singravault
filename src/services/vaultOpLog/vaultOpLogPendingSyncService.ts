// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE
/**
 * Replays locally signed pending OpLog operations after reconnect.
 *
 * This service never creates trust and never writes legacy vault tables. It
 * submits already signed operations through submit_vault_operation and lets
 * the server/RPC plus local verification path decide whether they commit,
 * require rebase, or become conflicts.
 */

import { submitVaultOperation, type SupabaseRpcClient } from './vaultOpLogRepository';
import { VaultOpLogPendingQueue, classifySubmitResult } from './vaultOpLogPendingQueue';
import { IndexedDbQueuePersistence } from './vaultOpLogQueuePersistence';
import type { PendingLocalOperation, QueuePersistence } from './vaultOpLogPendingQueueTypes';
import type { VaultOpLogTrustReadClient } from './vaultOpLogUiOrchestrator';

export interface PendingOpLogSyncResult {
  readonly processed: number;
  readonly remaining: number;
  readonly blocked: number;
}

export async function syncPendingVaultOpLogOperations(input: {
  readonly rpcClient: SupabaseRpcClient;
  readonly vaultId: string;
  readonly authorDeviceId?: string;
  readonly trustClient?: VaultOpLogTrustReadClient;
  readonly queuePersistence?: QueuePersistence;
}): Promise<PendingOpLogSyncResult> {
  const queuePersistence = input.queuePersistence ?? new IndexedDbQueuePersistence();
  const queue = new VaultOpLogPendingQueue(input.vaultId, queuePersistence);
  await queue.load();
  await queue.recoverAfterCrash();
  if (typeof navigator !== 'undefined' && navigator.onLine === false) {
    return { processed: 0, remaining: queue.getPending().length, blocked: 0 };
  }

  const pending = queue.getPending();
  const preflight = await verifyAuthorStillTrustedBeforePush({
    vaultId: input.vaultId,
    authorDeviceId: input.authorDeviceId,
    trustClient: input.trustClient,
    pending,
  });
  if (preflight.kind === 'blocked') {
    await queue.blockAllForRevokedDevice(preflight.authorDeviceId);
    await queue.load();
    return {
      processed: 0,
      remaining: queue.getOperations().filter((entry) =>
        entry.state === 'pending'
        || entry.state === 'syncing'
        || entry.state === 'submitted_unverified'
        || entry.state === 'submitted_unverified_needs_verification'
        || entry.state === 'rebase_needed'
        || entry.state === 'conflict'
      ).length,
      blocked: pending.filter((entry) => entry.op.authorDeviceId === preflight.authorDeviceId).length,
    };
  }
  if (preflight.kind === 'unverified') {
    return { processed: 0, remaining: pending.length, blocked: pending.length };
  }

  let processed = 0;
  let blocked = 0;

  for (const entry of queue.getPending()) {
    await queue.markSyncing(entry.op.opId);
    const classified = await submitAndClassify(input.rpcClient, entry, queuePersistence);
    if (classified === 'submitted_unverified') {
      processed += 1;
      continue;
    }
    if (classified === 'retryable') {
      break;
    }
    blocked += 1;
    break;
  }

  await queue.load();
  const remaining = queue.getOperations().filter((entry) =>
    entry.state === 'pending'
    || entry.state === 'syncing'
    || entry.state === 'submitted_unverified'
    || entry.state === 'submitted_unverified_needs_verification'
    || entry.state === 'rebase_needed'
    || entry.state === 'conflict'
  ).length;
  return { processed, remaining, blocked };
}

type AuthorTrustPreflightResult =
  | { readonly kind: 'ok' }
  | { readonly kind: 'blocked'; readonly authorDeviceId: string }
  | { readonly kind: 'unverified' };

async function verifyAuthorStillTrustedBeforePush(input: {
  readonly vaultId: string;
  readonly authorDeviceId?: string;
  readonly trustClient?: VaultOpLogTrustReadClient;
  readonly pending: readonly PendingLocalOperation[];
}): Promise<AuthorTrustPreflightResult> {
  if (input.pending.length === 0) {
    return { kind: 'ok' };
  }
  if (!input.authorDeviceId || !input.trustClient) {
    return { kind: 'ok' };
  }

  try {
    const { data, error } = await input.trustClient
      .from('vault_device_trust_records')
      .select('vault_id,device_id,trust_epoch,status')
      .eq('vault_id', input.vaultId);
    if (error || !Array.isArray(data)) {
      return { kind: 'unverified' };
    }

    const row = data.find((candidate) =>
      isTrustPreflightRow(candidate)
      && candidate.device_id === input.authorDeviceId
      && candidate.vault_id === input.vaultId
    );
    if (!row || row.status !== 'trusted') {
      return { kind: 'blocked', authorDeviceId: input.authorDeviceId };
    }

    const expectedEpoch = Number(row.trust_epoch);
    const hasEpochMismatch = input.pending.some((entry) =>
      entry.op.authorDeviceId === input.authorDeviceId
      && entry.op.trustEpoch !== expectedEpoch
    );
    if (hasEpochMismatch) {
      return { kind: 'blocked', authorDeviceId: input.authorDeviceId };
    }
    return { kind: 'ok' };
  } catch {
    return { kind: 'unverified' };
  }
}

function isTrustPreflightRow(value: unknown): value is {
  readonly vault_id: string;
  readonly device_id: string;
  readonly trust_epoch: number | string;
  readonly status: string;
} {
  if (!value || typeof value !== 'object') {
    return false;
  }
  const row = value as Record<string, unknown>;
  return typeof row.vault_id === 'string'
    && typeof row.device_id === 'string'
    && (typeof row.trust_epoch === 'number' || typeof row.trust_epoch === 'string')
    && typeof row.status === 'string';
}

async function submitAndClassify(
  rpcClient: SupabaseRpcClient,
  entry: PendingLocalOperation,
  queuePersistence: QueuePersistence,
): Promise<'submitted_unverified' | 'retryable' | 'blocked'> {
  const queue = new VaultOpLogPendingQueue(entry.op.vaultId, queuePersistence);
  await queue.load();

  try {
    const result = classifySubmitResult(await submitVaultOperation(
      rpcClient,
      entry.op,
      entry.record
        ? {
            aadHash: entry.record.aadHash,
            ciphertextHash: entry.record.ciphertextHash,
            nonce: entry.record.nonce,
            ciphertext: entry.record.ciphertext,
            keyVersion: entry.record.keyVersion,
          }
        : null,
      null,
    ));

    switch (result.kind) {
      case 'submittedUnverified':
      case 'idempotentSubmittedUnverified':
        await queue.markSubmittedUnverified(entry.op.opId, result.resultingVaultHead);
        return 'submitted_unverified';
      case 'retryable':
        await queue.markRetryable(entry.op.opId, result.error);
        return 'retryable';
      case 'rebaseNeeded':
        await queue.markRebaseNeeded(entry.op.opId);
        return 'blocked';
      case 'recordConflict':
        await queue.markConflict(entry.op.opId, 'record_conflict');
        return 'blocked';
      case 'permanentFailed':
      default:
        await queue.markFailed(entry.op.opId, result.kind === 'permanentFailed' ? result.error : 'unexpected_submit_classification');
        return 'blocked';
    }
  } catch {
    await queue.markRetryable(entry.op.opId, 'submit_vault_operation threw');
    return 'retryable';
  }
}
