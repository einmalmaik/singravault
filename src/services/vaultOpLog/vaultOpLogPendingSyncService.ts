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

export interface PendingOpLogSyncResult {
  readonly processed: number;
  readonly remaining: number;
  readonly blocked: number;
}

export async function syncPendingVaultOpLogOperations(input: {
  readonly rpcClient: SupabaseRpcClient;
  readonly vaultId: string;
  readonly queuePersistence?: QueuePersistence;
}): Promise<PendingOpLogSyncResult> {
  const queuePersistence = input.queuePersistence ?? new IndexedDbQueuePersistence();
  const queue = new VaultOpLogPendingQueue(input.vaultId, queuePersistence);
  await queue.load();
  await queue.recoverAfterCrash();
  if (typeof navigator !== 'undefined' && navigator.onLine === false) {
    return { processed: 0, remaining: queue.getPending().length, blocked: 0 };
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
