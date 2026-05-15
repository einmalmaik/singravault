import {
  isLikelyOfflineError,
  saveOfflineSnapshot,
  type OfflineVaultSnapshot,
} from '@/services/offlineVaultService';
import {
  type VaultIntegrityBlockedReason,
  type VaultIntegrityVerificationResult,
} from '@/services/vaultIntegrityService';
import { loadCurrentVaultIntegritySnapshot } from '@/services/offlineVaultRuntimeService';
import {
  loadTrustedRecoverySnapshotState,
  persistTrustedRecoverySnapshot,
  type TrustedRecoverySnapshotState,
} from '@/services/vaultRecoveryOrchestrator';
import {
  evaluateRuntimeVaultIntegrityV2,
  safeManifestPersistErrorCode,
} from '@/services/vaultIntegrityV2/runtimeBridge';

export interface VaultIntegrityRuntimeCallbacks {
  applyIntegrityResultState: (result: VaultIntegrityVerificationResult) => void;
  applyTrustedRecoveryState: (state: TrustedRecoverySnapshotState) => void;
  setBlockedIntegrityState: (
    activeKey: CryptoKey,
    blockedReason: VaultIntegrityBlockedReason,
    result?: VaultIntegrityVerificationResult | null,
  ) => Promise<void>;
  bumpVaultDataVersion: () => void;
}

function logIntegrityRuntimeDecision(
  stage: 'unlock:v2' | 'verify:v2' | 'verify:failure',
  input: {
    result: VaultIntegrityVerificationResult;
    source?: 'remote' | 'cache' | 'empty';
  },
): void {
  const isRoutineHealthyRefresh =
    stage === 'verify:v2'
    && input.result.mode === 'healthy'
    && input.result.quarantinedItems.length === 0
    && !input.result.nonTamperReason
    && !input.result.blockedReason;

  if (isRoutineHealthyRefresh) {
    return;
  }

  console.info('[VaultRuntime] Integrity decision.', {
    stage,
    source: input.source ?? 'unknown',
    mode: input.result.mode,
    nonTamperReason: input.result.nonTamperReason ?? null,
    blockedReason: input.result.blockedReason ?? null,
    itemCount: input.result.itemCount,
    categoryCount: input.result.categoryCount,
    quarantinedCount: input.result.quarantinedItems.length,
  });
}

async function persistVerifiedUnlockSnapshot(input: {
  snapshot: OfflineVaultSnapshot;
  source: 'remote' | 'cache' | 'empty';
}): Promise<void> {
  if (input.source !== 'remote') {
    return;
  }

  try {
    await saveOfflineSnapshot(input.snapshot);
  } catch {
    console.warn('Verified offline vault snapshot could not be stored.', {
      code: 'offline_snapshot_persist_failed',
    });
  }
}

export async function finalizeVaultUnlockIntegrity(input: {
  userId: string;
  activeKey: CryptoKey;
  encryptedUserKey?: string | null;
  callbacks: VaultIntegrityRuntimeCallbacks;
}): Promise<{ error: Error | null }> {
  const { userId, activeKey, callbacks } = input;

  try {
    const snapshotBundle = await loadCurrentVaultIntegritySnapshot({
      userId,
      persistRemoteSnapshot: false,
      preferRemote: true,
    });
    if (!snapshotBundle) {
      return { error: new Error('Vault snapshot unavailable') };
    }

    const trustedRecoveryState = await loadTrustedRecoverySnapshotState(userId);
    const v2Result = await evaluateRuntimeVaultIntegrityV2({
      userId,
      snapshot: snapshotBundle.rawSnapshot,
      vaultKey: activeKey,
      encryptedUserKey: input.encryptedUserKey,
      trustedRecoveryState,
      evaluationSource: 'unlock',
      snapshotSource: snapshotBundle.source,
    });
    if (v2Result) {
      logIntegrityRuntimeDecision('unlock:v2', {
        result: v2Result,
        source: snapshotBundle.source,
      });
      callbacks.applyIntegrityResultState(v2Result);
      if (v2Result.mode === 'blocked') {
        await callbacks.setBlockedIntegrityState(
          activeKey,
          v2Result.blockedReason ?? 'snapshot_malformed',
          v2Result,
        );
        return {
          error: new Error(
            'Die Integritätsprüfung des Tresors ist fehlgeschlagen. Safe Mode oder Reset ist erforderlich.',
          ),
        };
      }
      if (v2Result.mode === 'healthy') {
        await persistVerifiedUnlockSnapshot({
          snapshot: snapshotBundle.rawSnapshot,
          source: snapshotBundle.source,
        });
        callbacks.applyTrustedRecoveryState(
          await persistTrustedRecoverySnapshot(snapshotBundle.rawSnapshot),
        );
      } else {
        callbacks.applyTrustedRecoveryState(trustedRecoveryState);
      }
      return { error: null };
    }

    console.warn('[VaultRuntime] V2 evaluation returned null during unlock. Falling back to safe error.');
    const safeError: VaultIntegrityVerificationResult = {
      valid: false,
      isFirstCheck: false,
      computedRoot: '',
      storedRoot: '',
      itemCount: 0,
      categoryCount: 0,
      mode: 'blocked',
      blockedReason: 'unknown_integrity_failure',
      quarantinedItems: [],
    };
    callbacks.applyIntegrityResultState(safeError);
    await callbacks.setBlockedIntegrityState(activeKey, 'unknown_integrity_failure', safeError);
    return {
      error: new Error(
        'Die Integritätsprüfung des Tresors ist fehlgeschlagen. Safe Mode oder Reset ist erforderlich.',
      ),
    };
  } catch (error) {
    return {
      error: error instanceof Error
        ? error
        : new Error('Vault integrity verification failed.'),
    };
  }
}

/**
 * Phase 11: refreshVaultIntegrityBaseline no longer performs old V1 baseline
 * rebaseline, digest trust, or TTL-based decisions. It delegates strictly to
 * the V2 runtime integrity evaluation. If V2 cannot produce a result, it
 * returns a safe error rather than falling back to old logic.
 */
export async function refreshVaultIntegrityBaseline(input: {
  userId: string;
  encryptionKey: CryptoKey;
  encryptedUserKey?: string | null;
  callbacks: VaultIntegrityRuntimeCallbacks;
}): Promise<VaultIntegrityVerificationResult | null> {
  const { userId, encryptionKey, callbacks } = input;

  const snapshotBundle = await loadCurrentVaultIntegritySnapshot({
    userId,
    preferRemote: true,
  });
  if (!snapshotBundle) {
    return null;
  }

  const v2Result = await evaluateRuntimeVaultIntegrityV2({
    userId,
    snapshot: snapshotBundle.rawSnapshot,
    vaultKey: encryptionKey,
    encryptedUserKey: input.encryptedUserKey,
    trustedRecoveryState: await loadTrustedRecoverySnapshotState(userId),
    evaluationSource: 'sync',
    snapshotSource: snapshotBundle.source,
  });

  if (v2Result) {
    callbacks.applyIntegrityResultState(v2Result);
    callbacks.bumpVaultDataVersion();
    return v2Result;
  }

  console.warn('[VaultRuntime] V2 evaluation returned null during refresh. Returning safe error.');
  const safeError: VaultIntegrityVerificationResult = {
    valid: false,
    isFirstCheck: false,
    computedRoot: '',
    storedRoot: '',
    itemCount: snapshotBundle.rawSnapshot.items.length,
    categoryCount: snapshotBundle.rawSnapshot.categories.length,
    mode: 'revalidation_failed',
    nonTamperReason: 'revalidation_failed',
    quarantinedItems: [],
  };
  callbacks.applyIntegrityResultState(safeError);
  callbacks.bumpVaultDataVersion();
  return safeError;
}

/**
 * Phase 11: verifyVaultIntegrity no longer performs old V1 baseline
 * rebaseline, digest trust, or TTL-based decisions. It delegates strictly to
 * the V2 runtime integrity evaluation.
 */
export async function verifyVaultIntegrity(input: {
  userId: string;
  encryptionKey: CryptoKey;
  encryptedUserKey?: string | null;
  snapshot?: OfflineVaultSnapshot;
  source?: 'remote' | 'cache' | 'empty';
  callbacks: VaultIntegrityRuntimeCallbacks;
}): Promise<VaultIntegrityVerificationResult | null> {
  const { userId, encryptionKey, snapshot, source, callbacks } = input;

  try {
    const loadedSnapshotBundle = snapshot
      ? null
      : await loadCurrentVaultIntegritySnapshot({
        userId,
        persistRemoteSnapshot: false,
        preferRemote: true,
      });
    const rawSnapshot = snapshot ?? loadedSnapshotBundle?.rawSnapshot;
    if (!rawSnapshot) {
      return null;
    }

    const trustedRecoveryState = await loadTrustedRecoverySnapshotState(userId);
    const v2Result = await evaluateRuntimeVaultIntegrityV2({
      userId,
      snapshot: rawSnapshot,
      vaultKey: encryptionKey,
      encryptedUserKey: input.encryptedUserKey,
      trustedRecoveryState,
      evaluationSource: 'manual_recheck',
      snapshotSource: source ?? (snapshot ? undefined : loadedSnapshotBundle?.source),
    });
    if (v2Result) {
      logIntegrityRuntimeDecision('verify:v2', {
        result: v2Result,
        source: source ?? (snapshot ? undefined : loadedSnapshotBundle?.source),
      });
      callbacks.applyIntegrityResultState(v2Result);
      if (v2Result.mode === 'blocked') {
        await callbacks.setBlockedIntegrityState(
          encryptionKey,
          v2Result.blockedReason ?? 'snapshot_malformed',
          v2Result,
        );
      } else if (v2Result.mode === 'healthy') {
        callbacks.applyTrustedRecoveryState(await persistTrustedRecoverySnapshot(rawSnapshot));
      } else {
        callbacks.applyTrustedRecoveryState(trustedRecoveryState);
      }
      return v2Result;
    }

    console.warn('[VaultRuntime] V2 evaluation returned null during manual verify. Returning safe error.');
    const failureResult: VaultIntegrityVerificationResult = {
      valid: false,
      isFirstCheck: false,
      computedRoot: '',
      itemCount: 0,
      categoryCount: 0,
      mode: 'revalidation_failed',
      nonTamperReason: 'revalidation_failed',
      quarantinedItems: [],
    };
    logIntegrityRuntimeDecision('verify:failure', {
      result: failureResult,
    });
    callbacks.applyIntegrityResultState(failureResult);
    return failureResult;
  } catch (error) {
    const level = isLikelyOfflineError(error) ? 'warn' : 'error';
    console[level]('Vault integrity revalidation failed.', {
      code: safeManifestPersistErrorCode(error),
    });
    const failureResult: VaultIntegrityVerificationResult = {
      valid: false,
      isFirstCheck: false,
      computedRoot: '',
      itemCount: 0,
      categoryCount: 0,
      mode: 'revalidation_failed',
      nonTamperReason: 'revalidation_failed',
      quarantinedItems: [],
    };
    logIntegrityRuntimeDecision('verify:failure', {
      result: failureResult,
    });
    callbacks.applyIntegrityResultState(failureResult);
    return failureResult;
  }
}
