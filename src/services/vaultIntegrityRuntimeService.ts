import type { OfflineVaultSnapshot } from '@/services/offlineVaultService';
import {
  VaultIntegrityBaselineError,
  isNonTamperIntegrityMode,
  persistIntegrityBaseline,
  persistTrustedMutationIntegrityBaseline,
  type VaultIntegrityBaselineInspection,
  type VaultIntegrityBlockedReason,
  type VaultIntegritySnapshot,
  type VaultIntegrityVerificationResult,
} from '@/services/vaultIntegrityService';
import {
  assessVaultIntegritySnapshot,
  buildVaultIntegritySnapshot,
  canRebaselineRecentLocalMutation,
  canRebaselineTrustedMutation,
  hasTrustedDrift,
  hasTrustedMutationScope,
  normalizeTrustedVaultMutation,
  type VaultIntegrityAssessment,
  type TrustedVaultMutation,
} from '@/services/vaultIntegrityDecisionEngine';
import { loadCurrentVaultIntegritySnapshot } from '@/services/offlineVaultRuntimeService';
import { isLikelyOfflineError } from '@/services/offlineVaultService';
import {
  loadTrustedRecoverySnapshotState,
  persistTrustedRecoverySnapshot,
  type TrustedRecoverySnapshotState,
} from '@/services/vaultRecoveryOrchestrator';
import {
  evaluateRuntimeVaultIntegrityV2,
  persistRuntimeManifestV2ForTrustedSnapshot,
  retryPendingRuntimeManifestV2ForSnapshot,
  safeManifestPersistErrorCode,
} from '@/services/vaultIntegrityV2/runtimeBridge';
import { saveManifestPersistRetryRecord } from '@/services/vaultIntegrityV2/manifestPersistRetryStore';
import { parseVaultItemEnvelopeV2 } from '@/services/vaultIntegrityV2/itemEnvelopeCrypto';

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

export function canPersistIntegrityBaselineImmediately(
  assessment: VaultIntegrityAssessment,
  snapshot: OfflineVaultSnapshot,
): boolean {
  return !assessment.inspection.nonTamperState
    && (
      assessment.inspection.baselineKind !== 'missing'
      || (snapshot.items.length === 0 && snapshot.categories.length === 0)
    );
}

export function shouldDowngradeCrossDeviceV2BaselineDrift(input: {
  assessment: VaultIntegrityAssessment;
  snapshot: OfflineVaultSnapshot;
  source?: 'remote' | 'cache' | 'empty';
  trustedItemIds?: Iterable<string>;
}): boolean {
  const result = input.assessment.result;
  if (input.source === 'empty' || result.mode !== 'quarantine') {
    return false;
  }

  const trustedItemIds = new Set(input.trustedItemIds ?? []);
  const untrustedQuarantinedItems = result.quarantinedItems.filter((item) => !trustedItemIds.has(item.id));

  if (
    input.assessment.unreadableCategoryReason
    || input.assessment.inspection.categoryDriftIds.length > 0
    || untrustedQuarantinedItems.length === 0
    || untrustedQuarantinedItems.some((item) => item.reason !== 'ciphertext_changed')
  ) {
    return false;
  }

  const itemsById = new Map(input.snapshot.items.map((item) => [item.id, item]));
  return untrustedQuarantinedItems.every((quarantinedItem) => {
    const item = itemsById.get(quarantinedItem.id);
    if (!item) {
      return false;
    }
    const parsed = parseVaultItemEnvelopeV2(item.encrypted_data);
    return parsed.ok
      && parsed.envelope.itemId === item.id
      && parsed.envelope.userId === input.snapshot.userId
      && parsed.envelope.vaultId === input.snapshot.vaultId;
  });
}

function buildCrossDeviceRevalidationResult(
  snapshot: OfflineVaultSnapshot,
  assessment: VaultIntegrityAssessment,
): VaultIntegrityVerificationResult {
  return {
    valid: false,
    isFirstCheck: false,
    computedRoot: assessment.inspection.digest,
    storedRoot: assessment.inspection.storedRoot,
    itemCount: snapshot.items.length,
    categoryCount: snapshot.categories.length,
    mode: 'revalidation_failed',
    nonTamperReason: 'revalidation_failed',
    quarantinedItems: [],
  };
}

function buildManifestPersistFailedResult(input: {
  snapshot: OfflineVaultSnapshot;
  snapshotDigest: string;
  itemCount: number;
  categoryCount: number;
}): VaultIntegrityVerificationResult {
  return {
    valid: false,
    isFirstCheck: false,
    computedRoot: input.snapshotDigest,
    storedRoot: input.snapshotDigest,
    itemCount: input.itemCount,
    categoryCount: input.categoryCount,
    mode: 'revalidation_failed',
    nonTamperReason: 'manifest_persist_failed',
    quarantinedItems: [],
  };
}

async function persistRuntimeManifestV2ForHealthyPublish(input: {
  userId: string;
  snapshot: OfflineVaultSnapshot;
  vaultKey: CryptoKey;
  encryptedUserKey?: string | null;
  trustedMutation?: TrustedVaultMutation;
  snapshotDigest: string;
  itemCount: number;
  categoryCount: number;
}): Promise<
  | { ok: true; status: 'persisted' | 'skipped_legacy_items' | 'skipped_missing_vault' }
  | { ok: false; result: VaultIntegrityVerificationResult }
> {
  try {
    const status = await persistRuntimeManifestV2ForTrustedSnapshot({
      userId: input.userId,
      snapshot: input.snapshot,
      vaultKey: input.vaultKey,
      encryptedUserKey: input.encryptedUserKey,
      trustedMutation: input.trustedMutation,
    });
    return { ok: true, status };
  } catch (error) {
    const errorCode = safeManifestPersistErrorCode(error);
    if (input.snapshot.vaultId) {
      try {
        await saveManifestPersistRetryRecord({
          userId: input.userId,
          vaultId: input.snapshot.vaultId,
          snapshotDigest: input.snapshotDigest,
          lastErrorCode: errorCode,
        });
      } catch {
        console.warn('Manifest V2 persist retry state could not be stored.', {
          code: 'manifest_retry_store_unavailable',
        });
      }
    }
    console.warn('Manifest V2 persist failed after trusted integrity refresh.', { code: errorCode });
    return {
      ok: false,
      result: buildManifestPersistFailedResult(input),
    };
  }
}

async function surfacePendingManifestRetryFailure(input: {
  userId: string;
  snapshot: OfflineVaultSnapshot;
  activeKey: CryptoKey;
  encryptedUserKey?: string | null;
  trustedMutation?: TrustedVaultMutation;
  digest: string;
}): Promise<VaultIntegrityVerificationResult | null> {
  const retryResult = await retryPendingRuntimeManifestV2ForSnapshot({
    userId: input.userId,
    snapshot: input.snapshot,
    vaultKey: input.activeKey,
    encryptedUserKey: input.encryptedUserKey,
    trustedMutation: input.trustedMutation,
    snapshotDigest: input.digest,
  });

  if (
    retryResult.status !== 'failed'
    && retryResult.status !== 'store_unavailable'
    && retryResult.status !== 'snapshot_digest_unavailable'
    && retryResult.status !== 'snapshot_mismatch'
  ) {
    return null;
  }

  return buildManifestPersistFailedResult({
    snapshot: input.snapshot,
    snapshotDigest: input.digest,
    itemCount: input.snapshot.items.length,
    categoryCount: input.snapshot.categories.length,
  });
}

export async function persistMissingOrLegacyBaseline(input: {
  userId: string;
  integritySnapshot: VaultIntegritySnapshot;
  activeKey: CryptoKey;
  inspection: VaultIntegrityBaselineInspection;
  vaultId?: string | null;
}): Promise<void> {
  const { userId, integritySnapshot, activeKey, inspection, vaultId } = input;
  if (inspection.snapshotValidationError || inspection.nonTamperState || inspection.legacyBaselineMismatch) {
    return;
  }

  if (inspection.baselineKind === 'missing' || inspection.baselineKind === 'v1') {
    await persistIntegrityBaseline(userId, integritySnapshot, activeKey, inspection.digest, { vaultId });
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
        callbacks.applyTrustedRecoveryState(
          await persistTrustedRecoverySnapshot(snapshotBundle.rawSnapshot),
        );
      } else {
        callbacks.applyTrustedRecoveryState(trustedRecoveryState);
      }
      return { error: null };
    }

    const integrityAssessment = await assessVaultIntegritySnapshot({
      userId,
      snapshot: snapshotBundle.rawSnapshot,
      activeKey,
      source: snapshotBundle.source,
    });
    const integrityResult = integrityAssessment.result;
    if (shouldDowngradeCrossDeviceV2BaselineDrift({
      assessment: integrityAssessment,
      snapshot: snapshotBundle.rawSnapshot,
      source: snapshotBundle.source,
    })) {
      const revalidationResult = buildCrossDeviceRevalidationResult(
        snapshotBundle.rawSnapshot,
        integrityAssessment,
      );
      callbacks.applyIntegrityResultState(revalidationResult);
      callbacks.applyTrustedRecoveryState(trustedRecoveryState);
      return { error: null };
    }
    callbacks.applyIntegrityResultState(integrityResult);

    if (integrityResult.mode === 'blocked') {
      await callbacks.setBlockedIntegrityState(
        activeKey,
        integrityResult.blockedReason ?? 'snapshot_malformed',
        integrityResult,
      );
      return {
        error: new Error(
          'Die Integritätsprüfung des Tresors ist fehlgeschlagen. Safe Mode oder Reset ist erforderlich.',
        ),
      };
    }

    if (integrityResult.mode === 'healthy') {
      if (canPersistIntegrityBaselineImmediately(integrityAssessment, snapshotBundle.rawSnapshot)) {
        await persistMissingOrLegacyBaseline({
          userId,
          integritySnapshot: snapshotBundle.integritySnapshot,
          activeKey,
          inspection: integrityAssessment.inspection,
          vaultId: snapshotBundle.rawSnapshot.vaultId,
        });
        callbacks.applyTrustedRecoveryState(
          await persistTrustedRecoverySnapshot(snapshotBundle.rawSnapshot),
        );
      }
    } else {
      callbacks.applyTrustedRecoveryState(await loadTrustedRecoverySnapshotState(userId));
    }
  } catch (error) {
    if (error instanceof VaultIntegrityBaselineError) {
      await callbacks.setBlockedIntegrityState(activeKey, 'baseline_unreadable');
      return {
        error: new Error(
          'Der lokale Integritätszustand des Tresors ist unlesbar. Safe Mode oder Reset ist erforderlich.',
        ),
      };
    }
    return {
      error: error instanceof Error
        ? error
        : new Error('Vault integrity verification failed.'),
    };
  }

  return { error: null };
}

export async function refreshVaultIntegrityBaseline(input: {
  userId: string;
  encryptionKey: CryptoKey;
  encryptedUserKey?: string | null;
  trustedMutation?: TrustedVaultMutation;
  callbacks: VaultIntegrityRuntimeCallbacks;
}): Promise<void> {
  const { userId, encryptionKey, callbacks } = input;
  const normalizedTrustedMutation = normalizeTrustedVaultMutation(input.trustedMutation);
  const snapshotBundle = await loadCurrentVaultIntegritySnapshot({
    userId,
    useLocalMutationOverlay: hasTrustedMutationScope(normalizedTrustedMutation),
  });
  if (!snapshotBundle) {
    return;
  }

  const integrityAssessment = await assessVaultIntegritySnapshot({
    userId,
    snapshot: snapshotBundle.rawSnapshot,
    activeKey: encryptionKey,
    source: snapshotBundle.source,
  });
  const pendingManifestFailure = await surfacePendingManifestRetryFailure({
    userId,
    snapshot: snapshotBundle.rawSnapshot,
    activeKey: encryptionKey,
    encryptedUserKey: input.encryptedUserKey,
    trustedMutation: normalizedTrustedMutation,
    digest: integrityAssessment.inspection.digest,
  });
  if (pendingManifestFailure) {
    callbacks.applyIntegrityResultState(pendingManifestFailure);
    callbacks.applyTrustedRecoveryState(await loadTrustedRecoverySnapshotState(userId));
    callbacks.bumpVaultDataVersion();
    return;
  }
  const integrityResult = integrityAssessment.result;
  if (shouldDowngradeCrossDeviceV2BaselineDrift({
    assessment: integrityAssessment,
    snapshot: snapshotBundle.rawSnapshot,
    source: snapshotBundle.source,
    trustedItemIds: normalizedTrustedMutation.itemIds,
  })) {
    const revalidationResult = buildCrossDeviceRevalidationResult(
      snapshotBundle.rawSnapshot,
      integrityAssessment,
    );
    callbacks.applyIntegrityResultState(revalidationResult);
    callbacks.applyTrustedRecoveryState(await loadTrustedRecoverySnapshotState(userId));
    callbacks.bumpVaultDataVersion();
    return;
  }
  const trustedRebaselineAllowed = canRebaselineTrustedMutation(
    integrityAssessment,
    normalizedTrustedMutation,
  );
  const trustedFirstBaselineAllowed = integrityResult.mode === 'healthy'
    && integrityAssessment.inspection.baselineKind === 'missing'
    && snapshotBundle.rawSnapshot.items.every((item) => normalizedTrustedMutation.itemIds.has(item.id))
    && snapshotBundle.rawSnapshot.categories.every((category) => normalizedTrustedMutation.categoryIds.has(category.id));

  if (
    integrityResult.mode === 'quarantine'
    && !trustedRebaselineAllowed
    && !trustedFirstBaselineAllowed
    && hasTrustedDrift(integrityAssessment, normalizedTrustedMutation)
  ) {
    const selectiveDigest = await persistTrustedMutationIntegrityBaseline(
      userId,
      snapshotBundle.integritySnapshot,
      encryptionKey,
      normalizedTrustedMutation,
      { vaultId: snapshotBundle.rawSnapshot.vaultId },
    );
    if (selectiveDigest) {
      const reassessment = await assessVaultIntegritySnapshot({
        userId,
        snapshot: snapshotBundle.rawSnapshot,
        activeKey: encryptionKey,
        source: snapshotBundle.source,
      });
      const reassessedResult = reassessment.result;
      if (reassessedResult.mode === 'quarantine') {
        callbacks.applyIntegrityResultState(reassessedResult);
        callbacks.applyTrustedRecoveryState(await loadTrustedRecoverySnapshotState(userId));
        callbacks.bumpVaultDataVersion();
        return;
      }
      if (reassessedResult.mode === 'healthy') {
        callbacks.applyTrustedRecoveryState(
          await persistTrustedRecoverySnapshot(snapshotBundle.rawSnapshot),
        );
        const manifestPersist = await persistRuntimeManifestV2ForHealthyPublish({
          userId,
          snapshot: snapshotBundle.rawSnapshot,
          vaultKey: encryptionKey,
          encryptedUserKey: input.encryptedUserKey,
          trustedMutation: normalizedTrustedMutation,
          snapshotDigest: selectiveDigest,
          itemCount: snapshotBundle.integritySnapshot.items.length,
          categoryCount: snapshotBundle.integritySnapshot.categories.length,
        });
        if (!manifestPersist.ok) {
          callbacks.applyIntegrityResultState(manifestPersist.result);
          callbacks.bumpVaultDataVersion();
          return;
        }
        callbacks.applyIntegrityResultState({
          valid: true,
          isFirstCheck: false,
          computedRoot: selectiveDigest,
          storedRoot: selectiveDigest,
          itemCount: snapshotBundle.integritySnapshot.items.length,
          categoryCount: snapshotBundle.integritySnapshot.categories.length,
          mode: 'healthy',
          quarantinedItems: [],
        });
        callbacks.bumpVaultDataVersion();
        return;
      }
    }
  }

  if (integrityResult.mode === 'blocked' && !trustedRebaselineAllowed && !trustedFirstBaselineAllowed) {
    await callbacks.setBlockedIntegrityState(
      encryptionKey,
      integrityResult.blockedReason ?? 'snapshot_malformed',
      integrityResult,
    );
    return;
  }

  if (integrityResult.mode === 'quarantine' && !trustedRebaselineAllowed && !trustedFirstBaselineAllowed) {
    callbacks.applyIntegrityResultState(integrityResult);
    callbacks.applyTrustedRecoveryState(await loadTrustedRecoverySnapshotState(userId));
    return;
  }

  if (isNonTamperIntegrityMode(integrityResult.mode) && !trustedRebaselineAllowed && !trustedFirstBaselineAllowed) {
    callbacks.applyIntegrityResultState(integrityResult);
    callbacks.applyTrustedRecoveryState(await loadTrustedRecoverySnapshotState(userId));
    return;
  }

  if (integrityAssessment.inspection.baselineKind === 'missing' && !trustedFirstBaselineAllowed) {
    callbacks.applyIntegrityResultState(integrityResult);
    return;
  }

  const digest = await persistIntegrityBaseline(
    userId,
    snapshotBundle.integritySnapshot,
    encryptionKey,
    integrityAssessment.inspection.digest,
    { vaultId: snapshotBundle.rawSnapshot.vaultId },
  );
  callbacks.applyTrustedRecoveryState(
    await persistTrustedRecoverySnapshot(snapshotBundle.rawSnapshot),
  );
  const manifestPersist = await persistRuntimeManifestV2ForHealthyPublish({
    userId,
    snapshot: snapshotBundle.rawSnapshot,
    vaultKey: encryptionKey,
    encryptedUserKey: input.encryptedUserKey,
    trustedMutation: normalizedTrustedMutation,
    snapshotDigest: digest,
    itemCount: snapshotBundle.integritySnapshot.items.length,
    categoryCount: snapshotBundle.integritySnapshot.categories.length,
  });
  if (!manifestPersist.ok) {
    callbacks.applyIntegrityResultState(manifestPersist.result);
    callbacks.bumpVaultDataVersion();
    return;
  }
  callbacks.applyIntegrityResultState({
    valid: true,
    isFirstCheck: false,
    computedRoot: digest,
    storedRoot: digest,
    itemCount: snapshotBundle.integritySnapshot.items.length,
    categoryCount: snapshotBundle.integritySnapshot.categories.length,
    mode: 'healthy',
    quarantinedItems: [],
  });
  callbacks.bumpVaultDataVersion();
}

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
        useLocalMutationOverlay: true,
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

    const integrityAssessment = await assessVaultIntegritySnapshot({
      userId,
      snapshot: rawSnapshot,
      activeKey: encryptionKey,
      source: source ?? (snapshot ? undefined : loadedSnapshotBundle?.source),
    });
    const result = integrityAssessment.result;
    const assessmentSource = source ?? (snapshot ? undefined : loadedSnapshotBundle?.source);
    if (shouldDowngradeCrossDeviceV2BaselineDrift({
      assessment: integrityAssessment,
      snapshot: rawSnapshot,
      source: assessmentSource,
    })) {
      const revalidationResult = buildCrossDeviceRevalidationResult(rawSnapshot, integrityAssessment);
      callbacks.applyIntegrityResultState(revalidationResult);
      callbacks.applyTrustedRecoveryState(trustedRecoveryState);
      return revalidationResult;
    }
    const recentLocalRebaselineAllowed = canRebaselineRecentLocalMutation(userId, integrityAssessment);
    if (result.mode === 'blocked' && !recentLocalRebaselineAllowed) {
      await callbacks.setBlockedIntegrityState(
        encryptionKey,
        result.blockedReason ?? 'snapshot_malformed',
        result,
      );
      return result;
    }

    if (recentLocalRebaselineAllowed) {
      const digest = await persistIntegrityBaseline(
        userId,
        buildVaultIntegritySnapshot(rawSnapshot),
        encryptionKey,
        integrityAssessment.inspection.digest,
        { vaultId: rawSnapshot.vaultId },
      );
      callbacks.applyTrustedRecoveryState(await persistTrustedRecoverySnapshot(rawSnapshot));
      const trustedResult: VaultIntegrityVerificationResult = {
        valid: true,
        isFirstCheck: false,
        computedRoot: digest,
        storedRoot: digest,
        itemCount: rawSnapshot.items.length,
        categoryCount: rawSnapshot.categories.length,
        mode: 'healthy',
        quarantinedItems: [],
      };
      callbacks.applyIntegrityResultState(trustedResult);
      return trustedResult;
    }

    callbacks.applyIntegrityResultState(result);
    if (result.mode === 'healthy') {
      if (canPersistIntegrityBaselineImmediately(integrityAssessment, rawSnapshot)) {
        await persistMissingOrLegacyBaseline({
          userId,
          integritySnapshot: buildVaultIntegritySnapshot(rawSnapshot),
          activeKey: encryptionKey,
          inspection: integrityAssessment.inspection,
          vaultId: rawSnapshot.vaultId,
        });
        callbacks.applyTrustedRecoveryState(await persistTrustedRecoverySnapshot(rawSnapshot));
      }
    } else {
      callbacks.applyTrustedRecoveryState(await loadTrustedRecoverySnapshotState(userId));
    }

    return result;
  } catch (error) {
    if (!(error instanceof VaultIntegrityBaselineError)) {
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
      callbacks.applyIntegrityResultState(failureResult);
      return failureResult;
    }

    console.error('Vault integrity verification error.', { code: 'baseline_unreadable' });
    const blockedReason: VaultIntegrityBlockedReason = 'baseline_unreadable';
    const failureResult: VaultIntegrityVerificationResult = {
      valid: false,
      isFirstCheck: false,
      computedRoot: '',
      itemCount: 0,
      categoryCount: 0,
      mode: 'blocked',
      blockedReason,
      quarantinedItems: [],
    };
    await callbacks.setBlockedIntegrityState(encryptionKey, blockedReason, failureResult);
    return failureResult;
  }
}
