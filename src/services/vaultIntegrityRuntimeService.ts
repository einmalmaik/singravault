import type { OfflineVaultSnapshot } from '@/services/offlineVaultService';
import {
  VaultIntegrityBaselineError,
  persistIntegrityBaseline,
  persistTrustedMutationIntegrityBaseline,
  type VaultIntegrityAssessment,
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
  type TrustedVaultMutation,
} from '@/services/vaultIntegrityDecisionEngine';
import { loadCurrentVaultIntegritySnapshot } from '@/services/offlineVaultRuntimeService';
import { isLikelyOfflineError } from '@/services/offlineVaultService';
import {
  loadTrustedRecoverySnapshotState,
  persistTrustedRecoverySnapshot,
  type TrustedRecoverySnapshotState,
} from '@/services/vaultRecoveryOrchestrator';

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
  return assessment.inspection.baselineKind !== 'missing'
    || (snapshot.items.length === 0 && snapshot.categories.length === 0);
}

export async function persistMissingOrLegacyBaseline(input: {
  userId: string;
  integritySnapshot: VaultIntegritySnapshot;
  activeKey: CryptoKey;
  inspection: VaultIntegrityBaselineInspection;
}): Promise<void> {
  const { userId, integritySnapshot, activeKey, inspection } = input;
  if (inspection.snapshotValidationError || inspection.legacyBaselineMismatch) {
    return;
  }

  if (inspection.baselineKind === 'missing' || inspection.baselineKind === 'v1') {
    await persistIntegrityBaseline(userId, integritySnapshot, activeKey, inspection.digest);
  }
}

export async function finalizeVaultUnlockIntegrity(input: {
  userId: string;
  activeKey: CryptoKey;
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

    const integrityAssessment = await assessVaultIntegritySnapshot({
      userId,
      snapshot: snapshotBundle.rawSnapshot,
      activeKey,
    });
    const integrityResult = integrityAssessment.result;
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
  });
  const integrityResult = integrityAssessment.result;
  const trustedRebaselineAllowed = canRebaselineTrustedMutation(
    integrityAssessment,
    normalizedTrustedMutation,
  );
  const trustedFirstBaselineAllowed = integrityAssessment.inspection.baselineKind === 'missing'
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
    );
    if (selectiveDigest) {
      const reassessment = await assessVaultIntegritySnapshot({
        userId,
        snapshot: snapshotBundle.rawSnapshot,
        activeKey: encryptionKey,
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

  if (integrityAssessment.inspection.baselineKind === 'missing' && !trustedFirstBaselineAllowed) {
    callbacks.applyIntegrityResultState(integrityResult);
    return;
  }

  const digest = await persistIntegrityBaseline(
    userId,
    snapshotBundle.integritySnapshot,
    encryptionKey,
    integrityAssessment.inspection.digest,
  );
  callbacks.applyTrustedRecoveryState(
    await persistTrustedRecoverySnapshot(snapshotBundle.rawSnapshot),
  );
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
  snapshot?: OfflineVaultSnapshot;
  callbacks: VaultIntegrityRuntimeCallbacks;
}): Promise<VaultIntegrityVerificationResult | null> {
  const { userId, encryptionKey, snapshot, callbacks } = input;

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

    const integrityAssessment = await assessVaultIntegritySnapshot({
      userId,
      snapshot: rawSnapshot,
      activeKey: encryptionKey,
    });
    const result = integrityAssessment.result;
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
      console[level]('Vault integrity revalidation failed without changing integrity state:', error);
      return null;
    }

    console.error('Vault integrity verification error:', error);
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
