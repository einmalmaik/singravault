import { decrypt } from './cryptoService';
import {
  inspectVaultSnapshotIntegrity,
  toVaultIntegrityVerificationResult,
  type QuarantinedVaultItem,
  type VaultIntegrityBaselineInspection,
  type VaultIntegrityBlockedReason,
  type VaultIntegrityMode,
  type VaultIntegritySnapshot,
  type VaultIntegrityVerificationResult,
} from './vaultIntegrityService';
import { isRecentLocalVaultMutation, type OfflineVaultSnapshot } from './offlineVaultService';

export interface VaultIntegrityDecision {
  mode: VaultIntegrityMode;
  blockedReason: VaultIntegrityBlockedReason | null;
  quarantinedItems: QuarantinedVaultItem[];
  driftedCategoryIds: string[];
  recoverableFromTrustedSnapshot: boolean;
  uiSafeMessageCode:
    | 'vault_integrity_healthy'
    | 'vault_item_quarantine'
    | 'vault_integrity_blocked';
  debugSafeReason: string;
}

export interface VaultIntegrityDecisionInput {
  inspection: VaultIntegrityBaselineInspection;
  trustedSnapshotItemIds?: Iterable<string>;
}

export interface TrustedVaultMutation {
  itemIds?: Iterable<string>;
  categoryIds?: Iterable<string>;
}

export interface NormalizedTrustedVaultMutation {
  itemIds: Set<string>;
  categoryIds: Set<string>;
}

export interface VaultIntegrityAssessmentLike {
  inspection: VaultIntegrityBaselineInspection;
  unreadableCategoryReason: VaultIntegrityBlockedReason | null;
}

export interface VaultIntegrityAssessment extends VaultIntegrityAssessmentLike {
  result: VaultIntegrityVerificationResult;
}

export function buildVaultIntegritySnapshot(snapshot: {
  items: Array<{
    id: string;
    encrypted_data: string;
    updated_at?: string | null;
    item_type?: 'password' | 'note' | 'totp' | 'card' | null;
  }>;
  categories: Array<{ id: string; name: string; icon: string | null; color: string | null }>;
}): VaultIntegritySnapshot {
  return {
    items: snapshot.items.map((item) => ({
      id: item.id,
      encrypted_data: item.encrypted_data,
      updated_at: item.updated_at ?? null,
      item_type: 'item_type' in item ? item.item_type : null,
    })),
    categories: snapshot.categories.map((category) => ({
      id: category.id,
      name: category.name,
      icon: typeof category.icon === 'string' ? category.icon : null,
      color: typeof category.color === 'string' ? category.color : null,
    })),
  };
}

export async function detectUnreadableCategories(
  snapshot: OfflineVaultSnapshot,
  activeKey: CryptoKey,
): Promise<VaultIntegrityBlockedReason | null> {
  const encryptedCategoryPrefix = 'enc:cat:v1:';

  for (const category of snapshot.categories) {
    const encryptedFields = [category.name, category.icon, category.color]
      .filter((value): value is string => typeof value === 'string' && value.startsWith(encryptedCategoryPrefix))
      .map((value) => value.slice(encryptedCategoryPrefix.length));

    for (const encryptedField of encryptedFields) {
      try {
        await decrypt(encryptedField, activeKey);
      } catch {
        return 'category_structure_mismatch';
      }
    }
  }

  return null;
}

export async function assessVaultIntegritySnapshot(input: {
  userId: string;
  snapshot: OfflineVaultSnapshot;
  activeKey: CryptoKey;
}): Promise<VaultIntegrityAssessment> {
  const inspection = await inspectVaultSnapshotIntegrity(
    input.userId,
    buildVaultIntegritySnapshot(input.snapshot),
    input.activeKey,
  );
  const baseResult = toVaultIntegrityVerificationResult(inspection);

  if (baseResult.mode === 'blocked') {
    return {
      inspection,
      unreadableCategoryReason: null,
      result: baseResult,
    };
  }

  const categoryIssue = await detectUnreadableCategories(input.snapshot, input.activeKey);
  if (categoryIssue) {
    return {
      inspection,
      unreadableCategoryReason: categoryIssue,
      result: {
        ...baseResult,
        valid: false,
        mode: 'blocked',
        blockedReason: categoryIssue,
        quarantinedItems: [],
      },
    };
  }

  const quarantinedItems = baseResult.quarantinedItems;
  if (quarantinedItems.length > 0) {
    return {
      inspection,
      unreadableCategoryReason: null,
      result: {
        ...baseResult,
        valid: true,
        mode: 'quarantine',
        blockedReason: undefined,
        quarantinedItems,
      },
    };
  }

  return {
    inspection,
    unreadableCategoryReason: null,
    result: {
      ...baseResult,
      valid: true,
      mode: 'healthy',
      blockedReason: undefined,
      quarantinedItems: [],
    },
  };
}

export function normalizeTrustedVaultMutation(
  mutation?: TrustedVaultMutation,
): NormalizedTrustedVaultMutation {
  return {
    itemIds: new Set(mutation?.itemIds ?? []),
    categoryIds: new Set(mutation?.categoryIds ?? []),
  };
}

export function canRebaselineTrustedMutation(
  assessment: VaultIntegrityAssessmentLike,
  trustedMutation: NormalizedTrustedVaultMutation,
): boolean {
  if (assessment.unreadableCategoryReason) {
    return false;
  }

  if (
    assessment.inspection.snapshotValidationError
    || assessment.inspection.legacyBaselineMismatch
  ) {
    return false;
  }

  if (
    assessment.inspection.categoryDriftIds.some((categoryId) => !trustedMutation.categoryIds.has(categoryId))
    || assessment.inspection.itemDrifts.some((item) => !trustedMutation.itemIds.has(item.id))
  ) {
    return false;
  }

  return (
    assessment.inspection.categoryDriftIds.length > 0
    || assessment.inspection.itemDrifts.length > 0
  );
}

export function hasTrustedDrift(
  assessment: VaultIntegrityAssessmentLike,
  trustedMutation: NormalizedTrustedVaultMutation,
): boolean {
  return assessment.inspection.itemDrifts.some((item) => trustedMutation.itemIds.has(item.id))
    || assessment.inspection.categoryDriftIds.some((categoryId) => trustedMutation.categoryIds.has(categoryId));
}

export function canRebaselineRecentLocalMutation(
  userId: string,
  assessment: VaultIntegrityAssessmentLike,
): boolean {
  if (
    assessment.unreadableCategoryReason
    || assessment.inspection.snapshotValidationError
    || assessment.inspection.legacyBaselineMismatch
  ) {
    return false;
  }

  if (
    assessment.inspection.itemDrifts.length === 0
    && assessment.inspection.categoryDriftIds.length === 0
  ) {
    return false;
  }

  return isRecentLocalVaultMutation(userId, {
    itemIds: assessment.inspection.itemDrifts.map((item) => item.id),
    categoryIds: assessment.inspection.categoryDriftIds,
  });
}

export function hasTrustedMutationScope(
  trustedMutation: NormalizedTrustedVaultMutation,
): boolean {
  return trustedMutation.itemIds.size > 0 || trustedMutation.categoryIds.size > 0;
}

export function decideVaultIntegrity(input: VaultIntegrityDecisionInput): VaultIntegrityDecision {
  const result = toVaultIntegrityVerificationResult(input.inspection);
  const trustedItemIds = new Set(input.trustedSnapshotItemIds ?? []);
  const recoverableFromTrustedSnapshot = result.quarantinedItems.some((item) => trustedItemIds.has(item.id));

  if (result.mode === 'blocked') {
    return {
      mode: 'blocked',
      blockedReason: result.blockedReason ?? 'unknown_integrity_failure',
      quarantinedItems: [],
      driftedCategoryIds: result.driftedCategoryIds ?? [],
      recoverableFromTrustedSnapshot: false,
      uiSafeMessageCode: 'vault_integrity_blocked',
      debugSafeReason: result.blockedReason ?? 'unknown_integrity_failure',
    };
  }

  if (result.mode === 'quarantine') {
    return {
      mode: 'quarantine',
      blockedReason: null,
      quarantinedItems: result.quarantinedItems,
      driftedCategoryIds: [],
      recoverableFromTrustedSnapshot,
      uiSafeMessageCode: 'vault_item_quarantine',
      debugSafeReason: result.quarantinedItems.map((item) => item.reason).sort().join(',') || 'item_quarantine',
    };
  }

  return {
    mode: 'healthy',
    blockedReason: null,
    quarantinedItems: [],
    driftedCategoryIds: [],
    recoverableFromTrustedSnapshot: false,
    uiSafeMessageCode: 'vault_integrity_healthy',
    debugSafeReason: 'healthy',
  };
}
