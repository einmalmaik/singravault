import {
  toVaultIntegrityVerificationResult,
  type QuarantinedVaultItem,
  type VaultIntegrityBaselineInspection,
  type VaultIntegrityBlockedReason,
  type VaultIntegrityMode,
} from './vaultIntegrityService';

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
