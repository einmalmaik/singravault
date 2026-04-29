import type { QuarantinedVaultItem } from './vaultIntegrityService';

export interface VaultQuarantineSummary {
  quarantinedItems: QuarantinedVaultItem[];
  decryptableItemIds: string[];
}

export function buildVaultQuarantineSummary(
  quarantinedItems: QuarantinedVaultItem[],
  allItemIds: Iterable<string>,
): VaultQuarantineSummary {
  const quarantinedIds = new Set(quarantinedItems.map((item) => item.id));
  const decryptableItemIds = [...allItemIds]
    .filter((itemId) => !quarantinedIds.has(itemId))
    .sort((left, right) => left.localeCompare(right));

  return {
    quarantinedItems: [...quarantinedItems].sort((left, right) => left.id.localeCompare(right.id)),
    decryptableItemIds,
  };
}
