import type { QuarantinedVaultItem, VaultIntegrityVerificationResult } from './vaultIntegrityService';

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

export function mergeQuarantinedItems(
  ...groups: QuarantinedVaultItem[][]
): QuarantinedVaultItem[] {
  const merged = new Map<string, QuarantinedVaultItem>();

  for (const group of groups) {
    for (const item of group) {
      const existing = merged.get(item.id);
      if (!existing || (item.updatedAt ?? '') > (existing.updatedAt ?? '')) {
        merged.set(item.id, item);
      }
    }
  }

  return [...merged.values()].sort((left, right) => {
    const leftDate = left.updatedAt ?? '';
    const rightDate = right.updatedAt ?? '';
    return rightDate.localeCompare(leftDate) || left.id.localeCompare(right.id);
  });
}

export function buildDisplayedIntegrityResult(
  result: VaultIntegrityVerificationResult | null,
  runtimeUnreadableItems: QuarantinedVaultItem[] = [],
): VaultIntegrityVerificationResult | null {
  if (!result) {
    if (runtimeUnreadableItems.length === 0) {
      return null;
    }

    return {
      valid: true,
      isFirstCheck: false,
      computedRoot: '',
      itemCount: runtimeUnreadableItems.length,
      categoryCount: 0,
      mode: 'quarantine',
      quarantinedItems: runtimeUnreadableItems,
    };
  }

  const mergedItems = mergeQuarantinedItems(result.quarantinedItems, runtimeUnreadableItems);
  if (mergedItems.length === 0) {
    return {
      ...result,
      quarantinedItems: [],
    };
  }

  if (result.mode === 'blocked') {
    return {
      ...result,
      quarantinedItems: mergedItems,
    };
  }

  return {
    ...result,
    valid: true,
    mode: 'quarantine',
    blockedReason: undefined,
    quarantinedItems: mergedItems,
  };
}

export function assertItemDecryptable(
  quarantinedItems: QuarantinedVaultItem[],
  itemId: string,
): void {
  const quarantineSummary = buildVaultQuarantineSummary(quarantinedItems, [itemId]);
  if (!quarantineSummary.decryptableItemIds.includes(itemId)) {
    throw new Error('Vault item is quarantined and will not be decrypted.');
  }
}
