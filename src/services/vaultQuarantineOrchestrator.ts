import {
  isNonTamperIntegrityMode,
  type QuarantinedVaultItem,
  type VaultIntegrityMode,
  type VaultIntegrityVerificationResult,
} from './vaultIntegrityService';

export interface VaultQuarantineSummary {
  quarantinedItems: QuarantinedVaultItem[];
  decryptableItemIds: string[];
}

function isActiveItemQuarantine(item: QuarantinedVaultItem): boolean {
  return new Set<string>([
    'ciphertext_changed',
    'aead_auth_failed',
    'item_envelope_malformed',
    'item_aad_mismatch',
    'item_manifest_hash_mismatch',
    'item_revision_replay',
    'item_key_id_mismatch',
    'duplicate_active_item_record',
  ]).has(item.reason);
}

export function buildVaultQuarantineSummary(
  quarantinedItems: QuarantinedVaultItem[],
  allItemIds: Iterable<string>,
): VaultQuarantineSummary {
  const activeQuarantinedItems = mergeQuarantinedItems(quarantinedItems);
  const quarantinedIds = new Set(activeQuarantinedItems.map((item) => item.id));
  const decryptableItemIds = [...allItemIds]
    .filter((itemId) => !quarantinedIds.has(itemId))
    .sort((left, right) => left.localeCompare(right));

  return {
    quarantinedItems: activeQuarantinedItems,
    decryptableItemIds,
  };
}

export function mergeQuarantinedItems(
  ...groups: QuarantinedVaultItem[][]
): QuarantinedVaultItem[] {
  const merged = new Map<string, QuarantinedVaultItem>();

  for (const group of groups) {
    for (const item of group) {
      if (!isActiveItemQuarantine(item)) {
        continue;
      }

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
      valid: false,
      isFirstCheck: false,
      computedRoot: '',
      itemCount: 0,
      categoryCount: 0,
      mode: 'revalidation_failed',
      nonTamperReason: 'revalidation_failed',
      quarantinedItems: [],
    };
  }

  if (
    runtimeUnreadableItems.length > 0
    && result.quarantinedItems.length === 0
  ) {
    return {
      ...result,
      valid: false,
      mode: 'revalidation_failed',
      nonTamperReason: 'revalidation_failed',
      blockedReason: undefined,
      quarantinedItems: [],
    };
  }

  if (isNonTamperIntegrityMode(result.mode)) {
    return {
      ...result,
      quarantinedItems: [],
    };
  }

  const mergedItems = mergeQuarantinedItems(result.quarantinedItems);
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
  input: {
    mode: VaultIntegrityMode | 'safe' | string;
    quarantinedItems: QuarantinedVaultItem[];
    itemId: string;
  },
): void {
  if (input.mode !== 'healthy' && input.mode !== 'quarantine') {
    throw new VaultIntegrityDecryptBlockedError(input.mode);
  }

  if (input.mode === 'quarantine' || input.quarantinedItems.length > 0) {
    const quarantineSummary = buildVaultQuarantineSummary(input.quarantinedItems, [input.itemId]);
    if (!quarantineSummary.decryptableItemIds.includes(input.itemId)) {
      throw new Error('Vault item is quarantined and will not be decrypted.');
    }
  }
}

export class VaultIntegrityDecryptBlockedError extends Error {
  readonly code = 'vault_integrity_decrypt_blocked';
  readonly mode: string;

  constructor(mode: string) {
    super('Vault item decrypt is blocked until vault integrity is trusted.');
    this.name = 'VaultIntegrityDecryptBlockedError';
    this.mode = mode;
  }
}
