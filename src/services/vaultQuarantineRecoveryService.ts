import type { Database } from '@/integrations/supabase/types';
import type { OfflineVaultSnapshot } from '@/services/offlineVaultService';
import type { QuarantinedVaultItem } from '@/services/vaultIntegrityService';
import { isActiveQuarantineReasonV2 } from '@/services/vaultIntegrityV2/runtimeBridge';

type VaultItemRow = Database['public']['Tables']['vault_items']['Row'];

export interface QuarantineResolutionRuntimeState {
  isBusy: boolean;
  lastError: string | null;
}

export interface QuarantineResolutionState extends QuarantineResolutionRuntimeState {
  reason: QuarantinedVaultItem['reason'];
  canRestore: boolean;
  canDelete: boolean;
  hasTrustedLocalCopy: boolean;
}

export type TrustedSnapshotItemsById = Record<string, VaultItemRow>;

export function indexTrustedSnapshotItems(
  snapshot: OfflineVaultSnapshot | null,
): TrustedSnapshotItemsById {
  if (!snapshot) {
    return {};
  }

  return Object.fromEntries(
    snapshot.items.map((item) => [item.id, item]),
  );
}

export function buildQuarantineResolutionMap(
  items: QuarantinedVaultItem[],
  trustedItemsById: TrustedSnapshotItemsById,
  runtimeStateById: Record<string, QuarantineResolutionRuntimeState> = {},
): Record<string, QuarantineResolutionState> {
  return Object.fromEntries(
    items.map((item) => {
      const runtimeState = runtimeStateById[item.id] ?? { isBusy: false, lastError: null };
      const hasTrustedLocalCopy = Boolean(trustedItemsById[item.id]);

      return [
        item.id,
        {
          reason: item.reason,
          canRestore: hasTrustedLocalCopy && isActiveQuarantineReasonV2(item.reason),
          canDelete: isActiveQuarantineReasonV2(item.reason) || item.reason === 'unknown_on_server',
          hasTrustedLocalCopy,
          isBusy: runtimeState.isBusy,
          lastError: runtimeState.lastError,
        } satisfies QuarantineResolutionState,
      ];
    }),
  );
}

