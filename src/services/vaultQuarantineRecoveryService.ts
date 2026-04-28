import { supabase } from '@/integrations/supabase/client';
import type { Database } from '@/integrations/supabase/types';
import {
  buildVaultItemRowFromInsert,
  enqueueOfflineMutation,
  isAppOnline,
  isLikelyOfflineError,
  resolveDefaultVaultId,
  type OfflineVaultSnapshot,
  removeOfflineItemRow,
  upsertOfflineItemRow,
} from '@/services/offlineVaultService';
import { neutralizeVaultItemServerMetadata } from '@/services/vaultMetadataPolicy';
import type { QuarantinedVaultItem } from '@/services/vaultIntegrityService';

type VaultItemRow = Database['public']['Tables']['vault_items']['Row'];
type VaultItemInsert = Database['public']['Tables']['vault_items']['Insert'];

export interface QuarantineResolutionRuntimeState {
  isBusy: boolean;
  lastError: string | null;
}

export interface QuarantineResolutionState extends QuarantineResolutionRuntimeState {
  reason: QuarantinedVaultItem['reason'];
  canRestore: boolean;
  canDelete: boolean;
  canAcceptMissing: boolean;
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
          canRestore: hasTrustedLocalCopy && item.reason !== 'unknown_on_server',
          canDelete: item.reason === 'ciphertext_changed' || item.reason === 'unknown_on_server',
          canAcceptMissing: item.reason === 'missing_on_server',
          hasTrustedLocalCopy,
          isBusy: runtimeState.isBusy,
          lastError: runtimeState.lastError,
        } satisfies QuarantineResolutionState,
      ];
    }),
  );
}

export async function restoreQuarantinedItemFromTrustedSnapshot(
  userId: string,
  trustedItem: VaultItemRow,
): Promise<{ syncedOnline: boolean }> {
  const payload = await buildTrustedItemUpsertPayload(userId, trustedItem);
  const allowOfflineQueue = !isAppOnline();
  let syncedOnline = false;

  if (!allowOfflineQueue) {
    try {
      const { data, error } = await supabase
        .from('vault_items')
        .upsert(payload, { onConflict: 'id' })
        .select('*')
        .single();

      if (error) {
        throw error;
      }

      if (data) {
        await upsertOfflineItemRow(userId, data as VaultItemRow, payload.vault_id);
      }
      syncedOnline = true;
    } catch (error) {
      if (!isLikelyOfflineError(error)) {
        throw error;
      }

      return { syncedOnline: false };
    }
  }

  if (allowOfflineQueue && !syncedOnline) {
    await upsertOfflineItemRow(userId, buildVaultItemRowFromInsert(payload), payload.vault_id);
    await enqueueOfflineMutation({
      userId,
      type: 'upsert_item',
      payload,
    });
  }

  return { syncedOnline };
}

export async function deleteQuarantinedItemFromVault(
  userId: string,
  itemId: string,
): Promise<{ syncedOnline: boolean }> {
  const allowOfflineQueue = !isAppOnline();
  let syncedOnline = false;

  if (!allowOfflineQueue) {
    try {
      const { data, error } = await supabase
        .from('vault_items')
        .delete()
        .select('id')
        .eq('user_id', userId)
        .eq('id', itemId);

      if (error) {
        throw error;
      }
      if (!Array.isArray(data) || data.length === 0) {
        const alreadyAbsentOnServer = await isVaultItemAbsentOnServer(userId, itemId);
        if (!alreadyAbsentOnServer) {
          throw new Error('Der Quarantäne-Eintrag konnte serverseitig nicht gelöscht werden.');
        }
      }
      syncedOnline = true;
    } catch (error) {
      if (!isLikelyOfflineError(error)) {
        throw error;
      }

      return { syncedOnline: false };
    }
  }

  if (syncedOnline || allowOfflineQueue) {
    await removeOfflineItemRow(userId, itemId);
  }
  if (allowOfflineQueue && !syncedOnline) {
    await enqueueOfflineMutation({
      userId,
      type: 'delete_item',
      payload: { id: itemId },
    });
  }

  return { syncedOnline };
}

async function isVaultItemAbsentOnServer(userId: string, itemId: string): Promise<boolean> {
  const { data, error } = await supabase
    .from('vault_items')
    .select('id')
    .eq('user_id', userId)
    .eq('id', itemId);

  if (error) {
    throw error;
  }

  return Array.isArray(data) && data.length === 0;
}

async function buildTrustedItemUpsertPayload(
  userId: string,
  trustedItem: VaultItemRow,
): Promise<VaultItemInsert & { id: string }> {
  const vaultId = trustedItem.vault_id ?? await resolveDefaultVaultId(userId);
  if (!vaultId) {
    throw new Error('Kein Standard-Tresor verfügbar.');
  }

  return neutralizeVaultItemServerMetadata({
    id: trustedItem.id,
    user_id: userId,
    vault_id: vaultId,
    encrypted_data: trustedItem.encrypted_data,
  });
}
