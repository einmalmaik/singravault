// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE

import { supabase } from '@/integrations/supabase/client';
import type { Database } from '@/integrations/supabase/types';
import type { VaultItemData } from '@/services/cryptoService';
import {
  hasLegacyVaultItemServerMetadata,
  mergeLegacyVaultItemMetadataIntoPayload,
  neutralizeVaultItemServerMetadata,
} from '@/services/vaultMetadataPolicy';
import { upsertOfflineItemRow } from '@/services/offlineVaultService';

type VaultItemRow = Database['public']['Tables']['vault_items']['Row'];

export interface LegacyVaultMetadataMigrationInput {
  userId: string;
  vaultId: string | null;
  item: VaultItemRow;
  decryptedData: VaultItemData;
  canPersistRemote: boolean;
  encryptItem: (data: VaultItemData, entryId: string) => Promise<string>;
  now?: () => Date;
}

export interface LegacyVaultMetadataMigrationResult {
  item: VaultItemRow;
  decryptedData: VaultItemData;
  migrated: boolean;
}

/**
 * Migrates one legacy item after the vault is already unlocked. The function
 * never drops item payload data: it first merges server-visible legacy metadata
 * into the decrypted payload locally, then rewrites only encrypted_data plus
 * neutral server metadata.
 */
export async function migrateLegacyVaultItemMetadata(
  input: LegacyVaultMetadataMigrationInput,
): Promise<LegacyVaultMetadataMigrationResult> {
  if (!hasLegacyVaultItemServerMetadata(input.item)) {
    return {
      item: input.item,
      decryptedData: input.decryptedData,
      migrated: false,
    };
  }

  const mergedDecryptedData = mergeLegacyVaultItemMetadataIntoPayload(input.decryptedData, input.item);

  if (!input.canPersistRemote) {
    return {
      item: {
        ...input.item,
        ...neutralizeVaultItemServerMetadata({}),
      },
      decryptedData: mergedDecryptedData,
      migrated: false,
    };
  }

  const migratedEncryptedData = await input.encryptItem(mergedDecryptedData, input.item.id);
  const neutralPayload = neutralizeVaultItemServerMetadata({
    id: input.item.id,
    user_id: input.item.user_id,
    vault_id: input.item.vault_id,
    encrypted_data: migratedEncryptedData,
  });
  const updatedAt = (input.now ?? (() => new Date()))().toISOString();

  const { error } = await supabase
    .from('vault_items')
    .update(neutralPayload)
    .eq('id', input.item.id)
    .eq('user_id', input.userId);

  if (error) {
    return {
      item: {
        ...input.item,
        ...neutralizeVaultItemServerMetadata({}),
      },
      decryptedData: mergedDecryptedData,
      migrated: false,
    };
  }

  const migratedItem: VaultItemRow = {
    ...input.item,
    ...neutralPayload,
    updated_at: updatedAt,
  };

  await upsertOfflineItemRow(input.userId, migratedItem, input.vaultId);

  return {
    item: migratedItem,
    decryptedData: mergedDecryptedData,
    migrated: true,
  };
}
