// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE

import type { Database } from '@/integrations/supabase/types';
import type { VaultItemData } from '@/services/cryptoService';
import {
  hasLegacyVaultItemServerMetadata,
  mergeLegacyVaultItemMetadataIntoPayload,
  neutralizeVaultItemServerMetadata,
} from '@/services/vaultMetadataPolicy';
import { blockLegacyVaultRuntimeWrite } from '@/services/vaultOpLog/vaultLegacyWriteBlocker';

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

export class LegacyVaultMetadataMigrationPersistenceError extends Error {
  constructor(
    public readonly itemId: string,
    message = `Could not persist legacy metadata migration for item ${itemId}.`,
    public readonly cause?: unknown,
  ) {
    super(message);
    this.name = 'LegacyVaultMetadataMigrationPersistenceError';
  }
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

  blockLegacyVaultRuntimeWrite('legacy-vault-item-metadata-migration');
}

export async function migrateLegacyVaultItemEncryptionAndMetadata(
  input: LegacyVaultMetadataMigrationInput,
): Promise<LegacyVaultMetadataMigrationResult> {
  const mergedDecryptedData = hasLegacyVaultItemServerMetadata(input.item)
    ? mergeLegacyVaultItemMetadataIntoPayload(input.decryptedData, input.item)
    : input.decryptedData;
  blockLegacyVaultRuntimeWrite('legacy-vault-item-encryption-metadata-migration');
}
