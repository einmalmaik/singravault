// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE
/**
 * Controlled runtime entrypoint for Phase 12 migration.
 *
 * This module is the only UI-facing path that may call `migrateVault`.
 * It performs read-only legacy loading, local device signing key setup,
 * migration execution, and post-commit OpLog verification before the
 * caller may unlock the normal vault UI.
 */

import { supabase } from '@/integrations/supabase/client';
import type { VaultItemData } from '@/services/cryptoService';
import { generateDeviceSigningKeyPair } from './operationSigningService';
import { migrateVault, type MigrateVaultResult } from './migrationService';
import type { LegacyCategoryRow, LegacyVaultItemRow } from './migrationTypes';
import { saveVaultOpLogDeviceIdentity, loadVaultOpLogDeviceIdentity } from './vaultOpLogDeviceStore';
import {
  loadVaultOpLogDeviceSigningKey,
  saveVaultOpLogDeviceSigningKey,
} from './vaultOpLogDeviceSigningKeyStore';
import { loadVaultOpLogUiState } from './vaultOpLogUiOrchestrator';
import type { SupabaseRpcClient } from './vaultOpLogRepository';

export interface MigrationKeyContext {
  readonly activeKey: CryptoKey;
  readonly vaultEncryptionKey: Uint8Array;
}

export interface RunControlledMigrationInput {
  readonly userId: string;
  readonly vaultId: string;
  readonly migrationKeyContext: MigrationKeyContext;
  readonly decryptLegacyItem: (
    encryptedData: string,
    entryId: string,
  ) => Promise<{ data: VaultItemData; legacyEnvelopeUsed: boolean; legacyNoAadFallbackUsed: boolean }>;
  readonly client?: Pick<typeof supabase, 'from'>;
  readonly rpcClient?: SupabaseRpcClient;
}

export interface RunControlledMigrationResult {
  readonly success: boolean;
  readonly migrationResult: MigrateVaultResult | null;
  readonly error: Error | null;
}

interface DeviceSigningContext {
  readonly deviceId: string;
  readonly privateKey: CryptoKey;
  readonly publicSigningKeyB64Url: string;
}

export async function runControlledMigration(
  input: RunControlledMigrationInput,
): Promise<RunControlledMigrationResult> {
  const client = input.client ?? supabase;
  const rpcClient = input.rpcClient ?? supabase;

  try {
    const [legacyItems, legacyCategories, device] = await Promise.all([
      loadLegacyItems(client, input.userId, input.vaultId),
      loadLegacyCategories(client, input.userId),
      getOrCreateDeviceSigningContext(input.userId, input.vaultId),
    ]);

    const migrationResult = await migrateVault({
      vaultId: input.vaultId,
      userId: input.userId,
      deviceId: device.deviceId,
      deviceSigningKey: device.privateKey,
      publicSigningKeyB64Url: device.publicSigningKeyB64Url,
      vaultEncryptionKey: input.migrationKeyContext.vaultEncryptionKey,
      legacyItems,
      legacyCategories,
      decryptItem: async (legacyItem) => {
        const result = await input.decryptLegacyItem(legacyItem.encryptedData, legacyItem.id);
        return result.data;
      },
      rpcClient,
    });

    if (!migrationResult.success) {
      return {
        success: false,
        migrationResult,
        error: new Error(migrationResult.error?.message ?? 'Tresor-Migration fehlgeschlagen.'),
      };
    }

    const verification = await loadVaultOpLogUiState({
      rpcClient,
      vaultId: input.vaultId,
      deviceId: device.deviceId,
      publicSigningKeyB64Url: device.publicSigningKeyB64Url,
      vaultEncryptionKey: input.migrationKeyContext.vaultEncryptionKey,
    });

    if (verification.error || !verification.localVaultState) {
      return {
        success: false,
        migrationResult,
        error: new Error(verification.error ?? 'Migration konnte nach Commit nicht verifiziert werden.'),
      };
    }

    if (verification.uiView?.vaultSecurityMode === 'lockedCritical') {
      return {
        success: false,
        migrationResult,
        error: new Error('Migration wurde verifiziert, aber der Tresor ist lockedCritical.'),
      };
    }

    return { success: true, migrationResult, error: null };
  } catch (error) {
    return {
      success: false,
      migrationResult: null,
      error: error instanceof Error ? error : new Error('Tresor-Migration fehlgeschlagen.'),
    };
  }
}

async function getOrCreateDeviceSigningContext(
  userId: string,
  vaultId: string,
): Promise<DeviceSigningContext> {
  const existingIdentity = loadVaultOpLogDeviceIdentity();
  if (existingIdentity) {
    const privateKey = await loadVaultOpLogDeviceSigningKey({
      userId,
      vaultId,
      deviceId: existingIdentity.deviceId,
    });
    if (!privateKey) {
      throw new Error('Lokaler Device-Signing-Key fehlt. Migration kann nicht sicher fortgesetzt werden.');
    }
    return {
      deviceId: existingIdentity.deviceId,
      privateKey,
      publicSigningKeyB64Url: existingIdentity.publicSigningKeyB64Url,
    };
  }

  const keyPair = await generateDeviceSigningKeyPair();
  const deviceId = crypto.randomUUID();
  await saveVaultOpLogDeviceSigningKey({
    userId,
    vaultId,
    deviceId,
    privateKey: keyPair.privateKey,
  });
  saveVaultOpLogDeviceIdentity({
    deviceId,
    publicSigningKeyB64Url: keyPair.publicKeyB64Url,
  });

  return {
    deviceId,
    privateKey: keyPair.privateKey,
    publicSigningKeyB64Url: keyPair.publicKeyB64Url,
  };
}

async function loadLegacyItems(
  client: Pick<typeof supabase, 'from'>,
  userId: string,
  vaultId: string,
): Promise<LegacyVaultItemRow[]> {
  const { data, error } = await client
    .from('vault_items')
    .select('id,user_id,vault_id,category_id,encrypted_data,title,website_url,item_type,is_favorite,sort_order,created_at,updated_at')
    .eq('user_id', userId)
    .eq('vault_id', vaultId);
  if (error) {
    throw error;
  }

  return (data ?? []).map((row) => ({
    id: row.id,
    userId: row.user_id,
    vaultId: row.vault_id,
    categoryId: row.category_id,
    encryptedData: row.encrypted_data,
    title: row.title ?? '',
    websiteUrl: row.website_url,
    itemType: row.item_type ?? 'password',
    isFavorite: row.is_favorite,
    sortOrder: row.sort_order,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  }));
}

async function loadLegacyCategories(
  client: Pick<typeof supabase, 'from'>,
  userId: string,
): Promise<LegacyCategoryRow[]> {
  const { data, error } = await client
    .from('categories')
    .select('id,user_id,name,color,icon,parent_id,sort_order,created_at,updated_at')
    .eq('user_id', userId);
  if (error) {
    throw error;
  }

  return (data ?? []).map((row) => ({
    id: row.id,
    userId: row.user_id,
    name: row.name ?? '',
    color: row.color,
    icon: row.icon,
    parentId: row.parent_id,
    sortOrder: row.sort_order,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  }));
}
