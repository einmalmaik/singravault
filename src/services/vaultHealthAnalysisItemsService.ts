import type { VaultItemData } from '@/services/cryptoService';
import {
  loadVaultSnapshot,
  type OfflineVaultSnapshot,
} from '@/services/offlineVaultService';
import type { VaultIntegrityVerificationResult } from '@/services/vaultIntegrityService';
import { assertItemDecryptable } from '@/services/vaultQuarantineOrchestrator';
import type { VaultHealthAnalysisItem } from '@/extensions/types';
import type { LocalVaultState, LocalVerifiedRecord } from '@/services/vaultOpLog/vaultStateMachine';
import type { VaultMigrationRolloutStatus } from '@/services/vaultOpLog/vaultMigrationRolloutService';

type DecryptVaultItem = (encryptedData: string, entryId: string) => Promise<VaultItemData>;
type VerifyVaultSnapshot = (
  snapshot?: OfflineVaultSnapshot,
  options?: { source?: 'remote' | 'cache' | 'empty' },
) => Promise<VaultIntegrityVerificationResult | null>;

export interface LoadVaultHealthAnalysisItemsInput {
  userId: string;
  vaultMigrationStatus: VaultMigrationRolloutStatus | null;
  opLogLocalVaultState: LocalVaultState | null;
  decryptItem: DecryptVaultItem;
  verifyIntegrity: VerifyVaultSnapshot;
}

function isPasswordItemType(value: unknown): value is 'password' {
  return value === undefined || value === null || value === 'password';
}

function parseVerifiedRecordPlaintext(record: LocalVerifiedRecord): Record<string, unknown> | null {
  if (
    (record.recordState !== 'verified' && record.recordState !== 'restoredFromSnapshot')
    || record.record.recordType !== 'item'
    || !record.plaintext
  ) {
    return null;
  }

  try {
    const parsed = JSON.parse(new TextDecoder().decode(record.plaintext)) as unknown;
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed)
      ? parsed as Record<string, unknown>
      : null;
  } catch {
    return null;
  }
}

export function getVaultHealthAnalysisItemsFromOpLog(
  state: LocalVaultState | null,
): VaultHealthAnalysisItem[] {
  if (!state) {
    return [];
  }

  return Array.from(state.recordsById.values()).flatMap((record) => {
    const plaintext = parseVerifiedRecordPlaintext(record);
    if (!plaintext || !isPasswordItemType(plaintext.itemType) || typeof plaintext.password !== 'string' || !plaintext.password) {
      return [];
    }

    return [{
      id: record.record.recordId,
      title: typeof plaintext.title === 'string' ? plaintext.title : 'Unnamed',
      password: plaintext.password,
      itemType: 'password' as const,
      username: typeof plaintext.username === 'string' ? plaintext.username : undefined,
      websiteUrl: typeof plaintext.websiteUrl === 'string' ? plaintext.websiteUrl : undefined,
      updatedAt: record.record.updatedAt,
    }];
  });
}

export async function getVaultHealthAnalysisItemsFromLegacySnapshot(
  snapshot: OfflineVaultSnapshot,
  integrityResult: VaultIntegrityVerificationResult | null,
  decryptItem: DecryptVaultItem,
): Promise<VaultHealthAnalysisItem[]> {
  const items: VaultHealthAnalysisItem[] = [];

  for (const item of snapshot.items) {
    try {
      assertItemDecryptable({
        mode: integrityResult?.mode ?? 'integrity_unknown',
        quarantinedItems: integrityResult?.quarantinedItems ?? [],
        itemId: item.id,
      });

      const decrypted = await decryptItem(item.encrypted_data, item.id);
      const resolvedItemType = decrypted.itemType || item.item_type || 'password';
      if (resolvedItemType !== 'password' || !decrypted.password) {
        continue;
      }

      items.push({
        id: item.id,
        title: decrypted.title || 'Unnamed',
        password: decrypted.password,
        itemType: 'password',
        username: decrypted.username,
        websiteUrl: decrypted.websiteUrl || item.website_url || undefined,
        updatedAt: item.updated_at,
      });
    } catch {
      continue;
    }
  }

  return items;
}

export async function loadVaultHealthAnalysisItems(
  input: LoadVaultHealthAnalysisItemsInput,
): Promise<VaultHealthAnalysisItem[]> {
  if (input.vaultMigrationStatus === 'verified') {
    return getVaultHealthAnalysisItemsFromOpLog(input.opLogLocalVaultState);
  }

  const { snapshot, source } = await loadVaultSnapshot(input.userId);
  const integrityResult = await input.verifyIntegrity(snapshot, { source });
  return getVaultHealthAnalysisItemsFromLegacySnapshot(snapshot, integrityResult, input.decryptItem);
}
