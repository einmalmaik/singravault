import type { VaultItemData } from '@/services/cryptoService';
import type { QuarantinedVaultItem } from '@/services/vaultIntegrityService';
import { VaultIntegrityDecryptBlockedError } from '@/services/vaultQuarantineOrchestrator';

type ExportableVaultItemRow = {
  id: string;
  title: string;
  website_url: string | null;
  item_type: 'password' | 'note' | 'totp' | 'card';
  is_favorite: boolean | null;
  category_id: string | null;
  encrypted_data: string;
  updated_at?: string | null;
};

export interface VaultExportPayload {
  version: string;
  mode: 'normal' | 'safe';
  exportedAt: string;
  itemCount: number;
  quarantinedItems: QuarantinedVaultItem[];
  items: Array<{
    id: string;
    title: string;
    website_url: string | null;
    item_type: 'password' | 'note' | 'totp' | 'card';
    is_favorite: boolean;
    category_id: string | null;
    updated_at: string | null;
    data: VaultItemData;
  }>;
}

export async function buildVaultExportPayload(
  items: ExportableVaultItemRow[],
  decryptItem: (encryptedData: string, entryId?: string) => Promise<VaultItemData>,
  options?: {
    mode?: 'normal' | 'safe';
    quarantinedItems?: QuarantinedVaultItem[];
  },
): Promise<VaultExportPayload> {
  const decryptedItems = await Promise.all(
    items.map(async (item) => {
      try {
        const decrypted = await decryptItem(item.encrypted_data, item.id);
        return {
          id: item.id,
          title: decrypted.title || item.title,
          website_url: decrypted.websiteUrl || item.website_url,
          item_type: decrypted.itemType || item.item_type || 'password',
          is_favorite: typeof decrypted.isFavorite === 'boolean'
            ? decrypted.isFavorite
            : !!item.is_favorite,
          category_id: decrypted.categoryId ?? item.category_id ?? null,
          updated_at: item.updated_at ?? null,
          data: decrypted,
        };
      } catch (error) {
        if (error instanceof VaultIntegrityDecryptBlockedError) {
          throw error;
        }
        return null;
      }
    }),
  );

  const validItems = decryptedItems.filter((item): item is NonNullable<typeof item> => item !== null);

  return {
    version: '1.1',
    mode: options?.mode ?? 'normal',
    exportedAt: new Date().toISOString(),
    itemCount: validItems.length,
    quarantinedItems: options?.quarantinedItems ?? [],
    items: validItems,
  };
}
