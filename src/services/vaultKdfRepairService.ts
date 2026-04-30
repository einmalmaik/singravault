import {
  decrypt,
  decryptVaultItem,
  deriveKey,
  reEncryptVault,
} from '@/services/cryptoService';
import { supabase } from '@/integrations/supabase/client';
import { isTauriDevUserId } from '@/platform/tauriDevMode';

const ENCRYPTED_CATEGORY_PREFIX = 'enc:cat:v1:';

type VaultItemCipherRow = { id: string; encrypted_data: string };
type CategoryCipherRow = { id: string; name: string; icon: string | null; color: string | null };

export class KdfRepairPersistenceError extends Error {
  constructor(
    message: string,
    public readonly rowKind: 'vault_item' | 'category',
    public readonly rowId: string,
    public readonly cause?: unknown,
  ) {
    super(message);
    this.name = 'KdfRepairPersistenceError';
  }
}

export async function repairBrokenKdfUpgradeIfNeeded(input: {
  userId: string;
  masterPassword: string;
  salt: string;
  kdfVersion: number;
  activeKey: CryptoKey;
  contextLabel?: string;
}): Promise<void> {
  const { userId, masterPassword, salt, kdfVersion, activeKey, contextLabel } = input;
  if (isTauriDevUserId(userId) || kdfVersion < 2) {
    return;
  }

  try {
    const { data: probeItems, error: probeItemsError } = await supabase
      .from('vault_items')
      .select('id, encrypted_data')
      .eq('user_id', userId)
      .order('created_at', { ascending: true })
      .limit(5);
    if (probeItemsError) {
      throw probeItemsError;
    }

    const { data: probeCategories, error: probeCategoriesError } = await supabase
      .from('categories')
      .select('id, name, icon, color')
      .eq('user_id', userId)
      .order('created_at', { ascending: true })
      .limit(5);
    if (probeCategoriesError) {
      throw probeCategoriesError;
    }

    if (!(await needsFullRepair(probeItems || [], probeCategories || [], activeKey))) {
      return;
    }

    console.warn(`Detected broken KDF upgrade in sample${formatContext(contextLabel)}. Starting full vault scan and repair...`);
    const { data: allItems, error: allItemsError } = await supabase
      .from('vault_items')
      .select('id, encrypted_data')
      .eq('user_id', userId);
    if (allItemsError) {
      throw allItemsError;
    }

    const { data: allCategories, error: allCategoriesError } = await supabase
      .from('categories')
      .select('id, name, icon, color')
      .eq('user_id', userId);
    if (allCategoriesError) {
      throw allCategoriesError;
    }

    const brokenItems = await findBrokenItems(allItems || [], activeKey);
    const brokenCategories = await findBrokenCategories(allCategories || [], activeKey);
    if (brokenItems.length === 0 && brokenCategories.length === 0) {
      return;
    }

    console.warn(
      `Detected broken KDF upgrade${formatContext(contextLabel)}: ${brokenItems.length} items, `
      + `${brokenCategories.length} categories encrypted with older key. Starting repair...`,
    );
    for (let oldVersion = kdfVersion - 1; oldVersion >= 1; oldVersion -= 1) {
      try {
        const oldKey = await deriveKey(masterPassword, salt, oldVersion);
        await assertOldKeyMatchesBrokenRows(oldKey, brokenItems, brokenCategories);
        const repairResult = await reEncryptVault(brokenItems, brokenCategories, oldKey, activeKey);
        await persistRepairResult(userId, repairResult);
        console.info(
          `KDF repair${formatContext(contextLabel)} complete: re-encrypted `
          + `${repairResult.itemsReEncrypted} items, ${repairResult.categoriesReEncrypted} categories.`,
        );
        break;
      } catch (error) {
        if (error instanceof KdfRepairPersistenceError) {
          throw error;
        }
        continue;
      }
    }
  } catch (error) {
    console.error(`KDF repair check failed${formatContext(contextLabel)}:`, error);
    if (error instanceof KdfRepairPersistenceError) {
      throw error;
    }
  }
}

async function needsFullRepair(
  items: VaultItemCipherRow[],
  categories: CategoryCipherRow[],
  activeKey: CryptoKey,
): Promise<boolean> {
  return (await findBrokenItems(items, activeKey)).length > 0
    || (await findBrokenCategories(categories, activeKey)).length > 0;
}

async function findBrokenItems(
  items: VaultItemCipherRow[],
  activeKey: CryptoKey,
): Promise<VaultItemCipherRow[]> {
  const brokenItems: VaultItemCipherRow[] = [];
  for (const item of items) {
    try {
      await decryptVaultItem(item.encrypted_data, activeKey, item.id);
    } catch {
      brokenItems.push(item);
    }
  }
  return brokenItems;
}

async function findBrokenCategories(
  categories: CategoryCipherRow[],
  activeKey: CryptoKey,
): Promise<CategoryCipherRow[]> {
  const brokenCategories: CategoryCipherRow[] = [];
  for (const category of categories) {
    try {
      await decryptCategoryFields(category, activeKey);
    } catch {
      brokenCategories.push(category);
    }
  }
  return brokenCategories;
}

async function decryptCategoryFields(category: CategoryCipherRow, activeKey: CryptoKey): Promise<void> {
  const encryptedFields = [category.name, category.icon, category.color]
    .filter((value): value is string => typeof value === 'string' && value.startsWith(ENCRYPTED_CATEGORY_PREFIX))
    .map((value) => value.slice(ENCRYPTED_CATEGORY_PREFIX.length));

  for (const encryptedField of encryptedFields) {
    await decrypt(encryptedField, activeKey);
  }
}

async function assertOldKeyMatchesBrokenRows(
  oldKey: CryptoKey,
  brokenItems: VaultItemCipherRow[],
  brokenCategories: CategoryCipherRow[],
): Promise<void> {
  if (brokenItems.length > 0) {
    await decryptVaultItem(brokenItems[0].encrypted_data, oldKey, brokenItems[0].id);
    return;
  }

  if (brokenCategories.length === 0) {
    return;
  }

  await decryptCategoryFields(brokenCategories[0], oldKey);
}

async function persistRepairResult(
  userId: string,
  repairResult: Awaited<ReturnType<typeof reEncryptVault>>,
): Promise<void> {
  for (const itemUpdate of repairResult.itemUpdates) {
    const { error } = await supabase
      .from('vault_items')
      .update({ encrypted_data: itemUpdate.encrypted_data })
      .eq('id', itemUpdate.id)
      .eq('user_id', userId);
    if (error) {
      throw new KdfRepairPersistenceError(
        `KDF repair could not persist vault item ${itemUpdate.id}. Repair is incomplete and retryable.`,
        'vault_item',
        itemUpdate.id,
        error,
      );
    }
  }

  for (const categoryUpdate of repairResult.categoryUpdates) {
    const { error } = await supabase
      .from('categories')
      .update({ name: categoryUpdate.name, icon: categoryUpdate.icon, color: categoryUpdate.color })
      .eq('id', categoryUpdate.id)
      .eq('user_id', userId);
    if (error) {
      throw new KdfRepairPersistenceError(
        `KDF repair could not persist category ${categoryUpdate.id}. Repair is incomplete and retryable.`,
        'category',
        categoryUpdate.id,
        error,
      );
    }
  }
}

function formatContext(contextLabel: string | undefined): string {
  return contextLabel ? ` (${contextLabel})` : '';
}
