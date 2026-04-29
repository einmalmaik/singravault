import { supabase } from '@/integrations/supabase/client';
import {
  decrypt,
  decryptPrivateKeyLegacy,
  decryptVaultItem,
  reEncryptVault,
  wrapPrivateKeyWithUserKey,
} from './cryptoService';

export interface LegacyVaultRepairItem {
  id: string;
  encrypted_data: string;
}

export interface LegacyVaultRepairCategory {
  id: string;
  name: string;
  icon: string | null;
  color: string | null;
}

const ENCRYPTED_CATEGORY_PREFIX = 'enc:cat:v1:';

export async function migrateLegacyPrivateKeysToUserKey(
  userId: string,
  masterPassword: string,
  userKey: CryptoKey,
): Promise<void> {
  try {
    const { data: keyRow } = await supabase
      .from('user_keys')
      .select('encrypted_private_key')
      .eq('user_id', userId)
      .maybeSingle();

    const encRsa = keyRow?.encrypted_private_key as string | null | undefined;
    if (encRsa && !encRsa.startsWith('usk-v1:')) {
      const plainPrivateKey = await decryptPrivateKeyLegacy(encRsa, masterPassword, false);
      const newEncRsa = await wrapPrivateKeyWithUserKey(plainPrivateKey, userKey);
      const { error: rsaUpdateErr } = await supabase
        .from('user_keys')
        .update({ encrypted_private_key: newEncRsa, updated_at: new Date().toISOString() })
        .eq('user_id', userId);

      if (rsaUpdateErr) {
        console.warn('USK private key migration: RSA key update failed:', rsaUpdateErr);
      } else {
        console.info('USK private key migration: RSA key re-wrapped to usk-v1 format.');
      }
    }
  } catch (err) {
    console.warn('USK migration: RSA private key migration failed (non-fatal):', err);
  }

  try {
    const { data: profileRow } = await supabase
      .from('profiles')
      .select('pq_encrypted_private_key')
      .eq('user_id', userId)
      .maybeSingle();

    const encPq = profileRow?.pq_encrypted_private_key as string | null | undefined;
    if (encPq && !encPq.startsWith('usk-v1:')) {
      const plainPqKey = await decryptPrivateKeyLegacy(encPq, masterPassword, false);
      const newEncPq = await wrapPrivateKeyWithUserKey(plainPqKey, userKey);
      const { error: pqUpdateErr } = await supabase
        .from('profiles')
        .update({ pq_encrypted_private_key: newEncPq, updated_at: new Date().toISOString() } as Record<string, unknown>)
        .eq('user_id', userId);

      if (pqUpdateErr) {
        console.warn('USK migration: PQ key update failed:', pqUpdateErr);
      } else {
        console.info('USK private key migration: PQ key re-wrapped to usk-v1 format.');
      }
    }
  } catch (err) {
    console.warn('USK migration: PQ private key migration failed (non-fatal):', err);
  }
}

export async function canRecoverLegacyKeyWithoutVerifier(
  userId: string,
  candidateKey: CryptoKey,
): Promise<boolean> {
  const { data: probeItems } = await supabase
    .from('vault_items')
    .select('id, encrypted_data')
    .eq('user_id', userId)
    .order('created_at', { ascending: true })
    .limit(1);

  if (probeItems && probeItems.length > 0) {
    try {
      await decryptVaultItem(probeItems[0].encrypted_data, candidateKey, probeItems[0].id);
      return true;
    } catch {
      return false;
    }
  }

  const { data: probeCategories } = await supabase
    .from('categories')
    .select('name, icon, color')
    .eq('user_id', userId)
    .order('created_at', { ascending: true })
    .limit(1);

  const category = probeCategories?.[0];
  if (!category) {
    return true;
  }

  const encryptedFields = [category.name, category.icon, category.color]
    .filter((value): value is string => typeof value === 'string' && value.startsWith(ENCRYPTED_CATEGORY_PREFIX))
    .map((value) => value.slice(ENCRYPTED_CATEGORY_PREFIX.length));

  if (encryptedFields.length === 0) {
    return true;
  }

  for (const encryptedField of encryptedFields) {
    try {
      await decrypt(encryptedField, candidateKey);
      return true;
    } catch {
      continue;
    }
  }

  return false;
}

export async function findLegacyVaultRepairCandidates(
  userId: string,
  activeKey: CryptoKey,
): Promise<{
  needsFullRepair: boolean;
  brokenItems: LegacyVaultRepairItem[];
  brokenCategories: LegacyVaultRepairCategory[];
}> {
  const { data: probeItems } = await supabase
    .from('vault_items')
    .select('id, encrypted_data')
    .eq('user_id', userId)
    .order('created_at', { ascending: true })
    .limit(5);

  const { data: probeCategories } = await supabase
    .from('categories')
    .select('id, name, icon, color')
    .eq('user_id', userId)
    .order('created_at', { ascending: true })
    .limit(5);

  let needsFullRepair = false;
  if (probeItems) {
    for (const item of probeItems) {
      try {
        await decryptVaultItem(item.encrypted_data, activeKey, item.id);
      } catch {
        needsFullRepair = true;
        break;
      }
    }
  }

  if (!needsFullRepair && probeCategories) {
    for (const cat of probeCategories) {
      try {
        await decryptLegacyCategoryFields(cat, activeKey);
      } catch {
        needsFullRepair = true;
        break;
      }
    }
  }

  if (!needsFullRepair) {
    return { needsFullRepair: false, brokenItems: [], brokenCategories: [] };
  }

  const { data: allItems } = await supabase
    .from('vault_items')
    .select('id, encrypted_data')
    .eq('user_id', userId);

  const { data: allCategories } = await supabase
    .from('categories')
    .select('id, name, icon, color')
    .eq('user_id', userId);

  const brokenItems: LegacyVaultRepairItem[] = [];
  const brokenCategories: LegacyVaultRepairCategory[] = [];

  for (const item of allItems ?? []) {
    try {
      await decryptVaultItem(item.encrypted_data, activeKey, item.id);
    } catch {
      brokenItems.push(item);
    }
  }

  for (const cat of allCategories ?? []) {
    try {
      await decryptLegacyCategoryFields(cat, activeKey);
    } catch {
      brokenCategories.push(cat);
    }
  }

  return { needsFullRepair: true, brokenItems, brokenCategories };
}

export async function repairLegacyVaultCandidates(input: {
  userId: string;
  masterPassword: string;
  salt: string;
  activeKdfVersion: number;
  activeKey: CryptoKey;
  deriveOldKey: (masterPassword: string, salt: string, kdfVersion: number) => Promise<CryptoKey>;
}): Promise<boolean> {
  const { userId, masterPassword, salt, activeKdfVersion, activeKey, deriveOldKey } = input;
  const candidates = await findLegacyVaultRepairCandidates(userId, activeKey);
  if (!candidates.needsFullRepair || (candidates.brokenItems.length === 0 && candidates.brokenCategories.length === 0)) {
    return false;
  }

  for (let oldVersion = activeKdfVersion - 1; oldVersion >= 1; oldVersion--) {
    try {
      const oldKey = await deriveOldKey(masterPassword, salt, oldVersion);
      await assertOldKeyMatchesCandidate(candidates.brokenItems, candidates.brokenCategories, oldKey);
      const repairResult = await reEncryptVault(
        candidates.brokenItems,
        candidates.brokenCategories,
        oldKey,
        activeKey,
      );

      for (const itemUpdate of repairResult.itemUpdates) {
        await supabase
          .from('vault_items')
          .update({ encrypted_data: itemUpdate.encrypted_data })
          .eq('id', itemUpdate.id)
          .eq('user_id', userId);
      }

      for (const catUpdate of repairResult.categoryUpdates) {
        await supabase
          .from('categories')
          .update({ name: catUpdate.name, icon: catUpdate.icon, color: catUpdate.color })
          .eq('id', catUpdate.id)
          .eq('user_id', userId);
      }

      console.info(`KDF repair complete: re-encrypted ${repairResult.itemsReEncrypted} items and ${repairResult.categoriesReEncrypted} categories.`);
      return true;
    } catch {
      continue;
    }
  }

  return false;
}

async function decryptLegacyCategoryFields(
  category: Pick<LegacyVaultRepairCategory, 'name' | 'icon' | 'color'>,
  key: CryptoKey,
): Promise<void> {
  if (category.name.startsWith(ENCRYPTED_CATEGORY_PREFIX)) {
    await decrypt(category.name.slice(ENCRYPTED_CATEGORY_PREFIX.length), key);
  }
  if (category.icon?.startsWith(ENCRYPTED_CATEGORY_PREFIX)) {
    await decrypt(category.icon.slice(ENCRYPTED_CATEGORY_PREFIX.length), key);
  }
  if (category.color?.startsWith(ENCRYPTED_CATEGORY_PREFIX)) {
    await decrypt(category.color.slice(ENCRYPTED_CATEGORY_PREFIX.length), key);
  }
}

async function assertOldKeyMatchesCandidate(
  brokenItems: LegacyVaultRepairItem[],
  brokenCategories: LegacyVaultRepairCategory[],
  oldKey: CryptoKey,
): Promise<void> {
  if (brokenItems.length > 0) {
    await decryptVaultItem(brokenItems[0].encrypted_data, oldKey, brokenItems[0].id);
    return;
  }

  if (brokenCategories.length > 0) {
    await decryptLegacyCategoryFields(brokenCategories[0], oldKey);
    return;
  }

  throw new Error('No legacy repair candidate found.');
}
