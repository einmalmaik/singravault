import { supabase } from '@/integrations/supabase/client';
import { clearOfflineVaultData } from '@/services/offlineVaultService';
import { clearIntegrityBaseline } from '@/services/vaultIntegrityService';
import { deleteDeviceKey } from '@/services/deviceKeyService';

/**
 * Removes the current user's vault state so a compromised vault can be
 * re-initialized from a clean baseline. The auth account itself remains intact.
 */
export async function resetUserVaultState(userId: string): Promise<void> {
  const deleteByUserId = async (table: string): Promise<void> => {
    const { error } = await supabase.from(table as never).delete().eq('user_id', userId);
    if (error) {
      throw error;
    }
  };

  await deleteByUserId('file_attachments');
  await deleteByUserId('vault_items');
  await deleteByUserId('categories');
  await deleteByUserId('passkey_credentials');
  await deleteByUserId('user_keys');
  await deleteByUserId('vaults');

  const { error: profileError } = await supabase
    .from('profiles')
    .update({
      encryption_salt: null,
      master_password_verifier: null,
      kdf_version: 1,
      duress_kdf_version: null,
      duress_password_verifier: null,
      duress_salt: null,
      pq_encrypted_private_key: null,
      pq_enforced_at: null,
      pq_key_version: null,
      pq_public_key: null,
      encrypted_user_key: null,
    } as Record<string, unknown>)
    .eq('user_id', userId);

  if (profileError) {
    throw profileError;
  }

  await Promise.all([
    clearOfflineVaultData(userId),
    clearIntegrityBaseline(userId),
    deleteDeviceKey(userId),
  ]);
}
