import { supabase } from '@/integrations/supabase/client';
import { clearOfflineVaultData } from '@/services/offlineVaultService';
import { clearIntegrityBaseline } from '@/services/vaultIntegrityService';
import { deleteDeviceKey } from '@/services/deviceKeyService';

/**
 * Removes the current user's vault state so a compromised vault can be
 * re-initialized from a clean baseline. The auth account itself remains intact.
 */
export async function resetUserVaultState(userId: string): Promise<void> {
  const { error } = await supabase.rpc('reset_user_vault_state');
  if (error) {
    throw error;
  }

  await Promise.all([
    clearOfflineVaultData(userId),
    clearIntegrityBaseline(userId),
    deleteDeviceKey(userId),
  ]);
}
