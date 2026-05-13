// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE
/**
 * Resolve the Vault ID used by migrated OpLog flows.
 *
 * SECURITY: The offline cache is used only to discover the last verified
 * vaultId. It does not grant access. Callers must still enforce local
 * device trust and verify the cached OpLog before exposing or mutating data.
 */

import { supabase } from '@/integrations/supabase/client';
import { isAppOnline, resolveDefaultVaultId } from '@/services/offlineVaultService';
import { listVerifiedVaultOpLogOfflineCachesForUser } from './vaultOpLogOfflineStore';

export async function resolveVaultOpLogDefaultVaultId(userId: string): Promise<string | null> {
  if (!isAppOnline()) {
    const offlineCaches = await listVerifiedVaultOpLogOfflineCachesForUser({ userId }).catch(() => []);
    if (offlineCaches[0]?.vaultId) {
      return offlineCaches[0].vaultId;
    }

    return resolveDefaultVaultId(userId).catch(() => null);
  }

  const { data, error } = await supabase
    .from('vaults')
    .select('id')
    .eq('user_id', userId)
    .eq('is_default', true)
    .maybeSingle();

  if (error || typeof data?.id !== 'string') {
    return null;
  }

  return data.id;
}
