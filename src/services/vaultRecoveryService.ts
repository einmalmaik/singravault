import { supabase } from '@/integrations/supabase/client';
import { clearOfflineVaultData } from '@/services/offlineVaultService';
import { clearIntegrityBaseline } from '@/services/vaultIntegrityService';
import { deleteDeviceKey } from '@/services/deviceKeyService';

const BEGIN_VAULT_RESET_RECOVERY_RPC = 'begin_vault_reset_recovery';
const RESET_USER_VAULT_STATE_RPC = 'reset_user_vault_state';

export type VaultRecoveryResetErrorCode =
  | 'REAUTH_REQUIRED'
  | 'RECOVERY_CHALLENGE_REQUIRED'
  | 'RESET_FAILED';

export class VaultRecoveryResetError extends Error {
  code: VaultRecoveryResetErrorCode;
  cause?: unknown;

  constructor(code: VaultRecoveryResetErrorCode, options?: { cause?: unknown }) {
    super(code);
    this.name = 'VaultRecoveryResetError';
    this.code = code;
    this.cause = options?.cause;
  }
}

/**
 * Removes the current user's vault state so a compromised vault can be
 * re-initialized from a clean baseline. The auth account itself remains intact.
 */
export async function resetUserVaultState(userId: string): Promise<void> {
  const recoveryChallengeId = await beginVaultResetRecovery();

  const { error } = await supabase.rpc(RESET_USER_VAULT_STATE_RPC, {
    p_recovery_challenge_id: recoveryChallengeId,
  });
  if (error) {
    throw mapVaultRecoveryResetError(error);
  }

  await Promise.all([
    clearOfflineVaultData(userId),
    clearIntegrityBaseline(userId),
    deleteDeviceKey(userId),
  ]);
}

async function beginVaultResetRecovery(): Promise<string> {
  const { data, error } = await supabase.rpc(BEGIN_VAULT_RESET_RECOVERY_RPC);
  if (error) {
    throw mapVaultRecoveryResetError(error);
  }

  const challengeId = extractRecoveryChallengeId(data);
  if (!challengeId) {
    throw new VaultRecoveryResetError('RECOVERY_CHALLENGE_REQUIRED');
  }

  return challengeId;
}

function extractRecoveryChallengeId(data: unknown): string | null {
  if (!data || typeof data !== 'object') {
    return null;
  }

  const challengeId = Reflect.get(data, 'challenge_id');
  if (typeof challengeId !== 'string' || !challengeId.trim()) {
    return null;
  }

  return challengeId;
}

function mapVaultRecoveryResetError(error: { message?: string } | null): VaultRecoveryResetError {
  const message = typeof error?.message === 'string' ? error.message : '';

  if (message.includes('REAUTH_REQUIRED')) {
    return new VaultRecoveryResetError('REAUTH_REQUIRED', { cause: error });
  }

  if (message.includes('RECOVERY_CHALLENGE_REQUIRED')) {
    return new VaultRecoveryResetError('RECOVERY_CHALLENGE_REQUIRED', { cause: error });
  }

  return new VaultRecoveryResetError('RESET_FAILED', { cause: error });
}
