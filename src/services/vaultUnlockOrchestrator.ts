import { isAppOnline, getOfflineVaultTwoFactorRequirement, saveOfflineVaultTwoFactorRequirement } from './offlineVaultService';
import { getTwoFactorRequirement } from './twoFactorService';

export interface VaultTwoFactorGateOptions {
  verifyTwoFactor?: () => Promise<boolean>;
}

export interface VaultTwoFactorGateInput {
  userId: string;
  options?: VaultTwoFactorGateOptions;
}

export async function enforceVaultTwoFactorBeforeKeyRelease(
  input: VaultTwoFactorGateInput,
): Promise<{ error: Error | null }> {
  const { userId, options } = input;

  if (!isAppOnline()) {
    const cachedRequired = await getOfflineVaultTwoFactorRequirement(userId);
    if (cachedRequired === false) {
      return { error: null };
    }

    return {
      error: new Error(
        cachedRequired === true
          ? 'Vault 2FA is required and must be verified online before offline unlock.'
          : 'Vault 2FA status is not cached. Unlock online once before using this vault offline.',
      ),
    };
  }

  const requirement = await getTwoFactorRequirement({
    userId,
    context: 'vault_unlock',
  });

  if (requirement.status === 'unavailable') {
    return { error: new Error('Vault 2FA status unavailable. Vault remains locked.') };
  }

  if (!requirement.required) {
    await saveOfflineVaultTwoFactorRequirement(userId, false);
    return { error: null };
  }

  if (!options?.verifyTwoFactor) {
    return { error: new Error('Vault 2FA verification required before unlock.') };
  }

  const verified = await options.verifyTwoFactor();
  if (!verified) {
    return { error: new Error('Vault 2FA verification failed.') };
  }

  await saveOfflineVaultTwoFactorRequirement(userId, true);
  return { error: null };
}
