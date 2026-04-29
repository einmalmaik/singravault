import {
  CURRENT_KDF_VERSION,
  createEncryptedUserKey,
  createVerificationHash,
  deriveRawKey,
  generateSalt,
} from '@/services/cryptoService';
import { VAULT_PROTECTION_MODE_MASTER_ONLY } from '@/services/deviceKeyProtectionPolicy';
import { getOfflineCredentials, saveOfflineCredentials } from '@/services/offlineVaultService';
import type { VaultRuntimeCredentials } from '@/services/offlineVaultRuntimeService';
import { ensureTauriDevVaultSnapshot, loadCachedVaultCredentials } from '@/services/offlineVaultRuntimeService';
import { supabase } from '@/integrations/supabase/client';
import { isTauriDevUserId } from '@/platform/tauriDevMode';

export interface VaultSetupResult {
  error: Error | null;
  credentials?: VaultRuntimeCredentials;
  existingProfileSalt?: string;
  activeUserKey?: CryptoKey;
}

export async function setupInitialVault(input: {
  userId: string;
  masterPassword: string;
}): Promise<VaultSetupResult> {
  const { userId, masterPassword } = input;

  try {
    const cached = await getOfflineCredentials(userId);
    if (cached) {
      const credentials = await loadCachedVaultCredentials(userId);
      return {
        error: new Error('Master password is already set for this account.'),
        credentials: credentials ?? undefined,
      };
    }

    if (!isTauriDevUserId(userId)) {
      const { data: existingProfile, error: existingProfileError } = await supabase
        .from('profiles')
        .select('encryption_salt')
        .eq('user_id', userId)
        .maybeSingle() as { data: Record<string, unknown> | null; error: unknown };

      if (existingProfileError) {
        return {
          error: new Error('Could not verify current master password state. Please try again online.'),
        };
      }

      if (existingProfile?.encryption_salt) {
        return {
          error: new Error('Master password is already set for this account.'),
          existingProfileSalt: existingProfile.encryption_salt as string,
        };
      }
    }

    return createInitialVault(input);
  } catch (error) {
    return {
      error: error instanceof Error ? error : new Error('Vault setup failed.'),
    };
  }
}

async function createInitialVault(input: {
  userId: string;
  masterPassword: string;
}): Promise<VaultSetupResult> {
  const { userId, masterPassword } = input;
  const newSalt = generateSalt();
  const kdfOutputBytes = await deriveRawKey(masterPassword, newSalt, CURRENT_KDF_VERSION);
  let userKeyBundle: Awaited<ReturnType<typeof createEncryptedUserKey>>;

  try {
    userKeyBundle = await createEncryptedUserKey(kdfOutputBytes);
  } finally {
    kdfOutputBytes.fill(0);
  }

  const verificationHash = await createVerificationHash(userKeyBundle.userKey);
  const credentials: VaultRuntimeCredentials = {
    salt: newSalt,
    verificationHash,
    kdfVersion: CURRENT_KDF_VERSION,
    encryptedUserKey: userKeyBundle.encryptedUserKey,
    vaultProtectionMode: VAULT_PROTECTION_MODE_MASTER_ONLY,
  };

  if (isTauriDevUserId(userId)) {
    await saveOfflineCredentials(
      userId,
      newSalt,
      verificationHash,
      CURRENT_KDF_VERSION,
      userKeyBundle.encryptedUserKey,
      VAULT_PROTECTION_MODE_MASTER_ONLY,
    );
    await ensureTauriDevVaultSnapshot(userId);
    return {
      error: null,
      credentials,
      activeUserKey: userKeyBundle.userKey,
    };
  }

  const { data: existingVault } = await supabase
    .from('vaults')
    .select('id')
    .eq('user_id', userId)
    .eq('is_default', true)
    .single();

  if (!existingVault) {
    await supabase.from('vaults').insert({
      user_id: userId,
      name: 'Encrypted Vault',
      is_default: true,
    });
  }

  const { error: updateError } = await supabase
    .from('profiles')
    .update({
      encryption_salt: newSalt,
      master_password_verifier: verificationHash,
      kdf_version: CURRENT_KDF_VERSION,
      encrypted_user_key: userKeyBundle.encryptedUserKey,
      vault_protection_mode: VAULT_PROTECTION_MODE_MASTER_ONLY,
      device_key_version: null,
      device_key_enabled_at: null,
      device_key_backup_acknowledged_at: null,
    } as Record<string, unknown>)
    .eq('user_id', userId);

  if (updateError) {
    return { error: new Error(updateError.message) };
  }

  await saveOfflineCredentials(
    userId,
    newSalt,
    verificationHash,
    CURRENT_KDF_VERSION,
    userKeyBundle.encryptedUserKey,
    VAULT_PROTECTION_MODE_MASTER_ONLY,
  );

  return {
    error: null,
    credentials,
    activeUserKey: userKeyBundle.userKey,
  };
}
