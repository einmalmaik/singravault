import {
  createVerificationHash,
  migrateToUserKey,
  type VaultItemData,
} from '@/services/cryptoService';
import type { VaultProtectionMode } from '@/services/deviceKeyProtectionPolicy';
import { saveOfflineCredentials } from '@/services/offlineVaultService';
import {
  canRecoverLegacyKeyWithoutVerifier,
  migrateLegacyPrivateKeysToUserKey,
} from '@/services/legacyVaultRepairService';
import { supabase } from '@/integrations/supabase/client';

export type { VaultItemData };

export async function backfillVerificationHashForVault(input: {
  userId: string;
  salt: string;
  kdfVersion: number;
  encryptedUserKey: string | null;
  vaultProtectionMode: VaultProtectionMode;
  activeKey: CryptoKey;
}): Promise<string | null> {
  const newVerifier = await createVerificationHash(input.activeKey);
  const { error } = await supabase
    .from('profiles')
    .update({ master_password_verifier: newVerifier } as Record<string, unknown>)
    .eq('user_id', input.userId);

  if (error) {
    console.warn('Failed to backfill missing verifier:', error);
    return null;
  }

  await saveOfflineCredentials(
    input.userId,
    input.salt,
    newVerifier,
    input.kdfVersion,
    input.encryptedUserKey,
    input.vaultProtectionMode,
  );
  return newVerifier;
}

export async function recoverLegacyUserKeyWithoutVerifier(input: {
  userId: string;
  candidateKey: CryptoKey;
}): Promise<boolean> {
  return canRecoverLegacyKeyWithoutVerifier(input.userId, input.candidateKey);
}

export async function migrateLegacyVaultToUserKey(input: {
  userId: string;
  salt: string;
  kdfVersion: number;
  vaultProtectionMode: VaultProtectionMode;
  kdfOutputBytes: Uint8Array;
}): Promise<{
  userKey: CryptoKey;
  verifier: string;
  encryptedUserKey: string;
  persisted: boolean;
}> {
  const userKeyBundle = await migrateToUserKey(input.kdfOutputBytes);
  const newVerifier = await createVerificationHash(userKeyBundle.userKey);

  try {
    const { error } = await supabase
      .from('profiles')
      .update({
        encrypted_user_key: userKeyBundle.encryptedUserKey,
        master_password_verifier: newVerifier,
      } as Record<string, unknown>)
      .eq('user_id', input.userId);

    if (error) {
      console.warn('USK migration: DB write failed, will retry next unlock.', error);
      return {
        userKey: userKeyBundle.userKey,
        verifier: newVerifier,
        encryptedUserKey: userKeyBundle.encryptedUserKey,
        persisted: false,
      };
    }

    await saveOfflineCredentials(
      input.userId,
      input.salt,
      newVerifier,
      input.kdfVersion,
      userKeyBundle.encryptedUserKey,
      input.vaultProtectionMode,
    );
    console.info('USK migration complete: encrypted_user_key persisted.');

    return {
      userKey: userKeyBundle.userKey,
      verifier: newVerifier,
      encryptedUserKey: userKeyBundle.encryptedUserKey,
      persisted: true,
    };
  } catch (error) {
    console.warn('USK migration: unexpected failure, will retry next unlock.', error);
    return {
      userKey: userKeyBundle.userKey,
      verifier: newVerifier,
      encryptedUserKey: userKeyBundle.encryptedUserKey,
      persisted: false,
    };
  }
}

export async function migrateLegacyPrivateKeys(input: {
  userId: string;
  masterPassword: string;
  activeKey: CryptoKey;
}): Promise<void> {
  await migrateLegacyPrivateKeysToUserKey(input.userId, input.masterPassword, input.activeKey);
}
