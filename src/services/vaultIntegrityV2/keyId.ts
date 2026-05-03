export const VAULT_INTEGRITY_V2_USER_KEY_ID = 'user-key-v2';
export const VAULT_INTEGRITY_V2_LEGACY_KDF_KEY_ID = 'legacy-kdf-v1';

export function deriveVaultIntegrityKeyIdV2(input: {
  encryptedUserKey?: string | null;
}): string {
  return input.encryptedUserKey
    ? VAULT_INTEGRITY_V2_USER_KEY_ID
    : VAULT_INTEGRITY_V2_LEGACY_KDF_KEY_ID;
}
