import {
  decryptVaultItem,
  decryptVaultItemForMigration,
  type VaultItemData,
} from '@/services/cryptoService';
import { resolveDefaultVaultId } from '@/services/offlineVaultService';
import { deriveVaultIntegrityKeyIdV2 } from './keyId';
import {
  encryptItemEnvelopeV2,
  isVaultItemEnvelopeV2,
  parseVaultItemEnvelopeV2,
  verifyAndDecryptItemEnvelopeV2,
} from './itemEnvelopeCrypto';

export async function encryptProductVaultItemV2(input: {
  userId: string;
  encryptedUserKey?: string | null;
  vaultKey: CryptoKey;
  data: VaultItemData;
  entryId: string;
}): Promise<string> {
  const vaultId = await resolveDefaultVaultId(input.userId);
  if (!vaultId) {
    throw new Error('Vault ID is required for Item-AAD V2 encryption.');
  }

  return encryptItemEnvelopeV2(input.data, input.vaultKey, {
    vaultId,
    userId: input.userId,
    itemId: input.entryId,
    itemType: input.data.itemType ?? 'password',
    keyId: deriveVaultIntegrityKeyIdV2({ encryptedUserKey: input.encryptedUserKey }),
    itemRevision: Date.now(),
    schemaVersion: 1,
  });
}

export async function decryptProductVaultItem(input: {
  encryptedData: string;
  vaultKey: CryptoKey;
  entryId: string;
}): Promise<VaultItemData> {
  if (!isVaultItemEnvelopeV2(input.encryptedData)) {
    return decryptVaultItem(input.encryptedData, input.vaultKey, input.entryId);
  }

  const parsed = parseVaultItemEnvelopeV2(input.encryptedData);
  if (!parsed.ok || parsed.envelope.itemId !== input.entryId) {
    throw new Error('Item envelope metadata does not match this vault item.');
  }

  const result = await verifyAndDecryptItemEnvelopeV2(input.encryptedData, input.vaultKey, {
    vaultId: parsed.envelope.vaultId,
    userId: parsed.envelope.userId,
    itemId: parsed.envelope.itemId,
    itemType: parsed.envelope.itemType,
    keyId: parsed.envelope.keyId,
    itemRevision: parsed.envelope.itemRevision,
    schemaVersion: parsed.envelope.schemaVersion,
  });
  if (!result.ok) {
    throw new Error('Item envelope authentication failed.');
  }

  return result.data;
}

export async function decryptProductVaultItemForMigration(input: {
  encryptedData: string;
  vaultKey: CryptoKey;
  entryId: string;
}): Promise<{ data: VaultItemData; legacyEnvelopeUsed: boolean; legacyNoAadFallbackUsed: boolean }> {
  if (!isVaultItemEnvelopeV2(input.encryptedData)) {
    return decryptVaultItemForMigration(input.encryptedData, input.vaultKey, input.entryId);
  }

  return {
    data: await decryptProductVaultItem(input),
    legacyEnvelopeUsed: false,
    legacyNoAadFallbackUsed: false,
  };
}
