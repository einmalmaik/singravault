import type { VaultItemData } from '@/services/cryptoService';
import { buildManifestEnvelopeV2FromVerifiedInputs } from './decisionEngine';
import { encryptItemEnvelopeV2 } from './itemEnvelopeCrypto';
import {
  type ServerVaultCategoryV2,
  type ServerVaultItemV2,
  type VaultManifestEnvelopeV2,
  type VaultManifestV2,
} from './types';
import { hashVaultManifestV2 } from './manifestCrypto';

export async function buildTrustedItemUpsertMutationV2(input: {
  userId: string;
  vaultId: string;
  keyId: string;
  keysetVersion: number;
  vaultKey: CryptoKey;
  currentManifest: VaultManifestV2;
  categories: ServerVaultCategoryV2[];
  existingItems: ServerVaultItemV2[];
  itemId: string;
  itemType: string;
  itemRevision?: number;
  plaintext: VaultItemData;
}): Promise<{
  item: ServerVaultItemV2;
  manifest: VaultManifestV2;
  manifestHash: string;
  manifestEnvelope: VaultManifestEnvelopeV2;
}> {
  const previousManifestHash = await hashVaultManifestV2(input.currentManifest);
  const previousManifestItem = input.currentManifest.items.find((item) => item.itemId === input.itemId);
  const itemRevision = input.itemRevision ?? ((previousManifestItem?.itemRevision ?? 0) + 1);
  const encryptedData = await encryptItemEnvelopeV2(input.plaintext, input.vaultKey, {
    vaultId: input.vaultId,
    userId: input.userId,
    itemId: input.itemId,
    itemType: input.itemType,
    keyId: input.keyId,
    itemRevision,
    schemaVersion: 1,
  });

  const item: ServerVaultItemV2 = {
    id: input.itemId,
    user_id: input.userId,
    vault_id: input.vaultId,
    encrypted_data: encryptedData,
    item_type: input.itemType,
  };
  const nextItems = [
    item,
    ...input.existingItems.filter((existingItem) => existingItem.id !== input.itemId),
  ];
  const bundle = await buildManifestEnvelopeV2FromVerifiedInputs({
    userId: input.userId,
    vaultId: input.vaultId,
    keyId: input.keyId,
    keysetVersion: input.keysetVersion,
    manifestRevision: input.currentManifest.manifestRevision + 1,
    previousManifestHash,
    categories: input.categories,
    items: nextItems,
    vaultKey: input.vaultKey,
  });

  return {
    item,
    manifest: bundle.manifest,
    manifestHash: bundle.manifestHash,
    manifestEnvelope: bundle.envelope,
  };
}
