import type { VaultItemData } from '@/services/cryptoService';
import { canRestoreFromTrustedSnapshotV2 } from './snapshotTrust';
import { buildTrustedItemUpsertMutationV2 } from './mutationPipeline';
import type {
  ServerVaultCategoryV2,
  ServerVaultItemV2,
  TrustedLocalSnapshotMetadata,
  VaultManifestEnvelopeV2,
  VaultManifestV2,
} from './types';

export async function restoreVaultItemFromTrustedSnapshotV2(input: {
  userId: string;
  vaultId: string;
  keyId: string;
  keysetVersion: number;
  vaultKey: CryptoKey;
  currentManifest: VaultManifestV2;
  categories: ServerVaultCategoryV2[];
  serverItems: ServerVaultItemV2[];
  snapshot: TrustedLocalSnapshotMetadata;
  itemId: string;
  reason: string;
  itemType: string;
  trustedPlaintext: VaultItemData;
}): Promise<{
  item: ServerVaultItemV2;
  manifest: VaultManifestV2;
  manifestHash: string;
  manifestEnvelope: VaultManifestEnvelopeV2;
}> {
  if (!canRestoreFromTrustedSnapshotV2(input)) {
    throw new Error('Restore V2 requires a matching trusted snapshot and a restorable integrity reason.');
  }

  return buildTrustedItemUpsertMutationV2({
    userId: input.userId,
    vaultId: input.vaultId,
    keyId: input.keyId,
    keysetVersion: input.keysetVersion,
    vaultKey: input.vaultKey,
    currentManifest: input.currentManifest,
    categories: input.categories,
    existingItems: input.serverItems,
    itemId: input.itemId,
    itemType: input.itemType,
    plaintext: input.trustedPlaintext,
  });
}
