import { stableStringify } from './canonicalJson';
import type {
  VaultItemAadV2,
  VaultManifestAadV2,
  VaultManifestV2,
} from './types';

export function buildVaultItemAadV2(input: Omit<VaultItemAadV2, 'purpose' | 'envelopeVersion'>): VaultItemAadV2 {
  return {
    purpose: 'vault_item',
    envelopeVersion: 2,
    vaultId: input.vaultId,
    userId: input.userId,
    itemId: input.itemId,
    itemType: input.itemType,
    keyId: input.keyId,
    itemRevision: input.itemRevision,
    schemaVersion: input.schemaVersion,
  };
}

export function buildVaultManifestAadV2(input: {
  vaultId: string;
  userId: string;
  keyId: string;
  manifestRevision: number;
}): VaultManifestAadV2 {
  return {
    purpose: 'vault_manifest',
    envelopeVersion: 2,
    vaultId: input.vaultId,
    userId: input.userId,
    keyId: input.keyId,
    manifestVersion: 2,
    manifestRevision: input.manifestRevision,
  };
}

export function encodeAadV2(aad: VaultItemAadV2 | VaultManifestAadV2): string {
  return stableStringify(aad);
}

export function verifyVaultItemAadV2(actual: VaultItemAadV2, expected: VaultItemAadV2): boolean {
  return encodeAadV2(actual) === encodeAadV2(expected);
}

export function verifyVaultManifestAadV2(
  actual: VaultManifestAadV2,
  manifest: Pick<VaultManifestV2, 'vaultId' | 'userId' | 'manifestRevision'>,
  keyId: string,
): boolean {
  const expected = buildVaultManifestAadV2({
    vaultId: manifest.vaultId,
    userId: manifest.userId,
    keyId,
    manifestRevision: manifest.manifestRevision,
  });
  return encodeAadV2(actual) === encodeAadV2(expected);
}
