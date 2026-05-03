import { decrypt, encrypt, type VaultItemData } from '@/services/cryptoService';
import {
  base64ToBytes,
  bytesToBase64,
  sha256Base64,
  stableStringify,
} from './canonicalJson';
import { buildVaultItemAadV2, encodeAadV2, verifyVaultItemAadV2 } from './aad';
import {
  VAULT_ITEM_ENVELOPE_V2_PREFIX,
  type ActiveItemQuarantineReasonV2,
  type IntegrityDiagnostic,
  type VaultItemAadV2,
  type VaultItemEnvelopeV2,
} from './types';

const AES_GCM_NONCE_LENGTH = 12;

export interface VaultItemEnvelopeMetadataV2 {
  vaultId: string;
  userId: string;
  itemId: string;
  itemType: string;
  keyId: string;
  itemRevision: number;
  schemaVersion?: number;
}

export async function encryptItemEnvelopeV2(
  data: VaultItemData,
  key: CryptoKey,
  metadata: VaultItemEnvelopeMetadataV2,
): Promise<string> {
  const aad = buildVaultItemAadV2({
    ...metadata,
    schemaVersion: metadata.schemaVersion ?? 1,
  });
  const encryptedBase64 = await encrypt(stableStringify(data), key, encodeAadV2(aad));
  const envelope = buildEnvelopeFromEncryptedBase64(encryptedBase64, aad);
  return serializeVaultItemEnvelopeV2(envelope);
}

export async function verifyAndDecryptItemEnvelopeV2(
  encryptedData: string,
  key: CryptoKey,
  expectedMetadata: VaultItemEnvelopeMetadataV2,
): Promise<
  | { ok: true; data: VaultItemData; envelope: VaultItemEnvelopeV2; envelopeHash: string }
  | {
      ok: false;
      reason: ActiveItemQuarantineReasonV2;
      envelope?: VaultItemEnvelopeV2;
      envelopeHash?: string;
      diagnostics: IntegrityDiagnostic[];
    }
> {
  const parsed = parseVaultItemEnvelopeV2(encryptedData);
  if (!parsed.ok) {
    return {
      ok: false,
      reason: 'item_envelope_malformed',
      diagnostics: [diagnostic('item_envelope_malformed', expectedMetadata.itemId, 'Item envelope is malformed.')],
    };
  }

  const expectedAad = buildVaultItemAadV2({
    ...expectedMetadata,
    schemaVersion: expectedMetadata.schemaVersion ?? 1,
  });
  const envelopeHash = await hashVaultItemEnvelopeV2(encryptedData);
  const metadataReason = classifyItemEnvelopeMetadataMismatch(parsed.envelope, expectedAad);
  if (metadataReason) {
    return {
      ok: false,
      reason: metadataReason,
      envelope: parsed.envelope,
      envelopeHash,
      diagnostics: [diagnostic(metadataReason, expectedMetadata.itemId, 'Item envelope metadata does not match manifest context.')],
    };
  }

  try {
    const plaintext = await decrypt(
      combineEncryptedBase64(parsed.envelope),
      key,
      encodeAadV2(parsed.envelope.aad),
    );
    return {
      ok: true,
      data: JSON.parse(plaintext) as VaultItemData,
      envelope: parsed.envelope,
      envelopeHash,
    };
  } catch {
    return {
      ok: false,
      reason: 'aead_auth_failed',
      envelope: parsed.envelope,
      envelopeHash,
      diagnostics: [diagnostic('aead_auth_failed', expectedMetadata.itemId, 'Item AEAD authentication failed.')],
    };
  }
}

export function parseVaultItemEnvelopeV2(
  encryptedData: string,
): { ok: true; envelope: VaultItemEnvelopeV2 } | { ok: false; error: string } {
  if (!encryptedData.startsWith(VAULT_ITEM_ENVELOPE_V2_PREFIX)) {
    return { ok: false, error: 'missing_v2_prefix' };
  }

  try {
    const encoded = encryptedData.slice(VAULT_ITEM_ENVELOPE_V2_PREFIX.length);
    const json = new TextDecoder().decode(base64ToBytes(encoded));
    const envelope = JSON.parse(json) as VaultItemEnvelopeV2;
    if (!isValidVaultItemEnvelopeV2(envelope)) {
      return { ok: false, error: 'invalid_shape' };
    }
    return { ok: true, envelope };
  } catch {
    return { ok: false, error: 'parse_failed' };
  }
}

export function serializeVaultItemEnvelopeV2(envelope: VaultItemEnvelopeV2): string {
  const bytes = new TextEncoder().encode(stableStringify(envelope));
  return `${VAULT_ITEM_ENVELOPE_V2_PREFIX}${bytesToBase64(bytes)}`;
}

export async function hashVaultItemEnvelopeV2(encryptedData: string): Promise<string> {
  return sha256Base64(encryptedData);
}

export function isVaultItemEnvelopeV2(encryptedData: string): boolean {
  return encryptedData.startsWith(VAULT_ITEM_ENVELOPE_V2_PREFIX);
}

function buildEnvelopeFromEncryptedBase64(
  encryptedBase64: string,
  aad: VaultItemAadV2,
): VaultItemEnvelopeV2 {
  const combined = base64ToBytes(encryptedBase64);
  const nonce = combined.slice(0, AES_GCM_NONCE_LENGTH);
  const ciphertext = combined.slice(AES_GCM_NONCE_LENGTH);
  try {
    return {
      envelopeVersion: 2,
      vaultId: aad.vaultId,
      userId: aad.userId,
      itemId: aad.itemId,
      itemType: aad.itemType,
      keyId: aad.keyId,
      itemRevision: aad.itemRevision,
      schemaVersion: aad.schemaVersion,
      nonce: bytesToBase64(nonce),
      ciphertext: bytesToBase64(ciphertext),
      aad,
    };
  } finally {
    combined.fill(0);
    nonce.fill(0);
    ciphertext.fill(0);
  }
}

function combineEncryptedBase64(envelope: VaultItemEnvelopeV2): string {
  const nonce = base64ToBytes(envelope.nonce);
  const ciphertext = base64ToBytes(envelope.ciphertext);
  const combined = new Uint8Array(nonce.length + ciphertext.length);
  combined.set(nonce, 0);
  combined.set(ciphertext, nonce.length);
  try {
    return bytesToBase64(combined);
  } finally {
    nonce.fill(0);
    ciphertext.fill(0);
    combined.fill(0);
  }
}

function isValidVaultItemEnvelopeV2(envelope: VaultItemEnvelopeV2): boolean {
  return envelope?.envelopeVersion === 2
    && typeof envelope.vaultId === 'string'
    && typeof envelope.userId === 'string'
    && typeof envelope.itemId === 'string'
    && typeof envelope.itemType === 'string'
    && typeof envelope.keyId === 'string'
    && Number.isSafeInteger(envelope.itemRevision)
    && Number.isSafeInteger(envelope.schemaVersion)
    && typeof envelope.nonce === 'string'
    && typeof envelope.ciphertext === 'string'
    && verifyVaultItemAadV2(envelope.aad, buildVaultItemAadV2({
      vaultId: envelope.vaultId,
      userId: envelope.userId,
      itemId: envelope.itemId,
      itemType: envelope.itemType,
      keyId: envelope.keyId,
      itemRevision: envelope.itemRevision,
      schemaVersion: envelope.schemaVersion,
    }));
}

function classifyItemEnvelopeMetadataMismatch(
  envelope: VaultItemEnvelopeV2,
  expectedAad: VaultItemAadV2,
): ActiveItemQuarantineReasonV2 | null {
  if (envelope.keyId !== expectedAad.keyId || envelope.aad.keyId !== expectedAad.keyId) {
    return 'item_key_id_mismatch';
  }

  if (envelope.itemRevision < expectedAad.itemRevision || envelope.aad.itemRevision < expectedAad.itemRevision) {
    return 'item_revision_replay';
  }

  if (!verifyVaultItemAadV2(envelope.aad, expectedAad)) {
    return 'item_aad_mismatch';
  }

  return null;
}

function diagnostic(
  code: ActiveItemQuarantineReasonV2,
  itemId: string,
  message: string,
): IntegrityDiagnostic {
  return { code, itemId, message };
}
