import { decrypt, encrypt } from '@/services/cryptoService';
import {
  base64ToBytes,
  bytesToBase64,
  sha256Base64,
  stableStringify,
} from './canonicalJson';
import { buildVaultManifestAadV2, encodeAadV2, verifyVaultManifestAadV2 } from './aad';
import {
  VAULT_MANIFEST_ENVELOPE_V2_PREFIX,
  type IntegrityDiagnostic,
  type VaultManifestEnvelopeV2,
  type VaultManifestV2,
} from './types';

const AES_GCM_NONCE_LENGTH = 12;

export async function encryptVaultManifestV2(
  manifest: VaultManifestV2,
  key: CryptoKey,
  keyId: string,
): Promise<VaultManifestEnvelopeV2> {
  const aad = buildVaultManifestAadV2({
    vaultId: manifest.vaultId,
    userId: manifest.userId,
    keyId,
    manifestRevision: manifest.manifestRevision,
  });
  const encryptedBase64 = await encrypt(stableStringify(manifest), key, encodeAadV2(aad));
  const combined = base64ToBytes(encryptedBase64);
  const nonce = combined.slice(0, AES_GCM_NONCE_LENGTH);
  const ciphertext = combined.slice(AES_GCM_NONCE_LENGTH);
  try {
    return {
      envelopeVersion: 2,
      vaultId: manifest.vaultId,
      userId: manifest.userId,
      keyId,
      manifestRevision: manifest.manifestRevision,
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

export async function verifyVaultManifestV2(input: {
  envelope?: VaultManifestEnvelopeV2 | string;
  key?: CryptoKey;
  expectedUserId: string;
  expectedVaultId: string;
  expectedKeyId?: string;
}): Promise<
  | { ok: true; manifest: VaultManifestV2; manifestHash: string; diagnostics: IntegrityDiagnostic[] }
  | { ok: false; reason: 'manifest_invalid' | 'manifest_auth_failed'; diagnostics: IntegrityDiagnostic[] }
> {
  const envelopeResult = normalizeManifestEnvelope(input.envelope);
  if (!envelopeResult.ok) {
    return {
      ok: false,
      reason: 'manifest_invalid',
      diagnostics: [{ code: 'manifest_missing', message: 'Manifest V2 envelope is missing or malformed.' }],
    };
  }
  if (!input.key) {
    return {
      ok: false,
      reason: 'manifest_auth_failed',
      diagnostics: [{ code: 'manifest_auth_failed', message: 'Vault key is required to authenticate Manifest V2.' }],
    };
  }

  const envelope = envelopeResult.envelope;
  if (
    envelope.vaultId !== input.expectedVaultId
    || envelope.userId !== input.expectedUserId
    || (input.expectedKeyId && envelope.keyId !== input.expectedKeyId)
    || !isValidManifestEnvelopeShape(envelope)
  ) {
    return {
      ok: false,
      reason: 'manifest_invalid',
      diagnostics: [{ code: 'manifest_invalid', message: 'Manifest envelope metadata does not match the vault context.' }],
    };
  }

  try {
    const plaintext = await decrypt(
      combineManifestEnvelopeBase64(envelope),
      input.key,
      encodeAadV2(envelope.aad),
    );
    const manifest = JSON.parse(plaintext) as VaultManifestV2;
    if (
      !isValidManifest(manifest)
      || !isVaultManifestContextBoundToExpectedInput({
        envelope,
        manifest,
        expectedVaultId: input.expectedVaultId,
        expectedUserId: input.expectedUserId,
        expectedKeyId: input.expectedKeyId,
      })
    ) {
      return {
        ok: false,
        reason: 'manifest_invalid',
        diagnostics: [{ code: 'manifest_invalid', message: 'Manifest payload shape or AAD is invalid.' }],
      };
    }
    const manifestHash = await hashVaultManifestV2(manifest);
    return { ok: true, manifest, manifestHash, diagnostics: [] };
  } catch {
    return {
      ok: false,
      reason: 'manifest_auth_failed',
      diagnostics: [{ code: 'manifest_auth_failed', message: 'Manifest AEAD authentication failed.' }],
    };
  }
}

function isVaultManifestContextBoundToExpectedInput(input: {
  envelope: VaultManifestEnvelopeV2;
  manifest: VaultManifestV2;
  expectedVaultId: string;
  expectedUserId: string;
  expectedKeyId?: string;
}): boolean {
  const expectedKeyId = input.expectedKeyId ?? input.envelope.keyId;

  return input.manifest.vaultId === input.expectedVaultId
    && input.manifest.userId === input.expectedUserId
    && input.envelope.keyId === expectedKeyId
    && input.envelope.manifestRevision === input.manifest.manifestRevision
    && verifyVaultManifestAadV2(
      input.envelope.aad,
      {
        vaultId: input.expectedVaultId,
        userId: input.expectedUserId,
        manifestRevision: input.manifest.manifestRevision,
      },
      expectedKeyId,
    );
}

export function serializeVaultManifestEnvelopeV2(envelope: VaultManifestEnvelopeV2): string {
  const bytes = new TextEncoder().encode(stableStringify(envelope));
  return `${VAULT_MANIFEST_ENVELOPE_V2_PREFIX}${bytesToBase64(bytes)}`;
}

export function parseVaultManifestEnvelopeV2(
  value: string,
): { ok: true; envelope: VaultManifestEnvelopeV2 } | { ok: false; error: string } {
  if (!value.startsWith(VAULT_MANIFEST_ENVELOPE_V2_PREFIX)) {
    return { ok: false, error: 'missing_v2_prefix' };
  }

  try {
    const json = new TextDecoder().decode(base64ToBytes(value.slice(VAULT_MANIFEST_ENVELOPE_V2_PREFIX.length)));
    const envelope = JSON.parse(json) as VaultManifestEnvelopeV2;
    return isValidManifestEnvelopeShape(envelope)
      ? { ok: true, envelope }
      : { ok: false, error: 'invalid_shape' };
  } catch {
    return { ok: false, error: 'parse_failed' };
  }
}

export async function hashVaultManifestV2(manifest: VaultManifestV2): Promise<string> {
  return sha256Base64(stableStringify(manifest));
}

export function detectManifestRollback(
  manifest: VaultManifestV2,
  manifestHash: string,
  highWaterMark?: { manifestRevision: number; manifestHash: string },
): { ok: true; diagnostics: IntegrityDiagnostic[] } | { ok: false; diagnostics: IntegrityDiagnostic[] } {
  if (!highWaterMark) {
    return { ok: true, diagnostics: [] };
  }

  const rolledBack = manifest.manifestRevision < highWaterMark.manifestRevision
    || (
      manifest.manifestRevision === highWaterMark.manifestRevision
      && manifestHash !== highWaterMark.manifestHash
    );

  if (!rolledBack) {
    return { ok: true, diagnostics: [] };
  }

  return {
    ok: false,
    diagnostics: [{
      code: 'manifest_rollback_detected',
      message: 'Manifest revision/hash is older than the local high-water mark.',
      manifestRevision: manifest.manifestRevision,
      observedHashPrefix: manifestHash.slice(0, 12),
    }],
  };
}

function normalizeManifestEnvelope(envelope?: VaultManifestEnvelopeV2 | string) {
  if (!envelope) {
    return { ok: false as const, error: 'missing' };
  }

  if (typeof envelope === 'string') {
    return parseVaultManifestEnvelopeV2(envelope);
  }

  return isValidManifestEnvelopeShape(envelope)
    ? { ok: true as const, envelope }
    : { ok: false as const, error: 'invalid_shape' };
}

function combineManifestEnvelopeBase64(envelope: VaultManifestEnvelopeV2): string {
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

function isValidManifestEnvelopeShape(envelope: VaultManifestEnvelopeV2): boolean {
  return envelope?.envelopeVersion === 2
    && typeof envelope.vaultId === 'string'
    && typeof envelope.userId === 'string'
    && typeof envelope.keyId === 'string'
    && Number.isSafeInteger(envelope.manifestRevision)
    && typeof envelope.nonce === 'string'
    && typeof envelope.ciphertext === 'string'
    && envelope.aad?.purpose === 'vault_manifest'
    && envelope.aad.envelopeVersion === 2;
}

function isValidManifest(manifest: VaultManifestV2): boolean {
  return manifest?.manifestVersion === 2
    && typeof manifest.vaultId === 'string'
    && typeof manifest.userId === 'string'
    && Number.isSafeInteger(manifest.keysetVersion)
    && Number.isSafeInteger(manifest.manifestRevision)
    && typeof manifest.createdAt === 'string'
    && typeof manifest.categoriesHash === 'string'
    && Array.isArray(manifest.items)
    && (manifest.tombstones === undefined || (
      Array.isArray(manifest.tombstones)
      && manifest.tombstones.every((tombstone) => (
        typeof tombstone.itemId === 'string'
        && typeof tombstone.deletedAt === 'string'
        && Number.isSafeInteger(tombstone.deletedAtManifestRevision)
      ))
    ))
    && manifest.items.every((item) => (
      typeof item.itemId === 'string'
      && typeof item.itemType === 'string'
      && Number.isSafeInteger(item.itemRevision)
      && item.envelopeVersion === 2
      && typeof item.keyId === 'string'
      && typeof item.envelopeHash === 'string'
    ));
}
