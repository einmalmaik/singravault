import { decrypt, deriveRawKey, encrypt, importMasterKey } from './cryptoService';
import {
  loadLocalSecretString,
  removeLocalSecret,
  saveLocalSecretString,
} from '@/platform/localSecretStore';

const INTEGRITY_SECRET_PREFIX = 'vault-integrity:';

export interface VaultIntegritySnapshot {
  items: Array<{
    id: string;
    encrypted_data: string;
  }>;
  categories: Array<{
    id: string;
    name: string;
    icon: string | null;
    color: string | null;
  }>;
}

export interface VaultIntegrityVerificationResult {
  valid: boolean;
  isFirstCheck: boolean;
  computedRoot: string;
  storedRoot?: string;
  itemCount: number;
  categoryCount: number;
}

interface StoredIntegrityBaseline {
  version: 1;
  digest: string;
  itemCount: number;
  categoryCount: number;
  recordedAt: string;
}

export interface VaultItemForIntegrity {
  id: string;
  encrypted_data: string;
}

export interface IntegrityVerificationResult {
  valid: boolean;
  isFirstCheck: boolean;
  computedRoot: string;
  storedRoot?: string;
  itemCount: number;
}

export async function verifyVaultSnapshotIntegrity(
  userId: string,
  snapshot: VaultIntegritySnapshot,
  vaultKey: CryptoKey,
): Promise<VaultIntegrityVerificationResult> {
  const digest = await computeVaultSnapshotDigest(snapshot);
  const storedBaseline = await loadStoredIntegrityBaseline(userId, vaultKey);

  if (!storedBaseline) {
    await persistIntegrityBaseline(userId, snapshot, vaultKey, digest);
    return {
      valid: true,
      isFirstCheck: true,
      computedRoot: digest,
      itemCount: snapshot.items.length,
      categoryCount: snapshot.categories.length,
    };
  }

  return {
    valid: storedBaseline.digest === digest,
    isFirstCheck: false,
    computedRoot: digest,
    storedRoot: storedBaseline.digest,
    itemCount: snapshot.items.length,
    categoryCount: snapshot.categories.length,
  };
}

export async function persistIntegrityBaseline(
  userId: string,
  snapshot: VaultIntegritySnapshot,
  vaultKey: CryptoKey,
  precomputedDigest?: string,
): Promise<string> {
  const digest = precomputedDigest ?? await computeVaultSnapshotDigest(snapshot);
  const payload: StoredIntegrityBaseline = {
    version: 1,
    digest,
    itemCount: snapshot.items.length,
    categoryCount: snapshot.categories.length,
    recordedAt: new Date().toISOString(),
  };

  const encryptedPayload = await encrypt(JSON.stringify(payload), vaultKey);
  await saveLocalSecretString(getIntegrityStorageKey(userId), encryptedPayload);
  return digest;
}

export async function clearIntegrityBaseline(userId: string): Promise<void> {
  await removeLocalSecret(getIntegrityStorageKey(userId));
}

/**
 * Compatibility adapter for the legacy premium integrity hook contract.
 * The core no longer derives integrity from password+salt in its runtime path,
 * but the optional premium package still imports these symbols at build time.
 */
export async function deriveIntegrityKey(
  masterPassword: string,
  saltBase64: string,
): Promise<CryptoKey> {
  const rawBytes = await deriveRawKey(masterPassword, `${saltBase64}:integrity`, 1);
  try {
    return await importMasterKey(rawBytes);
  } finally {
    rawBytes.fill(0);
  }
}

export async function verifyVaultIntegrity(
  items: VaultItemForIntegrity[],
  integrityKey: CryptoKey,
  userId: string,
): Promise<IntegrityVerificationResult> {
  const snapshot: VaultIntegritySnapshot = {
    items: items.map((item) => ({
      id: item.id,
      encrypted_data: item.encrypted_data,
    })),
    categories: [],
  };

  const result = await verifyVaultSnapshotIntegrity(userId, snapshot, integrityKey);
  return {
    valid: result.valid,
    isFirstCheck: result.isFirstCheck,
    computedRoot: result.computedRoot,
    storedRoot: result.storedRoot,
    itemCount: result.itemCount,
  };
}

export async function updateIntegrityRoot(
  items: VaultItemForIntegrity[],
  integrityKey: CryptoKey,
  userId: string,
): Promise<string> {
  const snapshot: VaultIntegritySnapshot = {
    items: items.map((item) => ({
      id: item.id,
      encrypted_data: item.encrypted_data,
    })),
    categories: [],
  };

  return persistIntegrityBaseline(userId, snapshot, integrityKey);
}

export function clearIntegrityRoot(userId: string): void {
  void clearIntegrityBaseline(userId);
}

export async function computeVaultSnapshotDigest(snapshot: VaultIntegritySnapshot): Promise<string> {
  const canonicalPayload = JSON.stringify({
    items: [...snapshot.items]
      .sort((left, right) => left.id.localeCompare(right.id))
      .map((item) => ({
        id: item.id,
        encrypted_data: item.encrypted_data,
      })),
    categories: [...snapshot.categories]
      .sort((left, right) => left.id.localeCompare(right.id))
      .map((category) => ({
        id: category.id,
        name: category.name,
        icon: category.icon,
        color: category.color,
      })),
  });

  const digestBuffer = await crypto.subtle.digest(
    'SHA-256',
    new TextEncoder().encode(canonicalPayload),
  );

  return bytesToBase64(new Uint8Array(digestBuffer));
}

async function loadStoredIntegrityBaseline(
  userId: string,
  vaultKey: CryptoKey,
): Promise<StoredIntegrityBaseline | null> {
  const encryptedPayload = await loadLocalSecretString(getIntegrityStorageKey(userId));
  if (!encryptedPayload) {
    return null;
  }

  try {
    const rawPayload = await decrypt(encryptedPayload, vaultKey);
    const parsed = JSON.parse(rawPayload) as StoredIntegrityBaseline;
    if (!parsed?.digest || parsed.version !== 1) {
      return null;
    }

    return parsed;
  } catch {
    return null;
  }
}

function getIntegrityStorageKey(userId: string): string {
  return `${INTEGRITY_SECRET_PREFIX}${userId}`;
}

function bytesToBase64(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i += 1) {
    binary += String.fromCharCode(bytes[i]);
  }

  return btoa(binary);
}
