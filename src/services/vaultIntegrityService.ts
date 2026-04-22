import { decrypt, deriveRawKey, encrypt, importMasterKey } from './cryptoService';
import {
  loadLocalSecretString,
  removeLocalSecret,
} from '@/platform/localSecretStore';
import {
  loadIntegrityBaselineEnvelope,
  removeIntegrityBaselineEnvelope,
  saveIntegrityBaselineEnvelope,
} from './integrityBaselineStore';

const INTEGRITY_SECRET_PREFIX = 'vault-integrity:';

export interface VaultIntegritySnapshot {
  items: Array<{
    id: string;
    encrypted_data: string;
    updated_at?: string | null;
  }>;
  categories: Array<{
    id: string;
    name: string;
    icon: string | null;
    color: string | null;
  }>;
}

export type VaultIntegrityMode = 'healthy' | 'quarantine' | 'blocked';
export type VaultIntegrityBlockedReason =
  | 'baseline_unreadable'
  | 'legacy_baseline_mismatch'
  | 'category_structure_mismatch'
  | 'snapshot_malformed';
export type VaultIntegrityItemIssueReason =
  | 'ciphertext_changed'
  | 'missing_on_server'
  | 'unknown_on_server';

export interface QuarantinedVaultItem {
  id: string;
  reason: VaultIntegrityItemIssueReason;
  updatedAt: string | null;
}

export interface VaultIntegrityVerificationResult {
  valid: boolean;
  isFirstCheck: boolean;
  computedRoot: string;
  storedRoot?: string;
  itemCount: number;
  categoryCount: number;
  mode: VaultIntegrityMode;
  blockedReason?: VaultIntegrityBlockedReason;
  quarantinedItems: QuarantinedVaultItem[];
}

interface StoredIntegrityBaselineV1 {
  version: 1;
  digest: string;
  itemCount: number;
  categoryCount: number;
  recordedAt: string;
}

interface StoredIntegrityBaselineV2 {
  version: 2;
  snapshotDigest: string;
  itemDigests: Record<string, string>;
  categoryDigests: Record<string, string>;
  itemCount: number;
  categoryCount: number;
  recordedAt: string;
}

type StoredIntegrityBaseline = StoredIntegrityBaselineV1 | StoredIntegrityBaselineV2;

export class VaultIntegrityBaselineError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'VaultIntegrityBaselineError';
  }
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
      mode: 'healthy',
      quarantinedItems: [],
    };
  }

  if (storedBaseline.version === 1) {
    if (storedBaseline.digest === digest) {
      await persistIntegrityBaseline(userId, snapshot, vaultKey, digest);
      return {
        valid: true,
        isFirstCheck: false,
        computedRoot: digest,
        storedRoot: storedBaseline.digest,
        itemCount: snapshot.items.length,
        categoryCount: snapshot.categories.length,
        mode: 'healthy',
        quarantinedItems: [],
      };
    }

    return {
      valid: false,
      isFirstCheck: false,
      computedRoot: digest,
      storedRoot: storedBaseline.digest,
      itemCount: snapshot.items.length,
      categoryCount: snapshot.categories.length,
      mode: 'blocked',
      blockedReason: 'legacy_baseline_mismatch',
      quarantinedItems: [],
    };
  }

  const assessment = assessSnapshotAgainstBaseline(snapshot, storedBaseline, digest);
  return {
    valid: assessment.mode !== 'blocked',
    isFirstCheck: false,
    computedRoot: digest,
    storedRoot: storedBaseline.snapshotDigest,
    itemCount: snapshot.items.length,
    categoryCount: snapshot.categories.length,
    mode: assessment.mode,
    blockedReason: assessment.blockedReason,
    quarantinedItems: assessment.quarantinedItems,
  };
}

export async function persistIntegrityBaseline(
  userId: string,
  snapshot: VaultIntegritySnapshot,
  vaultKey: CryptoKey,
  precomputedDigest?: string,
): Promise<string> {
  const digest = precomputedDigest ?? await computeVaultSnapshotDigest(snapshot);
  const payload: StoredIntegrityBaselineV2 = {
    version: 2,
    snapshotDigest: digest,
    itemDigests: buildItemDigestMap(snapshot),
    categoryDigests: buildCategoryDigestMap(snapshot),
    itemCount: snapshot.items.length,
    categoryCount: snapshot.categories.length,
    recordedAt: new Date().toISOString(),
  };

  const encryptedPayload = await encrypt(JSON.stringify(payload), vaultKey);
  await saveIntegrityBaselineEnvelope(userId, encryptedPayload);
  return digest;
}

export async function clearIntegrityBaseline(userId: string): Promise<void> {
  await Promise.all([
    removeIntegrityBaselineEnvelope(userId),
    removeLocalSecret(getIntegrityStorageKey(userId)),
  ]);
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
  const encryptedPayload = await loadCurrentIntegrityBaselineEnvelope(userId);
  if (!encryptedPayload) {
    return null;
  }

  try {
    const rawPayload = await decrypt(encryptedPayload, vaultKey);
    const parsed = JSON.parse(rawPayload) as StoredIntegrityBaseline;
    if (parsed?.version === 1 && parsed.digest) {
      return parsed;
    }

    if (
      parsed?.version === 2 &&
      parsed.snapshotDigest &&
      parsed.itemDigests &&
      parsed.categoryDigests
    ) {
      return parsed;
    }

    if (!parsed) {
      throw new VaultIntegrityBaselineError('Stored integrity baseline is malformed.');
    }
  } catch (error) {
    if (error instanceof VaultIntegrityBaselineError) {
      throw error;
    }

    throw new VaultIntegrityBaselineError('Stored integrity baseline could not be decrypted.');
  }

  throw new VaultIntegrityBaselineError('Stored integrity baseline is malformed.');
}

function getIntegrityStorageKey(userId: string): string {
  return `${INTEGRITY_SECRET_PREFIX}${userId}`;
}

async function loadCurrentIntegrityBaselineEnvelope(userId: string): Promise<string | null> {
  const currentPayload = await loadIntegrityBaselineEnvelope(userId);
  if (currentPayload) {
    return currentPayload;
  }

  const legacyPayload = await loadLocalSecretString(getIntegrityStorageKey(userId));
  if (!legacyPayload) {
    return null;
  }

  await saveIntegrityBaselineEnvelope(userId, legacyPayload);
  await removeLocalSecret(getIntegrityStorageKey(userId));
  return legacyPayload;
}

function bytesToBase64(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i += 1) {
    binary += String.fromCharCode(bytes[i]);
  }

  return btoa(binary);
}

function buildItemDigestMap(snapshot: VaultIntegritySnapshot): Record<string, string> {
  const digests: Record<string, string> = {};
  for (const item of snapshot.items) {
    digests[item.id] = `${item.id}:${item.encrypted_data}`;
  }

  return digests;
}

function buildCategoryDigestMap(snapshot: VaultIntegritySnapshot): Record<string, string> {
  const digests: Record<string, string> = {};
  for (const category of snapshot.categories) {
    digests[category.id] = JSON.stringify({
      id: category.id,
      name: category.name,
      icon: category.icon,
      color: category.color,
    });
  }

  return digests;
}

function assessSnapshotAgainstBaseline(
  snapshot: VaultIntegritySnapshot,
  baseline: StoredIntegrityBaselineV2,
  digest: string,
): {
  mode: VaultIntegrityMode;
  blockedReason?: VaultIntegrityBlockedReason;
  quarantinedItems: QuarantinedVaultItem[];
} {
  const currentItemDigests = buildItemDigestMap(snapshot);
  const currentCategoryDigests = buildCategoryDigestMap(snapshot);

  const categoryIds = new Set([
    ...Object.keys(baseline.categoryDigests),
    ...Object.keys(currentCategoryDigests),
  ]);

  for (const categoryId of categoryIds) {
    if (baseline.categoryDigests[categoryId] !== currentCategoryDigests[categoryId]) {
      return {
        mode: 'blocked',
        blockedReason: 'category_structure_mismatch',
        quarantinedItems: [],
      };
    }
  }

  const currentItemsById = new Map(snapshot.items.map((item) => [item.id, item]));
  const quarantinedItems: QuarantinedVaultItem[] = [];

  for (const [itemId, storedDigest] of Object.entries(baseline.itemDigests)) {
    const currentDigest = currentItemDigests[itemId];
    if (!currentDigest) {
      quarantinedItems.push({
        id: itemId,
        reason: 'missing_on_server',
        updatedAt: null,
      });
      continue;
    }

    if (storedDigest !== currentDigest) {
      quarantinedItems.push({
        id: itemId,
        reason: 'ciphertext_changed',
        updatedAt: currentItemsById.get(itemId)?.updated_at ?? null,
      });
    }
  }

  for (const item of snapshot.items) {
    if (baseline.itemDigests[item.id]) {
      continue;
    }

    quarantinedItems.push({
      id: item.id,
      reason: 'unknown_on_server',
      updatedAt: item.updated_at ?? null,
    });
  }

  if (quarantinedItems.length > 0) {
    return {
      mode: 'quarantine',
      quarantinedItems: sortQuarantinedItems(quarantinedItems),
    };
  }

  return {
    mode: digest === baseline.snapshotDigest ? 'healthy' : 'blocked',
    blockedReason: digest === baseline.snapshotDigest ? undefined : 'snapshot_malformed',
    quarantinedItems: [],
  };
}

function sortQuarantinedItems(items: QuarantinedVaultItem[]): QuarantinedVaultItem[] {
  return [...items].sort((left, right) => {
    const leftDate = left.updatedAt ?? '';
    const rightDate = right.updatedAt ?? '';
    return rightDate.localeCompare(leftDate) || left.id.localeCompare(right.id);
  });
}
