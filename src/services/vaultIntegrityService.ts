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
export const INTEGRITY_BASELINE_SCHEMA_VERSION = 2;
export const INTEGRITY_CANONICALIZATION_VERSION = 1;

export interface VaultIntegritySnapshot {
  items: Array<{
    id: string;
    encrypted_data: string;
    updated_at?: string | null;
    item_type?: 'password' | 'note' | 'totp' | 'card' | null;
  }>;
  categories: Array<{
    id: string;
    name: string;
    icon: string | null;
    color: string | null;
  }>;
}

export type VaultIntegrityNonTamperMode =
  | 'integrity_unknown'
  | 'revalidation_failed'
  | 'migration_required'
  | 'scope_incomplete';
export type VaultIntegrityMode = 'healthy' | 'quarantine' | 'blocked' | VaultIntegrityNonTamperMode;
export type VaultIntegrityBlockedReason =
  | 'baseline_unreadable'
  | 'legacy_baseline_mismatch'
  | 'baseline_scope_mismatch'
  | 'category_structure_mismatch'
  | 'snapshot_malformed'
  | 'vault_key_unavailable'
  | 'device_key_required'
  | 'unknown_integrity_failure';
export type VaultIntegrityNonTamperReason =
  | 'snapshot_completeness_unknown'
  | 'snapshot_scope_incomplete'
  | 'snapshot_source_not_authoritative'
  | 'revalidation_failed'
  | 'baseline_schema_incompatible'
  | 'baseline_canonicalization_incompatible';
export type VaultIntegrityItemIssueReason =
  | 'ciphertext_changed'
  | 'aead_auth_failed'
  | 'item_envelope_malformed'
  | 'item_aad_mismatch'
  | 'item_manifest_hash_mismatch'
  | 'item_revision_replay'
  | 'item_key_id_mismatch'
  | 'duplicate_active_item_record'
  | 'missing_on_server'
  | 'unknown_on_server'
  | 'decrypt_failed';

export interface QuarantinedVaultItem {
  id: string;
  reason: VaultIntegrityItemIssueReason;
  updatedAt: string | null;
  itemType?: 'password' | 'note' | 'totp' | 'card' | null;
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
  nonTamperReason?: VaultIntegrityNonTamperReason;
  quarantinedItems: QuarantinedVaultItem[];
  driftedCategoryIds?: string[];
}

export interface VaultIntegrityNonTamperState {
  mode: VaultIntegrityNonTamperMode;
  reason: VaultIntegrityNonTamperReason;
}

export interface VaultIntegritySnapshotCompletenessContext {
  isComplete: boolean;
  canVerifyDrift: boolean;
  nonTamperState?: VaultIntegrityNonTamperState;
}

export interface VaultIntegrityBaselineInspection {
  digest: string;
  itemCount: number;
  categoryCount: number;
  baselineKind: 'missing' | 'v1' | 'v2';
  storedRoot?: string;
  snapshotValidationError?: VaultIntegrityBlockedReason;
  nonTamperState?: VaultIntegrityNonTamperState;
  legacyBaselineMismatch: boolean;
  itemDrifts: QuarantinedVaultItem[];
  categoryDriftIds: string[];
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
  userId?: string;
  vaultId?: string | null;
  source?: 'core' | 'legacy-migration' | 'trusted-mutation';
  schemaVersion?: number;
  canonicalizationVersion?: number;
  scopeKind?: 'private_default_vault';
  includesSharedCollections?: boolean;
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
  options: {
    vaultId?: string | null;
    completeness?: VaultIntegritySnapshotCompletenessContext;
  } = {},
): Promise<VaultIntegrityVerificationResult> {
  const inspection = await inspectVaultSnapshotIntegrity(userId, snapshot, vaultKey, options);
  const result = toVaultIntegrityVerificationResult(inspection);

  if (
    inspection.baselineKind === 'missing'
    && !inspection.snapshotValidationError
    && !inspection.nonTamperState
  ) {
    await persistIntegrityBaseline(userId, snapshot, vaultKey, inspection.digest, {
      vaultId: options.vaultId,
    });
  } else if (
    inspection.baselineKind === 'v1'
    && !inspection.snapshotValidationError
    && !inspection.nonTamperState
    && !inspection.legacyBaselineMismatch
  ) {
    await persistIntegrityBaseline(userId, snapshot, vaultKey, inspection.digest, {
      vaultId: options.vaultId,
    });
  }

  return result;
}

export async function inspectVaultSnapshotIntegrity(
  userId: string,
  snapshot: VaultIntegritySnapshot,
  vaultKey: CryptoKey,
  options: {
    vaultId?: string | null;
    completeness?: VaultIntegritySnapshotCompletenessContext;
  } = {},
): Promise<VaultIntegrityBaselineInspection> {
  const digest = await computeVaultSnapshotDigest(snapshot);
  const snapshotValidationError = validateSnapshotStructure(snapshot);
  if (snapshotValidationError) {
    return {
      digest,
      itemCount: snapshot.items.length,
      categoryCount: snapshot.categories.length,
      baselineKind: 'missing',
      snapshotValidationError,
      nonTamperState: undefined,
      legacyBaselineMismatch: false,
      itemDrifts: [],
      categoryDriftIds: [],
    };
  }

  const storedBaseline = await loadStoredIntegrityBaseline(userId, vaultKey);
  if (!storedBaseline) {
    return {
      digest,
      itemCount: snapshot.items.length,
      categoryCount: snapshot.categories.length,
      baselineKind: 'missing',
      nonTamperState: options.completeness?.nonTamperState,
      legacyBaselineMismatch: false,
      itemDrifts: [],
      categoryDriftIds: [],
    };
  }

  if (storedBaseline.version === 1) {
    return {
      digest,
      itemCount: snapshot.items.length,
      categoryCount: snapshot.categories.length,
      baselineKind: 'v1',
      storedRoot: storedBaseline.digest,
      nonTamperState: options.completeness?.nonTamperState,
      legacyBaselineMismatch: storedBaseline.digest !== digest,
      itemDrifts: [],
      categoryDriftIds: [],
    };
  }

  const baselineCompatibilityIssue = inspectStoredBaselineCompatibility(
    storedBaseline,
    userId,
    options.vaultId ?? null,
  );
  if (baselineCompatibilityIssue?.mode === 'blocked') {
    return {
      digest,
      itemCount: snapshot.items.length,
      categoryCount: snapshot.categories.length,
      baselineKind: 'v2',
      storedRoot: storedBaseline.snapshotDigest,
      snapshotValidationError: baselineCompatibilityIssue.blockedReason,
      nonTamperState: undefined,
      legacyBaselineMismatch: false,
      itemDrifts: [],
      categoryDriftIds: [],
    };
  }
  if (baselineCompatibilityIssue?.mode === 'migration_required') {
    return {
      digest,
      itemCount: snapshot.items.length,
      categoryCount: snapshot.categories.length,
      baselineKind: 'v2',
      storedRoot: storedBaseline.snapshotDigest,
      nonTamperState: {
        mode: 'migration_required',
        reason: baselineCompatibilityIssue.reason,
      },
      legacyBaselineMismatch: false,
      itemDrifts: [],
      categoryDriftIds: [],
    };
  }

  if (options.completeness?.nonTamperState) {
    return {
      digest,
      itemCount: snapshot.items.length,
      categoryCount: snapshot.categories.length,
      baselineKind: 'v2',
      storedRoot: storedBaseline.snapshotDigest,
      nonTamperState: options.completeness.nonTamperState,
      legacyBaselineMismatch: false,
      itemDrifts: [],
      categoryDriftIds: [],
    };
  }

  const itemDigests = buildItemDigestMap(snapshot);
  const categoryDigests = buildCategoryDigestMap(snapshot);
  const rawItemDrifts = detectItemDigestDrift(snapshot, storedBaseline.itemDigests, itemDigests);
  const itemDrifts = filterItemDriftsByBaselineScopeProof(rawItemDrifts, storedBaseline);
  const suppressedScopeDrift = itemDrifts.length !== rawItemDrifts.length;
  const categoryDriftIds = detectCategoryDigestDriftIds(storedBaseline.categoryDigests, categoryDigests);

  if (suppressedScopeDrift && itemDrifts.length === 0 && categoryDriftIds.length === 0) {
    return {
      digest,
      itemCount: snapshot.items.length,
      categoryCount: snapshot.categories.length,
      baselineKind: 'v2',
      storedRoot: storedBaseline.snapshotDigest,
      nonTamperState: {
        mode: 'scope_incomplete',
        reason: 'snapshot_scope_incomplete',
      },
      legacyBaselineMismatch: false,
      itemDrifts: [],
      categoryDriftIds: [],
    };
  }

  return {
    digest,
    itemCount: snapshot.items.length,
    categoryCount: snapshot.categories.length,
    baselineKind: 'v2',
    storedRoot: storedBaseline.snapshotDigest,
    legacyBaselineMismatch: false,
    itemDrifts,
    categoryDriftIds,
  };
}

export function toVaultIntegrityVerificationResult(
  inspection: VaultIntegrityBaselineInspection,
): VaultIntegrityVerificationResult {
  if (inspection.snapshotValidationError) {
    return {
      valid: false,
      isFirstCheck: false,
      computedRoot: inspection.digest,
      itemCount: inspection.itemCount,
      categoryCount: inspection.categoryCount,
      mode: 'blocked',
      blockedReason: inspection.snapshotValidationError,
      quarantinedItems: [],
    };
  }

  if (inspection.nonTamperState) {
    return {
      valid: false,
      isFirstCheck: inspection.baselineKind === 'missing',
      computedRoot: inspection.digest,
      storedRoot: inspection.storedRoot,
      itemCount: inspection.itemCount,
      categoryCount: inspection.categoryCount,
      mode: inspection.nonTamperState.mode,
      nonTamperReason: inspection.nonTamperState.reason,
      quarantinedItems: [],
    };
  }

  if (inspection.baselineKind === 'missing') {
    return {
      valid: true,
      isFirstCheck: true,
      computedRoot: inspection.digest,
      itemCount: inspection.itemCount,
      categoryCount: inspection.categoryCount,
      mode: 'healthy',
      quarantinedItems: [],
    };
  }

  if (inspection.legacyBaselineMismatch) {
    return {
      valid: false,
      isFirstCheck: false,
      computedRoot: inspection.digest,
      storedRoot: inspection.storedRoot,
      itemCount: inspection.itemCount,
      categoryCount: inspection.categoryCount,
      mode: 'blocked',
      blockedReason: 'legacy_baseline_mismatch',
      quarantinedItems: [],
    };
  }

  if (inspection.categoryDriftIds.length > 0) {
    return {
      valid: false,
      isFirstCheck: false,
      computedRoot: inspection.digest,
      storedRoot: inspection.storedRoot,
      itemCount: inspection.itemCount,
      categoryCount: inspection.categoryCount,
      mode: 'blocked',
      blockedReason: 'category_structure_mismatch',
      quarantinedItems: [],
      driftedCategoryIds: inspection.categoryDriftIds,
    };
  }

  if (inspection.itemDrifts.length > 0) {
    const activeItemQuarantine = inspection.itemDrifts.filter(isActiveItemQuarantineReason);
    if (activeItemQuarantine.length === 0) {
      return {
        valid: true,
        isFirstCheck: false,
        computedRoot: inspection.digest,
        storedRoot: inspection.storedRoot,
        itemCount: inspection.itemCount,
        categoryCount: inspection.categoryCount,
        mode: 'healthy',
        quarantinedItems: [],
      };
    }

    return {
      valid: true,
      isFirstCheck: false,
      computedRoot: inspection.digest,
      storedRoot: inspection.storedRoot,
      itemCount: inspection.itemCount,
      categoryCount: inspection.categoryCount,
      mode: 'quarantine',
      quarantinedItems: activeItemQuarantine,
    };
  }

  return {
    valid: true,
    isFirstCheck: false,
    computedRoot: inspection.digest,
    storedRoot: inspection.storedRoot,
    itemCount: inspection.itemCount,
    categoryCount: inspection.categoryCount,
    mode: 'healthy',
    quarantinedItems: [],
  };
}

export async function persistIntegrityBaseline(
  userId: string,
  snapshot: VaultIntegritySnapshot,
  vaultKey: CryptoKey,
  precomputedDigest?: string,
  options: { vaultId?: string | null } = {},
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
    userId,
    vaultId: options.vaultId ?? null,
    source: 'core',
    schemaVersion: INTEGRITY_BASELINE_SCHEMA_VERSION,
    canonicalizationVersion: INTEGRITY_CANONICALIZATION_VERSION,
    scopeKind: 'private_default_vault',
    includesSharedCollections: false,
  };

  const encryptedPayload = await encrypt(JSON.stringify(payload), vaultKey);
  await saveIntegrityBaselineEnvelope(userId, encryptedPayload);
  return digest;
}

export async function persistTrustedMutationIntegrityBaseline(
  userId: string,
  snapshot: VaultIntegritySnapshot,
  vaultKey: CryptoKey,
  trustedMutation: {
    itemIds?: Iterable<string>;
    categoryIds?: Iterable<string>;
  },
  options: { vaultId?: string | null } = {},
): Promise<string | null> {
  const storedBaseline = await loadStoredIntegrityBaseline(userId, vaultKey);
  if (!storedBaseline || storedBaseline.version !== 2) {
    return null;
  }

  const trustedItemIds = new Set(trustedMutation.itemIds ?? []);
  const trustedCategoryIds = new Set(trustedMutation.categoryIds ?? []);
  if (trustedItemIds.size === 0 && trustedCategoryIds.size === 0) {
    return null;
  }

  const currentItemDigests = buildItemDigestMap(snapshot);
  const currentCategoryDigests = buildCategoryDigestMap(snapshot);
  const nextItemDigests = { ...storedBaseline.itemDigests };
  const nextCategoryDigests = { ...storedBaseline.categoryDigests };

  for (const itemId of trustedItemIds) {
    if (currentItemDigests[itemId]) {
      nextItemDigests[itemId] = currentItemDigests[itemId];
    } else {
      delete nextItemDigests[itemId];
    }
  }

  for (const categoryId of trustedCategoryIds) {
    if (currentCategoryDigests[categoryId]) {
      nextCategoryDigests[categoryId] = currentCategoryDigests[categoryId];
    } else {
      delete nextCategoryDigests[categoryId];
    }
  }

  const payloadWithoutRoot = {
    version: 2 as const,
    itemDigests: nextItemDigests,
    categoryDigests: nextCategoryDigests,
    itemCount: Object.keys(nextItemDigests).length,
    categoryCount: Object.keys(nextCategoryDigests).length,
    recordedAt: new Date().toISOString(),
    schemaVersion: INTEGRITY_BASELINE_SCHEMA_VERSION,
    canonicalizationVersion: INTEGRITY_CANONICALIZATION_VERSION,
  };
  const digestBuffer = await crypto.subtle.digest(
    'SHA-256',
    new TextEncoder().encode(JSON.stringify(payloadWithoutRoot)),
  );
  const snapshotDigest = bytesToBase64(new Uint8Array(digestBuffer));
  const payload: StoredIntegrityBaselineV2 = {
    ...payloadWithoutRoot,
    snapshotDigest,
    userId,
    vaultId: options.vaultId ?? storedBaseline.vaultId ?? null,
    source: 'trusted-mutation',
    schemaVersion: INTEGRITY_BASELINE_SCHEMA_VERSION,
    canonicalizationVersion: INTEGRITY_CANONICALIZATION_VERSION,
    scopeKind: storedBaseline.scopeKind ?? 'private_default_vault',
    includesSharedCollections: storedBaseline.includesSharedCollections ?? false,
  };

  const encryptedPayload = await encrypt(JSON.stringify(payload), vaultKey);
  await saveIntegrityBaselineEnvelope(userId, encryptedPayload);
  return snapshotDigest;
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
        id: canonicalText(item.id),
        encrypted_data: canonicalText(item.encrypted_data),
      })),
    categories: [...snapshot.categories]
      .sort((left, right) => left.id.localeCompare(right.id))
      .map(canonicalCategoryForDigest),
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

export function isNonTamperIntegrityMode(
  mode: VaultIntegrityMode,
): mode is VaultIntegrityNonTamperMode {
  return mode === 'integrity_unknown'
    || mode === 'revalidation_failed'
    || mode === 'migration_required'
    || mode === 'scope_incomplete';
}

type BaselineCompatibilityIssue =
  | { mode: 'blocked'; blockedReason: VaultIntegrityBlockedReason }
  | { mode: 'migration_required'; reason: VaultIntegrityNonTamperReason };

function inspectStoredBaselineCompatibility(
  baseline: StoredIntegrityBaselineV2,
  userId: string,
  vaultId: string | null,
): BaselineCompatibilityIssue | null {
  if (baseline.userId && baseline.userId !== userId) {
    return { mode: 'blocked', blockedReason: 'baseline_scope_mismatch' };
  }

  if (baseline.vaultId && vaultId && baseline.vaultId !== vaultId) {
    return { mode: 'blocked', blockedReason: 'baseline_scope_mismatch' };
  }

  if (
    typeof baseline.schemaVersion === 'number'
    && baseline.schemaVersion !== INTEGRITY_BASELINE_SCHEMA_VERSION
  ) {
    return { mode: 'migration_required', reason: 'baseline_schema_incompatible' };
  }

  if (
    typeof baseline.canonicalizationVersion === 'number'
    && baseline.canonicalizationVersion !== INTEGRITY_CANONICALIZATION_VERSION
  ) {
    return { mode: 'migration_required', reason: 'baseline_canonicalization_incompatible' };
  }

  return null;
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
    const itemId = canonicalText(item.id);
    digests[itemId] = JSON.stringify({
      id: itemId,
      encrypted_data: canonicalText(item.encrypted_data),
    });
  }

  return digests;
}

function buildCategoryDigestMap(snapshot: VaultIntegritySnapshot): Record<string, string> {
  const digests: Record<string, string> = {};
  for (const category of snapshot.categories) {
    const canonicalCategory = canonicalCategoryForDigest(category);
    digests[canonicalCategory.id] = JSON.stringify(canonicalCategory);
  }

  return digests;
}

function canonicalCategoryForDigest(category: VaultIntegritySnapshot['categories'][number]) {
  return {
    id: canonicalText(category.id),
    name: canonicalText(category.name),
    icon: canonicalNullableText(category.icon),
    color: canonicalNullableText(category.color),
  };
}

function canonicalText(value: string): string {
  return value.normalize('NFC');
}

function canonicalNullableText(value: string | null | undefined): string | null {
  if (typeof value !== 'string') {
    return null;
  }

  return value.normalize('NFC');
}

function detectItemDigestDrift(
  snapshot: VaultIntegritySnapshot,
  storedItemDigests: Record<string, string>,
  currentItemDigests: Record<string, string>,
): QuarantinedVaultItem[] {
  const quarantinedItems = new Map<string, QuarantinedVaultItem>();

  for (const item of snapshot.items) {
    const storedDigest = storedItemDigests[item.id];
    if (!storedDigest) {
      quarantinedItems.set(item.id, {
        id: item.id,
        reason: 'unknown_on_server',
        updatedAt: item.updated_at ?? null,
        itemType: item.item_type ?? null,
      });
      continue;
    }

    if (storedDigest !== currentItemDigests[item.id]) {
      quarantinedItems.set(item.id, {
        id: item.id,
        reason: 'ciphertext_changed',
        updatedAt: item.updated_at ?? null,
        itemType: item.item_type ?? null,
      });
    }
  }

  for (const [itemId] of Object.entries(storedItemDigests)) {
    if (currentItemDigests[itemId]) {
      continue;
    }

    quarantinedItems.set(itemId, {
      id: itemId,
      reason: 'missing_on_server',
      updatedAt: null,
    });
  }

  return [...quarantinedItems.values()].sort((left, right) => {
    const leftDate = left.updatedAt ?? '';
    const rightDate = right.updatedAt ?? '';
    return rightDate.localeCompare(leftDate) || left.id.localeCompare(right.id);
  });
}

function isActiveItemQuarantineReason(item: QuarantinedVaultItem): boolean {
  return item.reason === 'ciphertext_changed';
}

function filterItemDriftsByBaselineScopeProof(
  itemDrifts: QuarantinedVaultItem[],
  baseline: StoredIntegrityBaselineV2,
): QuarantinedVaultItem[] {
  if (
    baseline.scopeKind === 'private_default_vault'
    && baseline.includesSharedCollections === false
  ) {
    return itemDrifts;
  }

  return itemDrifts.filter((item) => item.reason === 'ciphertext_changed');
}

function detectCategoryDigestDriftIds(
  storedCategoryDigests: Record<string, string>,
  currentCategoryDigests: Record<string, string>,
): string[] {
  const driftedIds = new Set<string>([
    ...Object.keys(storedCategoryDigests),
    ...Object.keys(currentCategoryDigests),
  ]);

  return [...driftedIds]
    .filter((categoryId) => storedCategoryDigests[categoryId] !== currentCategoryDigests[categoryId])
    .sort((left, right) => left.localeCompare(right));
}

function validateSnapshotStructure(
  snapshot: VaultIntegritySnapshot,
): VaultIntegrityBlockedReason | null {
  const itemIds = new Set<string>();
  for (const item of snapshot.items) {
    if (!item?.id || typeof item.id !== 'string' || typeof item.encrypted_data !== 'string') {
      return 'snapshot_malformed';
    }

    const itemId = canonicalText(item.id);
    if (itemIds.has(itemId)) {
      return 'snapshot_malformed';
    }

    itemIds.add(itemId);
  }

  const categoryIds = new Set<string>();
  for (const category of snapshot.categories) {
    if (!category?.id || typeof category.id !== 'string' || typeof category.name !== 'string') {
      return 'snapshot_malformed';
    }

    if (
      (category.icon !== null && typeof category.icon !== 'string')
      || (category.color !== null && typeof category.color !== 'string')
    ) {
      return 'snapshot_malformed';
    }

    const categoryId = canonicalText(category.id);
    if (categoryIds.has(categoryId)) {
      return 'snapshot_malformed';
    }

    categoryIds.add(categoryId);
  }

  return null;
}
