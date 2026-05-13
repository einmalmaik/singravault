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
  | 'manifest_rollback_detected'
  | 'unknown_integrity_failure';
export type VaultIntegrityNonTamperReason =
  | 'snapshot_completeness_unknown'
  | 'snapshot_scope_incomplete'
  | 'snapshot_source_not_authoritative'
  | 'revalidation_failed'
  | 'manifest_persist_failed'
  | 'rollback_check_unavailable'
  | 'manifest_snapshot_conflict'
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

const LEGACY_INTEGRITY_ADAPTER_DISABLED =
  'Legacy vault integrity adapter is disabled. Use the verified operation-log integrity runtime.';

export function isNonTamperIntegrityMode(
  mode: VaultIntegrityMode,
): mode is VaultIntegrityNonTamperMode {
  return mode === 'integrity_unknown'
    || mode === 'revalidation_failed'
    || mode === 'migration_required'
    || mode === 'scope_incomplete';
}

/**
 * Compatibility export for older premium bundles.
 *
 * The V1 password+salt integrity-root path was intentionally removed from the
 * runtime trust model. Keeping this symbol preserves build compatibility while
 * failing closed if an outdated integration still tries to use it.
 */
export async function deriveIntegrityKey(
  masterPassword: string,
  saltBase64: string,
): Promise<CryptoKey> {
  void masterPassword;
  void saltBase64;
  throw new Error(LEGACY_INTEGRITY_ADAPTER_DISABLED);
}

/**
 * Compatibility export for older premium bundles. This must not recreate the
 * removed local baseline trust path.
 */
export async function verifyVaultIntegrity(
  items: VaultItemForIntegrity[],
  integrityKey: CryptoKey,
  userId: string,
): Promise<IntegrityVerificationResult> {
  void items;
  void integrityKey;
  void userId;
  throw new Error(LEGACY_INTEGRITY_ADAPTER_DISABLED);
}

/**
 * Compatibility export for older premium bundles. Restore flows must create
 * verified OpLog operations instead of mutating a local integrity root.
 */
export async function updateIntegrityRoot(
  items: VaultItemForIntegrity[],
  integrityKey: CryptoKey,
  userId: string,
): Promise<string> {
  void items;
  void integrityKey;
  void userId;
  throw new Error(LEGACY_INTEGRITY_ADAPTER_DISABLED);
}

export function clearIntegrityRoot(userId: string): void {
  void userId;
}
