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

export function isNonTamperIntegrityMode(
  mode: VaultIntegrityMode,
): mode is VaultIntegrityNonTamperMode {
  return mode === 'integrity_unknown'
    || mode === 'revalidation_failed'
    || mode === 'migration_required'
    || mode === 'scope_incomplete';
}
