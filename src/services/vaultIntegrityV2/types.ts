import type { VaultProtectionMode } from '@/services/deviceKeyProtectionPolicy';

export const VAULT_ITEM_ENVELOPE_V2_PREFIX = 'sv-vault-v2:';
export const VAULT_MANIFEST_ENVELOPE_V2_PREFIX = 'sv-vault-manifest-v2:';

export type VaultIntegrityEvaluationSourceV2 =
  | 'unlock'
  | 'manual_recheck'
  | 'sync'
  | 'focus_refetch'
  | 'safe_mode_recovery'
  | 'migration';

export type VaultItemSchemaVersionV2 = 1;

export type VaultItemAadV2 = {
  purpose: 'vault_item';
  envelopeVersion: 2;
  vaultId: string;
  userId: string;
  itemId: string;
  itemType: string;
  keyId: string;
  itemRevision: number;
  schemaVersion: number;
};

export type VaultItemEnvelopeV2 = {
  envelopeVersion: 2;
  vaultId: string;
  userId: string;
  itemId: string;
  itemType: string;
  keyId: string;
  itemRevision: number;
  schemaVersion: number;
  nonce: string;
  ciphertext: string;
  authTag?: string;
  aad: VaultItemAadV2;
};

export type VaultManifestAadV2 = {
  purpose: 'vault_manifest';
  envelopeVersion: 2;
  vaultId: string;
  userId: string;
  keyId: string;
  manifestVersion: 2;
  manifestRevision: number;
};

export type VaultManifestV2 = {
  manifestVersion: 2;
  vaultId: string;
  userId: string;
  keysetVersion: number;
  manifestRevision: number;
  previousManifestHash?: string;
  createdByDeviceId?: string;
  createdAt: string;
  categoriesHash: string;
  items: Array<{
    itemId: string;
    itemType: string;
    itemRevision: number;
    envelopeVersion: 2;
    keyId: string;
    envelopeHash: string;
    deleted?: boolean;
  }>;
  tombstones?: Array<{
    itemId: string;
    deletedAt: string;
    deletedAtManifestRevision: number;
  }>;
};

export type VaultManifestEnvelopeV2 = {
  envelopeVersion: 2;
  vaultId: string;
  userId: string;
  keyId: string;
  manifestRevision: number;
  nonce: string;
  ciphertext: string;
  authTag?: string;
  aad: VaultManifestAadV2;
};

export interface ServerVaultItemV2 {
  id: string;
  user_id: string;
  vault_id: string;
  encrypted_data: string;
  item_type?: string | null;
  updated_at?: string | null;
}

export interface ServerVaultCategoryV2 {
  id: string;
  user_id: string;
  name: string;
  icon?: string | null;
  color?: string | null;
  parent_id?: string | null;
  sort_order?: number | null;
  updated_at?: string | null;
}

export type ActiveItemQuarantineReasonV2 =
  | 'ciphertext_changed'
  | 'aead_auth_failed'
  | 'item_envelope_malformed'
  | 'item_aad_mismatch'
  | 'item_manifest_hash_mismatch'
  | 'item_revision_replay'
  | 'item_key_id_mismatch'
  | 'duplicate_active_item_record';

export type DiagnosticOnlyReasonV2 =
  | 'decrypt_failed'
  | 'wrong_key'
  | 'policy_stale'
  | 'missing_on_server'
  | 'unknown_on_server'
  | 'orphan_remote'
  | 'stale_baseline_only'
  | 'sync_pending'
  | 'legacy_item_requires_migration';

export type IntegrityDiagnosticCodeV2 =
  | ActiveItemQuarantineReasonV2
  | DiagnosticOnlyReasonV2
  | 'vault_key_not_verified'
  | 'device_key_state_stale'
  | 'remote_policy_unavailable'
  | 'offline_cache_stale'
  | 'server_snapshot_unavailable'
  | 'manifest_missing'
  | 'manifest_invalid'
  | 'manifest_auth_failed'
  | 'manifest_rollback_detected'
  | 'manifest_hash_mismatch'
  | 'category_structure_mismatch'
  | 'vault_structure_corrupt'
  | 'conflict_detected'
  | 'migration_blocked'
  | 'trusted_snapshot_missing'
  | 'trusted_snapshot_scope_mismatch';

export interface IntegrityDiagnostic {
  code: IntegrityDiagnosticCodeV2;
  message: string;
  itemId?: string;
  categoryId?: string;
  manifestRevision?: number;
  observedHashPrefix?: string;
}

export interface QuarantinedItemDecisionV2 {
  itemId: string;
  reason: ActiveItemQuarantineReasonV2;
  manifestRevision: number;
  observedEnvelopeHash?: string;
  expectedEnvelopeHash?: string;
  updatedAt?: string | null;
  recoverable: boolean;
}

export interface OrphanRemoteItemDecision {
  itemId: string;
  reason: 'orphan_remote';
  observedEnvelopeHash?: string;
  updatedAt?: string | null;
}

export interface MissingRemoteItemDecision {
  itemId: string;
  reason: 'missing_on_server';
  recoverable: boolean;
}

export interface PendingVaultMutation {
  id: string;
  type: 'upsert_item' | 'delete_item' | 'upsert_category' | 'delete_category' | 'manifest_write';
  itemId?: string;
  categoryId?: string;
}

export interface IntegrityConflict {
  itemId?: string;
  categoryId?: string;
  reason: 'duplicate_active_item_record' | 'stale_base_revision' | 'competing_revision';
}

export interface TrustedLocalSnapshotMetadata {
  snapshotVersion: 2;
  snapshotId: string;
  userId: string;
  vaultId: string;
  manifestHash: string;
  manifestRevision: number;
  createdAt: string;
  itemCount: number;
  categoryCount: number;
  recoverableItemIds?: string[];
  encryptedSnapshotPayload?: string;
  integrityTag?: string;
}

export type SafeModeReasonV2 =
  | 'manifest_invalid'
  | 'manifest_auth_failed'
  | 'manifest_rollback_detected'
  | 'category_structure_mismatch'
  | 'vault_structure_corrupt';

export type VaultIntegrityDecisionV2 =
  | {
      mode: 'normal';
      manifestRevision: number;
      manifestHash: string;
      itemCount: number;
      healthyItemIds: string[];
      diagnostics: IntegrityDiagnostic[];
    }
  | {
      mode: 'locked';
      reason: 'missing_key' | 'invalid_vault_key';
      diagnostics: IntegrityDiagnostic[];
    }
  | {
      mode: 'revalidation_failed';
      reason:
        | 'vault_key_not_verified'
        | 'device_key_state_stale'
        | 'remote_policy_unavailable'
        | 'offline_cache_stale'
        | 'server_snapshot_unavailable'
        | 'unknown';
      diagnostics: IntegrityDiagnostic[];
    }
  | {
      mode: 'safe_mode';
      reason: SafeModeReasonV2;
      diagnostics: IntegrityDiagnostic[];
    }
  | {
      mode: 'item_quarantine';
      manifestRevision: number;
      manifestHash: string;
      quarantinedItems: QuarantinedItemDecisionV2[];
      healthyItemIds: string[];
      diagnostics: IntegrityDiagnostic[];
    }
  | {
      mode: 'orphan_remote';
      manifestRevision: number;
      manifestHash: string;
      orphanItems: OrphanRemoteItemDecision[];
      healthyItemIds: string[];
      diagnostics: IntegrityDiagnostic[];
    }
  | {
      mode: 'missing_remote';
      manifestRevision: number;
      manifestHash: string;
      missingItems: MissingRemoteItemDecision[];
      healthyItemIds: string[];
      diagnostics: IntegrityDiagnostic[];
    }
  | {
      mode: 'sync_pending';
      pendingMutations: PendingVaultMutation[];
      diagnostics: IntegrityDiagnostic[];
    }
  | {
      mode: 'conflict';
      conflicts: IntegrityConflict[];
      diagnostics: IntegrityDiagnostic[];
    };

export type IntegrityEvaluationInputV2 = {
  userId: string;
  vaultId: string;
  serverItems: ServerVaultItemV2[];
  serverCategories: ServerVaultCategoryV2[];
  serverManifestEnvelope?: VaultManifestEnvelopeV2 | string;
  localHighWaterMark?: {
    manifestRevision: number;
    manifestHash: string;
  };
  localSnapshots: TrustedLocalSnapshotMetadata[];
  pendingMutations: PendingVaultMutation[];
  unlockContext: {
    vaultKeyVerified: boolean;
    vaultKey?: CryptoKey;
    keyId?: string;
    protectionMode: VaultProtectionMode | 'master_only' | 'device_key_required' | string;
    deviceKeyStateStale?: boolean;
  };
  evaluationSource: VaultIntegrityEvaluationSourceV2;
};

export type MigrationBlockedReason =
  | 'vault_key_not_verified'
  | 'manifest_already_invalid'
  | 'legacy_items_require_reencrypt'
  | 'active_quarantine_present'
  | 'server_snapshot_unavailable'
  | 'category_structure_mismatch'
  | 'ambiguous_state';

export type VaultIntegrityMigrationResult =
  | { status: 'migrated'; manifestRevision: number; migratedItemCount: number; manifest: VaultManifestV2 }
  | { status: 'already_migrated'; manifestRevision: number }
  | { status: 'blocked'; reason: MigrationBlockedReason; diagnostics: IntegrityDiagnostic[] }
  | { status: 'requires_safe_mode'; reason: SafeModeReasonV2; diagnostics: IntegrityDiagnostic[] };
