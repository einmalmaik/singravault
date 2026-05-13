export type VaultIntegritySnapshotSource = 'remote' | 'cache' | 'empty';

export {
  type QuarantinedVaultItem,
  type VaultIntegrityBlockedReason,
  type VaultIntegrityMode,
  type VaultIntegrityVerificationResult,
  type VaultIntegritySnapshot,
  type VaultIntegritySnapshotCompletenessContext,
  type VaultIntegrityNonTamperReason,
} from './vaultIntegrityService';
