import type { VaultItemData } from '@/services/cryptoService';
import type { OfflineVaultSnapshot } from '@/services/offlineVaultService';
import type {
    QuarantinedVaultItem,
    VaultIntegrityBlockedReason,
    VaultIntegrityMode,
    VaultIntegrityVerificationResult,
} from '@/services/vaultIntegrityService';
import type { QuarantineResolutionState } from '@/services/vaultQuarantineRecoveryService';
import type { VaultItemForIntegrity } from '@/extensions/types';
import type { VaultProtectionMode } from '@/services/deviceKeyProtectionPolicy';
import type { VaultOpLogUiView } from '@/services/vaultOpLog/vaultOpLogUiAdapter';
import type { LocalVaultState } from '@/services/vaultOpLog/vaultStateMachine';
import type {
    CategoryPlaintext,
    ItemPlaintext,
    OpLogCategoryDeleteMode,
} from '@/services/vaultOpLog/vaultOpLogCrudService';
import type { VaultMigrationRolloutStatus } from '@/services/vaultOpLog/vaultMigrationRolloutService';
import type {
    CreateSharedCollectionInput,
    SharedCollectionSummary,
} from './useCollectionOpLogActions';

export type VaultSnapshotSource = 'remote' | 'cache' | 'empty';

export interface VaultUnlockOptions {
    verifyTwoFactor?: () => Promise<boolean>;
}

export interface VaultContextType {
    isLocked: boolean;
    isSetupRequired: boolean;
    isLoading: boolean;
    pendingSessionRestore: boolean;
    isDuressMode: boolean;
    deviceKeyActive: boolean;
    vaultProtectionMode: VaultProtectionMode;
    setupMasterPassword: (masterPassword: string) => Promise<{ error: Error | null }>;
    unlock: (masterPassword: string, options?: VaultUnlockOptions) => Promise<{ error: Error | null }>;
    unlockWithPasskey: (options?: VaultUnlockOptions) => Promise<{ error: Error | null }>;
    lock: () => void;
    enableDeviceKey: (masterPassword: string) => Promise<{ error: Error | null }>;
    disableDeviceKey: (masterPassword: string, twoFactorCode: string | undefined, confirmationWord: string) => Promise<{ error: Error | null }>;
    refreshDeviceKeyState: () => Promise<void>;
    webAuthnAvailable: boolean;
    hasPasskeyUnlock: boolean;
    refreshPasskeyUnlockStatus: () => Promise<void>;
    getPasskeyWrappingMaterial: (masterPassword: string) => Promise<Uint8Array | null>;
    encryptData: (plaintext: string, aad?: string) => Promise<string>;
    decryptData: (encrypted: string, aad?: string) => Promise<string>;
    encryptBinary: (plaintext: Uint8Array, aad?: string) => Promise<string>;
    decryptBinary: (encrypted: string, aad?: string) => Promise<Uint8Array>;
    encryptItem: (data: VaultItemData, entryId: string) => Promise<string>;
    decryptItem: (encryptedData: string, entryId: string) => Promise<VaultItemData>;
    decryptItemForLegacyMigration: (
        encryptedData: string,
        entryId: string,
    ) => Promise<{ data: VaultItemData; legacyEnvelopeUsed: boolean; legacyNoAadFallbackUsed: boolean }>;
    decryptTrustedRecoverySnapshotItem: (
        item: OfflineVaultSnapshot['items'][number],
        snapshotId: string,
        vaultId: string,
    ) => Promise<VaultItemData>;
    autoLockTimeout: number;
    setAutoLockTimeout: (timeout: number) => void;
    verifyIntegrity: (
        snapshot?: OfflineVaultSnapshot,
        options?: { source?: VaultSnapshotSource },
    ) => Promise<VaultIntegrityVerificationResult | null>;
    updateIntegrity: (items: VaultItemForIntegrity[]) => Promise<void>;
    refreshIntegrityBaseline: () => Promise<VaultIntegrityVerificationResult | null>;
    reportUnreadableItems: (items: QuarantinedVaultItem[]) => void;
    integrityVerified: boolean;
    lastIntegrityResult: VaultIntegrityVerificationResult | null;
    integrityMode: VaultIntegrityMode | 'safe';
    vaultMigrationStatus: VaultMigrationRolloutStatus | null;
    vaultMigrationError: string | null;
    vaultMigrationCanStart: boolean;
    startVaultMigration: () => Promise<{ error: Error | null }>;
    retryVaultMigration: () => Promise<{ error: Error | null }>;
    quarantinedItems: QuarantinedVaultItem[];
    quarantineResolutionById: Record<string, QuarantineResolutionState>;
    vaultDataVersion: number;
    integrityBlockedReason: VaultIntegrityBlockedReason | null;
    trustedRecoveryAvailable: boolean;
    enterSafeMode: () => Promise<{ error: Error | null }>;
    exitSafeMode: () => void;
    resetVaultAfterIntegrityFailure: () => Promise<{ error: Error | null }>;

    // Phase 9 — OpLog UI state (behind feature flag)
    opLogVaultId: string | null;
    opLogUiView: VaultOpLogUiView | null;
    opLogLocalVaultState: LocalVaultState | null;
    opLogUiLoading: boolean;
    opLogUiError: string | null;
    opLogUiRefresh: () => Promise<void>;
    opLogCreateItem: (plaintext: ItemPlaintext) => Promise<{ error: Error | null; recordId: string | null }>;
    opLogUpdateItem: (recordId: string, plaintext: ItemPlaintext) => Promise<{ error: Error | null }>;
    opLogDeleteItem: (recordId: string) => Promise<{ error: Error | null }>;
    opLogCreateCategory: (plaintext: CategoryPlaintext) => Promise<{ error: Error | null; recordId: string | null }>;
    opLogUpdateCategory: (recordId: string, plaintext: CategoryPlaintext) => Promise<{ error: Error | null }>;
    opLogDeleteCategory: (recordId: string, mode?: OpLogCategoryDeleteMode) => Promise<{ error: Error | null }>;
    opLogRestoreRecord: (recordId: string) => Promise<{ error: Error | null }>;
    opLogDeleteUntrustedRecord: (recordId: string) => Promise<{ error: Error | null }>;
    opLogResolveConflict: (recordId: string) => Promise<{ error: Error | null }>;
    opLogApproveDeviceRequest: (requestId: string) => Promise<{ error: Error | null }>;
    opLogRejectDeviceRequest: (requestId: string) => Promise<{ error: Error | null }>;

    // Shared Collections — Core-owned signed Collection OpLog facade for Premium.
    listSharedCollections: () => Promise<{ error: Error | null; collections: SharedCollectionSummary[] }>;
    createSharedCollection: (input: CreateSharedCollectionInput) => Promise<{ error: Error | null; collectionId: string | null }>;
    deleteSharedCollection: (collectionId: string) => Promise<{ error: Error | null }>;
}
