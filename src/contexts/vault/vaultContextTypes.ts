import type { VaultItemData } from '@/services/cryptoService';
import type { OfflineVaultSnapshot } from '@/services/offlineVaultService';
import type {
    QuarantinedVaultItem,
    VaultIntegrityBlockedReason,
    VaultIntegrityMode,
    VaultIntegrityVerificationResult,
} from '@/services/vaultIntegrityService';
import type { QuarantineResolutionState } from '@/services/vaultQuarantineRecoveryService';
import type { TrustedVaultMutation } from '@/services/vaultIntegrityDecisionEngine';
import type { VaultItemForIntegrity } from '@/extensions/types';

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
    setupMasterPassword: (masterPassword: string) => Promise<{ error: Error | null }>;
    unlock: (masterPassword: string, options?: VaultUnlockOptions) => Promise<{ error: Error | null }>;
    unlockWithPasskey: (options?: VaultUnlockOptions) => Promise<{ error: Error | null }>;
    lock: () => void;
    enableDeviceKey: (masterPassword: string) => Promise<{ error: Error | null }>;
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
    autoLockTimeout: number;
    setAutoLockTimeout: (timeout: number) => void;
    verifyIntegrity: (
        snapshot?: OfflineVaultSnapshot,
        options?: { source?: VaultSnapshotSource },
    ) => Promise<VaultIntegrityVerificationResult | null>;
    updateIntegrity: (items: VaultItemForIntegrity[]) => Promise<void>;
    refreshIntegrityBaseline: (trustedMutation?: TrustedVaultMutation) => Promise<void>;
    reportUnreadableItems: (items: QuarantinedVaultItem[]) => void;
    integrityVerified: boolean;
    lastIntegrityResult: VaultIntegrityVerificationResult | null;
    integrityMode: VaultIntegrityMode | 'safe';
    quarantinedItems: QuarantinedVaultItem[];
    quarantineResolutionById: Record<string, QuarantineResolutionState>;
    vaultDataVersion: number;
    integrityBlockedReason: VaultIntegrityBlockedReason | null;
    trustedRecoveryAvailable: boolean;
    enterSafeMode: () => Promise<{ error: Error | null }>;
    restoreQuarantinedItem: (itemId: string) => Promise<{ error: Error | null }>;
    deleteQuarantinedItem: (itemId: string) => Promise<{ error: Error | null }>;
    acceptMissingQuarantinedItem: (itemId: string) => Promise<{ error: Error | null }>;
    exitSafeMode: () => void;
    resetVaultAfterIntegrityFailure: () => Promise<{ error: Error | null }>;
}
