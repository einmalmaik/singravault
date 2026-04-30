import type { VaultItemData } from '@/services/cryptoService';
import type { QuarantinedVaultItem, VaultIntegrityVerificationResult } from '@/services/vaultIntegrityService';
import type { TrustedVaultMutation } from '@/services/vaultIntegrityDecisionEngine';
import type { VaultItemForIntegrity } from '@/extensions/types';
import type { VaultContextType, VaultSnapshotSource, VaultUnlockOptions } from './vaultContextTypes';
import type { VaultProviderState } from './useVaultProviderState';

export interface VaultProviderActionBindings {
  setupMasterPassword: (masterPassword: string) => Promise<{ error: Error | null }>;
  unlock: (masterPassword: string, options?: VaultUnlockOptions) => Promise<{ error: Error | null }>;
  unlockWithPasskey: (options?: VaultUnlockOptions) => Promise<{ error: Error | null }>;
  lock: () => void;
  enableDeviceKey: (masterPassword: string) => Promise<{ error: Error | null }>;
  disableDeviceKey: (masterPassword: string, twoFactorCode: string | undefined, confirmationWord: string) => Promise<{ error: Error | null }>;
  refreshDeviceKeyState: () => Promise<void>;
  webAuthnAvailable: boolean;
  refreshPasskeyUnlockStatus: () => Promise<void>;
  getPasskeyWrappingMaterial: (masterPassword: string) => Promise<Uint8Array | null>;
  encryptData: (plaintext: string, aad?: string) => Promise<string>;
  decryptData: (encrypted: string, aad?: string) => Promise<string>;
  encryptBinary: (plaintext: Uint8Array, aad?: string) => Promise<string>;
  decryptBinary: (encrypted: string, aad?: string) => Promise<Uint8Array>;
  encryptItem: (data: VaultItemData, entryId: string) => Promise<string>;
  decryptItem: (encryptedData: string, entryId: string) => Promise<VaultItemData>;
  decryptItemForLegacyMigration: VaultContextType['decryptItemForLegacyMigration'];
  verifyIntegrity: (
    snapshot?: Parameters<VaultContextType['verifyIntegrity']>[0],
    options?: { source?: VaultSnapshotSource },
  ) => Promise<VaultIntegrityVerificationResult | null>;
  updateIntegrity: (items: VaultItemForIntegrity[]) => Promise<void>;
  refreshIntegrityBaseline: (trustedMutation?: TrustedVaultMutation) => Promise<void>;
  reportUnreadableItems: (items: QuarantinedVaultItem[]) => void;
  enterSafeMode: () => Promise<{ error: Error | null }>;
  restoreQuarantinedItem: (itemId: string) => Promise<{ error: Error | null }>;
  deleteQuarantinedItem: (itemId: string) => Promise<{ error: Error | null }>;
  acceptMissingQuarantinedItem: (itemId: string) => Promise<{ error: Error | null }>;
  exitSafeMode: () => void;
  resetVaultAfterIntegrityFailure: () => Promise<{ error: Error | null }>;
}

export function buildVaultContextValue(
  state: VaultProviderState,
  actions: VaultProviderActionBindings,
): VaultContextType {
  return {
    isLocked: state.isLocked,
    isSetupRequired: state.isSetupRequired,
    isLoading: state.isLoading,
    isDuressMode: state.isDuressMode,
    deviceKeyActive: state.deviceKeyActive,
    vaultProtectionMode: state.vaultProtectionMode,
    setupMasterPassword: actions.setupMasterPassword,
    unlock: actions.unlock,
    unlockWithPasskey: actions.unlockWithPasskey,
    lock: actions.lock,
    enableDeviceKey: actions.enableDeviceKey,
    disableDeviceKey: actions.disableDeviceKey,
    refreshDeviceKeyState: actions.refreshDeviceKeyState,
    webAuthnAvailable: actions.webAuthnAvailable,
    hasPasskeyUnlock: state.hasPasskeyUnlock,
    refreshPasskeyUnlockStatus: actions.refreshPasskeyUnlockStatus,
    getPasskeyWrappingMaterial: actions.getPasskeyWrappingMaterial,
    encryptData: actions.encryptData,
    decryptData: actions.decryptData,
    encryptBinary: actions.encryptBinary,
    decryptBinary: actions.decryptBinary,
    encryptItem: actions.encryptItem,
    decryptItem: actions.decryptItem,
    decryptItemForLegacyMigration: actions.decryptItemForLegacyMigration,
    autoLockTimeout: state.autoLockTimeout,
    setAutoLockTimeout: state.setAutoLockTimeout,
    pendingSessionRestore: state.pendingSessionRestore,
    verifyIntegrity: actions.verifyIntegrity,
    updateIntegrity: actions.updateIntegrity,
    refreshIntegrityBaseline: actions.refreshIntegrityBaseline,
    reportUnreadableItems: actions.reportUnreadableItems,
    integrityVerified: state.integrityVerified,
    lastIntegrityResult: state.lastIntegrityResult,
    integrityMode: state.integrityMode,
    quarantinedItems: state.quarantinedItems,
    quarantineResolutionById: state.quarantineResolutionById,
    vaultDataVersion: state.vaultDataVersion,
    integrityBlockedReason: state.integrityBlockedReason,
    trustedRecoveryAvailable: state.trustedRecoveryAvailable,
    enterSafeMode: actions.enterSafeMode,
    restoreQuarantinedItem: actions.restoreQuarantinedItem,
    deleteQuarantinedItem: actions.deleteQuarantinedItem,
    acceptMissingQuarantinedItem: actions.acceptMissingQuarantinedItem,
    exitSafeMode: actions.exitSafeMode,
    resetVaultAfterIntegrityFailure: actions.resetVaultAfterIntegrityFailure,
  };
}
