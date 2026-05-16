import type { VaultItemData } from '@/services/cryptoService';
import type { QuarantinedVaultItem, VaultIntegrityVerificationResult } from '@/services/vaultIntegrityService';
import type { VaultItemForIntegrity } from '@/extensions/types';
import type { VaultContextType, VaultSnapshotSource, VaultUnlockOptions } from './vaultContextTypes';
import type { VaultProviderState } from './useVaultProviderState';
import type { VaultOpLogUiState } from './useVaultOpLogUiState';

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
  decryptTrustedRecoverySnapshotItem: VaultContextType['decryptTrustedRecoverySnapshotItem'];
  verifyIntegrity: (
    snapshot?: Parameters<VaultContextType['verifyIntegrity']>[0],
    options?: { source?: VaultSnapshotSource },
  ) => Promise<VaultIntegrityVerificationResult | null>;
  updateIntegrity: (items: VaultItemForIntegrity[]) => Promise<void>;
  refreshIntegrityBaseline: VaultContextType['refreshIntegrityBaseline'];
  reportUnreadableItems: (items: QuarantinedVaultItem[]) => void;
  enterSafeMode: () => Promise<{ error: Error | null }>;
  exitSafeMode: () => void;
  resetVaultAfterIntegrityFailure: () => Promise<{ error: Error | null }>;
  getVaultHealthAnalysisItems: VaultContextType['getVaultHealthAnalysisItems'];
  findLegacyDuressDecoyCandidates: VaultContextType['findLegacyDuressDecoyCandidates'];
  purgeLegacyDuressDecoys: VaultContextType['purgeLegacyDuressDecoys'];
  startVaultMigration: () => Promise<{ error: Error | null }>;
  retryVaultMigration: () => Promise<{ error: Error | null }>;

  // OpLog actions (optional until fully implemented)
  opLogCreateItem?: VaultContextType['opLogCreateItem'];
  opLogUpdateItem?: VaultContextType['opLogUpdateItem'];
  opLogDeleteItem?: VaultContextType['opLogDeleteItem'];
  opLogCreateCategory?: VaultContextType['opLogCreateCategory'];
  opLogUpdateCategory?: VaultContextType['opLogUpdateCategory'];
  opLogDeleteCategory?: VaultContextType['opLogDeleteCategory'];
  opLogRestoreRecord?: (recordId: string) => Promise<{ error: Error | null }>;
  opLogDeleteUntrustedRecord?: (recordId: string) => Promise<{ error: Error | null }>;
  opLogResolveConflict?: (recordId: string) => Promise<{ error: Error | null }>;
  opLogApproveDeviceRequest?: VaultContextType['opLogApproveDeviceRequest'];
  opLogRejectDeviceRequest?: VaultContextType['opLogRejectDeviceRequest'];
  opLogRevokeDevice?: VaultContextType['opLogRevokeDevice'];
  listSharedCollections?: VaultContextType['listSharedCollections'];
  createSharedCollection?: VaultContextType['createSharedCollection'];
  deleteSharedCollection?: VaultContextType['deleteSharedCollection'];
}

export function buildVaultContextValue(
  state: VaultProviderState,
  actions: VaultProviderActionBindings,
  opLogUiState: VaultOpLogUiState,
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
    decryptTrustedRecoverySnapshotItem: actions.decryptTrustedRecoverySnapshotItem,
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
    vaultMigrationStatus: state.vaultMigrationStatus,
    vaultMigrationError: state.vaultMigrationError,
    vaultMigrationCanStart: state.vaultMigrationCanStart,
    startVaultMigration: actions.startVaultMigration,
    retryVaultMigration: actions.retryVaultMigration,
    quarantinedItems: state.quarantinedItems,
    quarantineResolutionById: state.quarantineResolutionById,
    vaultDataVersion: state.vaultDataVersion,
    integrityBlockedReason: state.integrityBlockedReason,
    trustedRecoveryAvailable: state.trustedRecoveryAvailable,
    enterSafeMode: actions.enterSafeMode,
    exitSafeMode: actions.exitSafeMode,
    resetVaultAfterIntegrityFailure: actions.resetVaultAfterIntegrityFailure,
    getVaultHealthAnalysisItems: actions.getVaultHealthAnalysisItems,
    findLegacyDuressDecoyCandidates: actions.findLegacyDuressDecoyCandidates,
    purgeLegacyDuressDecoys: actions.purgeLegacyDuressDecoys,

    // Phase 9 — OpLog UI state
    opLogVaultId: opLogUiState.vaultId,
    opLogUiView: opLogUiState.uiView,
    opLogLocalVaultState: opLogUiState.localVaultState,
    opLogUiLoading: opLogUiState.isLoading,
    opLogUiError: opLogUiState.lastError,
    opLogUiRefresh: opLogUiState.refresh,
    opLogCreateItem: actions.opLogCreateItem ?? (() => Promise.resolve({ error: new Error('Not implemented'), recordId: null })),
    opLogUpdateItem: actions.opLogUpdateItem ?? (() => Promise.resolve({ error: new Error('Not implemented') })),
    opLogDeleteItem: actions.opLogDeleteItem ?? (() => Promise.resolve({ error: new Error('Not implemented') })),
    opLogCreateCategory: actions.opLogCreateCategory ?? (() => Promise.resolve({ error: new Error('Not implemented'), recordId: null })),
    opLogUpdateCategory: actions.opLogUpdateCategory ?? (() => Promise.resolve({ error: new Error('Not implemented') })),
    opLogDeleteCategory: actions.opLogDeleteCategory ?? (() => Promise.resolve({ error: new Error('Not implemented') })),
    opLogRestoreRecord: actions.opLogRestoreRecord ?? (() => Promise.resolve({ error: new Error('Not implemented') })),
    opLogDeleteUntrustedRecord: actions.opLogDeleteUntrustedRecord ?? (() => Promise.resolve({ error: new Error('Not implemented') })),
    opLogResolveConflict: actions.opLogResolveConflict ?? (() => Promise.resolve({ error: new Error('Not implemented') })),
    opLogApproveDeviceRequest: actions.opLogApproveDeviceRequest ?? (() => Promise.resolve({ error: new Error('Not implemented') })),
    opLogRejectDeviceRequest: actions.opLogRejectDeviceRequest ?? (() => Promise.resolve({ error: new Error('Not implemented') })),
    opLogRevokeDevice: actions.opLogRevokeDevice ?? (() => Promise.resolve({ error: new Error('Not implemented') })),
    listSharedCollections: actions.listSharedCollections ?? (() => Promise.resolve({ error: new Error('Not implemented'), collections: [] })),
    createSharedCollection: actions.createSharedCollection ?? (() => Promise.resolve({ error: new Error('Not implemented'), collectionId: null })),
    deleteSharedCollection: actions.deleteSharedCollection ?? (() => Promise.resolve({ error: new Error('Not implemented') })),
  };
}
