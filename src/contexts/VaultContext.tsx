// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE
/**
 * @fileoverview Vault Context for Singra Vault
 * 
 * Manages vault encryption state including:
 * - Master password unlock status
 * - Derived encryption key (kept in memory only)
 * - Auto-lock on inactivity
 * - Vault item encryption/decryption helpers
 */

import { createContext, useContext, useEffect, useState, useCallback, useMemo, useRef, ReactNode } from 'react';
import {
    deriveKey,
    deriveRawKey,
    generateSalt,
    encrypt,
    encryptBytes,
    decrypt,
    decryptBytes,
    importMasterKey,
    createVerificationHash,
    verifyKey,
    encryptVaultItem,
    decryptVaultItem,
    clearReferences,
    attemptKdfUpgrade,
    reEncryptVault,
    CURRENT_KDF_VERSION,
    VaultItemData,
    createEncryptedUserKey,
    migrateToUserKey,
    unwrapUserKey,
    unwrapUserKeyBytes,
    rewrapUserKey,
    decryptPrivateKeyLegacy,
    wrapPrivateKeyWithUserKey,
} from '@/services/cryptoService';
import {
    generateDeviceKey,
    storeDeviceKey,
    getDeviceKey as loadDeviceKey,
    hasDeviceKey as checkHasDeviceKey,
} from '@/services/deviceKeyService';
import {
    isAppOnline,
    isLikelyOfflineError,
    fetchRemoteOfflineSnapshot,
    getOfflineSnapshot,
    getOfflineCredentials,
    getOfflineVaultTwoFactorRequirement,
    getTrustedOfflineSnapshot,
    isRecentLocalVaultMutation,
    loadVaultSnapshot,
    saveOfflineSnapshot,
    saveTrustedOfflineSnapshot,
    saveOfflineCredentials,
    saveOfflineVaultTwoFactorRequirement,
    type OfflineVaultSnapshot,
} from '@/services/offlineVaultService';
import {
    authenticatePasskey,
    isWebAuthnAvailable,
    listPasskeys,
} from '@/services/passkeyService';
import { getServiceHooks } from '@/extensions/registry';
import type { DuressConfigHook, VaultItemForIntegrity } from '@/extensions/types';
import { supabase } from '@/integrations/supabase/client';
import { hasOptionalCookieConsent } from '@/lib/cookieConsent';
import { useAuth } from './AuthContext';
import {
    getUnlockCooldown,
    recordFailedAttempt,
    resetUnlockAttempts,
} from '@/services/rateLimiterService';
import { getTwoFactorRequirement } from '@/services/twoFactorService';
import {
    inspectVaultSnapshotIntegrity,
    persistIntegrityBaseline,
    persistTrustedMutationIntegrityBaseline,
    toVaultIntegrityVerificationResult,
    VaultIntegrityBaselineError,
    type VaultIntegrityBaselineInspection,
    type QuarantinedVaultItem,
    type VaultIntegrityBlockedReason,
    type VaultIntegrityMode,
    type VaultIntegritySnapshot,
    type VaultIntegrityVerificationResult,
} from '@/services/vaultIntegrityService';
import { resetUserVaultState } from '@/services/vaultRecoveryService';
import {
    buildQuarantineResolutionMap,
    deleteQuarantinedItemFromVault,
    indexTrustedSnapshotItems,
    restoreQuarantinedItemFromTrustedSnapshot,
    type QuarantineResolutionRuntimeState,
    type QuarantineResolutionState,
    type TrustedSnapshotItemsById,
} from '@/services/vaultQuarantineRecoveryService';
import { isTauriDevUserId, TAURI_DEV_VAULT_ID } from '@/platform/tauriDevMode';

// Auto-lock timeout in milliseconds (default 15 minutes)
const DEFAULT_AUTO_LOCK_TIMEOUT = 15 * 60 * 1000;

/**
 * Migrates legacy RSA and PQ private keys to USK (User Symmetric Key) format.
 *
 * Runs once per unlock after the UserKey is established. Re-wraps keys that
 * are still in the old KDF-derived format (e.g. `kdfVersion:salt:enc`) to the
 * new `usk-v1:` sentinel format. This is a non-destructive,
 * idempotent operation - it checks the sentinel before doing any work.
 */
async function migrateLegacyPrivateKeysToUserKey(
    userId: string,
    masterPassword: string,
    userKey: CryptoKey,
): Promise<void> {
    // RSA private key migration
    try {
        const { data: keyRow } = await supabase
            .from('user_keys')
            .select('encrypted_private_key')
            .eq('user_id', userId)
            .maybeSingle();

        const encRsa = keyRow?.encrypted_private_key as string | null | undefined;
        if (encRsa && !encRsa.startsWith('usk-v1:')) {
            const plainPrivateKey = await decryptPrivateKeyLegacy(encRsa, masterPassword, false);
            // wrapPrivateKeyWithUserKey includes the usk-v1: sentinel prefix.
            const newEncRsa = await wrapPrivateKeyWithUserKey(plainPrivateKey, userKey);
            const { error: rsaUpdateErr } = await supabase
                .from('user_keys')
                .update({ encrypted_private_key: newEncRsa, updated_at: new Date().toISOString() })
                .eq('user_id', userId);
            if (rsaUpdateErr) {
                console.warn('USK private key migration: RSA key update failed:', rsaUpdateErr);
            } else {
                console.info('USK private key migration: RSA key re-wrapped to usk-v1 format.');
            }
        }
    } catch (err) {
        console.warn('USK migration: RSA private key migration failed (non-fatal):', err);
    }

    // PQ private key migration
    try {
        const { data: profileRow } = await supabase
            .from('profiles')
            .select('pq_encrypted_private_key')
            .eq('user_id', userId)
            .maybeSingle();

        const encPq = profileRow?.pq_encrypted_private_key as string | null | undefined;
        if (encPq && !encPq.startsWith('usk-v1:')) {
            // profiles.pq_encrypted_private_key is always kdfVersion:salt:encData format.
            // (pq-v2: combined format only appears in user_keys.encrypted_private_key)
            const plainPqKey = await decryptPrivateKeyLegacy(encPq, masterPassword, false);
            // wrapPrivateKeyWithUserKey includes the usk-v1: sentinel prefix.
            const newEncPq = await wrapPrivateKeyWithUserKey(plainPqKey, userKey);
            const { error: pqUpdateErr } = await supabase
                .from('profiles')
                .update({ pq_encrypted_private_key: newEncPq, updated_at: new Date().toISOString() } as Record<string, unknown>)
                .eq('user_id', userId);
            if (pqUpdateErr) {
                console.warn('USK migration: PQ key update failed:', pqUpdateErr);
            } else {
                console.info('USK private key migration: PQ key re-wrapped to usk-v1 format.');
            }
        }
    } catch (err) {
        console.warn('USK migration: PQ private key migration failed (non-fatal):', err);
    }
}

// Session storage keys
const SESSION_KEY = 'singra_session';
const SESSION_TIMESTAMP_KEY = 'singra_session_ts';
const SESSION_PASSWORD_HINT_KEY = 'singra_session_hint';

interface TrustedVaultMutation {
    itemIds?: Iterable<string>;
    categoryIds?: Iterable<string>;
}

type VaultSnapshotSource = 'remote' | 'cache' | 'empty';

interface NormalizedTrustedVaultMutation {
    itemIds: Set<string>;
    categoryIds: Set<string>;
}

interface VaultIntegrityAssessment {
    inspection: VaultIntegrityBaselineInspection;
    unreadableCategoryReason: VaultIntegrityBlockedReason | null;
    result: VaultIntegrityVerificationResult;
}

function normalizeTrustedVaultMutation(
    mutation?: TrustedVaultMutation,
): NormalizedTrustedVaultMutation {
    return {
        itemIds: new Set(mutation?.itemIds ?? []),
        categoryIds: new Set(mutation?.categoryIds ?? []),
    };
}

function canRebaselineTrustedMutation(
    assessment: VaultIntegrityAssessment,
    trustedMutation: NormalizedTrustedVaultMutation,
): boolean {
    if (assessment.unreadableCategoryReason) {
        return false;
    }

    if (
        assessment.inspection.snapshotValidationError
        || assessment.inspection.legacyBaselineMismatch
    ) {
        return false;
    }

    if (
        assessment.inspection.categoryDriftIds.some((categoryId) => !trustedMutation.categoryIds.has(categoryId))
        || assessment.inspection.itemDrifts.some((item) => !trustedMutation.itemIds.has(item.id))
    ) {
        return false;
    }

    return (
        assessment.inspection.categoryDriftIds.length > 0
        || assessment.inspection.itemDrifts.length > 0
    );
}

function hasTrustedDrift(
    assessment: VaultIntegrityAssessment,
    trustedMutation: NormalizedTrustedVaultMutation,
): boolean {
    return assessment.inspection.itemDrifts.some((item) => trustedMutation.itemIds.has(item.id))
        || assessment.inspection.categoryDriftIds.some((categoryId) => trustedMutation.categoryIds.has(categoryId));
}

function canRebaselineRecentLocalMutation(
    userId: string,
    assessment: VaultIntegrityAssessment,
): boolean {
    if (
        assessment.unreadableCategoryReason
        || assessment.inspection.snapshotValidationError
        || assessment.inspection.legacyBaselineMismatch
    ) {
        return false;
    }

    if (
        assessment.inspection.itemDrifts.length === 0
        && assessment.inspection.categoryDriftIds.length === 0
    ) {
        return false;
    }

    return isRecentLocalVaultMutation(userId, {
        itemIds: assessment.inspection.itemDrifts.map((item) => item.id),
        categoryIds: assessment.inspection.categoryDriftIds,
    });
}

function hasTrustedMutationScope(
    trustedMutation: NormalizedTrustedVaultMutation,
): boolean {
    return trustedMutation.itemIds.size > 0 || trustedMutation.categoryIds.size > 0;
}

async function ensureTauriDevVaultSnapshot(userId: string): Promise<void> {
    if (!isTauriDevUserId(userId)) {
        return;
    }

    const snapshot = await getOfflineSnapshot(userId);
    if (!snapshot || snapshot.vaultId === TAURI_DEV_VAULT_ID) {
        return;
    }

    await saveOfflineSnapshot({
        ...snapshot,
        vaultId: TAURI_DEV_VAULT_ID,
        updatedAt: new Date().toISOString(),
    });
}

function canPersistIntegrityBaselineImmediately(
    assessment: VaultIntegrityAssessment,
    snapshot: OfflineVaultSnapshot,
): boolean {
    return assessment.inspection.baselineKind !== 'missing'
        || (snapshot.items.length === 0 && snapshot.categories.length === 0);
}

async function buildDecryptableRemoteRebaselineMutation(
    assessment: VaultIntegrityAssessment,
    snapshot: OfflineVaultSnapshot,
    activeKey: CryptoKey,
): Promise<TrustedVaultMutation | null> {
    if (
        assessment.unreadableCategoryReason
        || assessment.inspection.snapshotValidationError
        || assessment.inspection.legacyBaselineMismatch
        || assessment.inspection.categoryDriftIds.length > 0
        || assessment.inspection.itemDrifts.length === 0
    ) {
        return null;
    }

    const itemsById = new Map(snapshot.items.map((item) => [item.id, item]));
    const trustedItemIds: string[] = [];

    for (const drift of assessment.inspection.itemDrifts) {
        if (drift.reason === 'missing_on_server') {
            return null;
        }

        const item = itemsById.get(drift.id);
        if (!item) {
            return null;
        }

        try {
            await decryptVaultItem(item.encrypted_data, activeKey, item.id);
            trustedItemIds.push(item.id);
        } catch {
            return null;
        }
    }

    return { itemIds: trustedItemIds };
}

interface VaultContextType {
    // State
    isLocked: boolean;
    isSetupRequired: boolean;
    isLoading: boolean;
    pendingSessionRestore: boolean;
    /** Whether the vault is currently in duress (decoy) mode */
    isDuressMode: boolean;
    /** Whether a Device Key is stored on this device */
    deviceKeyActive: boolean;

    // Actions
    setupMasterPassword: (masterPassword: string) => Promise<{ error: Error | null }>;
    unlock: (masterPassword: string, options?: VaultUnlockOptions) => Promise<{ error: Error | null }>;
    unlockWithPasskey: (options?: VaultUnlockOptions) => Promise<{ error: Error | null }>;
    lock: () => void;
    /** Enables Device Key protection: generates key, re-encrypts vault */
    enableDeviceKey: (masterPassword: string) => Promise<{ error: Error | null }>;

    // Passkey support
    /** Whether the browser supports WebAuthn */
    webAuthnAvailable: boolean;
    /** Whether the user has registered passkeys with PRF */
    hasPasskeyUnlock: boolean;
    /** Refreshes whether at least one vault-unlock-capable passkey is available */
    refreshPasskeyUnlockStatus: () => Promise<void>;
    /**
     * Derives raw AES-256 key bytes from the master password (for passkey registration).
     * Must be called while vault is unlocked. Returns null if vault is locked.
     */
    getPasskeyWrappingMaterial: (masterPassword: string) => Promise<Uint8Array | null>;

    // Encryption helpers
    encryptData: (plaintext: string, aad?: string) => Promise<string>;
    decryptData: (encrypted: string, aad?: string) => Promise<string>;
    encryptBinary: (plaintext: Uint8Array, aad?: string) => Promise<string>;
    decryptBinary: (encrypted: string, aad?: string) => Promise<Uint8Array>;
    encryptItem: (data: VaultItemData, entryId: string) => Promise<string>;
    decryptItem: (encryptedData: string, entryId: string) => Promise<VaultItemData>;

    // Settings
    autoLockTimeout: number;
    setAutoLockTimeout: (timeout: number) => void;

    // Vault Integrity (tamper detection)
    /**
     * Verifies vault items against stored integrity root.
     * Call this after loading vault items to detect server-side tampering.
     * @returns Verification result with valid flag and details
     */
    verifyIntegrity: (
        snapshot?: OfflineVaultSnapshot,
        options?: { source?: VaultSnapshotSource },
    ) => Promise<VaultIntegrityVerificationResult | null>;
    /**
     * Updates the integrity root after vault modifications.
     * Call this after creating, updating, or deleting vault items.
     */
    updateIntegrity: (items: VaultItemForIntegrity[]) => Promise<void>;
    /**
     * Recomputes and persists the current local integrity baseline after a trusted mutation.
     */
    refreshIntegrityBaseline: (trustedMutation?: TrustedVaultMutation) => Promise<void>;
    /**
     * Records item decryptability failures discovered while rendering. This keeps
     * unlock digest-based and avoids decrypting the full vault twice.
     */
    reportUnreadableItems: (items: QuarantinedVaultItem[]) => void;
    /**
     * Whether integrity verification has been performed since unlock
     */
    integrityVerified: boolean;
    /**
     * Last integrity verification result (null if not yet verified)
     */
    lastIntegrityResult: VaultIntegrityVerificationResult | null;
    /**
     * Current integrity access mode for the active session.
     * "safe" is a local recovery mode backed by the last trusted snapshot.
     */
    integrityMode: VaultIntegrityMode | 'safe';
    /**
     * Item ids that were quarantined during the last integrity check.
     */
    quarantinedItems: QuarantinedVaultItem[];
    quarantineResolutionById: Record<string, QuarantineResolutionState>;
    vaultDataVersion: number;
    /**
     * Why normal unlock was blocked, if applicable.
     */
    integrityBlockedReason: VaultIntegrityBlockedReason | null;
    /**
     * Whether a trusted local recovery snapshot is available.
     */
    trustedRecoveryAvailable: boolean;
    /**
     * Enters read-only local recovery mode backed by the last trusted snapshot.
     */
    enterSafeMode: () => Promise<{ error: Error | null }>;
    restoreQuarantinedItem: (itemId: string) => Promise<{ error: Error | null }>;
    deleteQuarantinedItem: (itemId: string) => Promise<{ error: Error | null }>;
    acceptMissingQuarantinedItem: (itemId: string) => Promise<{ error: Error | null }>;
    /**
     * Leaves local recovery mode and returns to the blocked state.
     */
    exitSafeMode: () => void;
    /**
     * Clears the current user's vault state locally and remotely after
     * an integrity failure so the vault can be re-initialized safely.
     */
    resetVaultAfterIntegrityFailure: () => Promise<{ error: Error | null }>;
}

interface VaultUnlockOptions {
    verifyTwoFactor?: () => Promise<boolean>;
}

const VaultContext = createContext<VaultContextType | undefined>(undefined);

interface VaultProviderProps {
    children: ReactNode;
}

export function VaultProvider({ children }: VaultProviderProps) {
    const { user, authReady } = useAuth();
    const lastUserIdRef = useRef<string | null>(null);

    // Get initial auto-lock timeout from localStorage
    const getInitialAutoLockTimeout = () => {
        if (!hasOptionalCookieConsent()) {
            return DEFAULT_AUTO_LOCK_TIMEOUT;
        }

        const saved = localStorage.getItem('singra_autolock');
        return saved ? parseInt(saved, 10) : DEFAULT_AUTO_LOCK_TIMEOUT;
    };

    // Check if session is still valid based on timestamp and auto-lock settings
    const isSessionValid = () => {
        const sessionData = sessionStorage.getItem(SESSION_KEY);
        const timestamp = sessionStorage.getItem(SESSION_TIMESTAMP_KEY);
        const timeout = getInitialAutoLockTimeout();

        if (!sessionData || !timestamp) return false;

        // If auto-lock is disabled (0 = never), session is always valid
        if (timeout === 0) return true;

        // Check if session has expired based on auto-lock timeout
        const elapsed = Date.now() - parseInt(timestamp, 10);
        return elapsed < timeout;
    };

    // State - isLocked always starts true because encryptionKey cannot be persisted
    // pendingSessionRestore indicates if we should show the session restore hint
    const [isLocked, setIsLocked] = useState(true);
    const [isSetupRequired, setIsSetupRequired] = useState(false);
    const [isLoading, setIsLoading] = useState(true);
    const [encryptionKey, setEncryptionKey] = useState<CryptoKey | null>(null);
    const [salt, setSalt] = useState<string | null>(null);
    const [verificationHash, setVerificationHash] = useState<string | null>(null);
    const [kdfVersion, setKdfVersion] = useState<number>(1);
    const [autoLockTimeout, setAutoLockTimeoutState] = useState(getInitialAutoLockTimeout);
    // Show session restore hint if session is still valid (user just needs to re-enter password)
    const [pendingSessionRestore, setPendingSessionRestore] = useState(() => isSessionValid());
    // Passkey state
    const [hasPasskeyUnlock, setHasPasskeyUnlock] = useState(false);
    const webAuthnAvailable = isWebAuthnAvailable();
    // Duress (panic password) state
    const [isDuressMode, setIsDuressMode] = useState(false);
    const [duressConfig, setDuressConfig] = useState<DuressConfigHook | null>(null);
    // Device Key state
    const [deviceKeyActive, setDeviceKeyActive] = useState(false);
    const [currentDeviceKey, setCurrentDeviceKey] = useState<Uint8Array | null>(null);
    // USK (User Symmetric Key) â€” encrypted form stored in profiles.encrypted_user_key
    // null = pre-USK user (will be migrated on next unlock), string = already migrated
    const [encryptedUserKey, setEncryptedUserKey] = useState<string | null>(null);
    const [integrityVerified, setIntegrityVerified] = useState(false);
    const baseIntegrityResultRef = useRef<VaultIntegrityVerificationResult | null>(null);
    const [lastIntegrityResult, setLastIntegrityResult] = useState<VaultIntegrityVerificationResult | null>(null);
    const [integrityMode, setIntegrityMode] = useState<VaultIntegrityMode | 'safe'>('healthy');
    const [quarantinedItems, setQuarantinedItems] = useState<QuarantinedVaultItem[]>([]);
    const runtimeUnreadableItemsRef = useRef<QuarantinedVaultItem[]>([]);
    const [vaultDataVersion, setVaultDataVersion] = useState(0);
    const [quarantineActionStateById, setQuarantineActionStateById] = useState<
        Record<string, QuarantineResolutionRuntimeState>
    >({});
    const [integrityBlockedReason, setIntegrityBlockedReason] = useState<VaultIntegrityBlockedReason | null>(null);
    const [trustedRecoveryAvailable, setTrustedRecoveryAvailable] = useState(false);
    const [trustedSnapshotItemsById, setTrustedSnapshotItemsById] = useState<TrustedSnapshotItemsById>({});
    const [lastActivity, setLastActivity] = useState(Date.now());
    const [connectivityCheckNonce, setConnectivityCheckNonce] = useState(0);

    const clearActiveVaultSession = useCallback(() => {
        setEncryptionKey(null);
        setCurrentDeviceKey((existingKey) => {
            existingKey?.fill(0);
            return null;
        });
        setIsLocked(true);
        setIsDuressMode(false);
        setIntegrityVerified(false);
        baseIntegrityResultRef.current = null;
        setLastIntegrityResult(null);
        setIntegrityMode('healthy');
        setQuarantinedItems([]);
        runtimeUnreadableItemsRef.current = [];
        setVaultDataVersion(0);
        setQuarantineActionStateById({});
        setIntegrityBlockedReason(null);
        setTrustedRecoveryAvailable(false);
        setTrustedSnapshotItemsById({});
        setPendingSessionRestore(false);
        setLastActivity(Date.now());
        sessionStorage.removeItem(SESSION_KEY);
        sessionStorage.removeItem(SESSION_TIMESTAMP_KEY);
        sessionStorage.removeItem(SESSION_PASSWORD_HINT_KEY);
    }, []);

    const resetVaultState = useCallback(() => {
        clearActiveVaultSession();
        setIsSetupRequired(false);
        setSalt(null);
        setVerificationHash(null);
        setKdfVersion(1);
        setHasPasskeyUnlock(false);
        setDuressConfig(null);
        setDeviceKeyActive(false);
        setCurrentDeviceKey(null);
        setEncryptedUserKey(null);
        setTrustedRecoveryAvailable(false);
        setTrustedSnapshotItemsById({});
        setQuarantineActionStateById({});
    }, [clearActiveVaultSession]);

    useEffect(() => {
        const currentUserId = user?.id ?? null;
        if (lastUserIdRef.current === currentUserId) {
            return;
        }

        lastUserIdRef.current = currentUserId;
        resetVaultState();
        setIsLoading(Boolean(currentUserId));
    }, [resetVaultState, user?.id]);

    const setAutoLockTimeout = (timeout: number) => {
        // Check for optional cookie consent
        const consent = localStorage.getItem("singra-cookie-consent");
        if (consent) {
            try {
                const parsed = JSON.parse(consent);
                if (parsed.optional) {
                    localStorage.setItem('singra_autolock', timeout.toString());
                }
            } catch (e) {
                // If parse fails, err on safe side and don't save
            }
        }
        setAutoLockTimeoutState(timeout);
    };

    useEffect(() => {
        const refreshSetupState = () => setConnectivityCheckNonce((value) => value + 1);
        window.addEventListener('online', refreshSetupState);
        return () => window.removeEventListener('online', refreshSetupState);
    }, []);

    const refreshPasskeyUnlockStatus = useCallback(async (): Promise<void> => {
        if (!authReady || !user) {
            setHasPasskeyUnlock(false);
            return;
        }

        console.debug('[VaultContext] authReady is true, refreshing passkey unlock status...');

        try {
            const passkeys = await listPasskeys();
            setHasPasskeyUnlock(passkeys.some((passkey) => passkey.prf_enabled));
        } catch {
            // Non-fatal: passkey status check can fail silently
            setHasPasskeyUnlock(false);
        }
    }, [user, authReady]); // authReady required â€” stale closure fix

    const applyCachedVaultCredentials = useCallback(async (userId: string): Promise<boolean> => {
        const cached = await getOfflineCredentials(userId);
        if (!cached) {
            return false;
        }

        setIsSetupRequired(false);
        setSalt(cached.salt);
        setVerificationHash(cached.verifier);
        if (cached.kdfVersion !== null) {
            setKdfVersion(cached.kdfVersion);
        }
        setEncryptedUserKey(cached.encryptedUserKey);
        return true;
    }, []);

    const getResolvedDeviceKey = useCallback(async (): Promise<Uint8Array | null> => {
        if (currentDeviceKey) {
            return currentDeviceKey;
        }

        if (!user) {
            return null;
        }

        try {
            const storedDeviceKey = await loadDeviceKey(user.id);
            if (storedDeviceKey) {
                setCurrentDeviceKey(storedDeviceKey);
                setDeviceKeyActive(true);
            }
            return storedDeviceKey;
        } catch (error) {
            console.warn('Failed to load device key from local secret storage:', error);
            return null;
        }
    }, [currentDeviceKey, user]);

    const getRequiredDeviceKey = useCallback(async (): Promise<{
        deviceKey: Uint8Array | null;
        error: Error | null;
    }> => {
        const deviceKey = await getResolvedDeviceKey();
        if (deviceKeyActive && !deviceKey) {
            return {
                deviceKey: null,
                error: new Error(
                    'Device key is unavailable on this device. Restore the device key or use a recovery method.',
                ),
            };
        }

        return {
            deviceKey,
            error: null,
        };
    }, [deviceKeyActive, getResolvedDeviceKey]);

    const buildIntegritySnapshot = useCallback((
        snapshot: {
            items: Array<{
                id: string;
                encrypted_data: string;
                updated_at?: string | null;
                item_type?: 'password' | 'note' | 'totp' | 'card' | null;
            }>;
            categories: Array<{ id: string; name: string; icon: string | null; color: string | null }>;
        },
    ): VaultIntegritySnapshot => ({
        items: snapshot.items.map((item) => ({
            id: item.id,
            encrypted_data: item.encrypted_data,
            updated_at: item.updated_at ?? null,
            item_type: 'item_type' in item ? item.item_type : null,
        })),
        categories: snapshot.categories.map((category) => ({
            id: category.id,
            name: category.name,
            icon: category.icon,
            color: category.color,
        })),
    }), []);

    const loadCurrentIntegritySnapshot = useCallback(async (
        options?: { persistRemoteSnapshot?: boolean; useLocalMutationOverlay?: boolean },
    ): Promise<{
        rawSnapshot: OfflineVaultSnapshot;
        integritySnapshot: VaultIntegritySnapshot;
        source: VaultSnapshotSource;
    } | null> => {
        if (!user) {
            return null;
        }

        if (isTauriDevUserId(user.id)) {
            const { snapshot, source } = await loadVaultSnapshot(user.id);
            return {
                rawSnapshot: snapshot,
                integritySnapshot: buildIntegritySnapshot(snapshot),
                source,
            };
        }

        if (options?.useLocalMutationOverlay) {
            const { snapshot, source } = await loadVaultSnapshot(user.id);
            return {
                rawSnapshot: snapshot,
                integritySnapshot: buildIntegritySnapshot(snapshot),
                source,
            };
        }

        if (isAppOnline()) {
            try {
                const rawSnapshot = await fetchRemoteOfflineSnapshot(user.id, {
                    persist: options?.persistRemoteSnapshot !== false,
                });

                return {
                    rawSnapshot,
                    integritySnapshot: buildIntegritySnapshot(rawSnapshot),
                    source: 'remote',
                };
            } catch (error) {
                if (!isLikelyOfflineError(error)) {
                    throw error;
                }
            }
        }

        const { snapshot, source } = await loadVaultSnapshot(user.id);
        return {
            rawSnapshot: snapshot,
            integritySnapshot: buildIntegritySnapshot(snapshot),
            source,
        };
    }, [buildIntegritySnapshot, user]);

    const syncTrustedRecoverySnapshotState = useCallback(async (
        userId: string,
    ): Promise<OfflineVaultSnapshot | null> => {
        const trustedSnapshot = await getTrustedOfflineSnapshot(userId);
        setTrustedRecoveryAvailable(Boolean(trustedSnapshot));
        setTrustedSnapshotItemsById(indexTrustedSnapshotItems(trustedSnapshot));
        return trustedSnapshot;
    }, []);

    const persistTrustedIntegritySnapshot = useCallback(async (
        snapshot: OfflineVaultSnapshot,
    ): Promise<void> => {
        await saveTrustedOfflineSnapshot(snapshot);
        setTrustedRecoveryAvailable(true);
        setTrustedSnapshotItemsById(indexTrustedSnapshotItems(snapshot));
    }, []);

    const quarantineResolutionById = useMemo(
        () => buildQuarantineResolutionMap(
            quarantinedItems,
            trustedSnapshotItemsById,
            quarantineActionStateById,
        ),
        [quarantinedItems, quarantineActionStateById, trustedSnapshotItemsById],
    );

    const detectUnreadableCategories = useCallback(async (
        snapshot: OfflineVaultSnapshot,
        activeKey: CryptoKey,
    ): Promise<VaultIntegrityBlockedReason | null> => {
        const encryptedCategoryPrefix = 'enc:cat:v1:';

        for (const category of snapshot.categories) {
            const encryptedFields = [category.name, category.icon, category.color]
                .filter((value): value is string => typeof value === 'string' && value.startsWith(encryptedCategoryPrefix))
                .map((value) => value.slice(encryptedCategoryPrefix.length));

            for (const encryptedField of encryptedFields) {
                try {
                    await decrypt(encryptedField, activeKey);
                } catch {
                    return 'category_structure_mismatch';
                }
            }
        }

        return null;
    }, []);

    const mergeQuarantinedItems = useCallback((
        ...groups: QuarantinedVaultItem[][]
    ): QuarantinedVaultItem[] => {
        const merged = new Map<string, QuarantinedVaultItem>();

        for (const group of groups) {
            for (const item of group) {
                const existing = merged.get(item.id);
                if (!existing || (item.updatedAt ?? '') > (existing.updatedAt ?? '')) {
                    merged.set(item.id, item);
                }
            }
        }

        return [...merged.values()].sort((left, right) => {
            const leftDate = left.updatedAt ?? '';
            const rightDate = right.updatedAt ?? '';
            return rightDate.localeCompare(leftDate) || left.id.localeCompare(right.id);
        });
    }, []);

    const assessVaultIntegrity = useCallback(async (
        snapshot: OfflineVaultSnapshot,
        activeKey: CryptoKey,
    ): Promise<VaultIntegrityAssessment> => {
        if (!user) {
            throw new Error('No active user session');
        }

        const inspection = await inspectVaultSnapshotIntegrity(
            user.id,
            buildIntegritySnapshot(snapshot),
            activeKey,
        );
        const baseResult = toVaultIntegrityVerificationResult(inspection);

        if (baseResult.mode === 'blocked') {
            return {
                inspection,
                unreadableCategoryReason: null,
                result: baseResult,
            };
        }

        const categoryIssue = await detectUnreadableCategories(snapshot, activeKey);
        if (categoryIssue) {
            return {
                inspection,
                unreadableCategoryReason: categoryIssue,
                result: {
                    ...baseResult,
                    valid: false,
                    mode: 'blocked',
                    blockedReason: categoryIssue,
                    quarantinedItems: [],
                },
            };
        }

        const quarantinedItems = baseResult.quarantinedItems;
        if (quarantinedItems.length > 0) {
            return {
                inspection,
                unreadableCategoryReason: null,
                result: {
                    ...baseResult,
                    valid: true,
                    mode: 'quarantine',
                    blockedReason: undefined,
                    quarantinedItems,
                },
            };
        }

        return {
            inspection,
            unreadableCategoryReason: null,
            result: {
                ...baseResult,
                valid: true,
                mode: 'healthy',
                blockedReason: undefined,
                quarantinedItems: [],
            },
        };
    }, [
        buildIntegritySnapshot,
        detectUnreadableCategories,
        user,
    ]);

    const buildDisplayedIntegrityResult = useCallback((
        result: VaultIntegrityVerificationResult | null,
        runtimeUnreadableItems: QuarantinedVaultItem[] = runtimeUnreadableItemsRef.current,
    ): VaultIntegrityVerificationResult | null => {
        if (!result) {
            if (runtimeUnreadableItems.length === 0) {
                return null;
            }

            return {
                valid: true,
                isFirstCheck: false,
                computedRoot: '',
                itemCount: runtimeUnreadableItems.length,
                categoryCount: 0,
                mode: 'quarantine',
                quarantinedItems: runtimeUnreadableItems,
            };
        }

        const mergedItems = mergeQuarantinedItems(result.quarantinedItems, runtimeUnreadableItems);
        if (mergedItems.length === 0) {
            return {
                ...result,
                quarantinedItems: [],
            };
        }

        if (result.mode === 'blocked') {
            return {
                ...result,
                quarantinedItems: mergedItems,
            };
        }

        return {
            ...result,
            valid: true,
            mode: 'quarantine',
            blockedReason: undefined,
            quarantinedItems: mergedItems,
        };
    }, [mergeQuarantinedItems]);

    const applyDisplayedIntegrityState = useCallback((
        result: VaultIntegrityVerificationResult | null,
        runtimeUnreadableItems: QuarantinedVaultItem[] = runtimeUnreadableItemsRef.current,
    ): void => {
        const displayedResult = buildDisplayedIntegrityResult(result, runtimeUnreadableItems);
        setIntegrityVerified(displayedResult !== null);
        setLastIntegrityResult(displayedResult);
        setIntegrityMode(displayedResult?.mode ?? 'healthy');
        setQuarantinedItems(displayedResult?.quarantinedItems ?? []);
        setIntegrityBlockedReason(
            displayedResult?.mode === 'blocked'
                ? displayedResult.blockedReason ?? null
                : null,
        );
    }, [buildDisplayedIntegrityResult]);

    const applyIntegrityResultState = useCallback((result: VaultIntegrityVerificationResult): void => {
        baseIntegrityResultRef.current = result;
        applyDisplayedIntegrityState(result);
    }, [applyDisplayedIntegrityState]);

    useEffect(() => {
        setQuarantineActionStateById((currentState) => {
            const activeItemIds = new Set(quarantinedItems.map((item) => item.id));
            const nextState = Object.fromEntries(
                Object.entries(currentState).filter(([itemId]) => activeItemIds.has(itemId)),
            );

            return Object.keys(nextState).length === Object.keys(currentState).length
                ? currentState
                : nextState;
        });
    }, [quarantinedItems]);

    const reportUnreadableItems = useCallback((items: QuarantinedVaultItem[]): void => {
        runtimeUnreadableItemsRef.current = items;
        applyDisplayedIntegrityState(baseIntegrityResultRef.current, items);
    }, [applyDisplayedIntegrityState]);

    const persistMissingOrLegacyBaseline = useCallback(async (
        integritySnapshot: VaultIntegritySnapshot,
        activeKey: CryptoKey,
        inspection: VaultIntegrityBaselineInspection,
    ): Promise<void> => {
        if (!user || inspection.snapshotValidationError || inspection.legacyBaselineMismatch) {
            return;
        }

        if (inspection.baselineKind === 'missing' || inspection.baselineKind === 'v1') {
            await persistIntegrityBaseline(
                user.id,
                integritySnapshot,
                activeKey,
                inspection.digest,
            );
        }
    }, [user]);

    const runQuarantineAction = useCallback(async (
        itemId: string,
        action: () => Promise<void>,
    ): Promise<{ error: Error | null }> => {
        setQuarantineActionStateById((currentState) => ({
            ...currentState,
            [itemId]: {
                isBusy: true,
                lastError: null,
            },
        }));

        try {
            await action();
            const nextRuntimeUnreadableItems = runtimeUnreadableItemsRef.current.filter(
                (item) => item.id !== itemId,
            );
            if (nextRuntimeUnreadableItems.length !== runtimeUnreadableItemsRef.current.length) {
                runtimeUnreadableItemsRef.current = nextRuntimeUnreadableItems;
                applyDisplayedIntegrityState(baseIntegrityResultRef.current, nextRuntimeUnreadableItems);
            }
            setQuarantineActionStateById((currentState) => ({
                ...currentState,
                [itemId]: {
                    isBusy: false,
                    lastError: null,
                },
            }));
            return { error: null };
        } catch (error) {
            const resolvedError = error instanceof Error
                ? error
                : new Error('Quarantäne-Aktion fehlgeschlagen.');

            setQuarantineActionStateById((currentState) => ({
                ...currentState,
                [itemId]: {
                    isBusy: false,
                    lastError: resolvedError.message,
                },
            }));
            return { error: resolvedError };
        }
    }, [applyDisplayedIntegrityState]);

    const bumpVaultDataVersion = useCallback(() => {
        setVaultDataVersion((currentVersion) => currentVersion + 1);
    }, []);

    const setBlockedIntegrityState = useCallback(async (
        activeKey: CryptoKey,
        blockedReason: VaultIntegrityBlockedReason,
        result?: VaultIntegrityVerificationResult | null,
    ) => {
        const displayedResult = buildDisplayedIntegrityResult(result ?? null);
        setEncryptionKey(activeKey);
        setIsLocked(true);
        setIsDuressMode(false);
        setPendingSessionRestore(false);
        setIntegrityVerified(true);
        baseIntegrityResultRef.current = result ?? null;
        setIntegrityMode('blocked');
        setIntegrityBlockedReason(blockedReason);
        setQuarantinedItems(displayedResult?.quarantinedItems ?? []);
        setLastIntegrityResult(displayedResult);
        setLastActivity(Date.now());
        sessionStorage.removeItem(SESSION_KEY);
        sessionStorage.removeItem(SESSION_TIMESTAMP_KEY);
        sessionStorage.removeItem(SESSION_PASSWORD_HINT_KEY);
        await syncTrustedRecoverySnapshotState(user!.id);
    }, [buildDisplayedIntegrityResult, syncTrustedRecoverySnapshotState, user]);

    const finalizeVaultUnlock = useCallback(async (
        activeKey: CryptoKey,
    ): Promise<{ error: Error | null }> => {
        if (!user) {
            return { error: new Error('No active user session') };
        }

        try {
            const snapshotBundle = await loadCurrentIntegritySnapshot({
                persistRemoteSnapshot: false,
            });
            if (!snapshotBundle) {
                return { error: new Error('Vault snapshot unavailable') };
            }

            const integrityAssessment = await assessVaultIntegrity(snapshotBundle.rawSnapshot, activeKey);
            const integrityResult = integrityAssessment.result;

            if (integrityResult.mode === 'quarantine' && snapshotBundle.source === 'remote') {
                const trustedRemoteMutation = await buildDecryptableRemoteRebaselineMutation(
                    integrityAssessment,
                    snapshotBundle.rawSnapshot,
                    activeKey,
                );
                if (trustedRemoteMutation) {
                    const digest = await persistIntegrityBaseline(
                        user.id,
                        snapshotBundle.integritySnapshot,
                        activeKey,
                        integrityAssessment.inspection.digest,
                    );
                    await persistTrustedIntegritySnapshot(snapshotBundle.rawSnapshot);
                    applyIntegrityResultState({
                        valid: true,
                        isFirstCheck: false,
                        computedRoot: digest,
                        storedRoot: digest,
                        itemCount: snapshotBundle.integritySnapshot.items.length,
                        categoryCount: snapshotBundle.integritySnapshot.categories.length,
                        mode: 'healthy',
                        quarantinedItems: [],
                    });
                    setEncryptionKey(activeKey);
                    setIsLocked(false);
                    setIsDuressMode(false);
                    setIntegrityBlockedReason(null);
                    setLastActivity(Date.now());
                    sessionStorage.setItem(SESSION_KEY, 'active');
                    sessionStorage.setItem(SESSION_TIMESTAMP_KEY, Date.now().toString());
                    setPendingSessionRestore(false);
                    return { error: null };
                }
            }

            applyIntegrityResultState(integrityResult);

            if (integrityResult.mode === 'blocked') {
                await setBlockedIntegrityState(
                    activeKey,
                    integrityResult.blockedReason ?? 'snapshot_malformed',
                    integrityResult,
                );
                return {
                    error: new Error(
                        'Die Integritätsprüfung des Tresors ist fehlgeschlagen. Safe Mode oder Reset ist erforderlich.',
                    ),
                };
            }

            if (integrityResult.mode === 'healthy') {
                if (canPersistIntegrityBaselineImmediately(integrityAssessment, snapshotBundle.rawSnapshot)) {
                    await persistMissingOrLegacyBaseline(
                        snapshotBundle.integritySnapshot,
                        activeKey,
                        integrityAssessment.inspection,
                    );
                    await persistTrustedIntegritySnapshot(snapshotBundle.rawSnapshot);
                }
            } else {
                await syncTrustedRecoverySnapshotState(user.id);
            }
        } catch (error) {
            if (error instanceof VaultIntegrityBaselineError) {
                await setBlockedIntegrityState(activeKey, 'baseline_unreadable');
                return {
                    error: new Error(
                        'Der lokale Integritätszustand des Tresors ist unlesbar. Safe Mode oder Reset ist erforderlich.',
                    ),
                };
            }
            return {
                error: error instanceof Error
                    ? error
                    : new Error('Vault integrity verification failed.'),
            };
        }

        setEncryptionKey(activeKey);
        setIsLocked(false);
        setIsDuressMode(false);
        setIntegrityBlockedReason(null);
        setLastActivity(Date.now());
        sessionStorage.setItem(SESSION_KEY, 'active');
        sessionStorage.setItem(SESSION_TIMESTAMP_KEY, Date.now().toString());
        setPendingSessionRestore(false);

        return { error: null };
    }, [
        applyIntegrityResultState,
        assessVaultIntegrity,
        loadCurrentIntegritySnapshot,
        persistMissingOrLegacyBaseline,
        persistTrustedIntegritySnapshot,
        setBlockedIntegrityState,
        syncTrustedRecoverySnapshotState,
        user,
    ]);

    const enforceVaultTwoFactorBeforeKeyRelease = useCallback(async (
        options?: VaultUnlockOptions,
    ): Promise<{ error: Error | null }> => {
        if (!user) {
            return { error: new Error('No active user session') };
        }

        if (!isAppOnline()) {
            const cachedRequired = await getOfflineVaultTwoFactorRequirement(user.id);
            if (cachedRequired === false) {
                return { error: null };
            }

            return {
                error: new Error(
                    cachedRequired === true
                        ? 'Vault 2FA is required and must be verified online before offline unlock.'
                        : 'Vault 2FA status is not cached. Unlock online once before using this vault offline.',
                ),
            };
        }

        const requirement = await getTwoFactorRequirement({
            userId: user.id,
            context: 'vault_unlock',
        });

        if (requirement.status === 'unavailable') {
            return { error: new Error('Vault 2FA status unavailable. Vault remains locked.') };
        }

        if (!requirement.required) {
            await saveOfflineVaultTwoFactorRequirement(user.id, false);
            return { error: null };
        }

        if (!options?.verifyTwoFactor) {
            return { error: new Error('Vault 2FA verification required before unlock.') };
        }

        const verified = await options.verifyTwoFactor();
        if (!verified) {
            return { error: new Error('Vault 2FA verification failed.') };
        }

        await saveOfflineVaultTwoFactorRequirement(user.id, true);
        return { error: null };
    }, [user]);

    const refreshIntegrityBaseline = useCallback(async (
        trustedMutation?: TrustedVaultMutation,
    ): Promise<void> => {
        if (!user || !encryptionKey) {
            return;
        }

        const normalizedTrustedMutation = normalizeTrustedVaultMutation(trustedMutation);
        const snapshotBundle = await loadCurrentIntegritySnapshot({
            // Trusted writes update IndexedDB before re-baselining. The offline
            // service overlays only those fresh local rows onto the remote
            // snapshot, preserving the rest of the vault while Supabase catches up.
            useLocalMutationOverlay: hasTrustedMutationScope(normalizedTrustedMutation),
        });
        if (!snapshotBundle) {
            return;
        }

        const integrityAssessment = await assessVaultIntegrity(snapshotBundle.rawSnapshot, encryptionKey);
        const integrityResult = integrityAssessment.result;
        const trustedRebaselineAllowed = canRebaselineTrustedMutation(
            integrityAssessment,
            normalizedTrustedMutation,
        );
        const trustedFirstBaselineAllowed = integrityAssessment.inspection.baselineKind === 'missing'
            && snapshotBundle.rawSnapshot.items.every((item) => normalizedTrustedMutation.itemIds.has(item.id))
            && snapshotBundle.rawSnapshot.categories.every((category) => normalizedTrustedMutation.categoryIds.has(category.id));

        if (
            integrityResult.mode === 'quarantine'
            && !trustedRebaselineAllowed
            && !trustedFirstBaselineAllowed
            && hasTrustedDrift(integrityAssessment, normalizedTrustedMutation)
        ) {
            const selectiveDigest = await persistTrustedMutationIntegrityBaseline(
                user.id,
                snapshotBundle.integritySnapshot,
                encryptionKey,
                normalizedTrustedMutation,
            );
            if (selectiveDigest) {
                const reassessment = await assessVaultIntegrity(snapshotBundle.rawSnapshot, encryptionKey);
                const reassessedResult = reassessment.result;
                if (reassessedResult.mode === 'quarantine') {
                    applyIntegrityResultState(reassessedResult);
                    await syncTrustedRecoverySnapshotState(user.id);
                    bumpVaultDataVersion();
                    return;
                }
                if (reassessedResult.mode === 'healthy') {
                    await persistTrustedIntegritySnapshot(snapshotBundle.rawSnapshot);
                    applyIntegrityResultState({
                        valid: true,
                        isFirstCheck: false,
                        computedRoot: selectiveDigest,
                        storedRoot: selectiveDigest,
                        itemCount: snapshotBundle.integritySnapshot.items.length,
                        categoryCount: snapshotBundle.integritySnapshot.categories.length,
                        mode: 'healthy',
                        quarantinedItems: [],
                    });
                    bumpVaultDataVersion();
                    return;
                }
            }
        }

        if (integrityResult.mode === 'blocked' && !trustedRebaselineAllowed && !trustedFirstBaselineAllowed) {
            await setBlockedIntegrityState(
                encryptionKey,
                integrityResult.blockedReason ?? 'snapshot_malformed',
                integrityResult,
            );
            return;
        }

        if (integrityResult.mode === 'quarantine' && !trustedRebaselineAllowed && !trustedFirstBaselineAllowed) {
            applyIntegrityResultState(integrityResult);
            await syncTrustedRecoverySnapshotState(user.id);
            return;
        }

        if (integrityAssessment.inspection.baselineKind === 'missing' && !trustedFirstBaselineAllowed) {
            applyIntegrityResultState(integrityResult);
            return;
        }

        const digest = await persistIntegrityBaseline(
            user.id,
            snapshotBundle.integritySnapshot,
            encryptionKey,
            integrityAssessment.inspection.digest,
        );
        await persistTrustedIntegritySnapshot(snapshotBundle.rawSnapshot);
        applyIntegrityResultState({
            valid: true,
            isFirstCheck: false,
            computedRoot: digest,
            storedRoot: digest,
            itemCount: snapshotBundle.integritySnapshot.items.length,
            categoryCount: snapshotBundle.integritySnapshot.categories.length,
            mode: 'healthy',
            quarantinedItems: [],
        });
        bumpVaultDataVersion();
    }, [
        applyIntegrityResultState,
        assessVaultIntegrity,
        bumpVaultDataVersion,
        encryptionKey,
        loadCurrentIntegritySnapshot,
        persistTrustedIntegritySnapshot,
        setBlockedIntegrityState,
        syncTrustedRecoverySnapshotState,
        user,
    ]);

    const backfillVerificationHash = useCallback(async (
        activeKey: CryptoKey,
    ): Promise<string | null> => {
        if (!user || !salt) {
            return null;
        }

        const newVerifier = await createVerificationHash(activeKey);
        const { error } = await supabase
            .from('profiles')
            .update({ master_password_verifier: newVerifier } as Record<string, unknown>)
            .eq('user_id', user.id);

        if (error) {
            console.warn('Failed to backfill missing verifier:', error);
            return null;
        }

        setVerificationHash(newVerifier);
        await saveOfflineCredentials(user.id, salt, newVerifier, kdfVersion, encryptedUserKey);
        return newVerifier;
    }, [encryptedUserKey, kdfVersion, salt, user]);

    const recoverLegacyKeyWithoutVerifier = useCallback(async (
        candidateKey: CryptoKey,
    ): Promise<boolean> => {
        if (!user) {
            return false;
        }

        const { data: probeItems } = await supabase
            .from('vault_items')
            .select('id, encrypted_data')
            .eq('user_id', user.id)
            .order('created_at', { ascending: true })
            .limit(1);

        if (probeItems && probeItems.length > 0) {
            try {
                await decryptVaultItem(probeItems[0].encrypted_data, candidateKey, probeItems[0].id);
                return true;
            } catch {
                return false;
            }
        }

        const { data: probeCategories } = await supabase
            .from('categories')
            .select('name, icon, color')
            .eq('user_id', user.id)
            .order('created_at', { ascending: true })
            .limit(1);

        const category = probeCategories?.[0];
        if (!category) {
            // Legacy vaults without any encrypted payload cannot be distinguished
            // cryptographically. Allow migration so they can re-establish a verifier.
            return true;
        }

        const encryptedFields = [category.name, category.icon, category.color]
            .filter((value): value is string => typeof value === 'string' && value.startsWith('enc:cat:v1:'))
            .map((value) => value.slice('enc:cat:v1:'.length));

        if (encryptedFields.length === 0) {
            return true;
        }

        for (const encryptedField of encryptedFields) {
            try {
                await decrypt(encryptedField, candidateKey);
                return true;
            } catch {
                continue;
            }
        }

        return false;
    }, [user]);

    const migrateLegacyVaultToUserKey = useCallback(async (
        kdfOutputBytes: Uint8Array,
    ): Promise<{
        userKey: CryptoKey;
        verifier: string;
        encryptedUserKey: string;
        persisted: boolean;
    }> => {
        if (!user || !salt) {
            throw new Error('Vault migration requires an active user and salt');
        }

        const uskBundle = await migrateToUserKey(kdfOutputBytes);
        const newVerifier = await createVerificationHash(uskBundle.userKey);

        try {
            const { error: uskError } = await supabase
                .from('profiles')
                .update({
                    encrypted_user_key: uskBundle.encryptedUserKey,
                    master_password_verifier: newVerifier,
                } as Record<string, unknown>)
                .eq('user_id', user.id);

            if (uskError) {
                console.warn('USK migration: DB write failed, will retry next unlock.', uskError);
                return {
                    userKey: uskBundle.userKey,
                    verifier: newVerifier,
                    encryptedUserKey: uskBundle.encryptedUserKey,
                    persisted: false,
                };
            }

            setEncryptedUserKey(uskBundle.encryptedUserKey);
            setVerificationHash(newVerifier);
            await saveOfflineCredentials(
                user.id,
                salt,
                newVerifier,
                kdfVersion,
                uskBundle.encryptedUserKey,
            );
            console.info('USK migration complete: encrypted_user_key persisted.');

            return {
                userKey: uskBundle.userKey,
                verifier: newVerifier,
                encryptedUserKey: uskBundle.encryptedUserKey,
                persisted: true,
            };
        } catch (uskErr) {
            console.warn('USK migration: unexpected failure, will retry next unlock.', uskErr);
            return {
                userKey: uskBundle.userKey,
                verifier: newVerifier,
                encryptedUserKey: uskBundle.encryptedUserKey,
                persisted: false,
            };
        }
    }, [kdfVersion, salt, user]);

    // Check if master password is set up
    useEffect(() => {
        async function checkSetup() {
            // Case A: No user session â€” definitively nothing to load.
            // End loading so the UI can show the sign-in screen.
            if (!user) {
                setHasPasskeyUnlock(false);
                setIsLoading(false);
                return;
            }

            // Case B: User present but auth not yet fully synchronized
            // (INITIAL_SESSION fired before getSession() resolved).
            // Keep isLoading=true â€” checkSetup() will run once authReady flips,
            // thanks to authReady being in the dep array. Showing a spinner here
            // is correct; setting isLoading=false would cause a stale-defaults flash.
            if (!authReady) {
                return;
            }

            console.debug('[VaultContext] authReady is true, fetching user profiles...');

            if (isTauriDevUserId(user.id)) {
                if (await applyCachedVaultCredentials(user.id)) {
                    await ensureTauriDevVaultSnapshot(user.id);
                } else {
                    setIsSetupRequired(true);
                    setIsLocked(true);
                }
                setDeviceKeyActive(false);
                setCurrentDeviceKey(null);
                setIsLoading(false);
                return;
            }

            // ============ Offline-First: skip network if offline ============
            if (!isAppOnline()) {
                console.debug('[VaultContext] App is offline, loading cached credentials...');
                if (await applyCachedVaultCredentials(user.id)) {
                    setIsLoading(false);
                    return;
                }
                // Without a trusted local snapshot, offline clients cannot prove
                // that no master password exists. Fail closed and keep setup hidden.
                setIsSetupRequired(false);
                setIsLocked(true);
                setIsLoading(false);
                return;
            }

            // ============ Online path ============
            try {
                // NOTE: kdf_version may not exist in generated Supabase types until
                // types are regenerated. Using explicit column list + type assertion.
                const { data: profile, error } = await supabase
                    .from('profiles')
                    .select('encryption_salt, master_password_verifier, kdf_version, encrypted_user_key')
                    .eq('user_id', user.id)
                    .maybeSingle() as { data: Record<string, unknown> | null; error: unknown };

                if (error || !profile?.encryption_salt) {
                    // No profile found â€” try cache fallback for any error
                    if (await applyCachedVaultCredentials(user.id)) {
                        setIsLoading(false);
                        return;
                    }
                    if (error) {
                        console.warn('[VaultContext] Vault setup check failed; keeping setup flow hidden until state is known.', error);
                        setIsSetupRequired(false);
                    } else {
                        // A successful profile read with no encryption salt is the only
                        // normal web/PWA path that may offer first-time setup.
                        setIsSetupRequired(true);
                    }
                    setIsLocked(true);
                } else {
                    const profileKdfVersion = (profile.kdf_version as number) ?? 1;
                    const profileEncryptedUserKey = (profile.encrypted_user_key as string) || null;
                    setIsSetupRequired(false);
                    setSalt(profile.encryption_salt as string);
                    setVerificationHash((profile.master_password_verifier as string) || null);
                    setKdfVersion(profileKdfVersion);
                    setEncryptedUserKey(profileEncryptedUserKey);
                    // Cache credentials (including kdfVersion and encryptedUserKey) for offline use
                    await saveOfflineCredentials(
                        user.id,
                        profile.encryption_salt as string,
                        (profile.master_password_verifier as string) || null,
                        profileKdfVersion,
                        profileEncryptedUserKey,
                    );

                    await refreshPasskeyUnlockStatus();

                    // Load duress (panic password) configuration via premium hook
                    const hooks = getServiceHooks();
                    if (hooks.getDuressConfig) {
                        try {
                            const duress = await hooks.getDuressConfig(user.id);
                            setDuressConfig(duress);
                        } catch {
                            // Non-fatal: duress config can fail silently
                        }
                    }

                    // Check if device key exists on this device
                    try {
                        const hasDK = await checkHasDeviceKey(user.id);
                        setDeviceKeyActive(hasDK);
                        if (hasDK) {
                            const dk = await loadDeviceKey(user.id);
                            setCurrentDeviceKey(dk);
                        }
                    } catch {
                        // Non-fatal: device key check can fail silently
                    }
                }
            } catch (err) {
                console.error('Error checking vault setup:', err);
                // Robust fallback: try cache on ANY error (not just offline errors)
                if (await applyCachedVaultCredentials(user.id)) {
                    setIsLoading(false);
                    return;
                }
                setIsSetupRequired(false);
                setIsLocked(true);
            } finally {
                setIsLoading(false);
            }
        }

        checkSetup();
    }, [user, authReady, webAuthnAvailable, refreshPasskeyUnlockStatus, applyCachedVaultCredentials, connectivityCheckNonce]); // authReady required â€” stale closure fix

    // Auto-lock on inactivity
    useEffect(() => {
        if (isLocked || !encryptionKey) return;

        const checkInactivity = setInterval(() => {
            const timeSinceActivity = Date.now() - lastActivity;
            if (timeSinceActivity >= autoLockTimeout) {
                lock();
            }
        }, 10000); // Check every 10 seconds

        return () => clearInterval(checkInactivity);
        // eslint-disable-next-line react-hooks/exhaustive-deps -- lock is defined later via useCallback with stable identity
    }, [isLocked, encryptionKey, lastActivity, autoLockTimeout]);

    // Track user activity
    useEffect(() => {
        if (isLocked) return;

        const updateActivity = () => setLastActivity(Date.now());

        const events = ['mousedown', 'keydown', 'scroll', 'touchstart'];
        events.forEach(event => {
            document.addEventListener(event, updateActivity, { passive: true });
        });

        return () => {
            events.forEach(event => {
                document.removeEventListener(event, updateActivity);
            });
        };
    }, [isLocked]);

    /**
     * Sets up the master password for first-time users
     */
    const setupMasterPassword = useCallback(async (
        masterPassword: string
    ): Promise<{ error: Error | null }> => {
        if (!user) {
            return { error: new Error('No user logged in') };
        }

        try {
            const cached = await getOfflineCredentials(user.id);
            if (cached) {
                await applyCachedVaultCredentials(user.id);
                return { error: new Error('Master password is already set for this account.') };
            }

            if (!isTauriDevUserId(user.id)) {
                const { data: existingProfile, error: existingProfileError } = await supabase
                    .from('profiles')
                    .select('encryption_salt')
                    .eq('user_id', user.id)
                    .maybeSingle() as { data: Record<string, unknown> | null; error: unknown };

                if (existingProfileError) {
                    return { error: new Error('Could not verify current master password state. Please try again online.') };
                }

                if (existingProfile?.encryption_salt) {
                    setIsSetupRequired(false);
                    setSalt(existingProfile.encryption_salt as string);
                    return { error: new Error('Master password is already set for this account.') };
                }
            }

            // Generate new salt
            const newSalt = generateSalt();

            // Derive raw KDF bytes (new users start on latest KDF version)
            const kdfOutputBytes = await deriveRawKey(masterPassword, newSalt, CURRENT_KDF_VERSION);
            let uskBundle: Awaited<ReturnType<typeof createEncryptedUserKey>>;
            try {
                // â”€â”€ USK: create random UserKey, wrap under HKDF-derived wrapKey â”€â”€
                uskBundle = await createEncryptedUserKey(kdfOutputBytes);
            } finally {
                kdfOutputBytes.fill(0);
            }

            // Create verification hash from the UserKey (not raw KDF bytes)
            const verifyHash = await createVerificationHash(uskBundle.userKey);

            if (isTauriDevUserId(user.id)) {
                setSalt(newSalt);
                setVerificationHash(verifyHash);
                setEncryptedUserKey(uskBundle.encryptedUserKey);
                setKdfVersion(CURRENT_KDF_VERSION);
                setIsSetupRequired(false);

                await saveOfflineCredentials(
                    user.id,
                    newSalt,
                    verifyHash,
                    CURRENT_KDF_VERSION,
                    uskBundle.encryptedUserKey,
                );
                await ensureTauriDevVaultSnapshot(user.id);
                return finalizeVaultUnlock(uskBundle.userKey);
            }

            // Create default vault
            const { data: existingVault } = await supabase
                .from('vaults')
                .select('id')
                .eq('user_id', user.id)
                .eq('is_default', true)
                .single();

            if (!existingVault) {
                await supabase.from('vaults').insert({
                    user_id: user.id,
                    name: 'Encrypted Vault',
                    is_default: true,
                });
            }

            // Save salt, verifier, KDF version, and encrypted UserKey to profile
            const { error: updateError } = await supabase
                .from('profiles')
                .update({
                    encryption_salt: newSalt,
                    master_password_verifier: verifyHash,
                    kdf_version: CURRENT_KDF_VERSION,
                    encrypted_user_key: uskBundle.encryptedUserKey,
                } as Record<string, unknown>)
                .eq('user_id', user.id);

            if (updateError) {
                return { error: new Error(updateError.message) };
            }

            // Update state
            setSalt(newSalt);
            setVerificationHash(verifyHash);
            setEncryptedUserKey(uskBundle.encryptedUserKey);
            setKdfVersion(CURRENT_KDF_VERSION);
            setIsSetupRequired(false);

            // Cache credentials for offline use (including encryptedUserKey)
            await saveOfflineCredentials(user.id, newSalt, verifyHash, CURRENT_KDF_VERSION, uskBundle.encryptedUserKey);
            return finalizeVaultUnlock(uskBundle.userKey);
        } catch (err) {
            console.error('Error setting up master password:', err);
            return { error: err as Error };
        }
    }, [applyCachedVaultCredentials, finalizeVaultUnlock, user]);

    /**
     * Unlocks the vault with the master password.
     * Enforces client-side rate limiting with exponential backoff.
     * 
     * If duress mode is enabled and the entered password matches the duress
     * password (not the real one), the vault opens in duress mode showing
     * only decoy items.
     */
    const unlock = useCallback(async (
        masterPassword: string,
        options?: VaultUnlockOptions,
    ): Promise<{ error: Error | null }> => {
        if (!user || !salt) {
            return { error: new Error('Vault not set up') };
        }

        const cooldown = getUnlockCooldown();
        if (cooldown !== null) {
            const seconds = Math.ceil(cooldown / 1000);
            return { error: new Error(`Too many attempts. Try again in ${seconds}s.`) };
        }

        const verifier = verificationHash;

        try {
            if (duressConfig?.enabled && getServiceHooks().attemptDualUnlock) {
                if (!verifier) {
                    return { error: new Error('Duress unlock requires a current verifier. Please unlock online once with your master password.') };
                }

                const result = await getServiceHooks().attemptDualUnlock!(
                    masterPassword,
                    salt,
                    verifier,
                    kdfVersion,
                    duressConfig,
                );

                if (result.mode === 'invalid') {
                    recordFailedAttempt();
                    return { error: new Error('Invalid master password') };
                }

                resetUnlockAttempts();

                if (result.mode === 'duress') {
                    const twoFactorResult = await enforceVaultTwoFactorBeforeKeyRelease(options);
                    if (twoFactorResult.error) {
                        return twoFactorResult;
                    }

                    setEncryptionKey(result.key);
                    setIsDuressMode(true);
                    setIsLocked(false);
                    setIntegrityVerified(false);
                    baseIntegrityResultRef.current = null;
                    setLastIntegrityResult(null);
                    setIntegrityMode('healthy');
                    setQuarantinedItems([]);
                    runtimeUnreadableItemsRef.current = [];
                    setIntegrityBlockedReason(null);
                    setLastActivity(Date.now());
                    sessionStorage.setItem(SESSION_KEY, 'active');
                    sessionStorage.setItem(SESSION_TIMESTAMP_KEY, Date.now().toString());
                    setPendingSessionRestore(false);
                    return { error: null };
                }

                let activeKey = result.key!;
                let shouldBackfillVerifier = !verificationHash;

                try {
                    const upgrade = await attemptKdfUpgrade(masterPassword, salt, kdfVersion);
                    if (upgrade.upgraded && upgrade.newKey && upgrade.newVerifier) {
                        try {
                            const { data: vaultItems } = await supabase
                                .from('vault_items')
                                .select('id, encrypted_data')
                                .eq('user_id', user.id);

                            const { data: categories } = await supabase
                                .from('categories')
                                .select('id, name, icon, color')
                                .eq('user_id', user.id);

                            const reEncResult = await reEncryptVault(
                                vaultItems || [],
                                categories || [],
                                result.key!,
                                upgrade.newKey,
                            );

                            for (const itemUpdate of reEncResult.itemUpdates) {
                                const { error: itemError } = await supabase
                                    .from('vault_items')
                                    .update({ encrypted_data: itemUpdate.encrypted_data })
                                    .eq('id', itemUpdate.id)
                                    .eq('user_id', user.id);
                                if (itemError) {
                                    throw new Error(`Failed to update item ${itemUpdate.id}: ${itemError.message}`);
                                }
                            }

                            for (const catUpdate of reEncResult.categoryUpdates) {
                                const { error: catError } = await supabase
                                    .from('categories')
                                    .update({ name: catUpdate.name, icon: catUpdate.icon, color: catUpdate.color })
                                    .eq('id', catUpdate.id)
                                    .eq('user_id', user.id);
                                if (catError) {
                                    throw new Error(`Failed to update category ${catUpdate.id}: ${catError.message}`);
                                }
                            }

                            const { error: upgradeError } = await supabase
                                .from('profiles')
                                .update({
                                    master_password_verifier: upgrade.newVerifier,
                                    kdf_version: upgrade.activeVersion,
                                } as Record<string, unknown>)
                                .eq('user_id', user.id);

                            if (!upgradeError) {
                                activeKey = upgrade.newKey;
                                setVerificationHash(upgrade.newVerifier);
                                setKdfVersion(upgrade.activeVersion);
                                await saveOfflineCredentials(
                                    user.id,
                                    salt,
                                    upgrade.newVerifier,
                                    upgrade.activeVersion,
                                    encryptedUserKey,
                                );
                                shouldBackfillVerifier = false;
                                console.info(
                                    `KDF upgraded from v${kdfVersion} to v${upgrade.activeVersion}. ` +
                                    `Re-encrypted ${reEncResult.itemsReEncrypted} items and ` +
                                    `${reEncResult.categoriesReEncrypted} categories.`
                                );
                            }
                        } catch (reEncErr) {
                            console.warn('KDF upgrade: re-encryption failed, staying on old version', reEncErr);
                        }
                    }
                } catch {
                    console.warn('KDF upgrade failed, continuing with current version');
                }

                if (!isTauriDevUserId(user.id) && kdfVersion >= 2) {
                    try {
                        const { data: probeItems } = await supabase
                            .from('vault_items')
                            .select('id, encrypted_data')
                            .eq('user_id', user.id)
                            .order('created_at', { ascending: true })
                            .limit(5);

                        const { data: probeCategories } = await supabase
                            .from('categories')
                            .select('id, name, icon, color')
                            .eq('user_id', user.id)
                            .order('created_at', { ascending: true })
                            .limit(5);

                        const encryptedCategoryPrefix = 'enc:cat:v1:';
                        let needsFullRepair = false;

                        if (probeItems) {
                            for (const item of probeItems) {
                                try {
                                    await decryptVaultItem(item.encrypted_data, activeKey, item.id);
                                } catch {
                                    needsFullRepair = true;
                                    break;
                                }
                            }
                        }

                        if (!needsFullRepair && probeCategories) {
                            for (const cat of probeCategories) {
                                try {
                                    if (cat.name.startsWith(encryptedCategoryPrefix)) {
                                        await decrypt(cat.name.slice(encryptedCategoryPrefix.length), activeKey);
                                    }
                                    if (cat.icon && cat.icon.startsWith(encryptedCategoryPrefix)) {
                                        await decrypt(cat.icon.slice(encryptedCategoryPrefix.length), activeKey);
                                    }
                                    if (cat.color && cat.color.startsWith(encryptedCategoryPrefix)) {
                                        await decrypt(cat.color.slice(encryptedCategoryPrefix.length), activeKey);
                                    }
                                } catch {
                                    needsFullRepair = true;
                                    break;
                                }
                            }
                        }

                        if (needsFullRepair) {
                            console.warn('Detected broken KDF upgrade in sample (duress path). Starting full vault scan and repair...');

                            const { data: allItems } = await supabase
                                .from('vault_items')
                                .select('id, encrypted_data')
                                .eq('user_id', user.id);

                            const { data: allCategories } = await supabase
                                .from('categories')
                                .select('id, name, icon, color')
                                .eq('user_id', user.id);

                            if ((allItems && allItems.length > 0) || (allCategories && allCategories.length > 0)) {
                                const brokenItems = [];
                                const brokenCategories = [];

                                if (allItems) {
                                    for (const item of allItems) {
                                        try {
                                            await decryptVaultItem(item.encrypted_data, activeKey, item.id);
                                        } catch {
                                            brokenItems.push(item);
                                        }
                                    }
                                }

                                if (allCategories) {
                                    for (const cat of allCategories) {
                                        try {
                                            if (cat.name.startsWith(encryptedCategoryPrefix)) {
                                                await decrypt(cat.name.slice(encryptedCategoryPrefix.length), activeKey);
                                            }
                                            if (cat.icon && cat.icon.startsWith(encryptedCategoryPrefix)) {
                                                await decrypt(cat.icon.slice(encryptedCategoryPrefix.length), activeKey);
                                            }
                                            if (cat.color && cat.color.startsWith(encryptedCategoryPrefix)) {
                                                await decrypt(cat.color.slice(encryptedCategoryPrefix.length), activeKey);
                                            }
                                        } catch {
                                            brokenCategories.push(cat);
                                        }
                                    }
                                }

                                if (brokenItems.length > 0 || brokenCategories.length > 0) {
                                    console.warn(`Detected broken KDF upgrade (duress path): ${brokenItems.length} items, ${brokenCategories.length} categories. Starting repair...`);
                                    for (let oldVersion = kdfVersion - 1; oldVersion >= 1; oldVersion--) {
                                        try {
                                            const oldKey = await deriveKey(masterPassword, salt, oldVersion);
                                            if (brokenItems.length > 0) {
                                                await decryptVaultItem(brokenItems[0].encrypted_data, oldKey, brokenItems[0].id);
                                            } else if (brokenCategories.length > 0) {
                                                const catToTest = brokenCategories[0];
                                                if (catToTest.name.startsWith(encryptedCategoryPrefix)) {
                                                    await decrypt(catToTest.name.slice(encryptedCategoryPrefix.length), oldKey);
                                                } else if (catToTest.icon && catToTest.icon.startsWith(encryptedCategoryPrefix)) {
                                                    await decrypt(catToTest.icon.slice(encryptedCategoryPrefix.length), oldKey);
                                                } else if (catToTest.color && catToTest.color.startsWith(encryptedCategoryPrefix)) {
                                                    await decrypt(catToTest.color.slice(encryptedCategoryPrefix.length), oldKey);
                                                } else {
                                                    throw new Error('No encrypted fields found on broken category to test old key against');
                                                }
                                            }

                                            const repairResult = await reEncryptVault(brokenItems, brokenCategories, oldKey, activeKey);

                                            for (const itemUpdate of repairResult.itemUpdates) {
                                                await supabase
                                                    .from('vault_items')
                                                    .update({ encrypted_data: itemUpdate.encrypted_data })
                                                    .eq('id', itemUpdate.id)
                                                    .eq('user_id', user.id);
                                            }

                                            for (const catUpdate of repairResult.categoryUpdates) {
                                                await supabase
                                                    .from('categories')
                                                    .update({ name: catUpdate.name, icon: catUpdate.icon, color: catUpdate.color })
                                                    .eq('id', catUpdate.id)
                                                    .eq('user_id', user.id);
                                            }

                                            console.info(`KDF repair (duress path) complete: re-encrypted ${repairResult.itemsReEncrypted} items, ${repairResult.categoriesReEncrypted} categories.`);
                                            break;
                                        } catch {
                                            continue;
                                        }
                                    }
                                }
                            }
                        }
                    } catch (repairErr) {
                        console.error('KDF repair check failed (duress path):', repairErr);
                    }
                }

                const twoFactorResult = await enforceVaultTwoFactorBeforeKeyRelease(options);
                if (twoFactorResult.error) {
                    return twoFactorResult;
                }

                const finalizeResult = await finalizeVaultUnlock(activeKey);
                if (finalizeResult.error) {
                    return finalizeResult;
                }

                if (shouldBackfillVerifier) {
                    await backfillVerificationHash(activeKey);
                }

                return { error: null };
            }

            const { deviceKey, error: deviceKeyError } = await getRequiredDeviceKey();
            if (deviceKeyError) {
                return { error: deviceKeyError };
            }
            const kdfOutputBytes = await deriveRawKey(masterPassword, salt, kdfVersion, deviceKey || undefined);
            let activeKey: CryptoKey;
            let shouldBackfillVerifier = !verificationHash;

            try {
                if (encryptedUserKey) {
                    const userKey = await unwrapUserKey(encryptedUserKey, kdfOutputBytes);
                    if (verifier) {
                        const isValid = await verifyKey(verifier, userKey);
                        if (!isValid) {
                            recordFailedAttempt();
                            return { error: new Error('Invalid master password') };
                        }
                    }

                    resetUnlockAttempts();
                    activeKey = userKey;

                    try {
                        const upgrade = await attemptKdfUpgrade(masterPassword, salt, kdfVersion, deviceKey || undefined, encryptedUserKey, kdfOutputBytes);
                        if (upgrade.upgraded && upgrade.newEncryptedUserKey && upgrade.newVerifier) {
                            const { error: upgradeError } = await supabase
                                .from('profiles')
                                .update({
                                    master_password_verifier: upgrade.newVerifier,
                                    kdf_version: upgrade.activeVersion,
                                    encrypted_user_key: upgrade.newEncryptedUserKey,
                                } as Record<string, unknown>)
                                .eq('user_id', user.id);
                            if (!upgradeError) {
                                setVerificationHash(upgrade.newVerifier);
                                setKdfVersion(upgrade.activeVersion);
                                setEncryptedUserKey(upgrade.newEncryptedUserKey);
                                await saveOfflineCredentials(user.id, salt, upgrade.newVerifier, upgrade.activeVersion, upgrade.newEncryptedUserKey);
                                shouldBackfillVerifier = false;
                                console.info(`KDF upgraded (USK rewrap-only) from v${kdfVersion} to v${upgrade.activeVersion}. No vault re-encryption needed.`);
                            }
                        }
                    } catch {
                        console.warn('KDF upgrade (USK path) failed, continuing with current version');
                    }
                } else {
                    const legacyKey = await importMasterKey(kdfOutputBytes);
                    const isValid = verifier ? await verifyKey(verifier, legacyKey) : await recoverLegacyKeyWithoutVerifier(legacyKey);
                    if (!isValid) {
                        recordFailedAttempt();
                        return { error: new Error('Invalid master password') };
                    }

                    resetUnlockAttempts();
                    const migration = await migrateLegacyVaultToUserKey(kdfOutputBytes);
                    activeKey = migration.userKey;
                    shouldBackfillVerifier = false;
                }
            } finally {
                kdfOutputBytes.fill(0);
            }

            if (!isTauriDevUserId(user.id) && kdfVersion >= 2) {
                try {
                    const { data: probeItems } = await supabase
                        .from('vault_items')
                        .select('id, encrypted_data')
                        .eq('user_id', user.id)
                        .order('created_at', { ascending: true })
                        .limit(5);

                    const { data: probeCategories } = await supabase
                        .from('categories')
                        .select('id, name, icon, color')
                        .eq('user_id', user.id)
                        .order('created_at', { ascending: true })
                        .limit(5);

                        const encryptedCategoryPrefix = 'enc:cat:v1:';
                        let needsFullRepair = false;

                        if (probeItems) {
                            for (const item of probeItems) {
                                try {
                                    await decryptVaultItem(item.encrypted_data, activeKey, item.id);
                                } catch {
                                    needsFullRepair = true;
                                    break;
                                }
                            }
                        }

                        if (!needsFullRepair && probeCategories) {
                            for (const cat of probeCategories) {
                                try {
                                    if (cat.name.startsWith(encryptedCategoryPrefix)) {
                                        await decrypt(cat.name.slice(encryptedCategoryPrefix.length), activeKey);
                                    }
                                    if (cat.icon && cat.icon.startsWith(encryptedCategoryPrefix)) {
                                        await decrypt(cat.icon.slice(encryptedCategoryPrefix.length), activeKey);
                                    }
                                    if (cat.color && cat.color.startsWith(encryptedCategoryPrefix)) {
                                        await decrypt(cat.color.slice(encryptedCategoryPrefix.length), activeKey);
                                    }
                                } catch {
                                    needsFullRepair = true;
                                    break;
                                }
                            }
                        }

                    if (needsFullRepair) {
                        console.warn('Detected broken KDF upgrade in sample. Starting full vault scan and repair...');

                        const { data: allItems } = await supabase
                            .from('vault_items')
                            .select('id, encrypted_data')
                            .eq('user_id', user.id);

                        const { data: allCategories } = await supabase
                            .from('categories')
                            .select('id, name, icon, color')
                            .eq('user_id', user.id);

                        if ((allItems && allItems.length > 0) || (allCategories && allCategories.length > 0)) {
                            const brokenItems = [];
                            const brokenCategories = [];

                            if (allItems) {
                                for (const item of allItems) {
                                    try {
                                        await decryptVaultItem(item.encrypted_data, activeKey, item.id);
                                    } catch {
                                        brokenItems.push(item);
                                    }
                                }
                            }

                            if (allCategories) {
                                for (const cat of allCategories) {
                                    try {
                                        if (cat.name.startsWith(encryptedCategoryPrefix)) {
                                            await decrypt(cat.name.slice(encryptedCategoryPrefix.length), activeKey);
                                        }
                                        if (cat.icon && cat.icon.startsWith(encryptedCategoryPrefix)) {
                                            await decrypt(cat.icon.slice(encryptedCategoryPrefix.length), activeKey);
                                        }
                                        if (cat.color && cat.color.startsWith(encryptedCategoryPrefix)) {
                                            await decrypt(cat.color.slice(encryptedCategoryPrefix.length), activeKey);
                                        }
                                    } catch {
                                        brokenCategories.push(cat);
                                    }
                                }
                            }

                            if (brokenItems.length > 0 || brokenCategories.length > 0) {
                                console.warn(`Detected broken KDF upgrade: ${brokenItems.length} items, ${brokenCategories.length} categories encrypted with older key. Starting repair...`);

                                for (let oldVersion = kdfVersion - 1; oldVersion >= 1; oldVersion--) {
                                    try {
                                        const oldKey = await deriveKey(masterPassword, salt, oldVersion);
                                        if (brokenItems.length > 0) {
                                            await decryptVaultItem(brokenItems[0].encrypted_data, oldKey, brokenItems[0].id);
                                        } else if (brokenCategories.length > 0) {
                                            const catToTest = brokenCategories[0];
                                            if (catToTest.name.startsWith(encryptedCategoryPrefix)) {
                                                await decrypt(catToTest.name.slice(encryptedCategoryPrefix.length), oldKey);
                                            } else if (catToTest.icon && catToTest.icon.startsWith(encryptedCategoryPrefix)) {
                                                await decrypt(catToTest.icon.slice(encryptedCategoryPrefix.length), oldKey);
                                            } else if (catToTest.color && catToTest.color.startsWith(encryptedCategoryPrefix)) {
                                                await decrypt(catToTest.color.slice(encryptedCategoryPrefix.length), oldKey);
                                            } else {
                                                throw new Error('No encrypted fields found on broken category to test old key against');
                                            }
                                        }

                                        console.info(`Fallback key v${oldVersion} works. Re-encrypting broken vault data...`);

                                        const repairResult = await reEncryptVault(brokenItems, brokenCategories, oldKey, activeKey);

                                        for (const itemUpdate of repairResult.itemUpdates) {
                                            await supabase
                                                .from('vault_items')
                                                .update({ encrypted_data: itemUpdate.encrypted_data })
                                                .eq('id', itemUpdate.id)
                                                .eq('user_id', user.id);
                                        }

                                        for (const catUpdate of repairResult.categoryUpdates) {
                                            await supabase
                                                .from('categories')
                                                .update({ name: catUpdate.name, icon: catUpdate.icon, color: catUpdate.color })
                                                .eq('id', catUpdate.id)
                                                .eq('user_id', user.id);
                                        }

                                        console.info(`KDF repair complete: re-encrypted ${repairResult.itemsReEncrypted} items, ${repairResult.categoriesReEncrypted} categories from v${oldVersion} to v${kdfVersion}.`);
                                        break;
                                    } catch {
                                        continue;
                                    }
                                }
                            }
                        }
                    }
                } catch (repairErr) {
                    console.error('KDF repair check failed:', repairErr);
                }
            }

            if (!isTauriDevUserId(user.id)) {
                try {
                    await migrateLegacyPrivateKeysToUserKey(user.id, masterPassword, activeKey);
                } catch (pkMigrErr) {
                    console.warn('Private key USK migration failed, will retry next unlock:', pkMigrErr);
                }
            }

            const twoFactorResult = await enforceVaultTwoFactorBeforeKeyRelease(options);
            if (twoFactorResult.error) {
                return twoFactorResult;
            }

            const finalizeResult = await finalizeVaultUnlock(activeKey);
            if (finalizeResult.error) {
                return finalizeResult;
            }

            if (shouldBackfillVerifier && !isTauriDevUserId(user.id)) {
                await backfillVerificationHash(activeKey);
            }

            return { error: null };
        } catch (err) {
            console.error('Error unlocking vault:', err);
            recordFailedAttempt();
            return { error: new Error('Invalid master password') };
        }
    }, [
        user,
        salt,
        verificationHash,
        kdfVersion,
        duressConfig,
        encryptedUserKey,
        enforceVaultTwoFactorBeforeKeyRelease,
        finalizeVaultUnlock,
        backfillVerificationHash,
        getRequiredDeviceKey,
        recoverLegacyKeyWithoutVerifier,
        migrateLegacyVaultToUserKey,
    ]);

    const unlockWithPasskey = useCallback(async (options?: VaultUnlockOptions): Promise<{ error: Error | null }> => {
        if (!user) {
            console.warn('unlockWithPasskey called without active user session');
            return { error: new Error('User session not ready. Please wait a moment.') };
        }

        const cooldown = getUnlockCooldown();
        if (cooldown !== null) {
            const seconds = Math.ceil(cooldown / 1000);
            return { error: new Error(`Too many attempts. Try again in ${seconds}s.`) };
        }

        if (!isAppOnline()) {
            return {
                error: new Error(
                    'Passkey unlock requires an online WebAuthn challenge. Use your master password for offline unlock.',
                ),
            };
        }

        try {
            const result = await authenticatePasskey({ encryptedUserKey });

            if (!result.success) {
                if (result.error === 'CANCELLED') {
                    return { error: new Error('Passkey authentication was cancelled') };
                }
                if (result.error === 'NO_PRF') {
                    return { error: new Error('This passkey does not support vault unlock (no PRF)') };
                }
                recordFailedAttempt();
                return { error: new Error(result.error || 'Passkey authentication failed') };
            }

            if (!result.encryptionKey) {
                recordFailedAttempt();
                return { error: new Error('Passkey authenticated but no encryption key derived') };
            }

            let activeKey = result.encryptionKey;
            let shouldBackfillVerifier = !verificationHash;

            if (verificationHash) {
                const isValid = await verifyKey(verificationHash, activeKey);
                if (!isValid) {
                    recordFailedAttempt();
                    return { error: new Error('Passkey-derived key does not match vault - key may be outdated') };
                }
            } else if (encryptedUserKey || result.keySource === 'vault-key') {
                shouldBackfillVerifier = true;
            } else {
                const isValid = await recoverLegacyKeyWithoutVerifier(activeKey);
                if (!isValid) {
                    recordFailedAttempt();
                    return { error: new Error('Passkey-derived key does not match vault - key may be outdated') };
                }
            }

            if (!encryptedUserKey && result.keySource === 'legacy-kdf' && result.legacyKdfOutputBytes) {
                try {
                    const migration = await migrateLegacyVaultToUserKey(result.legacyKdfOutputBytes);
                    activeKey = migration.userKey;
                    shouldBackfillVerifier = false;
                } finally {
                    result.legacyKdfOutputBytes.fill(0);
                }
            } else {
                result.legacyKdfOutputBytes?.fill(0);
            }

            resetUnlockAttempts();
            const twoFactorResult = await enforceVaultTwoFactorBeforeKeyRelease(options);
            if (twoFactorResult.error) {
                return twoFactorResult;
            }

            const finalizeResult = await finalizeVaultUnlock(activeKey);
            if (finalizeResult.error) {
                return finalizeResult;
            }

            if (shouldBackfillVerifier) {
                await backfillVerificationHash(activeKey);
            }

            return { error: null };
        } catch (err) {
            console.error('Passkey unlock error:', err);
            recordFailedAttempt();
            return { error: new Error('Passkey unlock failed') };
        }
    }, [
        user,
        verificationHash,
        encryptedUserKey,
        enforceVaultTwoFactorBeforeKeyRelease,
        finalizeVaultUnlock,
        backfillVerificationHash,
        recoverLegacyKeyWithoutVerifier,
        migrateLegacyVaultToUserKey,
    ]);

    const getPasskeyWrappingMaterial = useCallback(async (
        masterPassword: string,
    ): Promise<Uint8Array | null> => {
        if (!user || !salt || isLocked) return null;

        let kdfOutputBytes: Uint8Array | null = null;
        try {
            const { deviceKey, error: deviceKeyError } = await getRequiredDeviceKey();
            if (deviceKeyError) {
                console.warn('Failed to derive passkey wrapping material:', deviceKeyError);
                return null;
            }
            kdfOutputBytes = await deriveRawKey(masterPassword, salt, kdfVersion, deviceKey || undefined);

            if (encryptedUserKey) {
                const userKey = await unwrapUserKey(encryptedUserKey, kdfOutputBytes);
                if (verificationHash) {
                    const isValid = await verifyKey(verificationHash, userKey);
                    if (!isValid) {
                        return null;
                    }
                }

                const wrappingMaterial = await unwrapUserKeyBytes(encryptedUserKey, kdfOutputBytes);
                return wrappingMaterial;
            }

            const derivedKey = await importMasterKey(kdfOutputBytes);
            if (verificationHash) {
                const isValid = await verifyKey(verificationHash, derivedKey);
                if (!isValid) {
                    return null;
                }
            } else {
                const recovered = await recoverLegacyKeyWithoutVerifier(derivedKey);
                if (!recovered) {
                    return null;
                }
            }

            const wrappingMaterial = kdfOutputBytes;
            kdfOutputBytes = null;
            return wrappingMaterial;
        } catch (err) {
            console.error('Failed to derive passkey wrapping material:', err);
            return null;
        } finally {
            kdfOutputBytes?.fill(0);
        }
    }, [
        user,
        salt,
        kdfVersion,
        isLocked,
        verificationHash,
        encryptedUserKey,
        getRequiredDeviceKey,
        recoverLegacyKeyWithoutVerifier,
    ]);

    const lock = useCallback(() => {
        clearActiveVaultSession();
        setIsLoading(false);
    }, [clearActiveVaultSession]);

    /**
     * Enables Device Key protection on this device.
     * Generates a 256-bit device key, re-encrypts the vault with the
     * combined key (Argon2id + HKDF-Expand), and stores the device key
     * in IndexedDB.
     *
     * @param masterPassword - The user's master password (needed to re-derive keys)
     */
    const enableDeviceKey = useCallback(async (
        masterPassword: string,
    ): Promise<{ error: Error | null }> => {
        if (!user || !salt || !encryptionKey) {
            return { error: new Error('Vault must be unlocked') };
        }

        try {
            // Generate new device key
            const newDeviceKey = generateDeviceKey();

            if (encryptedUserKey) {
                // â”€â”€ USK path: rewrap UserKey under device-key-enhanced KDF â”€â”€
                // Vault items stay encrypted under UserKey â€” no vault re-encryption needed.
                // Only the 32-byte UserKey wrapper changes.
                // Use currentDeviceKey so old bytes match what was used to wrap encryptedUserKey last time.
                const oldKdfOutputBytes = await deriveRawKey(masterPassword, salt, kdfVersion, currentDeviceKey || undefined);
                const newKdfOutputBytes = await deriveRawKey(masterPassword, salt, kdfVersion, newDeviceKey);
                let newEncryptedUserKey: string;
                try {
                    newEncryptedUserKey = await rewrapUserKey(
                        encryptedUserKey, oldKdfOutputBytes, newKdfOutputBytes,
                    );
                } finally {
                    oldKdfOutputBytes.fill(0);
                    newKdfOutputBytes.fill(0);
                }
                // Unwrap to create fresh verifier (kdfOutputBytes2 is the new device-enhanced bytes)
                const kdfOutputBytes2 = await deriveRawKey(masterPassword, salt, kdfVersion, newDeviceKey);
                let newVerifier: string;
                try {
                    const newUserKey = await unwrapUserKey(newEncryptedUserKey, kdfOutputBytes2);
                    newVerifier = await createVerificationHash(newUserKey);
                } finally {
                    kdfOutputBytes2.fill(0);
                }
                const { error: updateError } = await supabase
                    .from('profiles')
                    .update({
                        master_password_verifier: newVerifier,
                        encrypted_user_key: newEncryptedUserKey,
                    } as Record<string, unknown>)
                    .eq('user_id', user.id);
                if (updateError) {
                    throw new Error(`Failed to update profile: ${updateError.message}`);
                }
                await storeDeviceKey(user.id, newDeviceKey);
                setEncryptedUserKey(newEncryptedUserKey);
                setVerificationHash(newVerifier);
                setCurrentDeviceKey(newDeviceKey);
                setDeviceKeyActive(true);
                await saveOfflineCredentials(user.id, salt, newVerifier, kdfVersion, newEncryptedUserKey);
                console.info('Device Key enabled (USK path). No vault re-encryption needed.');
                return { error: null };
            }

            // â”€â”€ Legacy path (pre-USK, encryptedUserKey = null) â”€â”€
            // Vault items are encrypted directly with KDF-derived key â€” full re-encryption required.
            const newKey = await deriveKey(masterPassword, salt, kdfVersion, newDeviceKey);

            // Create new verification hash with the device-key-enhanced key
            const newVerifier = await createVerificationHash(newKey);

            // Load all vault items and categories for re-encryption
            const { data: vaultItems } = await supabase
                .from('vault_items')
                .select('id, encrypted_data')
                .eq('user_id', user.id);

            const { data: categories } = await supabase
                .from('categories')
                .select('id, name, icon, color')
                .eq('user_id', user.id);

            // Re-encrypt everything with the new key
            const reEncResult = await reEncryptVault(
                vaultItems || [],
                categories || [],
                encryptionKey, // old key (without device key)
                newKey,
            );

            // Persist re-encrypted items
            for (const itemUpdate of reEncResult.itemUpdates) {
                const { error: itemError } = await supabase
                    .from('vault_items')
                    .update({ encrypted_data: itemUpdate.encrypted_data })
                    .eq('id', itemUpdate.id)
                    .eq('user_id', user.id);
                if (itemError) {
                    throw new Error(`Failed to update item ${itemUpdate.id}: ${itemError.message}`);
                }
            }

            // Persist re-encrypted categories
            for (const catUpdate of reEncResult.categoryUpdates) {
                const { error: catError } = await supabase
                    .from('categories')
                    .update({ name: catUpdate.name, icon: catUpdate.icon, color: catUpdate.color })
                    .eq('id', catUpdate.id)
                    .eq('user_id', user.id);
                if (catError) {
                    throw new Error(`Failed to update category ${catUpdate.id}: ${catError.message}`);
                }
            }

            // Update the verifier in profile
            const { error: updateError } = await supabase
                .from('profiles')
                .update({
                    master_password_verifier: newVerifier,
                } as Record<string, unknown>)
                .eq('user_id', user.id);

            if (updateError) {
                throw new Error(`Failed to update profile: ${updateError.message}`);
            }

            // Store device key in IndexedDB
            await storeDeviceKey(user.id, newDeviceKey);

            // Update state
            setEncryptionKey(newKey);
            setVerificationHash(newVerifier);
            setCurrentDeviceKey(newDeviceKey);
            setDeviceKeyActive(true);

            // Update offline credentials
            await saveOfflineCredentials(user.id, salt, newVerifier, kdfVersion);

            console.info(
                `Device Key enabled. Re-encrypted ${reEncResult.itemsReEncrypted} items, ` +
                `${reEncResult.categoriesReEncrypted} categories.`
            );

            return { error: null };
        } catch (err) {
            console.error('Failed to enable Device Key:', err);
            return { error: err as Error };
        }
    }, [user, salt, kdfVersion, encryptionKey, encryptedUserKey, currentDeviceKey]);

    /**
     * Verifies vault items against stored integrity root.
     * Detects server-side tampering (deleted/modified/added items).
     */
    const verifyIntegrity = useCallback(async (
        snapshot?: OfflineVaultSnapshot,
        options?: { source?: VaultSnapshotSource },
    ): Promise<VaultIntegrityVerificationResult | null> => {
        if (!user || !encryptionKey) {
            return null;
        }

        try {
            const loadedSnapshotBundle = snapshot
                ? null
                : await loadCurrentIntegritySnapshot({
                    persistRemoteSnapshot: false,
                    useLocalMutationOverlay: true,
                });
            const rawSnapshot = snapshot ?? loadedSnapshotBundle?.rawSnapshot;
            if (!rawSnapshot) {
                return null;
            }

            const integrityAssessment = await assessVaultIntegrity(rawSnapshot, encryptionKey);
            const result = integrityAssessment.result;
            const recentLocalRebaselineAllowed = canRebaselineRecentLocalMutation(
                user.id,
                integrityAssessment,
            );
            const source = options?.source ?? loadedSnapshotBundle?.source;

            if (result.mode === 'blocked' && !recentLocalRebaselineAllowed) {
                await setBlockedIntegrityState(
                    encryptionKey,
                    result.blockedReason ?? 'snapshot_malformed',
                    result,
                );
                return result;
            }

            if (recentLocalRebaselineAllowed) {
                const digest = await persistIntegrityBaseline(
                    user.id,
                    buildIntegritySnapshot(rawSnapshot),
                    encryptionKey,
                    integrityAssessment.inspection.digest,
                );
                await persistTrustedIntegritySnapshot(rawSnapshot);
                const trustedResult: VaultIntegrityVerificationResult = {
                    valid: true,
                    isFirstCheck: false,
                    computedRoot: digest,
                    storedRoot: digest,
                    itemCount: rawSnapshot.items.length,
                    categoryCount: rawSnapshot.categories.length,
                    mode: 'healthy',
                    quarantinedItems: [],
                };
                applyIntegrityResultState(trustedResult);
                return trustedResult;
            }

            if (result.mode === 'quarantine' && source === 'remote') {
                const trustedRemoteMutation = await buildDecryptableRemoteRebaselineMutation(
                    integrityAssessment,
                    rawSnapshot,
                    encryptionKey,
                );
                if (trustedRemoteMutation) {
                    const digest = await persistIntegrityBaseline(
                        user.id,
                        buildIntegritySnapshot(rawSnapshot),
                        encryptionKey,
                        integrityAssessment.inspection.digest,
                    );
                    await persistTrustedIntegritySnapshot(rawSnapshot);
                    const trustedResult: VaultIntegrityVerificationResult = {
                        valid: true,
                        isFirstCheck: false,
                        computedRoot: digest,
                        storedRoot: digest,
                        itemCount: rawSnapshot.items.length,
                        categoryCount: rawSnapshot.categories.length,
                        mode: 'healthy',
                        quarantinedItems: [],
                    };
                    applyIntegrityResultState(trustedResult);
                    return trustedResult;
                }
            }

            applyIntegrityResultState(result);

            if (result.mode === 'healthy') {
                if (canPersistIntegrityBaselineImmediately(integrityAssessment, rawSnapshot)) {
                    await persistMissingOrLegacyBaseline(
                        buildIntegritySnapshot(rawSnapshot),
                        encryptionKey,
                        integrityAssessment.inspection,
                    );
                    await persistTrustedIntegritySnapshot(rawSnapshot);
                }
            } else {
                await syncTrustedRecoverySnapshotState(user.id);
            }

            return result;
        } catch (err) {
            console.error('Vault integrity verification error:', err);
            const blockedReason: VaultIntegrityBlockedReason = err instanceof VaultIntegrityBaselineError
                ? 'baseline_unreadable'
                : 'snapshot_malformed';
            const failureResult: VaultIntegrityVerificationResult = {
                valid: false,
                isFirstCheck: false,
                computedRoot: '',
                itemCount: 0,
                categoryCount: 0,
                mode: 'blocked',
                blockedReason,
                quarantinedItems: [],
            };
            await setBlockedIntegrityState(
                encryptionKey,
                blockedReason,
                failureResult,
            );
            return failureResult;
        }
    }, [
        applyIntegrityResultState,
        assessVaultIntegrity,
        buildIntegritySnapshot,
        encryptionKey,
        loadCurrentIntegritySnapshot,
        persistMissingOrLegacyBaseline,
        persistTrustedIntegritySnapshot,
        setBlockedIntegrityState,
        syncTrustedRecoverySnapshotState,
        user,
    ]);

    const updateIntegrity = useCallback(async (
        items: VaultItemForIntegrity[]
    ): Promise<void> => {
        await refreshIntegrityBaseline({
            itemIds: items.map((item) => item.id),
        });
    }, [refreshIntegrityBaseline]);

    const restoreQuarantinedItem = useCallback(async (
        itemId: string,
    ): Promise<{ error: Error | null }> => {
        if (!user || !encryptionKey) {
            return { error: new Error('No active user session') };
        }

        const resolution = quarantineResolutionById[itemId];
        const trustedSnapshotItem = trustedSnapshotItemsById[itemId];
        if (!resolution?.canRestore || !trustedSnapshotItem) {
            return { error: new Error('Für diesen Eintrag ist keine vertrauenswürdige lokale Kopie verfügbar.') };
        }

        return runQuarantineAction(itemId, async () => {
            try {
                await decryptVaultItem(trustedSnapshotItem.encrypted_data, encryptionKey, itemId);
            } catch {
                throw new Error('Die lokale Wiederherstellungskopie für diesen Eintrag ist nicht mehr entschlüsselbar.');
            }

            const { syncedOnline } = await restoreQuarantinedItemFromTrustedSnapshot(user.id, trustedSnapshotItem);
            if (isAppOnline() && !syncedOnline) {
                throw new Error('Die Wiederherstellung konnte nicht mit dem Server synchronisiert werden.');
            }
            const integrityResult = await verifyIntegrity();
            if (integrityResult?.quarantinedItems.some((quarantinedItem) => quarantinedItem.id === itemId)) {
                throw new Error('Die Wiederherstellung konnte nicht bestätigt werden. Der Eintrag bleibt in Quarantäne.');
            }

            bumpVaultDataVersion();
        });
    }, [
        bumpVaultDataVersion,
        encryptionKey,
        quarantineResolutionById,
        runQuarantineAction,
        trustedSnapshotItemsById,
        user,
        verifyIntegrity,
    ]);

    const deleteQuarantinedItem = useCallback(async (
        itemId: string,
    ): Promise<{ error: Error | null }> => {
        if (!user) {
            return { error: new Error('No active user session') };
        }

        const resolution = quarantineResolutionById[itemId];
        if (!resolution?.canDelete) {
            return { error: new Error('Dieser Quarantäne-Eintrag kann nicht gelöscht werden.') };
        }

        return runQuarantineAction(itemId, async () => {
            const { syncedOnline } = await deleteQuarantinedItemFromVault(user.id, itemId);
            if (isAppOnline() && !syncedOnline) {
                throw new Error('Der Quarantäne-Eintrag konnte nicht mit dem Server synchronisiert gelöscht werden.');
            }
            if (resolution.reason === 'ciphertext_changed') {
                await refreshIntegrityBaseline({ itemIds: [itemId] });
            } else {
                await verifyIntegrity();
            }

            bumpVaultDataVersion();
        });
    }, [
        bumpVaultDataVersion,
        quarantineResolutionById,
        refreshIntegrityBaseline,
        runQuarantineAction,
        user,
        verifyIntegrity,
    ]);

    const acceptMissingQuarantinedItem = useCallback(async (
        itemId: string,
    ): Promise<{ error: Error | null }> => {
        if (!user) {
            return { error: new Error('No active user session') };
        }

        const resolution = quarantineResolutionById[itemId];
        if (!resolution?.canAcceptMissing) {
            return { error: new Error('Dieser Quarantäne-Eintrag kann nicht bestätigt werden.') };
        }

        return runQuarantineAction(itemId, async () => {
            await refreshIntegrityBaseline({ itemIds: [itemId] });
            bumpVaultDataVersion();
        });
    }, [
        bumpVaultDataVersion,
        quarantineResolutionById,
        refreshIntegrityBaseline,
        runQuarantineAction,
        user,
    ]);

    const enterSafeMode = useCallback(async (): Promise<{ error: Error | null }> => {
        if (!user || !encryptionKey) {
            return { error: new Error('Safe Mode requires an active recovery session.') };
        }

        const trustedSnapshot = await syncTrustedRecoverySnapshotState(user.id);
        if (!trustedSnapshot) {
            return { error: new Error('No trusted local recovery snapshot is available on this device.') };
        }

        setIntegrityMode('safe');
        setPendingSessionRestore(false);
        return { error: null };
    }, [encryptionKey, syncTrustedRecoverySnapshotState, user]);

    const exitSafeMode = useCallback(() => {
        setIntegrityMode(integrityBlockedReason ? 'blocked' : 'healthy');
    }, [integrityBlockedReason]);

    const resetVaultAfterIntegrityFailure = useCallback(async (): Promise<{ error: Error | null }> => {
        if (!user) {
            return { error: new Error('No active user session') };
        }

        try {
            await resetUserVaultState(user.id);
            resetVaultState();
            setIsSetupRequired(true);
            setIsLoading(false);
            return { error: null };
        } catch (error) {
            return {
                error: error instanceof Error
                    ? error
                    : new Error('Vault reset failed.'),
            };
        }
    }, [resetVaultState, user]);

    /**
     * Encrypts plaintext data
     */
    const encryptData = useCallback(async (plaintext: string, aad?: string): Promise<string> => {
        if (!encryptionKey) {
            throw new Error('Vault is locked');
        }
        return encrypt(plaintext, encryptionKey, aad);
    }, [encryptionKey]);

    /**
     * Decrypts encrypted data
     */
    const decryptData = useCallback(async (encrypted: string, aad?: string): Promise<string> => {
        if (!encryptionKey) {
            throw new Error('Vault is locked');
        }
        return decrypt(encrypted, encryptionKey, aad);
    }, [encryptionKey]);

    const encryptBinary = useCallback(async (plaintext: Uint8Array, aad?: string): Promise<string> => {
        if (!encryptionKey) {
            throw new Error('Vault is locked');
        }
        return encryptBytes(plaintext, encryptionKey, aad);
    }, [encryptionKey]);

    const decryptBinary = useCallback(async (encrypted: string, aad?: string): Promise<Uint8Array> => {
        if (!encryptionKey) {
            throw new Error('Vault is locked');
        }
        return decryptBytes(encrypted, encryptionKey, aad);
    }, [encryptionKey]);

    /**
     * Encrypts a vault item
     */
    const encryptItem = useCallback(async (data: VaultItemData, entryId: string): Promise<string> => {
        if (!encryptionKey) {
            throw new Error('Vault is locked');
        }
        return encryptVaultItem(data, encryptionKey, entryId);
    }, [encryptionKey]);

    /**
     * Decrypts a vault item
     */
    const decryptItem = useCallback(async (encryptedData: string, entryId: string): Promise<VaultItemData> => {
        if (!encryptionKey) {
            throw new Error('Vault is locked');
        }
        return decryptVaultItem(encryptedData, encryptionKey, entryId);
    }, [encryptionKey]);

    return (
        <VaultContext.Provider
            value={{
                isLocked,
                isSetupRequired,
                isLoading,
                isDuressMode,
                deviceKeyActive,
                setupMasterPassword,
                unlock,
                unlockWithPasskey,
                lock,
                enableDeviceKey,
                webAuthnAvailable,
                hasPasskeyUnlock,
                refreshPasskeyUnlockStatus,
                getPasskeyWrappingMaterial,
                encryptData,
                decryptData,
                encryptBinary,
                decryptBinary,
                encryptItem,
                decryptItem,
                autoLockTimeout,
                setAutoLockTimeout,
                pendingSessionRestore,
                verifyIntegrity,
                updateIntegrity,
                refreshIntegrityBaseline,
                reportUnreadableItems,
                integrityVerified,
                lastIntegrityResult,
                integrityMode,
                quarantinedItems,
                quarantineResolutionById,
                vaultDataVersion,
                integrityBlockedReason,
                trustedRecoveryAvailable,
                enterSafeMode,
                restoreQuarantinedItem,
                deleteQuarantinedItem,
                acceptMissingQuarantinedItem,
                exitSafeMode,
                resetVaultAfterIntegrityFailure,
            }}
        >
            {children}
        </VaultContext.Provider>
    );
}

/**
 * Hook to access vault context
 */
// eslint-disable-next-line react-refresh/only-export-components
export function useVault() {
    const context = useContext(VaultContext);
    if (context === undefined) {
        throw new Error('useVault must be used within a VaultProvider');
    }
    return context;
}
