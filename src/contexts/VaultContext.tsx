// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 — see LICENSE
/**
 * @fileoverview Vault Context for Singra Vault
 * 
 * Manages vault encryption state including:
 * - Master password unlock status
 * - Derived encryption key (kept in memory only)
 * - Auto-lock on inactivity
 * - Vault item encryption/decryption helpers
 */

import { createContext, useContext, useEffect, useState, useCallback, ReactNode } from 'react';
import {
    deriveKey,
    deriveRawKey,
    generateSalt,
    encrypt,
    decrypt,
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
    getOfflineCredentials,
    saveOfflineCredentials,
} from '@/services/offlineVaultService';
import {
    authenticatePasskey,
    isWebAuthnAvailable,
} from '@/services/passkeyService';
import { getServiceHooks } from '@/extensions/registry';
import type {
    DuressConfigHook,
    VaultItemForIntegrity,
    IntegrityVerificationResult,
} from '@/extensions/types';
import { supabase } from '@/integrations/supabase/client';
import { hasOptionalCookieConsent } from '@/lib/cookieConsent';
import { useAuth } from './AuthContext';
import {
    getUnlockCooldown,
    recordFailedAttempt,
    resetUnlockAttempts,
} from '@/services/rateLimiterService';

// Auto-lock timeout in milliseconds (default 15 minutes)
const DEFAULT_AUTO_LOCK_TIMEOUT = 15 * 60 * 1000;

/**
 * Migrates legacy RSA and PQ private keys to USK (User Symmetric Key) format.
 *
 * Runs once per unlock after the UserKey is established. Re-wraps keys that
 * are still in the old KDF-derived format (e.g. `kdfVersion:salt:enc`) to the
 * new `usk-v1:` sentinel format. This is a non-destructive,
 * idempotent operation — it checks the sentinel before doing any work.
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
    unlock: (masterPassword: string) => Promise<{ error: Error | null }>;
    unlockWithPasskey: () => Promise<{ error: Error | null }>;
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
    getRawKeyForPasskey: (masterPassword: string) => Promise<Uint8Array | null>;

    // Encryption helpers
    encryptData: (plaintext: string) => Promise<string>;
    decryptData: (encrypted: string) => Promise<string>;
    encryptItem: (data: VaultItemData, entryId?: string) => Promise<string>;
    decryptItem: (encryptedData: string, entryId?: string) => Promise<VaultItemData>;

    // Settings
    autoLockTimeout: number;
    setAutoLockTimeout: (timeout: number) => void;

    // Vault Integrity (tamper detection)
    /**
     * Verifies vault items against stored integrity root.
     * Call this after loading vault items to detect server-side tampering.
     * @returns Verification result with valid flag and details
     */
    verifyIntegrity: (items: VaultItemForIntegrity[]) => Promise<IntegrityVerificationResult | null>;
    /**
     * Updates the integrity root after vault modifications.
     * Call this after creating, updating, or deleting vault items.
     */
    updateIntegrity: (items: VaultItemForIntegrity[]) => Promise<void>;
    /**
     * Whether integrity verification has been performed since unlock
     */
    integrityVerified: boolean;
    /**
     * Last integrity verification result (null if not yet verified)
     */
    lastIntegrityResult: IntegrityVerificationResult | null;
}

const VaultContext = createContext<VaultContextType | undefined>(undefined);

interface VaultProviderProps {
    children: ReactNode;
}

export function VaultProvider({ children }: VaultProviderProps) {
    const { user, authReady } = useAuth();

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
    // USK (User Symmetric Key) — encrypted form stored in profiles.encrypted_user_key
    // null = pre-USK user (will be migrated on next unlock), string = already migrated
    const [encryptedUserKey, setEncryptedUserKey] = useState<string | null>(null);
    // Vault integrity state
    const [integrityKey, setIntegrityKey] = useState<CryptoKey | null>(null);
    const [integrityVerified, setIntegrityVerified] = useState(false);
    const [lastIntegrityResult, setLastIntegrityResult] = useState<IntegrityVerificationResult | null>(null);

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

    const [lastActivity, setLastActivity] = useState(Date.now());

    const refreshPasskeyUnlockStatus = useCallback(async (): Promise<void> => {
        if (!authReady || !user || !webAuthnAvailable) {
            setHasPasskeyUnlock(false);
            return;
        }

        console.debug('[VaultContext] authReady is true, refreshing passkey unlock status...');

        try {
            const { data: passkeys } = await supabase
                .from('passkey_credentials')
                .select('id')
                .eq('user_id', user.id)
                .eq('prf_enabled', true)
                .limit(1);

            setHasPasskeyUnlock((passkeys?.length || 0) > 0);
        } catch {
            // Non-fatal: passkey status check can fail silently
            setHasPasskeyUnlock(false);
        }
    }, [user, webAuthnAvailable, authReady]); // authReady required — stale closure fix

    // Check if master password is set up
    useEffect(() => {
        async function checkSetup() {
            // Case A: No user session — definitively nothing to load.
            // End loading so the UI can show the sign-in screen.
            if (!user) {
                setHasPasskeyUnlock(false);
                setIsLoading(false);
                return;
            }

            // Case B: User present but auth not yet fully synchronized
            // (INITIAL_SESSION fired before getSession() resolved).
            // Keep isLoading=true — checkSetup() will run once authReady flips,
            // thanks to authReady being in the dep array. Showing a spinner here
            // is correct; setting isLoading=false would cause a stale-defaults flash.
            if (!authReady) {
                return;
            }

            console.debug('[VaultContext] authReady is true, fetching user profiles...');

            // ============ Offline-First: skip network if offline ============
            if (!isAppOnline()) {
                console.debug('[VaultContext] App is offline, loading cached credentials...');
                const cached = await getOfflineCredentials(user.id);
                if (cached) {
                    setIsSetupRequired(false);
                    setSalt(cached.salt);
                    setVerificationHash(cached.verifier);
                    if (cached.kdfVersion !== null) {
                        setKdfVersion(cached.kdfVersion);
                    }
                    setEncryptedUserKey(cached.encryptedUserKey);
                    setIsLoading(false);
                    return;
                }
                // No cache available while offline — cannot determine setup state
                setIsSetupRequired(true);
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
                    .single() as { data: Record<string, unknown> | null; error: unknown };

                if (error || !profile?.encryption_salt) {
                    // No profile found — try cache fallback for any error
                    const cached = await getOfflineCredentials(user.id);
                    if (cached) {
                        setIsSetupRequired(false);
                        setSalt(cached.salt);
                        setVerificationHash(cached.verifier);
                        if (cached.kdfVersion !== null) {
                            setKdfVersion(cached.kdfVersion);
                        }
                        setEncryptedUserKey(cached.encryptedUserKey);
                        setIsLoading(false);
                        return;
                    }
                    // No cached data or truly no profile - setup required
                    setIsSetupRequired(true);
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
                const cached = await getOfflineCredentials(user.id);
                if (cached) {
                    setIsSetupRequired(false);
                    setSalt(cached.salt);
                    setVerificationHash(cached.verifier);
                    if (cached.kdfVersion !== null) {
                        setKdfVersion(cached.kdfVersion);
                    }
                    setEncryptedUserKey(cached.encryptedUserKey);
                    setIsLoading(false);
                    return;
                }
                setIsSetupRequired(true);
            } finally {
                setIsLoading(false);
            }
        }

        checkSetup();
    }, [user, authReady, webAuthnAvailable, refreshPasskeyUnlockStatus]); // authReady required — stale closure fix

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
            // Generate new salt
            const newSalt = generateSalt();

            // Derive raw KDF bytes (new users start on latest KDF version)
            const kdfOutputBytes = await deriveRawKey(masterPassword, newSalt, CURRENT_KDF_VERSION);
            let uskBundle: Awaited<ReturnType<typeof createEncryptedUserKey>>;
            try {
                // ── USK: create random UserKey, wrap under HKDF-derived wrapKey ──
                uskBundle = await createEncryptedUserKey(kdfOutputBytes);
            } finally {
                kdfOutputBytes.fill(0);
            }

            // Create verification hash from the UserKey (not raw KDF bytes)
            const verifyHash = await createVerificationHash(uskBundle.userKey);

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
            setEncryptionKey(uskBundle.userKey);
            setEncryptedUserKey(uskBundle.encryptedUserKey);
            setKdfVersion(CURRENT_KDF_VERSION);
            setIsSetupRequired(false);
            setIsLocked(false);
            setLastActivity(Date.now());

            // Derive integrity key for tamper detection
            const hooks = getServiceHooks();
            if (hooks.deriveIntegrityKey) {
                try {
                    const iKey = await hooks.deriveIntegrityKey(masterPassword, newSalt);
                    setIntegrityKey(iKey);
                } catch {
                    console.warn('Failed to derive integrity key during setup');
                }
            } else {
                setIntegrityKey(null);
            }

            // Store session indicator in sessionStorage
            sessionStorage.setItem(SESSION_KEY, 'active');
            sessionStorage.setItem(SESSION_TIMESTAMP_KEY, Date.now().toString());
            setPendingSessionRestore(false);

            // Cache credentials for offline use (including encryptedUserKey)
            await saveOfflineCredentials(user.id, newSalt, verifyHash, CURRENT_KDF_VERSION, uskBundle.encryptedUserKey);

            return { error: null };
        } catch (err) {
            console.error('Error setting up master password:', err);
            return { error: err as Error };
        }
    }, [user]);

    /**
     * Unlocks the vault with the master password.
     * Enforces client-side rate limiting with exponential backoff.
     * 
     * If duress mode is enabled and the entered password matches the duress
     * password (not the real one), the vault opens in duress mode showing
     * only decoy items.
     */
    const unlock = useCallback(async (
        masterPassword: string
    ): Promise<{ error: Error | null }> => {
        if (!user || !salt) {
            return { error: new Error('Vault not set up') };
        }

        // Check rate-limit cooldown
        const cooldown = getUnlockCooldown();
        if (cooldown !== null) {
            const seconds = Math.ceil(cooldown / 1000);
            return { error: new Error(`Too many attempts. Try again in ${seconds}s.`) };
        }

        // Primary verifier from profile, fallback to legacy localStorage.
        const legacyHash = localStorage.getItem(`singra_verify_${user.id}`);
        const verifier = verificationHash || legacyHash;

        if (!verifier) {
            return { error: new Error('Vault verification data missing') };
        }

        try {
            // ── Dual Unlock: Check both real and duress passwords ──
            // If duress mode is enabled, we check both passwords to determine
            // which vault to open. This is done in parallel to maintain
            // constant timing (prevent timing attacks).
            if (duressConfig?.enabled && getServiceHooks().attemptDualUnlock) {
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

                // Success — reset rate-limiter
                resetUnlockAttempts();

                if (result.mode === 'duress') {
                    // Duress mode: user entered panic password
                    // Note: No integrity key for duress mode (decoy vault)
                    setEncryptionKey(result.key);
                    setIsDuressMode(true);
                    setIsLocked(false);
                    setIntegrityKey(null); // No integrity for duress
                    setLastActivity(Date.now());

                    // Store session indicator
                    sessionStorage.setItem(SESSION_KEY, 'active');
                    sessionStorage.setItem(SESSION_TIMESTAMP_KEY, Date.now().toString());
                    setPendingSessionRestore(false);

                    return { error: null };
                }

                // Real mode: continue with normal flow (KDF migration, etc.)
                // result.key is already the real key
                let activeKey = result.key!;

                // KDF Auto-Migration with Re-Encryption (only for real password, not duress)
                try {
                    const upgrade = await attemptKdfUpgrade(masterPassword, salt, kdfVersion);
                    if (upgrade.upgraded && upgrade.newKey && upgrade.newVerifier) {
                        try {
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
                                result.key!, // old key
                                upgrade.newKey,
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

                            // Only NOW update the profile
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
                                await saveOfflineCredentials(user.id, salt, upgrade.newVerifier);
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

                // One-time migration: persist legacy verifier to profile.
                if (!verificationHash && legacyHash) {
                    const { error: migrateError } = await supabase
                        .from('profiles')
                        .update({ master_password_verifier: legacyHash })
                        .eq('user_id', user.id);

                    if (!migrateError) {
                        setVerificationHash(legacyHash);
                    }
                }

                // ── Fallback: Detect and repair broken KDF upgrades (duress real-mode path) ──
                // This MUST run BEFORE setIsLocked(false) to prevent UI race conditions.
                if (kdfVersion >= 2) {
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

                        const ENCRYPTED_CATEGORY_PREFIX = 'enc:cat:v1:';
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
                                    if (cat.name.startsWith(ENCRYPTED_CATEGORY_PREFIX)) {
                                        await decrypt(cat.name.slice(ENCRYPTED_CATEGORY_PREFIX.length), activeKey);
                                    }
                                    if (cat.icon && cat.icon.startsWith(ENCRYPTED_CATEGORY_PREFIX)) {
                                        await decrypt(cat.icon.slice(ENCRYPTED_CATEGORY_PREFIX.length), activeKey);
                                    }
                                    if (cat.color && cat.color.startsWith(ENCRYPTED_CATEGORY_PREFIX)) {
                                        await decrypt(cat.color.slice(ENCRYPTED_CATEGORY_PREFIX.length), activeKey);
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
                                            if (cat.name.startsWith(ENCRYPTED_CATEGORY_PREFIX)) {
                                                await decrypt(cat.name.slice(ENCRYPTED_CATEGORY_PREFIX.length), activeKey);
                                            }
                                            if (cat.icon && cat.icon.startsWith(ENCRYPTED_CATEGORY_PREFIX)) {
                                                await decrypt(cat.icon.slice(ENCRYPTED_CATEGORY_PREFIX.length), activeKey);
                                            }
                                            if (cat.color && cat.color.startsWith(ENCRYPTED_CATEGORY_PREFIX)) {
                                                await decrypt(cat.color.slice(ENCRYPTED_CATEGORY_PREFIX.length), activeKey);
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
                                                if (catToTest.name.startsWith(ENCRYPTED_CATEGORY_PREFIX)) {
                                                    await decrypt(catToTest.name.slice(ENCRYPTED_CATEGORY_PREFIX.length), oldKey);
                                                } else if (catToTest.icon && catToTest.icon.startsWith(ENCRYPTED_CATEGORY_PREFIX)) {
                                                    await decrypt(catToTest.icon.slice(ENCRYPTED_CATEGORY_PREFIX.length), oldKey);
                                                } else if (catToTest.color && catToTest.color.startsWith(ENCRYPTED_CATEGORY_PREFIX)) {
                                                    await decrypt(catToTest.color.slice(ENCRYPTED_CATEGORY_PREFIX.length), oldKey);
                                                } else {
                                                    throw new Error('No encrypted fields found on broken category to test old key against');
                                                }
                                            }

                                            const repairResult = await reEncryptVault(
                                                brokenItems,
                                                brokenCategories,
                                                oldKey,
                                                activeKey,
                                            );

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

                                            console.info(
                                                `KDF repair (duress path) complete: re-encrypted ${repairResult.itemsReEncrypted} items, ${repairResult.categoriesReEncrypted} categories.`
                                            );
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

                setEncryptionKey(activeKey);
                setIsLocked(false);
                setIsDuressMode(false);
                setLastActivity(Date.now());

                // Derive integrity key for tamper detection (real vault only)
                const hooks = getServiceHooks();
                if (hooks.deriveIntegrityKey) {
                    try {
                        const iKey = await hooks.deriveIntegrityKey(masterPassword, salt);
                        setIntegrityKey(iKey);
                    } catch {
                        console.warn('Failed to derive integrity key');
                    }
                } else {
                    setIntegrityKey(null);
                }

                sessionStorage.setItem(SESSION_KEY, 'active');
                sessionStorage.setItem(SESSION_TIMESTAMP_KEY, Date.now().toString());
                setPendingSessionRestore(false);

                return { error: null };
            }

            // ── Standard Unlock (no duress configured) ──
            // Derive raw KDF bytes; keep them for USK operations below, wipe when done.
            const kdfOutputBytes = await deriveRawKey(masterPassword, salt, kdfVersion, currentDeviceKey || undefined);

            let activeKey: CryptoKey;
            // Tracks whether the PRE-USK migration wrote a new verifier this unlock.
            // Prevents the legacy localStorage verifier migration from overwriting it
            // (React setState is async — the state variable hasn't updated yet).
            let uskMigrationWroteNewVerifier = false;

            try {
                if (encryptedUserKey) {
                    // ── POST-USK PATH: unwrap UserKey, verify, KDF upgrade if needed ──
                    const userKey = await unwrapUserKey(encryptedUserKey, kdfOutputBytes);
                    const isValid = await verifyKey(verifier, userKey);
                    if (!isValid) {
                        recordFailedAttempt();
                        return { error: new Error('Invalid master password') };
                    }
                    resetUnlockAttempts();
                    activeKey = userKey;

                    // KDF upgrade: rewrap-only (vault items NOT re-encrypted)
                    try {
                        const upgrade = await attemptKdfUpgrade(
                            masterPassword, salt, kdfVersion,
                            currentDeviceKey || undefined,
                            encryptedUserKey,
                            kdfOutputBytes, // avoid re-deriving already-computed bytes
                        );
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
                                await saveOfflineCredentials(
                                    user.id, salt, upgrade.newVerifier,
                                    upgrade.activeVersion, upgrade.newEncryptedUserKey,
                                );
                                console.info(`KDF upgraded (USK rewrap-only) from v${kdfVersion} to v${upgrade.activeVersion}. No vault re-encryption needed.`);
                            }
                        }
                    } catch {
                        console.warn('KDF upgrade (USK path) failed, continuing with current version');
                    }
                } else {
                    // ── PRE-USK MIGRATION (first unlock for this user) ──
                    // Verify with the legacy KDF-derived key first
                    const legacyKey = await importMasterKey(kdfOutputBytes);
                    const isValid = await verifyKey(verifier, legacyKey);
                    if (!isValid) {
                        recordFailedAttempt();
                        return { error: new Error('Invalid master password') };
                    }
                    resetUnlockAttempts();

                    // Derive deterministic UserKey (same as old vault key, no re-encryption needed)
                    const uskBundle = await migrateToUserKey(kdfOutputBytes);
                    const newVerifier = await createVerificationHash(uskBundle.userKey);

                    // Persist the new USK wrapper to profiles (non-fatal if fails — retry next unlock)
                    try {
                        const { error: uskError } = await supabase
                            .from('profiles')
                            .update({
                                encrypted_user_key: uskBundle.encryptedUserKey,
                                master_password_verifier: newVerifier,
                            } as Record<string, unknown>)
                            .eq('user_id', user.id);
                        if (!uskError) {
                            uskMigrationWroteNewVerifier = true;
                            setEncryptedUserKey(uskBundle.encryptedUserKey);
                            setVerificationHash(newVerifier);
                            await saveOfflineCredentials(
                                user.id, salt, newVerifier, kdfVersion, uskBundle.encryptedUserKey,
                            );
                            console.info('USK migration complete: encrypted_user_key persisted.');
                        } else {
                            console.warn('USK migration: DB write failed, will retry next unlock.', uskError);
                        }
                    } catch (uskErr) {
                        console.warn('USK migration: unexpected error, will retry next unlock.', uskErr);
                    }

                    activeKey = uskBundle.userKey;

                    // KDF upgrade is intentionally NOT run here.
                    //
                    // The USK migration sets encrypted_user_key wrapped with the current
                    // (v1) KDF output. Running a KDF upgrade in the same session would
                    // update kdf_version to v2 in the DB but leave the USK blob still
                    // wrapped with v1 bytes → permanent lockout on next unlock.
                    //
                    // Instead, the KDF upgrade is handled on the NEXT unlock via the
                    // POST-USK path (encryptedUserKey is now non-null), which uses
                    // rewrapUserKey (rewrap-only, no vault re-encryption needed).
                    // Vault items do NOT need re-encryption: the UserKey bytes are
                    // identical to the old kdfOutputBytes, so data remains readable.
                }
            } finally {
                kdfOutputBytes.fill(0);
            }

            // One-time migration: persist legacy verifier to profile.
            // Guard: skip if USK migration already wrote a fresh verifier this unlock
            // (React setState is async — verificationHash hasn't updated in this execution context).
            if (!verificationHash && legacyHash && !uskMigrationWroteNewVerifier) {
                const { error: migrateError } = await supabase
                    .from('profiles')
                    .update({ master_password_verifier: legacyHash })
                    .eq('user_id', user.id);
                if (!migrateError) {
                    setVerificationHash(legacyHash);
                }
            }

            // ── Fallback: Detect and repair broken KDF upgrades ──
            // This MUST run BEFORE setIsLocked(false) so that UI components
            // don't try to decrypt with the wrong key while repair is in progress.
            // If a previous KDF upgrade updated the verifier + kdf_version
            // but failed to re-encrypt vault data, existing items are still
            // encrypted with the old key.
            if (kdfVersion >= 2) {
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

                    const ENCRYPTED_CATEGORY_PREFIX = 'enc:cat:v1:';
                    let needsFullRepair = false;

                    if (probeItems) {
                        for (const item of probeItems) {
                            try {
                                await decryptVaultItem(item.encrypted_data, activeKey);
                            } catch {
                                needsFullRepair = true;
                                break;
                            }
                        }
                    }

                    if (!needsFullRepair && probeCategories) {
                        for (const cat of probeCategories) {
                            try {
                                if (cat.name.startsWith(ENCRYPTED_CATEGORY_PREFIX)) {
                                    await decrypt(cat.name.slice(ENCRYPTED_CATEGORY_PREFIX.length), activeKey);
                                }
                                if (cat.icon && cat.icon.startsWith(ENCRYPTED_CATEGORY_PREFIX)) {
                                    await decrypt(cat.icon.slice(ENCRYPTED_CATEGORY_PREFIX.length), activeKey);
                                }
                                if (cat.color && cat.color.startsWith(ENCRYPTED_CATEGORY_PREFIX)) {
                                    await decrypt(cat.color.slice(ENCRYPTED_CATEGORY_PREFIX.length), activeKey);
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
                                        await decryptVaultItem(item.encrypted_data, activeKey);
                                    } catch {
                                        brokenItems.push(item);
                                    }
                                }
                            }

                            if (allCategories) {
                                for (const cat of allCategories) {
                                    try {
                                        if (cat.name.startsWith(ENCRYPTED_CATEGORY_PREFIX)) {
                                            await decrypt(cat.name.slice(ENCRYPTED_CATEGORY_PREFIX.length), activeKey);
                                        }
                                        if (cat.icon && cat.icon.startsWith(ENCRYPTED_CATEGORY_PREFIX)) {
                                            await decrypt(cat.icon.slice(ENCRYPTED_CATEGORY_PREFIX.length), activeKey);
                                        }
                                        if (cat.color && cat.color.startsWith(ENCRYPTED_CATEGORY_PREFIX)) {
                                            await decrypt(cat.color.slice(ENCRYPTED_CATEGORY_PREFIX.length), activeKey);
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
                                            await decryptVaultItem(brokenItems[0].encrypted_data, oldKey);
                                        } else if (brokenCategories.length > 0) {
                                            const catToTest = brokenCategories[0];
                                            if (catToTest.name.startsWith(ENCRYPTED_CATEGORY_PREFIX)) {
                                                await decrypt(catToTest.name.slice(ENCRYPTED_CATEGORY_PREFIX.length), oldKey);
                                            } else if (catToTest.icon && catToTest.icon.startsWith(ENCRYPTED_CATEGORY_PREFIX)) {
                                                await decrypt(catToTest.icon.slice(ENCRYPTED_CATEGORY_PREFIX.length), oldKey);
                                            } else if (catToTest.color && catToTest.color.startsWith(ENCRYPTED_CATEGORY_PREFIX)) {
                                                await decrypt(catToTest.color.slice(ENCRYPTED_CATEGORY_PREFIX.length), oldKey);
                                            } else {
                                                throw new Error('No encrypted fields found on broken category to test old key against');
                                            }
                                        }

                                        console.info(`Fallback key v${oldVersion} works. Re-encrypting broken vault data...`);

                                        const repairResult = await reEncryptVault(
                                            brokenItems,
                                            brokenCategories,
                                            oldKey,
                                            activeKey,
                                        );

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

                                        console.info(
                                            `KDF repair complete: re-encrypted ${repairResult.itemsReEncrypted} items, ${repairResult.categoriesReEncrypted} categories from v${oldVersion} to v${kdfVersion}.`
                                        );
                                        break; // Repair done, stop trying older versions
                                    } catch {
                                        continue;
                                    }
                                }
                            }
                        }
                    }
                } catch (repairErr) {
                    // Non-fatal: vault still opens with whatever key works
                    console.error('KDF repair check failed:', repairErr);
                }
            }

            // ── Private Key Migration: re-wrap legacy RSA/PQ keys to USK format ──
            // Non-fatal and idempotent — safe to call every unlock (no-op when already migrated).
            try {
                await migrateLegacyPrivateKeysToUserKey(user.id, masterPassword, activeKey);
            } catch (pkMigrErr) {
                console.warn('Private key USK migration failed, will retry next unlock:', pkMigrErr);
            }

            setEncryptionKey(activeKey);
            setIsLocked(false);
            setIsDuressMode(false);
            setLastActivity(Date.now());

            // Derive integrity key for tamper detection
            const hooks = getServiceHooks();
            if (hooks.deriveIntegrityKey) {
                try {
                    const iKey = await hooks.deriveIntegrityKey(masterPassword, salt);
                    setIntegrityKey(iKey);
                } catch {
                    console.warn('Failed to derive integrity key');
                }
            } else {
                setIntegrityKey(null);
            }

            sessionStorage.setItem(SESSION_KEY, 'active');
            sessionStorage.setItem(SESSION_TIMESTAMP_KEY, Date.now().toString());
            setPendingSessionRestore(false);

            return { error: null };
        } catch (err) {
            console.error('Error unlocking vault:', err);
            recordFailedAttempt();
            return { error: new Error('Invalid master password') };
        }
    }, [user, salt, verificationHash, kdfVersion, duressConfig, currentDeviceKey, encryptedUserKey]);

    /**
     * Unlocks the vault using a registered passkey with PRF.
     * The PRF output is used to unwrap the stored encryption key.
     */
    const unlockWithPasskey = useCallback(async (): Promise<{ error: Error | null }> => {
        // Explicitly check for user to prevent "Authentication required" edge function errors
        if (!user) {
            console.warn('unlockWithPasskey called without active user session');
            return { error: new Error('User session not ready. Please wait a moment.') };
        }

        const cooldown = getUnlockCooldown();
        if (cooldown !== null) {
            const seconds = Math.ceil(cooldown / 1000);
            return { error: new Error(`Too many attempts. Try again in ${seconds}s.`) };
        }

        const legacyHash = localStorage.getItem(`singra_verify_${user.id}`);
        const verifier = verificationHash || legacyHash;

        try {
            const result = await authenticatePasskey();

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

            // Verify the key works by checking the verification hash
            if (verifier) {
                const isValid = await verifyKey(verifier, result.encryptionKey);
                if (!isValid) {
                    recordFailedAttempt();
                    return { error: new Error('Passkey-derived key does not match vault — key may be outdated') };
                }
            }

            // Success — reset rate-limiter and unlock
            resetUnlockAttempts();

            setEncryptionKey(result.encryptionKey);
            setIsLocked(false);
            setIsDuressMode(false); // Passkey always unlocks real vault
            setLastActivity(Date.now());

            // Note: Cannot derive integrity key during passkey unlock because
            // we don't have access to the master password. Integrity verification
            // is skipped for passkey-unlocked sessions. This is an acceptable
            // trade-off since passkey unlock is already hardware-secured.
            setIntegrityKey(null);

            // Store session indicator
            sessionStorage.setItem(SESSION_KEY, 'active');
            sessionStorage.setItem(SESSION_TIMESTAMP_KEY, Date.now().toString());
            setPendingSessionRestore(false);

            return { error: null };
        } catch (err) {
            console.error('Passkey unlock error:', err);
            recordFailedAttempt();
            return { error: new Error('Passkey unlock failed') };
        }
    }, [user, verificationHash]);

    /**
     * Derives raw AES-256 key bytes for passkey registration.
     * Requires the master password and must be called while vault is unlocked.
     *
     * @param masterPassword - The user's master password
     * @returns Raw 32-byte key or null if derivation fails
     */
    const getRawKeyForPasskey = useCallback(async (
        masterPassword: string,
    ): Promise<Uint8Array | null> => {
        if (!user || !salt || isLocked) return null;

        let rawKeyBytes: Uint8Array | null = null;
        try {
            rawKeyBytes = await deriveRawKey(masterPassword, salt, kdfVersion, currentDeviceKey || undefined);

            const legacyHash = localStorage.getItem(`singra_verify_${user.id}`);
            const verifier = verificationHash || legacyHash;
            if (!verifier) {
                return rawKeyBytes;
            }

            // Post-USK: verify with UserKey (not raw KDF bytes) — verifier was created with UserKey.
            // Pre-USK / migrated accounts (UserKey = kdfOutputBytes): both paths are equivalent.
            if (encryptedUserKey) {
                const userKey = await unwrapUserKey(encryptedUserKey, rawKeyBytes);
                const isValid = await verifyKey(verifier, userKey);
                if (!isValid) {
                    rawKeyBytes.fill(0);
                    return null;
                }
            } else {
                const derivedKey = await importMasterKey(rawKeyBytes);
                const isValid = await verifyKey(verifier, derivedKey);
                if (!isValid) {
                    rawKeyBytes.fill(0);
                    return null;
                }
            }

            return rawKeyBytes;
        } catch (err) {
            if (rawKeyBytes) {
                rawKeyBytes.fill(0);
            }
            console.error('Failed to derive raw key for passkey:', err);
            return null;
        }
    }, [user, salt, kdfVersion, isLocked, verificationHash, encryptedUserKey]);

    /**
     * Locks the vault and clears encryption key from memory
     */
    const lock = useCallback(() => {
        setEncryptionKey(null);
        setIntegrityKey(null);
        setIsLocked(true);
        setIsDuressMode(false);
        setIntegrityVerified(false);
        setLastIntegrityResult(null);
        // Clear session data
        sessionStorage.removeItem(SESSION_KEY);
        sessionStorage.removeItem(SESSION_TIMESTAMP_KEY);
        setPendingSessionRestore(false);
    }, []);

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
                // ── USK path: rewrap UserKey under device-key-enhanced KDF ──
                // Vault items stay encrypted under UserKey — no vault re-encryption needed.
                // Only the 32-byte UserKey wrapper changes.
                const oldKdfOutputBytes = await deriveRawKey(masterPassword, salt, kdfVersion);
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

            // ── Legacy path (pre-USK, encryptedUserKey = null) ──
            // Vault items are encrypted directly with KDF-derived key — full re-encryption required.
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
    }, [user, salt, kdfVersion, encryptionKey, encryptedUserKey]);

    /**
     * Verifies vault items against stored integrity root.
     * Detects server-side tampering (deleted/modified/added items).
     */
    const verifyIntegrity = useCallback(async (
        items: VaultItemForIntegrity[]
    ): Promise<IntegrityVerificationResult | null> => {
        const hooks = getServiceHooks();
        if (!user || !integrityKey || !hooks.verifyVaultIntegrity || !hooks.updateIntegrityRoot) {
            return null;
        }

        try {
            const result = await hooks.verifyVaultIntegrity(items, integrityKey, user.id);
            setIntegrityVerified(true);
            setLastIntegrityResult(result);

            if (!result.valid && !result.isFirstCheck) {
                console.warn('Vault integrity check FAILED — possible tampering detected!');
            } else if (result.isFirstCheck) {
                // First check: establish baseline
                await hooks.updateIntegrityRoot(items, integrityKey, user.id);
                console.info('Vault integrity baseline established');
            }

            return result;
        } catch (err) {
            console.error('Vault integrity verification error:', err);
            return null;
        }
    }, [user, integrityKey]);

    /**
     * Updates the integrity root after vault modifications.
     */
    const updateIntegrity = useCallback(async (
        items: VaultItemForIntegrity[]
    ): Promise<void> => {
        const hooks = getServiceHooks();
        if (!user || !integrityKey || !hooks.updateIntegrityRoot) {
            return;
        }

        try {
            await hooks.updateIntegrityRoot(items, integrityKey, user.id);
        } catch (err) {
            console.error('Failed to update integrity root:', err);
        }
    }, [user, integrityKey]);

    /**
     * Encrypts plaintext data
     */
    const encryptData = useCallback(async (plaintext: string): Promise<string> => {
        if (!encryptionKey) {
            throw new Error('Vault is locked');
        }
        return encrypt(plaintext, encryptionKey);
    }, [encryptionKey]);

    /**
     * Decrypts encrypted data
     */
    const decryptData = useCallback(async (encrypted: string): Promise<string> => {
        if (!encryptionKey) {
            throw new Error('Vault is locked');
        }
        return decrypt(encrypted, encryptionKey);
    }, [encryptionKey]);

    /**
     * Encrypts a vault item
     */
    const encryptItem = useCallback(async (data: VaultItemData, entryId?: string): Promise<string> => {
        if (!encryptionKey) {
            throw new Error('Vault is locked');
        }
        return encryptVaultItem(data, encryptionKey, entryId);
    }, [encryptionKey]);

    /**
     * Decrypts a vault item
     */
    const decryptItem = useCallback(async (encryptedData: string, entryId?: string): Promise<VaultItemData> => {
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
                getRawKeyForPasskey,
                encryptData,
                decryptData,
                encryptItem,
                decryptItem,
                autoLockTimeout,
                setAutoLockTimeout,
                pendingSessionRestore,
                verifyIntegrity,
                updateIntegrity,
                integrityVerified,
                lastIntegrityResult,
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

