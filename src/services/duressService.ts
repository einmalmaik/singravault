// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE
/**
 * @fileoverview Duress (Panic) Password Service for Singra Vault
 *
 * Implements a plausible deniability feature where a secondary "duress" password
 * unlocks a decoy vault instead of the real vault. This protects users who may be
 * coerced into revealing their password (e.g., at border crossings, under threat).
 *
 * Architecture:
 * - Duress password has its own salt, verifier, and derived key
 * - Decoy items are stored in the same vault_items table but encrypted with duress key
 * - Decoy items have a `_duress: true` marker inside encrypted_data
 * - On unlock, both verifiers are checked in parallel (constant time)
 * - The matching key determines which items are decryptable
 *
 * Security Properties:
 * - An observer cannot distinguish real from duress unlock (same UI, timing)
 * - Database queries are identical for both vaults
 * - Without knowing both passwords, existence of duress vault is unprovable
 *
 * @see docs/SECURITY_HARDENING_PLAN.md Phase 5.2
 */

import {
    deriveKey,
    generateSalt,
    createVerificationHash,
    verifyKey,
    CURRENT_KDF_VERSION,
} from './cryptoService';
import { supabase } from '@/integrations/supabase/client';

// ============ Type Definitions ============

export interface DuressConfig {
    /** Whether duress mode is enabled for this user */
    enabled: boolean;
    /** Salt for duress key derivation (base64) */
    salt: string | null;
    /** Verifier hash for duress password */
    verifier: string | null;
    /** KDF version used for duress password */
    kdfVersion: number;
}

export interface DuressSetupResult {
    success: boolean;
    error?: string;
}

export interface DuressUnlockResult {
    /** Which vault was unlocked */
    mode: 'real' | 'duress' | 'invalid';
    /** The derived CryptoKey for the unlocked vault */
    key: CryptoKey | null;
    /** Error message if unlock failed */
    error?: string;
}

export interface DecoyItem {
    title: string;
    username?: string;
    password?: string;
    website?: string;
    notes?: string;
}

// ============ Constants ============

/** Marker field added to decoy items (inside encrypted JSON) */
export const DURESS_MARKER_FIELD = '_duress';

/** Generates a random password with 8-16 characters including upper/lowercase, digits, and symbols */
function generateDecoyPassword(): string {
    const upper = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    const lower = 'abcdefghijklmnopqrstuvwxyz';
    const digits = '0123456789';
    const symbols = '!@#$%&*?+-_=';
    const all = upper + lower + digits + symbols;

    const length = 8 + Math.floor(Math.random() * 9); // 8–16
    const required = [
        upper[Math.floor(Math.random() * upper.length)],
        lower[Math.floor(Math.random() * lower.length)],
        digits[Math.floor(Math.random() * digits.length)],
        symbols[Math.floor(Math.random() * symbols.length)],
    ];

    const rest = Array.from({ length: length - required.length }, () =>
        all[Math.floor(Math.random() * all.length)]
    );

    // Shuffle all characters together
    const chars = [...required, ...rest];
    for (let i = chars.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        [chars[i], chars[j]] = [chars[j], chars[i]];
    }
    return chars.join('');
}

/** Pool of possible decoy services with title, website, and username style */
const DECOY_SERVICE_POOL: { title: string; website: string; usernameType: 'email' | 'username' }[] = [
    { title: 'Gmail', website: 'https://mail.google.com', usernameType: 'email' },
    { title: 'Amazon', website: 'https://amazon.de', usernameType: 'email' },
    { title: 'Netflix', website: 'https://netflix.com', usernameType: 'email' },
    { title: 'PayPal', website: 'https://paypal.com', usernameType: 'email' },
    { title: 'Spotify', website: 'https://spotify.com', usernameType: 'email' },
    { title: 'Instagram', website: 'https://instagram.com', usernameType: 'username' },
    { title: 'Deutsche Bank Online', website: 'https://meine.deutsche-bank.de', usernameType: 'email' },
    { title: 'eBay Kleinanzeigen', website: 'https://www.kleinanzeigen.de', usernameType: 'email' },
    { title: 'Steam', website: 'https://store.steampowered.com', usernameType: 'username' },
    { title: 'LinkedIn', website: 'https://linkedin.com', usernameType: 'email' },
    { title: 'Apple ID', website: 'https://appleid.apple.com', usernameType: 'email' },
    { title: 'Outlook Mail', website: 'https://outlook.live.com', usernameType: 'email' },
    { title: 'Twitter / X', website: 'https://x.com', usernameType: 'username' },
    { title: 'GitHub', website: 'https://github.com', usernameType: 'username' },
    { title: 'Dropbox', website: 'https://dropbox.com', usernameType: 'email' },
    { title: 'Discord', website: 'https://discord.com', usernameType: 'email' },
    { title: 'Reddit', website: 'https://reddit.com', usernameType: 'username' },
    { title: 'Twitch', website: 'https://twitch.tv', usernameType: 'username' },
    { title: 'Adobe Creative Cloud', website: 'https://account.adobe.com', usernameType: 'email' },
    { title: 'Microsoft 365', website: 'https://office.com', usernameType: 'email' },
    { title: 'Zalando', website: 'https://zalando.de', usernameType: 'email' },
    { title: 'Otto', website: 'https://otto.de', usernameType: 'email' },
    { title: 'Disney+', website: 'https://disneyplus.com', usernameType: 'email' },
    { title: 'Snapchat', website: 'https://snapchat.com', usernameType: 'username' },
    { title: 'TikTok', website: 'https://tiktok.com', usernameType: 'username' },
    { title: 'Notion', website: 'https://notion.so', usernameType: 'email' },
    { title: 'Slack', website: 'https://slack.com', usernameType: 'email' },
    { title: 'Commerzbank', website: 'https://commerzbank.de', usernameType: 'email' },
    { title: 'ING DiBa', website: 'https://ing.de', usernameType: 'email' },
    { title: 'N26', website: 'https://n26.com', usernameType: 'email' },
];

const FIRST_NAMES = [
    'alex', 'chris', 'robin', 'sam', 'max', 'kim', 'luca', 'nico', 'leon', 'mika',
    'finn', 'noah', 'jamie', 'toni', 'sascha', 'kai', 'jona', 'emery', 'taylor', 'morgan',
];
const LAST_NAMES = [
    'richter', 'weber', 'schmidt', 'fischer', 'meyer', 'wagner', 'becker', 'schulz',
    'hoffmann', 'koch', 'braun', 'klein', 'wolf', 'lang', 'frank', 'berger', 'peters',
];
const EMAIL_DOMAINS = ['gmail.com', 'outlook.de', 'web.de', 'gmx.de', 'yahoo.com', 'protonmail.com'];
const USERNAME_ADJECTIVES = ['shadow', 'dark', 'cool', 'fast', 'silent', 'lucky', 'wild', 'lazy', 'epic', 'neon'];
const USERNAME_NOUNS = ['wolf', 'fox', 'hawk', 'tiger', 'panda', 'ninja', 'pixel', 'byte', 'storm', 'flame'];

function pickRandom<T>(arr: T[]): T {
    return arr[Math.floor(Math.random() * arr.length)];
}

function generateDecoyIdentity(): { emailMain: string; emailAlt: string } {
    const first = pickRandom(FIRST_NAMES);
    const last = pickRandom(LAST_NAMES);
    const year = 85 + Math.floor(Math.random() * 16); // 85–00
    const sep = pickRandom(['.', '_', '']);
    const domainMain = pickRandom(EMAIL_DOMAINS);
    let domainAlt = pickRandom(EMAIL_DOMAINS);
    while (domainAlt === domainMain) domainAlt = pickRandom(EMAIL_DOMAINS);

    const emailMain = `${first}${sep}${last}${year}@${domainMain}`;
    const emailAlt = `${first[0]}.${last}_${year}@${domainAlt}`;
    return { emailMain, emailAlt };
}

function generateDecoyUsername(): string {
    const style = Math.floor(Math.random() * 3);
    const num = Math.floor(Math.random() * 999);
    if (style === 0) return `${pickRandom(USERNAME_ADJECTIVES)}_${pickRandom(USERNAME_NOUNS)}${num}`;
    if (style === 1) return `${pickRandom(FIRST_NAMES)}${pickRandom(USERNAME_NOUNS)}${num}`;
    return `${pickRandom(USERNAME_NOUNS)}${pickRandom(USERNAME_ADJECTIVES)}${Math.floor(Math.random() * 99)}`;
}

/** Generates a fully randomized set of decoy items */
function generateDecoyItems(): DecoyItem[] {
    const { emailMain, emailAlt } = generateDecoyIdentity();
    const count = 10 + Math.floor(Math.random() * 5); // 10–14 items

    // Shuffle and pick from pool
    const shuffled = [...DECOY_SERVICE_POOL].sort(() => Math.random() - 0.5);
    const selected = shuffled.slice(0, count);

    return selected.map((service) => {
        let username: string;
        if (service.usernameType === 'username') {
            username = generateDecoyUsername();
        } else {
            username = Math.random() < 0.6 ? emailMain : emailAlt;
        }
        return {
            title: service.title,
            username,
            password: generateDecoyPassword(),
            website: service.website,
        };
    });
}

// ============ Core Functions ============

/**
 * Loads duress configuration for a user.
 *
 * @param userId - The user's ID
 * @returns Duress configuration or null if not set up
 */
export async function getDuressConfig(userId: string): Promise<DuressConfig | null> {
    try {
        const { data, error } = await supabase
            .from('profiles')
            .select('duress_salt, duress_password_verifier, duress_kdf_version')
            .eq('user_id', userId)
            .single() as { data: Record<string, unknown> | null; error: unknown };

        if (error || !data) {
            return null;
        }

        const duressSalt = data.duress_salt as string | null;
        const duressVerifier = data.duress_password_verifier as string | null;

        return {
            enabled: !!(duressSalt && duressVerifier),
            salt: duressSalt,
            verifier: duressVerifier,
            kdfVersion: (data.duress_kdf_version as number) ?? CURRENT_KDF_VERSION,
        };
    } catch (err) {
        console.error('Failed to load duress config:', err);
        return null;
    }
}

/**
 * Sets up a duress (panic) password for a user.
 *
 * This creates a separate encryption key and verifier that will unlock
 * a decoy vault instead of the real one. The duress password must be
 * different from the real master password.
 *
 * @param userId - The user's ID
 * @param duressPassword - The panic password to set up
 * @param realPassword - The real master password (to verify they're different)
 * @param realSalt - The salt used for the real password
 * @returns Setup result
 */
export async function setupDuressPassword(
    userId: string,
    duressPassword: string,
    realPassword: string,
    realSalt: string,
): Promise<DuressSetupResult> {
    // Prevent using the same password
    if (duressPassword === realPassword) {
        return {
            success: false,
            error: 'Duress password must be different from your master password',
        };
    }

    // Validate password strength (basic check)
    if (duressPassword.length < 8) {
        return {
            success: false,
            error: 'Duress password must be at least 8 characters',
        };
    }

    try {
        // Generate a new salt for the duress password (must be different!)
        const duressSalt = generateSalt();

        // Derive the duress key
        const duressKey = await deriveKey(duressPassword, duressSalt, CURRENT_KDF_VERSION);

        // Create verifier for the duress password
        const duressVerifier = await createVerificationHash(duressKey);

        // Store duress credentials in profile
        const { error: updateError } = await supabase
            .from('profiles')
            .update({
                duress_salt: duressSalt,
                duress_password_verifier: duressVerifier,
                duress_kdf_version: CURRENT_KDF_VERSION,
            } as Record<string, unknown>)
            .eq('user_id', userId);

        if (updateError) {
            return {
                success: false,
                error: `Failed to save duress password: ${updateError.message}`,
            };
        }

        return { success: true };
    } catch (err) {
        console.error('Error setting up duress password:', err);
        return {
            success: false,
            error: 'Failed to set up duress password',
        };
    }
}

/**
 * Attempts to unlock with either the real or duress password.
 *
 * Both verifications are performed to maintain constant-time behavior
 * (preventing timing attacks that could reveal duress mode existence).
 *
 * @param password - The entered password
 * @param realSalt - Salt for real password
 * @param realVerifier - Verifier for real password
 * @param realKdfVersion - KDF version for real password
 * @param duressConfig - Duress configuration (null if not enabled)
 * @returns Unlock result indicating which vault was opened
 */
export async function attemptDualUnlock(
    password: string,
    realSalt: string,
    realVerifier: string,
    realKdfVersion: number,
    duressConfig: DuressConfig | null,
): Promise<DuressUnlockResult> {
    try {
        // SECURITY: Constant-time execution to prevent timing attacks
        // Always derive BOTH keys to avoid timing leakage of duress presence.
        // Use the correct KDF version for each key to avoid breaking unlocks.

        const duressKdfVersion = duressConfig?.kdfVersion ?? realKdfVersion;

        // Always derive the real key with the user's actual KDF version
        const realKeyPromise = deriveKey(password, realSalt, realKdfVersion);

        // For duress: use real salt if enabled, dummy salt if disabled
        // The dummy salt ensures the same computational cost even when duress is disabled
        const dummySalt = 'Y29uc3RhbnRfdGltaW5nX2R1bW15X3NhbHQ='; // base64 for "constant_timing_dummy_salt"
        const duressKeyPromise = deriveKey(
            password,
            duressConfig?.salt || dummySalt,
            duressKdfVersion
        );

        // Wait for both derivations to complete
        const [realKey, duressKey] = await Promise.all([realKeyPromise, duressKeyPromise]);

        // SECURITY: Perform both verifications regardless of results
        // This prevents early-exit timing attacks
        const realValidPromise = verifyKey(realVerifier, realKey);
        const duressValidPromise = duressConfig?.verifier
            ? verifyKey(duressConfig.verifier, duressKey)
            : Promise.resolve(false);

        // Wait for both verifications
        const [realValid, duressValid] = await Promise.all([
            realValidPromise,
            duressValidPromise,
        ]);

        // Use constant-time comparison for the final decision
        // Return results based on which key validated successfully
        if (realValid) {
            // Add small random delay to mask any micro-timing differences
            await constantTimeDelay();
            return {
                mode: 'real',
                key: realKey,
            };
        }

        if (duressConfig?.enabled && duressValid) {
            // Add small random delay to mask any micro-timing differences
            await constantTimeDelay();
            return {
                mode: 'duress',
                key: duressKey,
            };
        }

        // Neither matched - add delay before returning
        await constantTimeDelay();
        return {
            mode: 'invalid',
            key: null,
            error: 'Invalid password',
        };
    } catch (err) {
        console.error('Dual unlock error:', err);
        // Even on error, add delay to maintain consistent timing
        await constantTimeDelay();
        return {
            mode: 'invalid',
            key: null,
            error: 'Unlock failed',
        };
    }
}

/**
 * Adds a small random delay (0-5ms) to mask micro-timing differences
 * This helps prevent timing attacks that could distinguish between code paths
 */
async function constantTimeDelay(): Promise<void> {
    const delay = crypto.getRandomValues(new Uint8Array(1))[0] % 6; // 0-5ms
    return new Promise(resolve => setTimeout(resolve, delay));
}

/**
 * Disables duress mode for a user.
 *
 * This removes the duress salt and verifier but does NOT delete decoy items.
 * Decoy items become inaccessible without the duress key.
 *
 * @param userId - The user's ID
 * @returns Success status
 */
export async function disableDuressMode(userId: string): Promise<{ success: boolean; error?: string }> {
    try {
        const { error } = await supabase
            .from('profiles')
            .update({
                duress_salt: null,
                duress_password_verifier: null,
                duress_kdf_version: null,
            } as Record<string, unknown>)
            .eq('user_id', userId);

        if (error) {
            return { success: false, error: error.message };
        }

        return { success: true };
    } catch (err) {
        console.error('Error disabling duress mode:', err);
        return { success: false, error: 'Failed to disable duress mode' };
    }
}

/**
 * Changes the duress password.
 *
 * This re-derives the key and updates the verifier. Existing decoy items
 * must be re-encrypted with the new key.
 *
 * @param userId - The user's ID
 * @param oldDuressPassword - Current duress password (for verification)
 * @param newDuressPassword - New duress password
 * @param realPassword - Real master password (to ensure they stay different)
 * @returns Change result
 */
export async function changeDuressPassword(
    userId: string,
    oldDuressPassword: string,
    newDuressPassword: string,
    realPassword: string,
): Promise<{ success: boolean; error?: string; newKey?: CryptoKey }> {
    // Prevent same password as real
    if (newDuressPassword === realPassword) {
        return {
            success: false,
            error: 'Duress password must be different from your master password',
        };
    }

    // Load current duress config
    const config = await getDuressConfig(userId);
    if (!config?.enabled || !config.salt) {
        return { success: false, error: 'Duress mode is not enabled' };
    }

    try {
        // Verify old duress password
        const oldKey = await deriveKey(oldDuressPassword, config.salt, config.kdfVersion);

        const { data } = await supabase
            .from('profiles')
            .select('duress_password_verifier')
            .eq('user_id', userId)
            .single() as { data: { duress_password_verifier?: string } | null };

        if (!data?.duress_password_verifier) {
            return { success: false, error: 'Duress verifier not found' };
        }

        const oldValid = await verifyKey(data.duress_password_verifier, oldKey);
        if (!oldValid) {
            return { success: false, error: 'Current duress password is incorrect' };
        }

        // Generate new salt and key
        const newSalt = generateSalt();
        const newKey = await deriveKey(newDuressPassword, newSalt, CURRENT_KDF_VERSION);
        const newVerifier = await createVerificationHash(newKey);

        // Update profile
        const { error: updateError } = await supabase
            .from('profiles')
            .update({
                duress_salt: newSalt,
                duress_password_verifier: newVerifier,
                duress_kdf_version: CURRENT_KDF_VERSION,
            } as Record<string, unknown>)
            .eq('user_id', userId);

        if (updateError) {
            return { success: false, error: updateError.message };
        }

        // Return new key so caller can re-encrypt decoy items
        return { success: true, newKey };
    } catch (err) {
        console.error('Error changing duress password:', err);
        return { success: false, error: 'Failed to change duress password' };
    }
}

/**
 * Checks if an item is a decoy item (encrypted with duress key).
 *
 * This check is performed AFTER decryption by looking for the marker field.
 *
 * @param decryptedData - The decrypted item data object
 * @returns True if this is a decoy item
 */
export function isDecoyItem(decryptedData: { _duress?: boolean } | Record<string, unknown>): boolean {
    return (decryptedData as Record<string, unknown>)[DURESS_MARKER_FIELD] === true;
}

/**
 * Adds the duress marker to an item before encryption.
 *
 * @param itemData - The item data to mark as decoy
 * @returns Item data with duress marker
 */
export function markAsDecoyItem<T extends Record<string, unknown>>(itemData: T): T & { _duress: true } {
    return {
        ...itemData,
        [DURESS_MARKER_FIELD]: true,
    };
}

/**
 * Removes the duress marker from decrypted item data for display.
 *
 * @param itemData - The decrypted item data
 * @returns Item data without the internal marker
 */
export function stripDecoyMarker<T extends Record<string, unknown>>(itemData: T): Omit<T, '_duress'> {
    const { _duress, ...rest } = itemData as T & { _duress?: boolean };
    return rest;
}

/**
 * Returns default decoy items to populate when duress mode is first enabled.
 *
 * @returns Array of generic-looking decoy items (deep copy)
 */
export function getDefaultDecoyItems(): DecoyItem[] {
    return generateDecoyItems();
}
