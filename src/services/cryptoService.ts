// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE
/**
 * @fileoverview Cryptographic Service for Singra Vault
 * 
 * Implements zero-knowledge client-side encryption using:
 * - Argon2id for key derivation from master password
 * - AES-256-GCM for authenticated encryption of vault data
 * 
 * Supports KDF parameter versioning for transparent auto-migration
 * to stronger parameters after successful unlock.
 * 
 * SECURITY: The master password NEVER leaves the client.
 * Only encrypted data is stored on the server.
 */

import { argon2id } from 'hash-wasm';
import { SecureBuffer } from './secureBuffer';
import { deriveWithDeviceKey } from './deviceKeyService';

// ============ KDF Parameter Definitions ============

/**
 * The latest KDF version. Newly set-up accounts use this version.
 * Existing users on older versions are auto-migrated on unlock.
 */
export const CURRENT_KDF_VERSION = 2;

/**
 * KDF parameter sets indexed by version number.
 *
 *   v1: Original (64 MiB) - ~300 ms on modern devices
 *   v2: Enhanced (128 MiB) - ~500-600 ms on modern devices, OWASP 2025 recommended
 *
 * IMPORTANT: Once a version is released, its parameters MUST NEVER be changed.
 * Only add new versions.
 */
export const KDF_PARAMS: Record<number, KdfParams> = {
    1: { memory: 65536, iterations: 3, parallelism: 4, hashLength: 32 },
    2: { memory: 131072, iterations: 3, parallelism: 4, hashLength: 32 },
};

const SALT_LENGTH = 16; // 128 bits
const IV_LENGTH = 12; // 96 bits (standard for AES-GCM)
const TAG_LENGTH = 128; // 128 bits authentication tag

/** Constant used in v3 verification hashes (no plaintext stored in DB) */
const VERIFICATION_CONSTANT_V3 = 'SINGRA_VAULT_VERIFY_V3';

/** Internal counter for legacy (no-AAD) decryption fallbacks (Phase 1 monitoring) */
let _legacyDecryptCount = 0;

/**
 * Generates a cryptographically secure random salt
 * @returns Base64-encoded salt string
 */
export function generateSalt(): string {
    const salt = crypto.getRandomValues(new Uint8Array(SALT_LENGTH));
    return uint8ArrayToBase64(salt);
}

/**
 * Derives raw AES-256 key bytes from master password using Argon2id.
 * When a deviceKey is provided, the result is additionally strengthened
 * via HKDF-Expand with the Device Key as salt.
 * 
 * @param masterPassword - The user's master password
 * @param saltBase64 - Base64-encoded salt from profiles table
 * @param kdfVersion - KDF parameter version (defaults to current version)
 * @param deviceKey - Optional 256-bit device key for additional strengthening
 * @returns Raw key bytes (caller is responsible for wiping with .fill(0))
 */
export async function deriveRawKey(
    masterPassword: string,
    saltBase64: string,
    kdfVersion: number = CURRENT_KDF_VERSION,
    deviceKey?: Uint8Array,
): Promise<Uint8Array> {
    const params = KDF_PARAMS[kdfVersion];
    if (!params) {
        throw new Error(`Unknown KDF version: ${kdfVersion}`);
    }

    const salt = base64ToUint8Array(saltBase64);

    // Derive raw key bytes using Argon2id via hash-wasm
    const result = await argon2id({
        password: masterPassword,
        salt: salt,
        parallelism: params.parallelism,
        iterations: params.iterations,
        memorySize: params.memory,
        hashLength: params.hashLength,
        outputType: 'binary',
    }) as unknown;

    // Be robust to different return types from mocks/test shims:
    // - Uint8Array (preferred for outputType 'binary')
    // - ArrayBuffer (convert to Uint8Array)
    // - string (hex) from older mocks - convert to bytes with secure cleanup
    let argon2Bytes: Uint8Array;
    if (result instanceof Uint8Array) {
        argon2Bytes = result;
    } else if (result instanceof ArrayBuffer) {
        argon2Bytes = new Uint8Array(result);
    } else if (typeof result === 'string') {
        // SECURITY: Hex string conversion with immediate cleanup
        // Use SecureBuffer to minimize heap exposure
        const hex = result;
        argon2Bytes = new Uint8Array(hex.length / 2);

        // Convert hex to bytes
        for (let i = 0; i < argon2Bytes.length; i++) {
            argon2Bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
        }

        // Attempt to clear the hex string from memory
        // Note: JavaScript strings are immutable, but this helps GC
        try {
            // Force the string out of any internal caches
            if (typeof (hex as any).fill === 'function') {
                (hex as any).fill(0);
            }
        } catch {
            // Best effort - strings are immutable in JS
        }
    } else {
        // Fallback: try to construct Uint8Array
        try {
            // @ts-ignore
            argon2Bytes = new Uint8Array(result);
        } catch {
            throw new Error('argon2id returned unsupported type');
        }
    }

    // If a Device Key is provided, strengthen via HKDF-Expand.
    // This produces a key that requires BOTH the master password AND the device key.
    if (deviceKey) {
        const combined = await deriveWithDeviceKey(argon2Bytes, deviceKey);
        // Wipe the intermediate Argon2id output
        argon2Bytes.fill(0);
        return combined;
    }

    return argon2Bytes;
}

/**
 * Derives raw AES-256 key bytes wrapped in a SecureBuffer for safer handling.
 * The SecureBuffer auto-zeros on destroy and prevents accidental leaks.
 *
 * @param masterPassword - The user's master password
 * @param saltBase64 - Base64-encoded salt from profiles table
 * @param kdfVersion - KDF parameter version (defaults to current version)
 * @param deviceKey - Optional 256-bit device key for additional strengthening
 * @returns SecureBuffer containing raw key bytes (caller MUST call .destroy())
 */
export async function deriveRawKeySecure(
    masterPassword: string,
    saltBase64: string,
    kdfVersion: number = CURRENT_KDF_VERSION,
    deviceKey?: Uint8Array,
): Promise<SecureBuffer> {
    const rawBytes = await deriveRawKey(masterPassword, saltBase64, kdfVersion, deviceKey);
    const secure = SecureBuffer.fromBytes(rawBytes);
    // Zero the temporary copy immediately
    rawBytes.fill(0);
    return secure;
}

/**
 * Derives an AES-256 encryption key from master password using Argon2id.
 * When a deviceKey is provided, the result is additionally strengthened
 * via HKDF-Expand with the Device Key as salt.
 * 
 * @param masterPassword - The user's master password
 * @param saltBase64 - Base64-encoded salt from profiles table
 * @param kdfVersion - KDF parameter version (defaults to current version)
 * @param deviceKey - Optional 256-bit device key for additional strengthening
 * @returns CryptoKey suitable for AES-GCM operations
 */
export async function deriveKey(
    masterPassword: string,
    saltBase64: string,
    kdfVersion: number = CURRENT_KDF_VERSION,
    deviceKey?: Uint8Array,
): Promise<CryptoKey> {
    const keyBytes = await deriveRawKey(masterPassword, saltBase64, kdfVersion, deviceKey);
    try {
        return await importMasterKey(keyBytes);
    } finally {
        // SECURITY: Wipe raw key bytes from memory as soon as the
        // non-extractable CryptoKey has been created.
        keyBytes.fill(0);
    }
}

/**
 * Imports a raw AES-256 key bytes into a CryptoKey
 * 
 * @param keyBytes - Raw key bytes
 * @returns CryptoKey suitable for AES-GCM operations
 */
export async function importMasterKey(
    keyBytes: Uint8Array | BufferSource
): Promise<CryptoKey> {
    return crypto.subtle.importKey(
        'raw',
        keyBytes as BufferSource, // BufferSource type for importKey
        { name: 'AES-GCM', length: 256 },
        false, // not extractable
        ['encrypt', 'decrypt']
    );
}

/**
 * Encrypts plaintext data using AES-256-GCM
 * 
 * Output format: base64(IV || ciphertext || authTag)
 * 
 * @param plaintext - String data to encrypt
 * @param key - CryptoKey derived from master password
 * @param aad - Optional Additional Authenticated Data (e.g. entry ID).
 *              AAD is included in the GCM auth tag but NOT stored in the
 *              ciphertext. The same AAD must be provided at decryption.
 *              SECURITY: Binds ciphertext to a context (e.g. vault entry ID)
 *              to prevent ciphertext-swap attacks.
 * @returns Base64-encoded encrypted data
 */
export async function encrypt(
    plaintext: string,
    key: CryptoKey,
    aad?: string
): Promise<string> {
    const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH));
    const plaintextBytes = new TextEncoder().encode(plaintext);
    const additionalData = aad ? new TextEncoder().encode(aad) : undefined;

    const ciphertext = await crypto.subtle.encrypt(
        {
            name: 'AES-GCM',
            iv: iv,
            tagLength: TAG_LENGTH,
            ...(additionalData && { additionalData }),
        },
        key,
        plaintextBytes
    );

    // Combine IV + ciphertext (includes auth tag)
    const combined = new Uint8Array(iv.length + ciphertext.byteLength);
    combined.set(iv, 0);
    combined.set(new Uint8Array(ciphertext), iv.length);

    return uint8ArrayToBase64(combined);
}

/**
 * Decrypts AES-256-GCM encrypted data
 * 
 * @param encryptedBase64 - Base64-encoded encrypted data (IV || ciphertext || authTag)
 * @param key - CryptoKey derived from master password
 * @param aad - Optional Additional Authenticated Data. Must match the AAD
 *              used during encryption, otherwise GCM auth tag verification
 *              fails and decryption throws.
 * @returns Decrypted plaintext string
 * @throws Error if decryption fails (wrong key, tampered data, or AAD mismatch)
 */
export async function decrypt(
    encryptedBase64: string,
    key: CryptoKey,
    aad?: string
): Promise<string> {
    const combined = base64ToUint8Array(encryptedBase64);

    // Extract IV and ciphertext
    const iv = combined.slice(0, IV_LENGTH);
    const ciphertext = combined.slice(IV_LENGTH);
    const additionalData = aad ? new TextEncoder().encode(aad) : undefined;

    const plaintextBytes = await crypto.subtle.decrypt(
        {
            name: 'AES-GCM',
            iv: iv,
            tagLength: TAG_LENGTH,
            ...(additionalData && { additionalData }),
        },
        key,
        ciphertext
    );

    return new TextDecoder().decode(plaintextBytes);
}

/**
 * Encrypts a vault item's sensitive data.
 *
 * SECURITY: When entryId is provided, it is used as AES-GCM Additional
 * Authenticated Data (AAD). This cryptographically binds the ciphertext
 * to this specific entry, preventing ciphertext-swap attacks where an
 * attacker with DB access swaps encrypted_data between rows.
 * 
 * @param data - Object containing sensitive vault item fields
 * @param key - CryptoKey derived from master password
 * @param entryId - Vault item UUID. Used as AAD to bind ciphertext to entry.
 * @returns Base64-encoded encrypted JSON
 */
export async function encryptVaultItem(
    data: VaultItemData,
    key: CryptoKey,
    entryId?: string
): Promise<string> {
    const json = JSON.stringify(data);
    return encrypt(json, key, entryId);
}

/**
 * Decrypts a vault item's sensitive data.
 *
 * SECURITY: When entryId is provided, tries decryption with AAD first.
 * Falls back to decryption without AAD for backward compatibility with
 * entries encrypted before the AAD fix was introduced.
 * 
 * @param encryptedData - Base64-encoded encrypted JSON from database
 * @param key - CryptoKey derived from master password
 * @param entryId - Vault item UUID. Must match the AAD used during encryption.
 * @returns Decrypted vault item data object
 * @throws Error if decryption fails with both AAD and no-AAD attempts
 */
export async function decryptVaultItem(
    encryptedData: string,
    key: CryptoKey,
    entryId?: string
): Promise<VaultItemData> {
    let json: string;
    let isLegacy = false;
    if (entryId) {
        try {
            // Try with AAD first (new format, swap-protected)
            json = await decrypt(encryptedData, key, entryId);
        } catch {
            // Backward compat: entry was encrypted without AAD (legacy format)
            // WARNING: Legacy entries are vulnerable to ciphertext-swap attacks
            console.warn(`Legacy entry without AAD detected: ${entryId}`);
            _legacyDecryptCount++;
            isLegacy = true;
            json = await decrypt(encryptedData, key);
        }
    } else {
        json = await decrypt(encryptedData, key);
    }
    return JSON.parse(json) as VaultItemData;
}

/**
 * Creates a password verification hash for validating unlock attempts
 * This allows checking if the master password is correct without storing it
 * 
 * @param key - Derived CryptoKey
 * @returns Base64-encoded verification hash
 */
export async function createVerificationHash(key: CryptoKey): Promise<string> {
    // v3: Encrypt a known constant with random IV. No plaintext stored.
    const encrypted = await encrypt(VERIFICATION_CONSTANT_V3, key);
    return `v3:${encrypted}`;
}

/**
 * Verifies that the provided key can decrypt the verification hash
 * 
 * @param verificationHash - Stored verification hash from profile
 * @param key - Derived CryptoKey to test
 * @returns true if the key is correct
 */
export async function verifyKey(
    verificationHash: string,
    key: CryptoKey
): Promise<boolean> {
    try {
        // v3: Decrypt and compare against known constant (no plaintext stored)
        if (verificationHash.startsWith('v3:')) {
            const encrypted = verificationHash.slice(3);
            const decrypted = await decrypt(encrypted, key);
            return decrypted === VERIFICATION_CONSTANT_V3;
        }

        // v2: Legacy format with plaintext challenge (backward compat)
        if (verificationHash.startsWith('v2:')) {
            const parts = verificationHash.split(':');
            if (parts.length !== 3) {
                return false;
            }

            const [, challenge, encryptedChallenge] = parts;
            const decrypted = await decrypt(encryptedChallenge, key);
            return decrypted === challenge;
        }

        // v1: Legacy format (backward compat)
        const decrypted = await decrypt(verificationHash, key);
        return decrypted === 'SINGRA_PW_VERIFICATION';
    } catch {
        return false;
    }
}

// ============ KDF Auto-Migration ============

/**
 * Result of a KDF upgrade attempt.
 */
export interface KdfUpgradeResult {
    /** Whether the upgrade succeeded */
    upgraded: boolean;
    /** New CryptoKey derived with upgraded parameters (only if upgraded) */
    newKey?: CryptoKey;
    /** Old CryptoKey (returned so caller can re-encrypt existing data) */
    oldKey?: CryptoKey;
    /** New verification hash (only if upgraded) */
    newVerifier?: string;
    /** The KDF version that is now active */
    activeVersion: number;
}

/**
 * Attempts to upgrade the KDF parameters to the latest version.
 *
 * This is called after a successful unlock. If the user is already on
 * the latest version, returns immediately. Otherwise it:
 *   1. Derives a new key using the latest KDF parameters
 *   2. Creates a new verification hash with the new key
 *   3. Returns BOTH the old key and new key for the caller to:
 *      a) Re-encrypt all vault data from oldKey -> newKey
 *      b) Only THEN switch the in-memory key to the new one
 *
 * IMPORTANT: The caller (VaultContext) MUST re-encrypt all existing
 * vault data before switching to the new key. Otherwise, existing
 * data encrypted with the old key will become unreadable.
 *
 * The caller (VaultContext) is responsible for:
 *   - Re-encrypting all vault items and categories with the new key
 *   - Saving the new verifier and kdf_version to the profiles table
 *   - Updating the in-memory encryption key AFTER re-encryption
 *   - Updating the offline credentials cache
 *
 * If the device cannot handle the higher memory requirement (OOM),
 * the upgrade is silently skipped and the user stays on the old version.
 *
 * @param masterPassword - The user's master password (still in memory from unlock)
 * @param saltBase64 - The user's encryption salt
 * @param currentVersion - The user's current KDF version from profiles
 * @param deviceKey - Optional 256-bit device key for additional strengthening
 * @returns Upgrade result
 */
export async function attemptKdfUpgrade(
    masterPassword: string,
    saltBase64: string,
    currentVersion: number,
    deviceKey?: Uint8Array,
): Promise<KdfUpgradeResult> {
    if (currentVersion >= CURRENT_KDF_VERSION) {
        return { upgraded: false, activeVersion: currentVersion };
    }

    try {
        // Derive key with the new, stronger parameters
        const newKey = await deriveKey(masterPassword, saltBase64, CURRENT_KDF_VERSION, deviceKey);

        // Also derive the old key so the caller can re-encrypt data
        const oldKey = await deriveKey(masterPassword, saltBase64, currentVersion, deviceKey);

        // Create a new verification hash so future unlocks use the new key
        const newVerifier = await createVerificationHash(newKey);

        return {
            upgraded: true,
            newKey,
            oldKey,
            newVerifier,
            activeVersion: CURRENT_KDF_VERSION,
        };
    } catch (err) {
        // If the device runs out of memory (OOM) or the WASM module fails,
        // silently skip the upgrade. The user stays on their current version
        // and can try again on a more capable device.
        console.warn(
            `KDF upgrade from v${currentVersion} to v${CURRENT_KDF_VERSION} failed (likely OOM), staying on v${currentVersion}:`,
            err,
        );
        return { upgraded: false, activeVersion: currentVersion };
    }
}

// ============ Vault Re-Encryption ============

/**
 * Encrypted category field prefix used for category name/icon/color.
 */
const ENCRYPTED_CATEGORY_PREFIX = 'enc:cat:v1:';

/**
 * Re-encrypts a single encrypted string from oldKey to newKey.
 *
 * When aad is provided, tries decryption with AAD first (new format),
 * falls back to without AAD (legacy format). Always re-encrypts WITH
 * AAD to migrate legacy entries to the new swap-protected format.
 *
 * @param encryptedBase64 - The encrypted data (base64)
 * @param oldKey - The old CryptoKey used to encrypt the data
 * @param newKey - The new CryptoKey to re-encrypt with
 * @param aad - Optional AAD (e.g. entry ID) for swap protection
 * @returns Re-encrypted base64 string
 * @throws Error if decryption or re-encryption fails
 */
export async function reEncryptString(
    encryptedBase64: string,
    oldKey: CryptoKey,
    newKey: CryptoKey,
    aad?: string,
): Promise<string> {
    let plaintext: string;
    if (aad) {
        try {
            // Try with AAD first (already migrated)
            plaintext = await decrypt(encryptedBase64, oldKey, aad);
        } catch {
            // Fallback: legacy entry without AAD
            plaintext = await decrypt(encryptedBase64, oldKey);
        }
    } else {
        plaintext = await decrypt(encryptedBase64, oldKey);
    }
    // Always re-encrypt with AAD if provided (migrate to new format)
    return encrypt(plaintext, newKey, aad);
}

/**
 * Result of a vault re-encryption operation.
 */
export interface ReEncryptionResult {
    /** Number of vault items re-encrypted */
    itemsReEncrypted: number;
    /** Number of categories re-encrypted */
    categoriesReEncrypted: number;
    /** Item updates to persist: array of { id, encrypted_data } */
    itemUpdates: Array<{ id: string; encrypted_data: string }>;
    /** Category updates to persist: array of { id, name, icon, color } */
    categoryUpdates: Array<{ id: string; name: string; icon: string | null; color: string | null }>;
    /** Number of legacy items found without AAD protection (Phase 1 monitoring) */
    legacyItemsFound: number;
}

/**
 * Re-encrypts all vault items and encrypted category fields from
 * an old key to a new key. This is required during KDF version upgrades
 * so that existing data remains readable with the new key.
 *
 * SECURITY: This function is pure (no DB side effects). The caller
 * is responsible for persisting the re-encrypted data atomically.
 *
 * @param items - Array of vault items with { id, encrypted_data }
 * @param categories - Array of categories with { id, name, icon, color }
 * @param oldKey - The old CryptoKey
 * @param newKey - The new CryptoKey
 * @returns Re-encryption result with all updates ready to persist
 */
export async function reEncryptVault(
    items: Array<{ id: string; encrypted_data: string }>,
    categories: Array<{ id: string; name: string; icon: string | null; color: string | null }>,
    oldKey: CryptoKey,
    newKey: CryptoKey,
): Promise<ReEncryptionResult> {
    // Re-encrypt vault items (with AAD binding to entry ID)
    const itemUpdates: Array<{ id: string; encrypted_data: string }> = [];
    for (const item of items) {
        try {
            // SECURITY: Pass item.id as AAD to bind ciphertext to entry ID.
            // reEncryptString handles legacy (no-AAD) → new (with-AAD) migration.
            const newEncrypted = await reEncryptString(item.encrypted_data, oldKey, newKey, item.id);
            itemUpdates.push({ id: item.id, encrypted_data: newEncrypted });
        } catch (err) {
            // If a single item fails, abort the entire operation.
            // Partial re-encryption is worse than no re-encryption.
            throw new Error(`Failed to re-encrypt vault item ${item.id}: ${err}`);
        }
    }

    // Re-encrypt category fields (only those with the encrypted prefix)
    const categoryUpdates: Array<{ id: string; name: string; icon: string | null; color: string | null }> = [];
    for (const cat of categories) {
        let newName = cat.name;
        let newIcon = cat.icon;
        let newColor = cat.color;
        let changed = false;

        if (cat.name.startsWith(ENCRYPTED_CATEGORY_PREFIX)) {
            try {
                const encPart = cat.name.slice(ENCRYPTED_CATEGORY_PREFIX.length);
                const reEncrypted = await reEncryptString(encPart, oldKey, newKey);
                newName = `${ENCRYPTED_CATEGORY_PREFIX}${reEncrypted}`;
                changed = true;
            } catch (err) {
                throw new Error(`Failed to re-encrypt category name ${cat.id}: ${err}`);
            }
        }

        if (cat.icon && cat.icon.startsWith(ENCRYPTED_CATEGORY_PREFIX)) {
            try {
                const encPart = cat.icon.slice(ENCRYPTED_CATEGORY_PREFIX.length);
                const reEncrypted = await reEncryptString(encPart, oldKey, newKey);
                newIcon = `${ENCRYPTED_CATEGORY_PREFIX}${reEncrypted}`;
                changed = true;
            } catch (err) {
                throw new Error(`Failed to re-encrypt category icon ${cat.id}: ${err}`);
            }
        }

        if (cat.color && cat.color.startsWith(ENCRYPTED_CATEGORY_PREFIX)) {
            try {
                const encPart = cat.color.slice(ENCRYPTED_CATEGORY_PREFIX.length);
                const reEncrypted = await reEncryptString(encPart, oldKey, newKey);
                newColor = `${ENCRYPTED_CATEGORY_PREFIX}${reEncrypted}`;
                changed = true;
            } catch (err) {
                throw new Error(`Failed to re-encrypt category color ${cat.id}: ${err}`);
            }
        }

        if (changed) {
            categoryUpdates.push({ id: cat.id, name: newName, icon: newIcon, color: newColor });
        }
    }

    // Capture legacy count before reset
    const legacyFound = _legacyDecryptCount;
    _legacyDecryptCount = 0;

    return {
        itemsReEncrypted: itemUpdates.length,
        categoriesReEncrypted: categoryUpdates.length,
        itemUpdates,
        categoryUpdates,
        legacyItemsFound: legacyFound,
    };
}

// ============ Utility Functions ============

/**
 * Converts Uint8Array to Base64 string
 */
function uint8ArrayToBase64(bytes: Uint8Array): string {
    let binary = '';
    for (let i = 0; i < bytes.length; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
}

/**
 * Converts Base64 string to Uint8Array
 */
function base64ToUint8Array(base64: string): Uint8Array {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
}

// ============ Type Definitions ============

/**
 * Argon2id parameter set for a given KDF version.
 */
export interface KdfParams {
    /** Memory in KiB (e.g. 65536 = 64 MiB) */
    memory: number;
    /** Number of Argon2id iterations */
    iterations: number;
    /** Degree of parallelism (threads) */
    parallelism: number;
    /** Output hash length in bytes */
    hashLength: number;
}

/**
 * Sensitive vault item data that gets encrypted
 */
export interface VaultItemData {
    title?: string;
    websiteUrl?: string;
    itemType?: 'password' | 'note' | 'totp' | 'card';
    isFavorite?: boolean;
    categoryId?: string | null;
    username?: string;
    password?: string;
    notes?: string;
    totpSecret?: string;
    customFields?: Record<string, string>;
    /** Internal marker for duress/decoy items (never exposed to UI) */
    _duress?: boolean;
}

/**
 * Clears sensitive data references from a VaultItemData object.
 *
 * ⚠️ WARNING: This function does NOT securely wipe memory!
 * JavaScript strings are immutable. This only removes references
 * so the GC can collect the original strings sooner.
 * The old string content MAY linger in the heap until the GC
 * reclaims it — there is no way to prevent this in JavaScript.
 *
 * For binary key material, use Uint8Array.fill(0) instead.
 *
 * @param data - VaultItemData object whose fields will be set to empty/default values
 */
export function clearReferences(data: VaultItemData): void {
    if (data.title) data.title = '';
    if (data.websiteUrl) data.websiteUrl = '';
    if (data.itemType) data.itemType = 'password';
    if (typeof data.isFavorite === 'boolean') data.isFavorite = false;
    if (typeof data.categoryId !== 'undefined') data.categoryId = null;
    if (data.username) data.username = '';
    if (data.password) data.password = '';
    if (data.notes) data.notes = '';
    if (data.totpSecret) data.totpSecret = '';
    if (data.customFields) {
        Object.keys(data.customFields).forEach(key => {
            data.customFields![key] = '';
        });
    }
}

/** @deprecated Use clearReferences instead. secureClear suggests memory wiping which JS cannot do. */
export const secureClear = clearReferences;

// ==========================================
// Asymmetric Encryption for Emergency Access
// ==========================================

export async function generateRSAKeyPair(): Promise<CryptoKeyPair> {
    return window.crypto.subtle.generateKey(
        {
            name: "RSA-OAEP",
            modulusLength: 4096,
            publicExponent: new Uint8Array([1, 0, 1]),
            hash: "SHA-256",
        },
        true,
        ["encrypt", "decrypt"]
    );
}

export async function exportPublicKey(key: CryptoKey): Promise<JsonWebKey> {
    return window.crypto.subtle.exportKey("jwk", key);
}

export async function importPublicKey(jwk: JsonWebKey): Promise<CryptoKey> {
    return window.crypto.subtle.importKey(
        "jwk",
        jwk,
        {
            name: "RSA-OAEP",
            hash: "SHA-256",
        },
        true,
        ["encrypt"]
    );
}

export async function importPrivateKey(jwk: JsonWebKey): Promise<CryptoKey> {
    return window.crypto.subtle.importKey(
        "jwk",
        jwk,
        {
            name: "RSA-OAEP",
            hash: "SHA-256",
        },
        false,
        ["decrypt"]
    );
}

export async function exportPrivateKey(key: CryptoKey): Promise<JsonWebKey> {
    return window.crypto.subtle.exportKey("jwk", key);
}

export async function encryptRSA(
    plaintext: string,
    publicKey: CryptoKey
): Promise<string> {
    const encoded = new TextEncoder().encode(plaintext);
    const encrypted = await window.crypto.subtle.encrypt(
        {
            name: "RSA-OAEP",
        },
        publicKey,
        encoded
    );
    return uint8ArrayToBase64(new Uint8Array(encrypted));
}

export async function decryptRSA(
    ciphertextBase64: string,
    privateKey: CryptoKey
): Promise<string> {
    const encrypted = base64ToUint8Array(ciphertextBase64);
    const decrypted = await window.crypto.subtle.decrypt(
        {
            name: "RSA-OAEP",
        },
        privateKey,
        encrypted as BufferSource
    );
    return new TextDecoder().decode(decrypted);
}

// ==========================================
// Shared Collections Encryption
// ==========================================

/**
 * Generates a user's hybrid key pair for shared collections
 * Supports both RSA-4096 (legacy) and hybrid PQ+RSA (v2) modes
 * Private keys are encrypted with the master password
 *
 * @param masterPassword - User's master password
 * @param version - Key pair version: 1 (RSA-only) or 2 (hybrid PQ+RSA)
 * @returns Object with public key (JWK) and encrypted private key
 *          Format v1: `kdfVersion:salt:encryptedData`
 *          Format v2: `pq-v2:kdfVersion:salt:encryptedRsaKey:encryptedPqKey`
 */
// TODO(security): Set default to 2 (hybrid PQ+RSA) once pqCryptoService
// is validated in production. Track: SINGRA-PQ-DEFAULT
// Current: version 1 (RSA-only) for stability during rollout.
export async function generateUserKeyPair(
    masterPassword: string,
    version: 1 | 2 = 1
): Promise<{
    publicKey: string;
    encryptedPrivateKey: string;
    pqPublicKey?: string; // Only for version 2
}> {
    if (version === 1) {
        // Legacy RSA-only mode (backward compatibility)
        const keyPair = await crypto.subtle.generateKey(
            {
                name: 'RSA-OAEP',
                modulusLength: 4096,
                publicExponent: new Uint8Array([1, 0, 1]),
                hash: 'SHA-256',
            },
            true,
            ['encrypt', 'decrypt']
        );

        const publicKeyJwk = await crypto.subtle.exportKey('jwk', keyPair.publicKey);
        const publicKey = JSON.stringify(publicKeyJwk);

        const privateKeyJwk = await crypto.subtle.exportKey('jwk', keyPair.privateKey);
        const privateKey = JSON.stringify(privateKeyJwk);

        const salt = generateSalt();
        const kdfVersion = CURRENT_KDF_VERSION;
        const key = await deriveKey(masterPassword, salt, kdfVersion);
        const encryptedPrivateKey = await encrypt(privateKey, key);

        const encryptedPrivateKeyWithSalt = `${kdfVersion}:${salt}:${encryptedPrivateKey}`;

        return { publicKey, encryptedPrivateKey: encryptedPrivateKeyWithSalt };
    }

    // Version 2: Hybrid PQ+RSA mode (NIST-approved post-quantum)
    // Import PQ crypto service for ML-KEM-768
    const { generatePQKeyPair } = await import('./pqCryptoService');

    // 1. Generate RSA-4096 Key Pair
    const rsaKeyPair = await crypto.subtle.generateKey(
        {
            name: 'RSA-OAEP',
            modulusLength: 4096,
            publicExponent: new Uint8Array([1, 0, 1]),
            hash: 'SHA-256',
        },
        true,
        ['encrypt', 'decrypt']
    );

    // 2. Generate ML-KEM-768 Key Pair (CRYSTALS-Kyber)
    const pqKeyPair = generatePQKeyPair();
    const { publicKey: pqPublicKeyBase64, secretKey: pqSecretKeyBase64 } = pqKeyPair;

    // 3. Export RSA keys
    const rsaPublicKeyJwk = await crypto.subtle.exportKey('jwk', rsaKeyPair.publicKey);
    const rsaPublicKey = JSON.stringify(rsaPublicKeyJwk);

    const rsaPrivateKeyJwk = await crypto.subtle.exportKey('jwk', rsaKeyPair.privateKey);
    const rsaPrivateKey = JSON.stringify(rsaPrivateKeyJwk);

    // 4. Encrypt both private keys with master password
    const salt = generateSalt();
    const kdfVersion = CURRENT_KDF_VERSION;
    const key = await deriveKey(masterPassword, salt, kdfVersion);

    const encryptedRsaKey = await encrypt(rsaPrivateKey, key);
    const encryptedPqKey = await encrypt(pqSecretKeyBase64, key);

    // 5. Create versioned format for hybrid keys
    // Format: pq-v2:kdfVersion:salt:encryptedRsaKey:encryptedPqKey
    const encryptedPrivateKey = `pq-v2:${kdfVersion}:${salt}:${encryptedRsaKey}:${encryptedPqKey}`;

    return {
        publicKey: rsaPublicKey,
        encryptedPrivateKey,
        pqPublicKey: pqPublicKeyBase64,
    };
}

/**
 * Migrates an existing RSA-only key pair to hybrid PQ+RSA
 *
 * @param encryptedPrivateKey - Existing encrypted RSA private key
 * @param masterPassword - User's master password
 * @returns Migrated hybrid key pair or null if migration fails
 */
export async function migrateToHybridKeyPair(
    encryptedPrivateKey: string,
    masterPassword: string
): Promise<{
    publicKey: string;
    encryptedPrivateKey: string;
    pqPublicKey: string;
} | null> {
    try {
        // Check if already migrated
        if (encryptedPrivateKey.startsWith('pq-v2:')) {
            return null; // Already hybrid
        }

        // Decrypt existing RSA key
        const parts = encryptedPrivateKey.split(':');
        let kdfVersion = 1;
        let salt: string;
        let encryptedData: string;

        if (parts.length === 2) {
            // Legacy format: salt:encryptedData
            salt = parts[0];
            encryptedData = parts[1];
        } else if (parts.length === 3) {
            // Current format: kdfVersion:salt:encryptedData
            kdfVersion = parseInt(parts[0], 10);
            salt = parts[1];
            encryptedData = parts[2];
        } else {
            throw new Error('Invalid encrypted private key format');
        }

        const key = await deriveKey(masterPassword, salt, kdfVersion);
        const rsaPrivateKey = await decrypt(encryptedData, key);

        // Import RSA key to get public key
        const rsaPrivateKeyJwk = JSON.parse(rsaPrivateKey);
        // Generate corresponding public key (reconstruct from private)
        // Note: In practice, we'd fetch the existing public key from storage
        const rsaPublicKeyJwk = {
            ...rsaPrivateKeyJwk,
            d: undefined,
            dp: undefined,
            dq: undefined,
            p: undefined,
            q: undefined,
            qi: undefined,
            key_ops: ['encrypt'],
        };
        const rsaPublicKey = JSON.stringify(rsaPublicKeyJwk);

        // Generate new PQ key pair
        const { generatePQKeyPair } = await import('./pqCryptoService');
        const pqKeyPair = generatePQKeyPair();
        const { publicKey: pqPublicKey, secretKey: pqSecretKey } = pqKeyPair;

        // Re-encrypt both keys with latest KDF version
        const newSalt = generateSalt();
        const newKdfVersion = CURRENT_KDF_VERSION;
        const newKey = await deriveKey(masterPassword, newSalt, newKdfVersion);

        const encryptedRsaKey = await encrypt(rsaPrivateKey, newKey);
        const encryptedPqKey = await encrypt(pqSecretKey, newKey);

        // Create hybrid format
        const hybridEncryptedKey = `pq-v2:${newKdfVersion}:${newSalt}:${encryptedRsaKey}:${encryptedPqKey}`;

        return {
            publicKey: rsaPublicKey,
            encryptedPrivateKey: hybridEncryptedKey,
            pqPublicKey,
        };
    } catch (err) {
        console.error('Failed to migrate to hybrid key pair:', err);
        return null;
    }
}

/**
 * Generates a random shared encryption key for a collection
 * 
 * @returns JWK string of AES-256 key
 */
export async function generateSharedKey(): Promise<string> {
    const key = await crypto.subtle.generateKey(
        { name: 'AES-GCM', length: 256 },
        true,
        ['encrypt', 'decrypt']
    );

    const keyJwk = await crypto.subtle.exportKey('jwk', key);
    return JSON.stringify(keyJwk);
}



/**
 * Encrypts vault item data with a shared key
 * 
 * SECURITY: When aad is provided (e.g., vault item ID), it binds the
 * ciphertext to that specific context, preventing ciphertext-swap attacks.
 * 
 * @param data - Vault item data to encrypt
 * @param sharedKey - JWK string of the shared AES key
 * @param aad - Optional Additional Authenticated Data (e.g. entry ID)
 * @returns Base64-encoded encrypted data
 */
export async function encryptWithSharedKey(
    data: VaultItemData,
    sharedKey: string,
    aad?: string
): Promise<string> {
    // Import Shared Key
    const keyJwk = JSON.parse(sharedKey);
    const key = await crypto.subtle.importKey(
        'jwk',
        keyJwk,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt']
    );

    // Encrypt data
    const json = JSON.stringify(data);
    return encrypt(json, key, aad);
}

/**
 * Decrypts vault item data with a shared key
 * 
 * SECURITY: When aad is provided, tries decryption with AAD first.
 * Falls back to decryption without AAD for backward compatibility with
 * existing shared items encrypted before the AAD fix.
 * 
 * @param encryptedData - Base64-encoded encrypted data
 * @param sharedKey - JWK string of the shared AES key
 * @param aad - Optional Additional Authenticated Data (e.g. entry ID)
 * @returns Decrypted vault item data
 * @throws Error if decryption fails with both AAD and no-AAD attempts
 */
export async function decryptWithSharedKey(
    encryptedData: string,
    sharedKey: string,
    aad?: string
): Promise<VaultItemData> {
    // Import Shared Key
    const keyJwk = JSON.parse(sharedKey);
    const key = await crypto.subtle.importKey(
        'jwk',
        keyJwk,
        { name: 'AES-GCM', length: 256 },
        false,
        ['decrypt']
    );

    // Decrypt data
    let json: string;
    if (aad) {
        try {
            // Try with AAD first (new swap-protected format)
            json = await decrypt(encryptedData, key, aad);
        } catch {
            // Backward compat: entry was encrypted without AAD
            // WARNING: Legacy entries are vulnerable to ciphertext-swap attacks
            console.warn(`Legacy shared entry without AAD detected: ${aad}`);
            _legacyDecryptCount++;
            json = await decrypt(encryptedData, key);
        }
    } else {
        json = await decrypt(encryptedData, key);
    }
    return JSON.parse(json) as VaultItemData;
}

/**
 * Encrypts data with a password (used for private key encryption)
 * 
 * @param plaintext - Data to encrypt
 * @param password - Password to derive key from
 * @returns Base64-encoded encrypted data
 */
async function encryptWithPassword(plaintext: string, password: string): Promise<string> {
    const salt = generateSalt();
    const kdfVersion = CURRENT_KDF_VERSION;
    const key = await deriveKey(password, salt, kdfVersion);
    const encrypted = await encrypt(plaintext, key);
    return `${kdfVersion}:${salt}:${encrypted}`;
}

/**
 * Decrypts data with a password
 * 
 * @param encryptedData - Encrypted data (format: salt:encryptedData)
 * @param password - Password to derive key from
 * @returns Decrypted plaintext
 */
async function decryptWithPassword(encryptedData: string, password: string): Promise<string> {
    const parts = encryptedData.split(':');
    let kdfVersion = 1;
    let salt: string | null = null;
    let encrypted: string | null = null;

    if (parts.length === 2) {
        salt = parts[0];
        encrypted = parts[1];
    } else if (parts.length === 3) {
        kdfVersion = parseInt(parts[0], 10);
        salt = parts[1];
        encrypted = parts[2];
    }

    if (!salt || !encrypted) {
        throw new Error('Invalid encrypted data format');
    }

    const key = await deriveKey(password, salt, kdfVersion);
    return decrypt(encrypted, key);
}
