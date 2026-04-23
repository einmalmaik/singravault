// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 — see LICENSE
/**
 * @fileoverview Device Key Service for Singra Vault
 *
 * Manages a 256-bit client-side Device Key that strengthens the vault
 * encryption key. The Device Key never leaves the local runtime.
 *
 * Key derivation with Device Key:
 *   VaultKey = HKDF-Expand(Argon2id(MasterPW, Salt), DeviceKey)
 *
 * SECURITY:
 * - Device Key is generated from crypto.getRandomValues (CSPRNG)
 * - Stored in the shared local secret store
 * - Browser runtimes without a secure local secret store must not enable it
 * - Never logged, never sent over the network
 * - Loss of Device Key + no backup = vault unrecoverable (by design)
 */

import {
    isLocalSecretStoreSupported,
    loadLocalSecretBytes,
    removeLocalSecret,
    saveLocalSecretBytes,
} from '@/platform/localSecretStore';

const DEVICE_KEY_LENGTH = 32; // 256 bits
const HKDF_INFO = 'SINGRA_DEVICE_KEY_V1';
const DEVICE_KEY_SECRET_PREFIX = 'device-key:';
const LEGACY_DEVICE_KEY_DB_NAME = 'singra_device_keys';
const LEGACY_DEVICE_KEY_DB_VERSION = 1;
const LEGACY_DEVICE_KEY_STORE = 'keys';
const LEGACY_WRAP_SALT = 'SINGRA_DEVICE_KEY_WRAP';
const LEGACY_WRAP_INFO = 'device-key-wrapping';

interface LegacyDeviceKeyRecord {
    userId: string;
    iv: number[];
    encrypted: number[];
    createdAt?: string;
}

// ============ Core Functions ============

/**
 * Generates a new 256-bit Device Key using CSPRNG.
 *
 * @returns Random 32-byte Uint8Array
 */
export function generateDeviceKey(): Uint8Array {
    return crypto.getRandomValues(new Uint8Array(DEVICE_KEY_LENGTH));
}

/**
 * Stores a Device Key in the shared local secret store.
 *
 * @param userId - The user's UUID
 * @param deviceKey - The 256-bit device key to store
 */
export async function storeDeviceKey(userId: string, deviceKey: Uint8Array): Promise<void> {
    if (!(await isLocalSecretStoreSupported())) {
        throw new Error('Secure local secret storage is not available in this runtime.');
    }

    await saveLocalSecretBytes(getDeviceKeySecretKey(userId), deviceKey);
}

/**
 * Retrieves the Device Key from local secret storage for a given user.
 * Legacy browser/webview IndexedDB records are migrated on read when possible.
 *
 * @param userId - The user's UUID
 * @returns The 256-bit device key, or null if not found
 */
export async function getDeviceKey(userId: string): Promise<Uint8Array | null> {
    const secretKey = getDeviceKeySecretKey(userId);

    try {
        const currentDeviceKey = await loadLocalSecretBytes(secretKey);
        if (currentDeviceKey) {
            return currentDeviceKey;
        }
    } catch {
        // Fall through to the legacy IndexedDB migration path.
    }

    try {
        const legacyDeviceKey = await loadLegacyIndexedDbDeviceKey(userId);
        if (!legacyDeviceKey) {
            return null;
        }

        await migrateLegacyDeviceKeyToLocalSecretStore(userId, legacyDeviceKey);
        return legacyDeviceKey;
    } catch {
        return null;
    }
}

/**
 * Checks whether a Device Key exists for the given user.
 *
 * @param userId - The user's UUID
 * @returns true if a device key is stored locally
 */
export async function hasDeviceKey(userId: string): Promise<boolean> {
    try {
        return (await getDeviceKey(userId)) !== null;
    } catch {
        return false;
    }
}

/**
 * Deletes the Device Key from current storage and the legacy IndexedDB store.
 *
 * @param userId - The user's UUID
 */
export async function deleteDeviceKey(userId: string): Promise<void> {
    await removeLocalSecret(getDeviceKeySecretKey(userId));

    try {
        await deleteLegacyIndexedDbDeviceKey(userId);
    } catch (error) {
        console.warn('Failed to remove legacy device key record:', error);
    }
}

// ============ HKDF-Expand: Combine Argon2id output with Device Key ============

/**
 * Combines the Argon2id-derived raw key with the Device Key using
 * HKDF-Expand. This produces a final key that requires BOTH the
 * master password AND the device key to derive.
 *
 * Flow:
 *   1. Import argon2Output as HKDF key material
 *   2. Use deviceKey as salt in HKDF
 *   3. Derive 256-bit AES key
 *
 * @param argon2Output - Raw key bytes from Argon2id (32 bytes)
 * @param deviceKey - The 256-bit device key (32 bytes)
 * @returns Final 32-byte key incorporating both inputs
 */
export async function deriveWithDeviceKey(
    argon2Output: Uint8Array,
    deviceKey: Uint8Array,
): Promise<Uint8Array> {
    // Import the Argon2id output as HKDF base key material
    const baseKey = await crypto.subtle.importKey(
        'raw',
        argon2Output as BufferSource,
        'HKDF',
        false,
        ['deriveBits'],
    );

    const info = new TextEncoder().encode(HKDF_INFO);

    // HKDF with deviceKey as salt, argon2Output as IKM
    const derivedBits = await crypto.subtle.deriveBits(
        {
            name: 'HKDF',
            hash: 'SHA-256',
            salt: deviceKey as BufferSource,
            info: info as BufferSource,
        },
        baseKey,
        256, // 32 bytes
    );

    return new Uint8Array(derivedBits);
}

// ============ QR / Transfer Functions ============

/**
 * Exports the device key as a base64-encoded string for QR code display.
 * The exported key is additionally encrypted with a user-chosen PIN
 * for secure transfer between devices.
 *
 * @param userId - The user's UUID
 * @param pin - A PIN/password chosen by the user for transfer encryption
 * @returns Base64-encoded encrypted device key, or null if no key exists
 */
export async function exportDeviceKeyForTransfer(
    userId: string,
    pin: string,
): Promise<string | null> {
    const deviceKey = await getDeviceKey(userId);
    if (!deviceKey) return null;

    // Derive a wrapping key from the PIN
    const pinKey = await derivePinKey(pin);
    const iv = crypto.getRandomValues(new Uint8Array(12));

    const encrypted = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv },
        pinKey,
        deviceKey as BufferSource,
    );

    // Format: base64(iv + encrypted)
    const combined = new Uint8Array(iv.length + encrypted.byteLength);
    combined.set(iv, 0);
    combined.set(new Uint8Array(encrypted), iv.length);

    return uint8ArrayToBase64(combined);
}

/**
 * Imports a device key from a transfer string (scanned from QR code).
 *
 * @param userId - The user's UUID
 * @param transferData - Base64-encoded encrypted device key
 * @param pin - The PIN used during export
 * @returns true if import succeeded, false if PIN was wrong or data invalid
 */
export async function importDeviceKeyFromTransfer(
    userId: string,
    transferData: string,
    pin: string,
): Promise<boolean> {
    try {
        const combined = base64ToUint8Array(transferData);
        if (combined.length < 13) return false; // 12 bytes IV + at least 1 byte

        const iv = combined.slice(0, 12);
        const encrypted = combined.slice(12);

        const pinKey = await derivePinKey(pin);

        const decrypted = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv },
            pinKey,
            encrypted as BufferSource,
        );

        const deviceKey = new Uint8Array(decrypted);
        if (deviceKey.length !== DEVICE_KEY_LENGTH) return false;

        await storeDeviceKey(userId, deviceKey);
        return true;
    } catch {
        // Decryption failed — wrong PIN or corrupted data
        return false;
    }
}

// ============ Internal Helpers ============

function getDeviceKeySecretKey(userId: string): string {
    return `${DEVICE_KEY_SECRET_PREFIX}${userId}`;
}

async function migrateLegacyDeviceKeyToLocalSecretStore(
    userId: string,
    deviceKey: Uint8Array,
): Promise<void> {
    if (!(await isLocalSecretStoreSupported())) {
        return;
    }

    try {
        await saveLocalSecretBytes(getDeviceKeySecretKey(userId), deviceKey);
        await deleteLegacyIndexedDbDeviceKey(userId);
    } catch (error) {
        console.warn('Failed to migrate legacy device key into the local secret store:', error);
    }
}

async function loadLegacyIndexedDbDeviceKey(userId: string): Promise<Uint8Array | null> {
    if (!isLegacyDeviceKeyStoreAvailable()) {
        return null;
    }

    try {
        const record = await withLegacyDeviceKeyStore<LegacyDeviceKeyRecord | null>(
            'readonly',
            (store, resolve, reject) => {
                const request = store.get(userId);
                request.onsuccess = () => resolve((request.result as LegacyDeviceKeyRecord | undefined) ?? null);
                request.onerror = () => reject(request.error);
            },
        );

        if (!record) {
            return null;
        }

        return decryptLegacyDeviceKeyRecord(userId, record);
    } catch (error) {
        console.warn('Failed to load legacy device key from IndexedDB:', error);
        return null;
    }
}

async function deleteLegacyIndexedDbDeviceKey(userId: string): Promise<void> {
    if (!isLegacyDeviceKeyStoreAvailable()) {
        return;
    }

    await withLegacyDeviceKeyStore<void>('readwrite', (store, resolve, reject) => {
        const request = store.delete(userId);
        request.onsuccess = () => resolve();
        request.onerror = () => reject(request.error);
    });
}

function isLegacyDeviceKeyStoreAvailable(): boolean {
    return typeof indexedDB !== 'undefined'
        && typeof crypto !== 'undefined'
        && typeof crypto.subtle !== 'undefined';
}

function openLegacyDeviceKeyDb(): Promise<IDBDatabase> {
    return new Promise((resolve, reject) => {
        const request = indexedDB.open(LEGACY_DEVICE_KEY_DB_NAME, LEGACY_DEVICE_KEY_DB_VERSION);

        request.onupgradeneeded = () => {
            const db = request.result;
            if (!db.objectStoreNames.contains(LEGACY_DEVICE_KEY_STORE)) {
                db.createObjectStore(LEGACY_DEVICE_KEY_STORE, { keyPath: 'userId' });
            }
        };

        request.onsuccess = () => resolve(request.result);
        request.onerror = () => reject(request.error);
    });
}

function withLegacyDeviceKeyStore<T>(
    mode: IDBTransactionMode,
    handler: (
        store: IDBObjectStore,
        resolve: (value: T) => void,
        reject: (reason?: unknown) => void,
    ) => void,
): Promise<T> {
    return new Promise((resolve, reject) => {
        openLegacyDeviceKeyDb()
            .then((db) => {
                const transaction = db.transaction(LEGACY_DEVICE_KEY_STORE, mode);
                const store = transaction.objectStore(LEGACY_DEVICE_KEY_STORE);
                handler(store, resolve, reject);
            })
            .catch(reject);
    });
}

async function decryptLegacyDeviceKeyRecord(
    userId: string,
    record: LegacyDeviceKeyRecord,
): Promise<Uint8Array | null> {
    if (!Array.isArray(record.iv) || !Array.isArray(record.encrypted)) {
        return null;
    }

    const wrappingKey = await deriveLegacyWrappingKey(userId);
    const decrypted = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: new Uint8Array(record.iv) },
        wrappingKey,
        new Uint8Array(record.encrypted),
    );

    return new Uint8Array(decrypted);
}

async function deriveLegacyWrappingKey(userId: string): Promise<CryptoKey> {
    const keyMaterial = await crypto.subtle.importKey(
        'raw',
        new TextEncoder().encode(userId),
        'HKDF',
        false,
        ['deriveKey'],
    );

    return crypto.subtle.deriveKey(
        {
            name: 'HKDF',
            hash: 'SHA-256',
            salt: new TextEncoder().encode(LEGACY_WRAP_SALT),
            info: new TextEncoder().encode(LEGACY_WRAP_INFO),
        },
        keyMaterial,
        { name: 'AES-GCM', length: 256 },
        false,
        ['decrypt'],
    );
}

/**
 * Derives an AES key from a PIN for transfer encryption.
 */
async function derivePinKey(pin: string): Promise<CryptoKey> {
    const keyMaterial = await crypto.subtle.importKey(
        'raw',
        new TextEncoder().encode(pin),
        'PBKDF2',
        false,
        ['deriveKey'],
    );

    return crypto.subtle.deriveKey(
        {
            name: 'PBKDF2',
            salt: new TextEncoder().encode('SINGRA_DEVICE_KEY_TRANSFER'),
            iterations: 100000,
            hash: 'SHA-256',
        },
        keyMaterial,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt'],
    );
}

// ============ Utility Functions ============

function uint8ArrayToBase64(bytes: Uint8Array): string {
    let binary = '';
    for (let i = 0; i < bytes.length; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
}

function base64ToUint8Array(base64: string): Uint8Array {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
}
