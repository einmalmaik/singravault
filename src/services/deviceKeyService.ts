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
 * Retrieves the Device Key from IndexedDB for a given user.
 *
 * @param userId - The user's UUID
 * @returns The 256-bit device key, or null if not found
 */
export async function getDeviceKey(userId: string): Promise<Uint8Array | null> {
    try {
        return await loadLocalSecretBytes(getDeviceKeySecretKey(userId));
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
 * Deletes the Device Key from IndexedDB for a given user.
 *
 * @param userId - The user's UUID
 */
export async function deleteDeviceKey(userId: string): Promise<void> {
    await removeLocalSecret(getDeviceKeySecretKey(userId));
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
