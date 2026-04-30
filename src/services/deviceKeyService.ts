// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 — see LICENSE
/**
 * @fileoverview Device Key Service for Singra Vault
 *
 * Manages a 256-bit client-side Device Key that strengthens the vault
 * encryption key. The Device Key stays in the local runtime except during
 * explicit encrypted transfer export initiated by the user.
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
import { argon2id } from 'hash-wasm';
import {
    deleteNativeDeviceKey,
    exportNativeDeviceKeyForTransfer,
    hasNativeDeviceKey,
    importNativeDeviceKeyFromTransfer,
    isNativeDeviceKeyBridgeRuntime,
} from './deviceKeyNativeBridge';

const DEVICE_KEY_LENGTH = 32; // 256 bits
const HKDF_INFO = 'SINGRA_DEVICE_KEY_V1';
const DEVICE_KEY_SECRET_PREFIX = 'device-key:';
const DEVICE_KEY_TRANSFER_V2_PREFIX = 'sv-dk-transfer-v2:';
export const DEVICE_KEY_TRANSFER_SECRET_MIN_LENGTH = 20;
const DEVICE_KEY_TRANSFER_MAX_ENVELOPE_LENGTH = 16_384;
const TRANSFER_SALT_LENGTH = 16;
const TRANSFER_IV_LENGTH = 12;
const TRANSFER_KDF_PARAMS = {
    memory: 65536,
    iterations: 3,
    parallelism: 1,
    hashLength: 32,
} as const;
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

interface DeviceKeyTransferEnvelopeV2 {
    version: 2;
    kdf: 'argon2id';
    memory: number;
    iterations: number;
    parallelism: number;
    salt: string;
    iv: string;
    ciphertext: string;
    createdAt: string;
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
 * Generates a high-entropy transfer secret for Device Key export/import.
 *
 * @returns URL/QR-friendly secret with about 192 bits of randomness
 */
export function generateDeviceKeyTransferSecret(): string {
    const randomBytes = crypto.getRandomValues(new Uint8Array(24));
    try {
        return uint8ArrayToBase64(randomBytes)
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=+$/g, '');
    } finally {
        randomBytes.fill(0);
    }
}

/**
 * Stores a Device Key in the shared local secret store.
 *
 * @param userId - The user's UUID
 * @param deviceKey - The 256-bit device key to store
 */
export async function storeDeviceKey(userId: string, deviceKey: Uint8Array): Promise<void> {
    assertDeviceKeyLength(deviceKey);

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
    // Tauri/Desktop keeps raw Device Key material inside Rust/OS keychain.
    // JS can query availability and request bounded native operations, but it
    // must not receive the long-lived Device Key bytes.
    if (isNativeDeviceKeyBridgeRuntime()) {
        return null;
    }

    const secretKey = getDeviceKeySecretKey(userId);

    try {
        const currentDeviceKey = await loadLocalSecretBytes(secretKey);
        if (currentDeviceKey) {
            if (!isValidDeviceKey(currentDeviceKey)) {
                currentDeviceKey.fill(0);
                return null;
            }
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
        if (!isValidDeviceKey(legacyDeviceKey)) {
            legacyDeviceKey.fill(0);
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
    if (isNativeDeviceKeyBridgeRuntime()) {
        try {
            return await hasNativeDeviceKey(userId);
        } catch {
            return false;
        }
    }

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
    if (isNativeDeviceKeyBridgeRuntime()) {
        await deleteNativeDeviceKey(userId);
        return;
    }

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
    if (argon2Output.length !== DEVICE_KEY_LENGTH) {
        throw new Error('Argon2id output must be exactly 32 bytes.');
    }
    assertDeviceKeyLength(deviceKey);

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
 * The exported key is additionally encrypted with a user-chosen transfer secret
 * for secure transfer between devices.
 *
 * @param userId - The user's UUID
 * @param pin - A transfer secret chosen by the user for transfer encryption
 * @returns Versioned encrypted device key envelope, or null if no key exists
 */
export async function exportDeviceKeyForTransfer(
    userId: string,
    pin: string,
): Promise<string | null> {
    if (!isValidTransferSecret(pin)) {
        return null;
    }

    if (isNativeDeviceKeyBridgeRuntime()) {
        return exportNativeDeviceKeyForTransfer(userId, pin);
    }

    const deviceKey = await getDeviceKey(userId);
    if (!deviceKey) return null;

    const iv = crypto.getRandomValues(new Uint8Array(TRANSFER_IV_LENGTH));
    const salt = crypto.getRandomValues(new Uint8Array(TRANSFER_SALT_LENGTH));
    let encryptedBytes: Uint8Array | null = null;
    try {
        const pinKey = await deriveTransferWrappingKey(pin, salt, TRANSFER_KDF_PARAMS);

        const encrypted = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv },
            pinKey,
            deviceKey as BufferSource,
        );

        encryptedBytes = new Uint8Array(encrypted);
        const envelope: DeviceKeyTransferEnvelopeV2 = {
            version: 2,
            kdf: 'argon2id',
            memory: TRANSFER_KDF_PARAMS.memory,
            iterations: TRANSFER_KDF_PARAMS.iterations,
            parallelism: TRANSFER_KDF_PARAMS.parallelism,
            salt: uint8ArrayToBase64(salt),
            iv: uint8ArrayToBase64(iv),
            ciphertext: uint8ArrayToBase64(encryptedBytes),
            createdAt: new Date().toISOString(),
        };

        return `${DEVICE_KEY_TRANSFER_V2_PREFIX}${jsonToBase64(envelope)}`;
    } finally {
        deviceKey.fill(0);
        iv.fill(0);
        salt.fill(0);
        encryptedBytes?.fill(0);
    }
}

/**
 * Imports a device key from a transfer string (scanned from QR code).
 *
 * @param userId - The user's UUID
 * @param transferData - Versioned encrypted device key envelope
 * @param pin - The transfer secret used during export
 * @returns true if import succeeded, false if the transfer secret or data is invalid
 */
export async function importDeviceKeyFromTransfer(
    userId: string,
    transferData: string,
    pin: string,
): Promise<boolean> {
    if (
        !isValidTransferSecret(pin)
        || !transferData.startsWith(DEVICE_KEY_TRANSFER_V2_PREFIX)
        || transferData.length > DEVICE_KEY_TRANSFER_MAX_ENVELOPE_LENGTH
    ) {
        return false;
    }

    if (isNativeDeviceKeyBridgeRuntime()) {
        try {
            return await importNativeDeviceKeyFromTransfer(userId, transferData, pin);
        } catch {
            return false;
        }
    }

    const existingDeviceKey = await getDeviceKey(userId);
    if (existingDeviceKey) {
        existingDeviceKey.fill(0);
        return false;
    }

    let iv = new Uint8Array();
    let salt = new Uint8Array();
    let encrypted = new Uint8Array();

    try {
        const envelope = parseTransferEnvelopeV2(transferData);
        iv = base64ToUint8Array(envelope.iv);
        salt = base64ToUint8Array(envelope.salt);
        encrypted = base64ToUint8Array(envelope.ciphertext);

        if (iv.length !== TRANSFER_IV_LENGTH || salt.length !== TRANSFER_SALT_LENGTH || encrypted.length === 0) {
            iv.fill(0);
            salt.fill(0);
            encrypted.fill(0);
            return false;
        }

        const pinKey = await deriveTransferWrappingKey(pin, salt, {
            memory: envelope.memory,
            iterations: envelope.iterations,
            parallelism: envelope.parallelism,
            hashLength: TRANSFER_KDF_PARAMS.hashLength,
        });

        const decrypted = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv },
            pinKey,
            encrypted as BufferSource,
        );

        const deviceKey = new Uint8Array(decrypted);
        try {
            if (deviceKey.length !== DEVICE_KEY_LENGTH) return false;

            await storeDeviceKey(userId, deviceKey);
            return true;
        } finally {
            deviceKey.fill(0);
            iv.fill(0);
            salt.fill(0);
            encrypted.fill(0);
        }
    } catch {
        iv.fill(0);
        salt.fill(0);
        encrypted.fill(0);
        // Decryption failed: wrong transfer secret, malformed envelope, or corrupted data.
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

function isValidTransferSecret(pin: string): boolean {
    return typeof pin === 'string' && pin.length >= DEVICE_KEY_TRANSFER_SECRET_MIN_LENGTH;
}

function isValidDeviceKey(deviceKey: Uint8Array): boolean {
    return deviceKey.length === DEVICE_KEY_LENGTH;
}

function assertDeviceKeyLength(deviceKey: Uint8Array): void {
    if (!isValidDeviceKey(deviceKey)) {
        throw new Error('Device key must be exactly 32 bytes.');
    }
}

async function deriveTransferWrappingKey(
    pin: string,
    salt: Uint8Array,
    params: { memory: number; iterations: number; parallelism: number; hashLength: number },
): Promise<CryptoKey> {
    if (!Number.isSafeInteger(params.memory)
        || !Number.isSafeInteger(params.iterations)
        || !Number.isSafeInteger(params.parallelism)
        || params.memory !== TRANSFER_KDF_PARAMS.memory
        || params.iterations !== TRANSFER_KDF_PARAMS.iterations
        || params.parallelism !== TRANSFER_KDF_PARAMS.parallelism
        || params.hashLength !== TRANSFER_KDF_PARAMS.hashLength) {
        throw new Error('Unsupported device key transfer KDF parameters.');
    }

    const result = await argon2id({
        password: pin,
        salt,
        parallelism: params.parallelism,
        iterations: params.iterations,
        memorySize: params.memory,
        hashLength: params.hashLength,
        outputType: 'binary',
    }) as unknown;

    const keyBytes = normalizeArgon2Output(result);
    try {
        return crypto.subtle.importKey(
            'raw',
            keyBytes as BufferSource,
            { name: 'AES-GCM', length: 256 },
            false,
            ['encrypt', 'decrypt'],
        );
    } finally {
        keyBytes.fill(0);
    }
}

function normalizeArgon2Output(result: unknown): Uint8Array {
    if (result instanceof Uint8Array) {
        return new Uint8Array(result);
    }

    if (result instanceof ArrayBuffer) {
        return new Uint8Array(result);
    }

    if (Array.isArray(result)) {
        return new Uint8Array(result);
    }

    if (ArrayBuffer.isView(result)) {
        return new Uint8Array(result.buffer, result.byteOffset, result.byteLength);
    }

    throw new Error('argon2id returned unsupported type');
}

function parseTransferEnvelopeV2(transferData: string): DeviceKeyTransferEnvelopeV2 {
    const envelope = JSON.parse(base64ToUtf8(transferData.slice(DEVICE_KEY_TRANSFER_V2_PREFIX.length))) as Partial<DeviceKeyTransferEnvelopeV2>;
    if (
        envelope.version !== 2
        || envelope.kdf !== 'argon2id'
        || !Number.isSafeInteger(envelope.memory)
        || !Number.isSafeInteger(envelope.iterations)
        || !Number.isSafeInteger(envelope.parallelism)
        || typeof envelope.salt !== 'string'
        || typeof envelope.iv !== 'string'
        || typeof envelope.ciphertext !== 'string'
        || typeof envelope.createdAt !== 'string'
    ) {
        throw new Error('Invalid device key transfer envelope.');
    }

    return envelope as DeviceKeyTransferEnvelopeV2;
}

// ============ Utility Functions ============

function jsonToBase64(value: unknown): string {
    return uint8ArrayToBase64(new TextEncoder().encode(JSON.stringify(value)));
}

function base64ToUtf8(base64: string): string {
    return new TextDecoder().decode(base64ToUint8Array(base64));
}

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
