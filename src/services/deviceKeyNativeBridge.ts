// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE

import { getTauriInvoke } from '@/platform/tauriInvoke';
import { isTauriRuntime } from '@/platform/runtime';

export type DeviceKeyNativeErrorCode =
    | 'DEVICE_KEY_MISSING'
    | 'DEVICE_KEY_ALREADY_EXISTS'
    | 'DEVICE_KEY_INVALID_USER_ID'
    | 'DEVICE_KEY_INVALID_INPUT'
    | 'DEVICE_KEY_STORE_UNAVAILABLE'
    | 'DEVICE_KEY_CRYPTO_FAILED'
    | 'DEVICE_KEY_OPERATION_UNSUPPORTED';

const NATIVE_DEVICE_KEY_ERRORS = new Set<DeviceKeyNativeErrorCode>([
    'DEVICE_KEY_MISSING',
    'DEVICE_KEY_ALREADY_EXISTS',
    'DEVICE_KEY_INVALID_USER_ID',
    'DEVICE_KEY_INVALID_INPUT',
    'DEVICE_KEY_STORE_UNAVAILABLE',
    'DEVICE_KEY_CRYPTO_FAILED',
    'DEVICE_KEY_OPERATION_UNSUPPORTED',
]);

export class DeviceKeyNativeError extends Error {
    constructor(public readonly code: DeviceKeyNativeErrorCode) {
        super(code);
        this.name = 'DeviceKeyNativeError';
    }
}

export function isNativeDeviceKeyBridgeRuntime(): boolean {
    return isTauriRuntime();
}

export async function hasNativeDeviceKey(userId: string): Promise<boolean> {
    const invoke = await requireNativeInvoke();
    return invoke<boolean>('verify_device_key_available', { userId });
}

export async function generateAndStoreNativeDeviceKey(userId: string): Promise<void> {
    const invoke = await requireNativeInvoke();
    await invoke<void>('generate_and_store_device_key', { userId });
}

export async function deriveNativeDeviceProtectedKey(
    userId: string,
    argon2Output: Uint8Array,
): Promise<Uint8Array> {
    const invoke = await requireNativeInvoke();
    const derivedBase64 = await invoke<string>('derive_device_protected_key', {
        userId,
        argon2OutputBase64: uint8ArrayToBase64(argon2Output),
        version: 1,
    });

    return base64ToUint8Array(derivedBase64);
}

export async function exportNativeDeviceKeyForTransfer(
    userId: string,
    transferSecret: string,
): Promise<string | null> {
    const invoke = await requireNativeInvoke();
    return invoke<string | null>('export_device_key_for_transfer', {
        userId,
        transferSecret,
    });
}

export async function importNativeDeviceKeyFromTransfer(
    userId: string,
    transferData: string,
    transferSecret: string,
): Promise<boolean> {
    const invoke = await requireNativeInvoke();
    return invoke<boolean>('import_device_key_from_transfer', {
        userId,
        transferData,
        transferSecret,
    });
}

async function requireNativeInvoke() {
    const invoke = await getTauriInvoke();
    if (!invoke) {
        throw new DeviceKeyNativeError('DEVICE_KEY_OPERATION_UNSUPPORTED');
    }

    return async <T>(command: string, args?: Record<string, unknown>): Promise<T> => {
        try {
            return await invoke<T>(command, args);
        } catch (error) {
            throw normalizeNativeError(error);
        }
    };
}

function normalizeNativeError(error: unknown): DeviceKeyNativeError {
    const code = typeof error === 'string' && NATIVE_DEVICE_KEY_ERRORS.has(error as DeviceKeyNativeErrorCode)
        ? error as DeviceKeyNativeErrorCode
        : 'DEVICE_KEY_CRYPTO_FAILED';

    return new DeviceKeyNativeError(code);
}

function uint8ArrayToBase64(bytes: Uint8Array): string {
    let binary = '';
    for (const byte of bytes) {
        binary += String.fromCharCode(byte);
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
