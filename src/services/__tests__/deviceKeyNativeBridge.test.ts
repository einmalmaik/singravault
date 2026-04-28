import { describe, expect, it, vi, beforeEach } from 'vitest';
import { deriveWithDeviceKey } from '../deviceKeyService';

const runtimeState = vi.hoisted(() => ({
    isTauri: true,
    invoke: vi.fn(),
}));

vi.mock('@/platform/runtime', () => ({
    isTauriRuntime: () => runtimeState.isTauri,
}));

vi.mock('@/platform/tauriInvoke', () => ({
    getTauriInvoke: async () => (runtimeState.isTauri ? runtimeState.invoke : null),
}));

function bytesToBase64(bytes: Uint8Array): string {
    let binary = '';
    for (const byte of bytes) {
        binary += String.fromCharCode(byte);
    }
    return btoa(binary);
}

describe('deviceKeyNativeBridge', () => {
    beforeEach(() => {
        vi.clearAllMocks();
        runtimeState.isTauri = true;
    });

    it('uses the native derive command and never requests the raw device key', async () => {
        const { deriveNativeDeviceProtectedKey } = await import('../deviceKeyNativeBridge');
        const argon2Output = new Uint8Array(Array.from({ length: 32 }, (_value, index) => index));
        const derived = new Uint8Array(Array.from({ length: 32 }, (_value, index) => 255 - index));
        runtimeState.invoke.mockResolvedValueOnce(bytesToBase64(derived));

        const result = await deriveNativeDeviceProtectedKey(
            '00000000-0000-4000-8000-000000000001',
            argon2Output,
        );

        expect(Array.from(result)).toEqual(Array.from(derived));
        expect(runtimeState.invoke).toHaveBeenCalledWith('derive_device_protected_key', {
            userId: '00000000-0000-4000-8000-000000000001',
            argon2OutputBase64: bytesToBase64(argon2Output),
            version: 1,
        });
        expect(runtimeState.invoke).not.toHaveBeenCalledWith('load_local_secret', expect.anything());
    });

    it('maps safe native error codes without exposing secret material', async () => {
        const { DeviceKeyNativeError, deriveNativeDeviceProtectedKey } = await import('../deviceKeyNativeBridge');
        runtimeState.invoke.mockRejectedValueOnce('DEVICE_KEY_MISSING');
        runtimeState.invoke.mockRejectedValueOnce('raw-device-key-material');

        await expect(deriveNativeDeviceProtectedKey(
            '00000000-0000-4000-8000-000000000001',
            new Uint8Array(32),
        )).rejects.toBeInstanceOf(DeviceKeyNativeError);
        await expect(deriveNativeDeviceProtectedKey(
            '00000000-0000-4000-8000-000000000001',
            new Uint8Array(32),
        )).rejects.toMatchObject({ code: 'DEVICE_KEY_CRYPTO_FAILED' });
    });

    it('matches the Rust HKDF compatibility vector in the browser implementation', async () => {
        runtimeState.isTauri = false;
        const argon2Output = new Uint8Array(Array.from({ length: 32 }, (_value, index) => index));
        const deviceKey = new Uint8Array(Array.from({ length: 32 }, (_value, index) => 255 - index));

        const derived = await deriveWithDeviceKey(argon2Output, deviceKey);

        expect(bytesToBase64(derived)).toBe('VW/q6Mi+eLJhEtBaRtt9/aYVr4IuZR8cndy7hqtX/dg=');
    });
});
