// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 — see LICENSE
/**
 * @fileoverview Passkey Service for Singra Vault
 *
 * Client-side WebAuthn integration with PRF extension for
 * zero-knowledge vault unlock via passkeys.
 *
 * Architecture:
 *   Registration (while vault is unlocked, master password available):
 *     1. Get options from server (includes PRF salt)
 *     2. Call startRegistration() with PRF extension
 *     3. If PRF supported: derive wrapping key from PRF output via HKDF
 *     4. Encrypt the raw vault key bytes with the wrapping key
 *     5. Send credential + encrypted key to server
 *
 *   Authentication (vault locked):
 *     1. Get options from server (includes PRF salts per credential)
 *     2. Call startAuthentication() with PRF extension
 *     3. Derive wrapping key from PRF output via HKDF
 *     4. Decrypt the wrapped key material
 *     5. Vault unlocked — no master password needed
 *
 * SECURITY:
 *   - PRF output (32 bytes) is never stored; only used transiently
 *   - Wrapping key is derived via HKDF-SHA-256 (not raw PRF output)
 *   - Raw key bytes are encrypted with AES-256-GCM (IV || ciphertext || tag)
 *   - The imported CryptoKey is non-extractable (same as password-derived)
 *   - Server never sees the unwrapped encryption key
 *   - PRF salt is generated server-side with CSPRNG
 *   - Raw key bytes are wiped from memory immediately after use
 */

import { startRegistration, startAuthentication, base64URLStringToBuffer } from '@simplewebauthn/browser';
import type {
    PublicKeyCredentialCreationOptionsJSON,
    PublicKeyCredentialRequestOptionsJSON,
    RegistrationResponseJSON,
    AuthenticationResponseJSON,
} from '@simplewebauthn/browser';
import { invokeAuthedFunction } from '@/services/edgeFunctionService';
import { importMasterKey, unwrapUserKeyBytes } from '@/services/cryptoService';
import { buildAuthenticationPrfExtension } from '@/services/passkeyPrf';

// ============ WebAuthn PRF Extension Types ============
// PRF is a WebAuthn Level 3 extension not yet reflected in
// @simplewebauthn's vendored DOM types, so we define the shapes locally.

/** PRF eval input (salt buffers sent to the authenticator). */
interface PrfEvalInput {
    first: ArrayBuffer;
    second?: ArrayBuffer;
}

/** PRF extension input passed via `extensions.prf`. */
interface PrfExtensionInput {
    eval?: PrfEvalInput;
    evalByCredential?: Record<string, PrfEvalInput>;
}

/** PRF eval output (raw PRF results returned by the authenticator). */
interface PrfEvalOutput {
    first: ArrayBuffer;
    second?: ArrayBuffer;
}

/** PRF extension output returned in `clientExtensionResults.prf`. */
interface PrfExtensionOutput {
    enabled?: boolean;
    results?: PrfEvalOutput;
}

/** Extended client extension inputs including the PRF extension. */
interface ExtensionsWithPrf extends AuthenticationExtensionsClientInputs {
    prf?: PrfExtensionInput;
}

/** Extended client extension outputs including the PRF extension. */
interface ClientExtensionOutputsWithPrf extends AuthenticationExtensionsClientOutputs {
    prf?: PrfExtensionOutput;
}

/** Options JSON with PRF-aware extensions for registration. */
interface CreationOptionsWithPrf extends Omit<PublicKeyCredentialCreationOptionsJSON, 'extensions'> {
    extensions?: ExtensionsWithPrf;
}

/** Options JSON with PRF-aware extensions for authentication. */
interface RequestOptionsWithPrf extends Omit<PublicKeyCredentialRequestOptionsJSON, 'extensions'> {
    extensions?: ExtensionsWithPrf;
}

/** Response JSON with PRF-aware clientExtensionResults. */
interface RegistrationResponseWithPrf extends Omit<RegistrationResponseJSON, 'clientExtensionResults'> {
    clientExtensionResults: ClientExtensionOutputsWithPrf;
}

/** Response JSON with PRF-aware clientExtensionResults. */
interface AuthenticationResponseWithPrf extends Omit<AuthenticationResponseJSON, 'clientExtensionResults'> {
    clientExtensionResults: ClientExtensionOutputsWithPrf;
}

// ============ Constants ============

/**
 * HKDF info string for deriving the wrapping key from PRF output.
 * This ensures domain separation even if PRF output were reused.
 */
const HKDF_INFO = new TextEncoder().encode('Singra Vault-PasskeyWrappingKey-v1');

/**
 * Static salt for HKDF. The PRF output already includes the per-credential
 * PRF salt, so the HKDF salt is a fixed domain separator.
 */
const HKDF_SALT = new TextEncoder().encode('Singra Vault-HKDF-Salt-v1');

/** AES-GCM IV length in bytes */
const IV_LENGTH = 12;
const PASSKEY_ENVELOPE_V2_PREFIX = 'sv-pk-v2:';

async function invokeWebauthn<TResponse>(
    body: Record<string, unknown>,
): Promise<{ data: TResponse | null; error: Error | null }> {
    try {
        const data = await invokeAuthedFunction<TResponse>('webauthn', body);
        return { data, error: null };
    } catch (error) {
        if (error instanceof Error) {
            return { data: null, error };
        }

        return { data: null, error: new Error('Edge function request failed') };
    }
}

// ============ Feature Detection ============

/**
 * Checks whether WebAuthn is available in this browser.
 *
 * @returns true if the browser supports WebAuthn
 */
export function isWebAuthnAvailable(): boolean {
    return (
        typeof window !== 'undefined' &&
        typeof window.PublicKeyCredential !== 'undefined'
    );
}

/**
 * Checks whether a platform authenticator (e.g. Windows Hello, Touch ID,
 * Face ID, Android biometrics) is available.
 *
 * @returns true if a platform authenticator is available
 */
export async function isPlatformAuthenticatorAvailable(): Promise<boolean> {
    if (!isWebAuthnAvailable()) return false;
    if (typeof PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable !== 'function') {
        return false;
    }
    try {
        return await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
    } catch {
        return false;
    }
}

async function upgradePasskeyWrappedKey(
    rawVaultKeyBytes: Uint8Array,
    credentialId: string,
): Promise<void> {
    // A wrapped-key rotation mutates unlock material. Reuse the PRF activation
    // ceremony so the server only accepts the update after a fresh WebAuthn
    // assertion scoped to the current RP ID.
    const result = await activatePasskeyPrf(rawVaultKeyBytes, credentialId);
    if (!result.success) {
        throw new Error(result.error || 'Failed to rotate passkey wrapped key');
    }
}

export interface PasskeyClientSupport {
    webAuthnAvailable: boolean;
    platformAuthenticatorAvailable: boolean;
    clientCapabilitiesAvailable: boolean;
    prfExtensionSupported: boolean | null;
}

type PublicKeyCredentialWithCapabilities = typeof PublicKeyCredential & {
    getClientCapabilities?: () => Promise<Record<string, boolean>>;
};

/**
 * Returns the current relying-party identifier used by the browser context.
 * WebAuthn credentials are scoped to this hostname.
 */
export function getCurrentPasskeyRpId(): string | null {
    if (typeof window === 'undefined') {
        return null;
    }

    try {
        return window.location.hostname || null;
    } catch {
        return null;
    }
}

/**
 * Checks whether the current browser client reports support for the PRF
 * extension. This is a client-level signal only: the authenticator itself may
 * still reject PRF, so registration/authentication results remain authoritative.
 */
export async function getPasskeyClientSupport(): Promise<PasskeyClientSupport> {
    const webAuthnAvailable = isWebAuthnAvailable();

    if (!webAuthnAvailable) {
        return {
            webAuthnAvailable: false,
            platformAuthenticatorAvailable: false,
            clientCapabilitiesAvailable: false,
            prfExtensionSupported: null,
        };
    }

    const platformAuthenticatorAvailable = await isPlatformAuthenticatorAvailable();
    const publicKeyCredential = PublicKeyCredential as PublicKeyCredentialWithCapabilities;

    if (typeof publicKeyCredential.getClientCapabilities !== 'function') {
        return {
            webAuthnAvailable: true,
            platformAuthenticatorAvailable,
            clientCapabilitiesAvailable: false,
            prfExtensionSupported: null,
        };
    }

    try {
        const capabilities = await publicKeyCredential.getClientCapabilities();

        return {
            webAuthnAvailable: true,
            platformAuthenticatorAvailable,
            clientCapabilitiesAvailable: true,
            prfExtensionSupported: Object.prototype.hasOwnProperty.call(capabilities, 'extension:prf')
                ? capabilities['extension:prf'] === true
                : null,
        };
    } catch {
        return {
            webAuthnAvailable: true,
            platformAuthenticatorAvailable,
            clientCapabilitiesAvailable: false,
            prfExtensionSupported: null,
        };
    }
}

// ============ Registration ============

/**
 * Registers a new passkey with optional PRF support.
 *
 * Must be called while the vault is unlocked AND the raw key bytes are
 * available (from a recent deriveRawKey call). The raw bytes are encrypted
 * with the PRF-derived wrapping key and stored server-side.
 *
 * @param rawKeyBytes - The raw 32-byte AES key (from deriveRawKey)
 * @param deviceName - User-friendly name for this passkey
 * @returns Result with success status and PRF support indication
 */
export async function registerPasskey(
    rawVaultKeyBytes: Uint8Array,
    deviceName: string = 'Passkey',
): Promise<PasskeyRegistrationResult> {
    // 1. Get registration options from server
    const { data: serverData, error: serverError } = await invokeWebauthn<{
        options: PublicKeyCredentialCreationOptionsJSON;
        prfSalt: string;
    }>({
        action: 'generate-registration-options',
        displayName: deviceName,
    });

    if (serverError || !serverData?.options) {
        return { success: false, error: serverError?.message || 'Failed to get registration options' };
    }

    const options: PublicKeyCredentialCreationOptionsJSON = serverData.options;
    const prfSalt: string = serverData.prfSalt;

    // 2. Convert PRF salt from base64url to ArrayBuffer
    const prfSaltBytes = base64URLStringToBuffer(prfSalt);

    // 3. Call startRegistration with PRF extension injected
    let regResponse: RegistrationResponseJSON;
    try {
        const optionsWithPrf: CreationOptionsWithPrf = {
            ...options,
            extensions: {
                ...(options.extensions || {}),
                prf: {
                    eval: {
                        first: prfSaltBytes,
                    },
                },
            },
        };
        regResponse = await startRegistration({
            optionsJSON: optionsWithPrf as PublicKeyCredentialCreationOptionsJSON,
        });
    } catch (err: unknown) {
        if (err instanceof Error && err.name === 'NotAllowedError') {
            return { success: false, error: 'CANCELLED' };
        }
        return { success: false, error: err instanceof Error ? err.message : 'Registration failed' };
    }

    // 4. Check if PRF is supported by this authenticator
    const clientExtResults = (regResponse as unknown as RegistrationResponseWithPrf).clientExtensionResults;
    const prfEnabled = clientExtResults?.prf?.enabled === true;

    let wrappedMasterKey: string | null = null;

    if (prfEnabled) {
        // PRF is supported — try to get PRF output from registration
        const prfResults = clientExtResults?.prf?.results;

        if (prfResults?.first) {
            // Got PRF output during registration — wrap the raw key now
            const prfOutput = new Uint8Array(prfResults.first);
            try {
                wrappedMasterKey = formatPasskeyEnvelopeV2(
                    await encryptRawKeyBytes(rawVaultKeyBytes, prfOutput),
                );
            } finally {
                prfOutput.fill(0);
            }
        }
        // If no PRF results during registration, we need a separate
        // authentication ceremony. The UI will handle this.
    }

    // 5. Verify registration on the server and store credential
    const { data: verifyData, error: verifyError } = await invokeWebauthn<{
        verified: boolean;
        credentialId: string;
    }>({
        action: 'verify-registration',
        credential: regResponse as unknown as Record<string, unknown>,
        deviceName,
        prfSalt,
        wrappedMasterKey,
        prfEnabled,
    });

    if (verifyError || !verifyData?.verified) {
        return { success: false, error: verifyError?.message || 'Server verification failed' };
    }

    return {
        success: true,
        credentialId: verifyData.credentialId,
        prfEnabled,
        needsPrfActivation: prfEnabled && !wrappedMasterKey,
    };
}

/**
 * Completes PRF activation by performing an authentication ceremony
 * to get PRF output and wrap the raw key bytes.
 *
 * Some authenticators only return PRF during get(), not create().
 *
 * @param rawKeyBytes - The raw 32-byte AES key (from deriveRawKey)
 * @param expectedCredentialId - The credential ID that should be activated
 * @returns Success status and the credential ID that was activated
 */
export async function activatePasskeyPrf(
    rawVaultKeyBytes: Uint8Array,
    expectedCredentialId: string,
): Promise<{ success: boolean; error?: string; credentialId?: string }> {
    if (!expectedCredentialId) {
        return { success: false, error: 'Missing target credential ID' };
    }

    // 1. Get authentication options
    const { data: serverData, error: serverError } = await invokeWebauthn<{
        options: PublicKeyCredentialRequestOptionsJSON;
        prfSalts: Record<string, string>;
    }>({
        action: 'generate-authentication-options',
        credentialId: expectedCredentialId,
    });

    if (serverError || !serverData?.options) {
        return { success: false, error: serverError?.message || 'Failed to get authentication options' };
    }

    const options: PublicKeyCredentialRequestOptionsJSON = serverData.options;
    const prfSalts: Record<string, string> = serverData.prfSalts || {};

    // Build PRF extension
    const prfExtension = buildAuthenticationPrfExtension(prfSalts);

    // 2. Call startAuthentication with PRF
    let authResponse: AuthenticationResponseJSON;
    try {
        const optionsWithPrf: RequestOptionsWithPrf = {
            ...options,
            extensions: {
                ...(options.extensions || {}),
                prf: prfExtension,
            },
        };
        authResponse = await startAuthentication({
            optionsJSON: optionsWithPrf as PublicKeyCredentialRequestOptionsJSON,
        });
    } catch (err: unknown) {
        if (err instanceof Error && err.name === 'NotAllowedError') {
            return { success: false, error: 'CANCELLED' };
        }
        return { success: false, error: err instanceof Error ? err.message : 'Authentication failed' };
    }

    if ((authResponse as { id?: string }).id !== expectedCredentialId) {
        return { success: false, error: 'Unexpected passkey credential used' };
    }

    // 3. Extract PRF output and wrap the key
    const clientExtResults = (authResponse as unknown as AuthenticationResponseWithPrf).clientExtensionResults;
    const prfResults = clientExtResults?.prf?.results;

    if (!prfResults?.first) {
        return { success: false, error: 'PRF output not available' };
    }

    const prfOutput = new Uint8Array(prfResults.first);
    try {
        const wrappedKey = formatPasskeyEnvelopeV2(
            await encryptRawKeyBytes(rawVaultKeyBytes, prfOutput),
        );

        // 4. Persist wrapped key server-side (credential ownership + assertion verified in Edge Function)
        const { data: activationData, error: activationError } = await invokeWebauthn<{
            activated: boolean;
            credentialId: string;
        }>({
            action: 'activate-prf',
            credential: authResponse as unknown as Record<string, unknown>,
            expectedCredentialId,
            wrappedMasterKey: wrappedKey,
        });

        if (activationError || !activationData?.activated) {
            return { success: false, error: activationError?.message || 'Failed to save wrapped key' };
        }

        return { success: true, credentialId: activationData.credentialId };
    } finally {
        prfOutput.fill(0);
    }
}

// ============ Authentication ============

/**
 * Authenticates using a registered passkey and derives the vault
 * encryption key from the PRF output.
 *
 * @returns The unwrapped encryption key on success
 */
export async function authenticatePasskey(
    authenticateOptions: { encryptedUserKey?: string | null } = {},
): Promise<PasskeyAuthenticationResult> {
    // 1. Get authentication options from server
    const { data: serverData, error: serverError } = await invokeWebauthn<{
        options: PublicKeyCredentialRequestOptionsJSON;
        prfSalts: Record<string, string>;
    }>({
        action: 'generate-authentication-options',
    });

    if (serverError || !serverData?.options) {
        return { success: false, error: serverError?.message || 'Failed to get authentication options' };
    }

    const requestOptions: PublicKeyCredentialRequestOptionsJSON = serverData.options;
    const prfSalts: Record<string, string> = serverData.prfSalts || {};

    // 2. Build PRF extension
    const prfExtension = buildAuthenticationPrfExtension(prfSalts);

    // 3. Call startAuthentication with PRF extension
    let authResponse: AuthenticationResponseJSON;
    try {
        const optionsWithPrf: RequestOptionsWithPrf = {
            ...requestOptions,
            extensions: {
                ...(requestOptions.extensions || {}),
                prf: prfExtension,
            },
        };
        authResponse = await startAuthentication({
            optionsJSON: optionsWithPrf as PublicKeyCredentialRequestOptionsJSON,
        });
    } catch (err: unknown) {
        if (err instanceof Error && err.name === 'NotAllowedError') {
            return { success: false, error: 'CANCELLED' };
        }
        return { success: false, error: err instanceof Error ? err.message : 'Authentication failed' };
    }

    // 4. Verify authentication on the server
    const { data: verifyData, error: verifyError } = await invokeWebauthn<{
        verified: boolean;
        credentialId: string;
        wrappedMasterKey?: string;
    }>({
        action: 'verify-authentication',
        credential: authResponse as unknown as Record<string, unknown>,
    });

    if (verifyError || !verifyData?.verified) {
        return { success: false, error: verifyError?.message || 'Server verification failed' };
    }

    // 5. Extract PRF output and unwrap the encryption key
    const clientExtResults = (authResponse as unknown as AuthenticationResponseWithPrf).clientExtensionResults;
    const prfResults = clientExtResults?.prf?.results;

    if (!prfResults?.first || !verifyData.wrappedMasterKey) {
        // Authentication succeeded but no PRF available.
        return {
            success: false,
            prfEnabled: false,
            error: 'NO_PRF',
        };
    }

    // 6. Derive wrapping key from PRF output and decrypt the raw key bytes
    const prfOutput = new Uint8Array(prfResults.first);
    try {
        const parsedEnvelope = parsePasskeyEnvelope(verifyData.wrappedMasterKey);
        const rawWrappedKeyBytes = await decryptRawKeyBytes(
            parsedEnvelope.payload,
            prfOutput,
        );

        if (parsedEnvelope.version === 2) {
            const encryptionKey = await importMasterKey(rawWrappedKeyBytes);
            rawWrappedKeyBytes.fill(0);

            return {
                success: true,
                encryptionKey,
                prfEnabled: true,
                credentialId: verifyData.credentialId,
                keySource: 'vault-key',
            };
        }

        if (authenticateOptions.encryptedUserKey) {
            const rawVaultKeyBytes = await unwrapUserKeyBytes(authenticateOptions.encryptedUserKey, rawWrappedKeyBytes);

            try {
                await upgradePasskeyWrappedKey(rawVaultKeyBytes, verifyData.credentialId);
            } catch (error) {
                console.warn('Failed to rotate legacy passkey envelope after successful unlock:', error);
            }

            rawWrappedKeyBytes.fill(0);

            try {
                const encryptionKey = await importMasterKey(rawVaultKeyBytes);
                return {
                    success: true,
                    encryptionKey,
                    prfEnabled: true,
                    credentialId: verifyData.credentialId,
                    keySource: 'vault-key',
                };
            } finally {
                rawVaultKeyBytes.fill(0);
            }
        }

        const encryptionKey = await importMasterKey(rawWrappedKeyBytes);

        return {
            success: true,
            encryptionKey,
            prfEnabled: true,
            credentialId: verifyData.credentialId,
            keySource: 'legacy-kdf',
            legacyKdfOutputBytes: rawWrappedKeyBytes,
        };
    } catch (err: unknown) {
        console.error('Failed to unwrap encryption key:', err);
        return { success: false, error: 'Key unwrapping failed — passkey data may be corrupted' };
    } finally {
        prfOutput.fill(0);
    }
}

// ============ Credential Management ============

/**
 * Lists all registered passkeys for the current user.
 *
 * @returns Array of credential summaries
 */
export async function listPasskeys(): Promise<PasskeyCredential[]> {
    const { data, error } = await invokeWebauthn<{ credentials: PasskeyCredential[] }>({
        action: 'list-credentials',
    });

    if (error) {
        console.error('Failed to list passkeys:', error);
        throw error;
    }

    if (!data?.credentials) {
        throw new Error('Failed to list passkeys');
    }

    return data.credentials;
}

/**
 * Deletes a registered passkey.
 *
 * @param credentialId - The UUID of the credential record to delete
 * @returns Success status
 */
export async function deletePasskey(
    credentialId: string,
): Promise<{ success: boolean; error?: string }> {
    const { data, error } = await invokeWebauthn<{ deleted: boolean }>({
        action: 'delete-credential',
        credentialId,
    });

    if (error || !data?.deleted) {
        return { success: false, error: error?.message || 'Failed to delete passkey' };
    }

    return { success: true };
}

// ============ PRF Key Wrapping (Internal) ============

/**
 * Derives an AES-256-GCM wrapping key from the PRF output using HKDF-SHA-256.
 *
 * HKDF provides proper domain separation and key stretching:
 *   - Extract: PRF output (32 bytes) + HKDF_SALT -> pseudorandom key
 *   - Expand: PRK + HKDF_INFO -> 256-bit AES key
 *
 * @param prfOutput - Raw 32-byte PRF output from the authenticator
 * @returns CryptoKey suitable for encrypt/decrypt
 */
async function deriveWrappingKey(prfOutput: Uint8Array): Promise<CryptoKey> {
    // Import PRF output as HKDF key material
    const baseKey = await crypto.subtle.importKey(
        'raw',
        prfOutput,
        'HKDF',
        false,
        ['deriveKey'],
    );

    // Derive AES-256-GCM key via HKDF-SHA-256
    return crypto.subtle.deriveKey(
        {
            name: 'HKDF',
            hash: 'SHA-256',
            salt: HKDF_SALT,
            info: HKDF_INFO,
        },
        baseKey,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt'],
    );
}

/**
 * Encrypts the raw AES key bytes with a PRF-derived wrapping key.
 *
 * Output format: base64(IV || ciphertext || authTag)
 *
 * @param rawKeyBytes - The raw 32-byte vault encryption key
 * @param prfOutput - Raw 32-byte PRF output
 * @returns Base64-encoded encrypted key
 */
async function encryptRawKeyBytes(
    rawKeyBytes: Uint8Array,
    prfOutput: Uint8Array,
): Promise<string> {
    const wrappingKey = await deriveWrappingKey(prfOutput);
    const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH));
    let ciphertextBytes: Uint8Array | null = null;
    let combined: Uint8Array | null = null;

    try {
        const ciphertext = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv, tagLength: 128 },
            wrappingKey,
            rawKeyBytes,
        );

        ciphertextBytes = new Uint8Array(ciphertext);
        // Combine IV + ciphertext (includes auth tag appended by AES-GCM)
        combined = new Uint8Array(iv.length + ciphertextBytes.byteLength);
        combined.set(iv, 0);
        combined.set(ciphertextBytes, iv.length);

        return uint8ArrayToBase64(combined);
    } finally {
        iv.fill(0);
        ciphertextBytes?.fill(0);
        combined?.fill(0);
    }
}

/**
 * Decrypts the raw AES key bytes using a PRF-derived wrapping key.
 *
 * @param encryptedBase64 - Base64-encoded encrypted key (IV || ciphertext || authTag)
 * @param prfOutput - Raw 32-byte PRF output
 * @returns The decrypted raw 32-byte key
 */
async function decryptRawKeyBytes(
    encryptedBase64: string,
    prfOutput: Uint8Array,
): Promise<Uint8Array> {
    const wrappingKey = await deriveWrappingKey(prfOutput);
    const combined = base64ToUint8Array(encryptedBase64);
    if (combined.length <= IV_LENGTH) {
        combined.fill(0);
        throw new Error('Invalid passkey key envelope');
    }

    const iv = combined.slice(0, IV_LENGTH);
    const ciphertext = combined.slice(IV_LENGTH);

    try {
        const plaintext = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv, tagLength: 128 },
            wrappingKey,
            ciphertext,
        );

        return new Uint8Array(plaintext);
    } finally {
        combined.fill(0);
        iv.fill(0);
        ciphertext.fill(0);
    }
}

function formatPasskeyEnvelopeV2(payload: string): string {
    return `${PASSKEY_ENVELOPE_V2_PREFIX}${payload}`;
}

function parsePasskeyEnvelope(envelope: string): { version: 1 | 2; payload: string } {
    if (envelope.startsWith(PASSKEY_ENVELOPE_V2_PREFIX)) {
        return {
            version: 2,
            payload: envelope.slice(PASSKEY_ENVELOPE_V2_PREFIX.length),
        };
    }

    return {
        version: 1,
        payload: envelope,
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
 * Result of passkey registration
 */
export interface PasskeyRegistrationResult {
    success: boolean;
    error?: string;
    credentialId?: string;
    /** Whether this authenticator supports PRF */
    prfEnabled?: boolean;
    /** If true, PRF is supported but needs a separate auth ceremony to activate */
    needsPrfActivation?: boolean;
}

/**
 * Result of passkey authentication
 */
export interface PasskeyAuthenticationResult {
    success: boolean;
    error?: string;
    /** The unwrapped vault encryption key (only if PRF succeeded) */
    encryptionKey?: CryptoKey;
    /** Whether PRF was used for key derivation */
    prfEnabled?: boolean;
    /** The credential that was used */
    credentialId?: string;
    /** Whether the passkey envelope already stored vault-key material or a legacy KDF blob */
    keySource?: 'vault-key' | 'legacy-kdf';
    /**
     * Only present for legacy passkeys on pre-USK accounts.
     * The caller must wipe this buffer after any migration/finalization work.
     */
    legacyKdfOutputBytes?: Uint8Array;
}

/**
 * Passkey credential summary (from server)
 */
export interface PasskeyCredential {
    id: string;
    credential_id: string;
    device_name: string;
    prf_enabled: boolean;
    created_at: string;
    last_used_at: string | null;
}
