// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE
/**
 * @fileoverview Key material provisioning service for hybrid (PQ + RSA) flows.
 *
 * Ensures that user-scoped key material exists before writing encrypted
 * collection/emergency keys:
 * - RSA-4096 public/private key pair in `user_keys`
 * - ML-KEM-768 key pair in `profiles` (`pq_*` columns)
 *
 * The service is idempotent and only creates missing material.
 */

import { supabase } from '@/integrations/supabase/client';
import {
    CURRENT_KDF_VERSION,
    deriveKey,
    encrypt,
    generateSalt,
    generateUserKeyPair,
    decryptPrivateKeyLegacy,
    wrapPrivateKeyWithUserKey,
} from '@/services/cryptoService';
import { generatePQKeyPair } from '@/services/pqCryptoService';
import { SECURITY_STANDARD_VERSION } from '@/services/securityStandard';

// ============ Constants ============

export const KEY_MATERIAL_ERROR_MASTER_PASSWORD_REQUIRED = 'MASTER_PASSWORD_REQUIRED';

// ============ Public API ============

/**
 * Ensures a user has RSA key material in `user_keys`.
 *
 * @param params - Provisioning parameters
 * @param params.userId - Auth user ID
 * @param params.masterPassword - Master password (required only when keys are missing)
 * @returns Existing or newly created RSA public key
 * @throws Error when database operations fail
 */
export async function ensureUserRsaKeyMaterial(
    params: EnsureRsaKeyMaterialParams,
): Promise<EnsureRsaKeyMaterialResult> {
    const { userId, masterPassword, userKey } = params;

    const { data: keyRow, error: fetchError } = await supabase
        .from('user_keys')
        .select('public_key')
        .eq('user_id', userId)
        .maybeSingle();

    if (fetchError) {
        throw fetchError;
    }

    if (keyRow?.public_key) {
        return {
            publicKey: keyRow.public_key,
            created: false,
        };
    }

    if (!masterPassword) {
        throw createKeyMaterialError(
            KEY_MATERIAL_ERROR_MASTER_PASSWORD_REQUIRED,
            'Master password is required to provision RSA key material.',
        );
    }

    const userKeyPair = await generateUserKeyPair(masterPassword);
    let encryptedPrivateKey = userKeyPair.encryptedPrivateKey;
    if (userKey) {
        // Decrypt the legacy-format key, then re-wrap under the UserKey
        const plainPrivateKey = await decryptPrivateKeyLegacy(userKeyPair.encryptedPrivateKey, masterPassword);
        encryptedPrivateKey = 'usk-v1:' + await wrapPrivateKeyWithUserKey(plainPrivateKey, userKey);
    }
    const { error: insertError } = await supabase
        .from('user_keys')
        .insert({
            user_id: userId,
            public_key: userKeyPair.publicKey,
            encrypted_private_key: encryptedPrivateKey,
            updated_at: new Date().toISOString(),
        });

    if (!insertError) {
        return {
            publicKey: userKeyPair.publicKey,
            created: true,
        };
    }

    if (isUniqueViolation(insertError)) {
        const { data: winnerRow, error: winnerError } = await supabase
            .from('user_keys')
            .select('public_key')
            .eq('user_id', userId)
            .maybeSingle();

        if (winnerError) {
            throw winnerError;
        }

        if (winnerRow?.public_key) {
            return {
                publicKey: winnerRow.public_key,
                created: false,
            };
        }
    }

    throw insertError;
}

/**
 * Ensures a user has post-quantum key material in `profiles`.
 *
 * @param params - Provisioning parameters
 * @param params.userId - Auth user ID
 * @param params.masterPassword - Master password (required only when keys are missing)
 * @returns Existing or newly created PQ public key
 * @throws Error when database operations fail
 */
export async function ensureUserPqKeyMaterial(
    params: EnsurePqKeyMaterialParams,
): Promise<EnsurePqKeyMaterialResult> {
    const { userId, masterPassword, userKey } = params;

    const { data: profileRow, error: fetchError } = await supabase
        .from('profiles')
        .select('pq_public_key, pq_encrypted_private_key, pq_key_version, pq_enforced_at, security_standard_version, legacy_crypto_disabled_at')
        .eq('user_id', userId)
        .maybeSingle();

    if (fetchError) {
        throw fetchError;
    }

    const hasPqKeyMaterial = !!(
        profileRow?.pq_public_key &&
        profileRow?.pq_encrypted_private_key &&
        profileRow?.pq_key_version
    );
    const nowIso = new Date().toISOString();
    const needsSecurityStandardMetadata = (
        profileRow?.security_standard_version !== SECURITY_STANDARD_VERSION ||
        !profileRow?.legacy_crypto_disabled_at ||
        !profileRow?.pq_enforced_at
    );

    if (hasPqKeyMaterial && !needsSecurityStandardMetadata) {
        return {
            publicKey: profileRow.pq_public_key as string,
            created: false,
            enforcedAtSet: false,
            securityStandardApplied: false,
        };
    }

    if (hasPqKeyMaterial && needsSecurityStandardMetadata) {
        const { error: updateMetadataError } = await supabase
            .from('profiles')
            .update({
                security_standard_version: SECURITY_STANDARD_VERSION,
                pq_enforced_at: profileRow?.pq_enforced_at ?? nowIso,
                legacy_crypto_disabled_at: profileRow?.legacy_crypto_disabled_at ?? nowIso,
                updated_at: nowIso,
            } as Record<string, unknown>)
            .eq('user_id', userId);

        if (updateMetadataError) {
            throw updateMetadataError;
        }

        return {
            publicKey: profileRow.pq_public_key as string,
            created: false,
            enforcedAtSet: !profileRow?.pq_enforced_at,
            securityStandardApplied: true,
        };
    }

    if (!masterPassword) {
        throw createKeyMaterialError(
            KEY_MATERIAL_ERROR_MASTER_PASSWORD_REQUIRED,
            'Master password is required to provision post-quantum key material.',
        );
    }

    const pqKeys = generatePQKeyPair();
    let pqEncryptedPrivateKeyField: string;
    if (userKey) {
        // Wrap PQ secret key with UserKey (USK format)
        pqEncryptedPrivateKeyField = 'pq-v2-usk:' + await wrapPrivateKeyWithUserKey(pqKeys.secretKey, userKey);
    } else {
        const salt = generateSalt();
        const kdfVersion = CURRENT_KDF_VERSION;
        const key = await deriveKey(masterPassword, salt, kdfVersion);
        const encryptedPrivateKey = await encrypt(pqKeys.secretKey, key);
        pqEncryptedPrivateKeyField = `${kdfVersion}:${salt}:${encryptedPrivateKey}`;
    }
    const needsEnforcedAt = !profileRow?.pq_enforced_at;

    const profilePayload = {
        user_id: userId,
        pq_public_key: pqKeys.publicKey,
        pq_encrypted_private_key: pqEncryptedPrivateKeyField,
        pq_key_version: 1,
        security_standard_version: SECURITY_STANDARD_VERSION,
        pq_enforced_at: profileRow?.pq_enforced_at ?? nowIso,
        legacy_crypto_disabled_at: profileRow?.legacy_crypto_disabled_at ?? nowIso,
        updated_at: nowIso,
    };

    if (profileRow) {
        const { data: claimRow, error: claimError } = await supabase
            .from('profiles')
            .update(profilePayload as Record<string, unknown>)
            .eq('user_id', userId)
            .is('pq_public_key', null)
            .is('pq_encrypted_private_key', null)
            .is('pq_key_version', null)
            .select('pq_public_key')
            .maybeSingle();

        if (claimError) {
            throw claimError;
        }

        if (claimRow?.pq_public_key === pqKeys.publicKey) {
            return {
                publicKey: pqKeys.publicKey,
                created: true,
                enforcedAtSet: needsEnforcedAt,
                securityStandardApplied: true,
            };
        }

        const { data: winnerRow, error: winnerError } = await supabase
            .from('profiles')
            .select('pq_public_key, pq_encrypted_private_key, pq_key_version, pq_enforced_at, security_standard_version, legacy_crypto_disabled_at')
            .eq('user_id', userId)
            .maybeSingle();

        if (winnerError) {
            throw winnerError;
        }

        const hasWinnerKeyMaterial = !!(
            winnerRow?.pq_public_key &&
            winnerRow?.pq_encrypted_private_key &&
            winnerRow?.pq_key_version
        );

        if (hasWinnerKeyMaterial) {
            const winnerNeedsMetadata = (
                winnerRow?.security_standard_version !== SECURITY_STANDARD_VERSION ||
                !winnerRow?.legacy_crypto_disabled_at ||
                !winnerRow?.pq_enforced_at
            );

            if (winnerNeedsMetadata) {
                const { error: winnerMetadataError } = await supabase
                    .from('profiles')
                    .update({
                        security_standard_version: SECURITY_STANDARD_VERSION,
                        pq_enforced_at: winnerRow?.pq_enforced_at ?? nowIso,
                        legacy_crypto_disabled_at: winnerRow?.legacy_crypto_disabled_at ?? nowIso,
                        updated_at: nowIso,
                    } as Record<string, unknown>)
                    .eq('user_id', userId);

                if (winnerMetadataError) {
                    throw winnerMetadataError;
                }
            }

            return {
                publicKey: winnerRow?.pq_public_key as string,
                created: false,
                enforcedAtSet: winnerNeedsMetadata && !winnerRow?.pq_enforced_at,
                securityStandardApplied: winnerNeedsMetadata,
            };
        }

        throw new Error('Failed to provision post-quantum key material due to concurrent writes.');
    }

    const { error: insertError } = await supabase
        .from('profiles')
        .insert(profilePayload as any);

    if (!insertError) {
        return {
            publicKey: pqKeys.publicKey,
            created: true,
            enforcedAtSet: needsEnforcedAt,
            securityStandardApplied: true,
        };
    }

    if (isUniqueViolation(insertError)) {
        const { data: winnerRow, error: winnerError } = await supabase
            .from('profiles')
            .select('pq_public_key, pq_encrypted_private_key, pq_key_version, pq_enforced_at, security_standard_version, legacy_crypto_disabled_at')
            .eq('user_id', userId)
            .maybeSingle();

        if (winnerError) {
            throw winnerError;
        }

        const hasWinnerKeyMaterial = !!(
            winnerRow?.pq_public_key &&
            winnerRow?.pq_encrypted_private_key &&
            winnerRow?.pq_key_version
        );

        if (hasWinnerKeyMaterial) {
            const winnerNeedsMetadata = (
                winnerRow?.security_standard_version !== SECURITY_STANDARD_VERSION ||
                !winnerRow?.legacy_crypto_disabled_at ||
                !winnerRow?.pq_enforced_at
            );

            if (winnerNeedsMetadata) {
                const { error: winnerMetadataError } = await supabase
                    .from('profiles')
                    .update({
                        security_standard_version: SECURITY_STANDARD_VERSION,
                        pq_enforced_at: winnerRow?.pq_enforced_at ?? nowIso,
                        legacy_crypto_disabled_at: winnerRow?.legacy_crypto_disabled_at ?? nowIso,
                        updated_at: nowIso,
                    } as Record<string, unknown>)
                    .eq('user_id', userId);

                if (winnerMetadataError) {
                    throw winnerMetadataError;
                }
            }

            return {
                publicKey: winnerRow.pq_public_key as string,
                created: false,
                enforcedAtSet: winnerNeedsMetadata && !winnerRow?.pq_enforced_at,
                securityStandardApplied: winnerNeedsMetadata,
            };
        }
    }

    throw insertError;
}

/**
 * Ensures hybrid key material (RSA + PQ) exists for a user.
 *
 * @param params - Provisioning parameters
 * @param params.userId - Auth user ID
 * @param params.masterPassword - Master password (required only when any key material is missing)
 * @returns Existing or newly created RSA and PQ public keys
 */
export async function ensureHybridKeyMaterial(
    params: EnsureHybridKeyMaterialParams,
): Promise<EnsureHybridKeyMaterialResult> {
    const rsa = await ensureUserRsaKeyMaterial(params);
    const pq = await ensureUserPqKeyMaterial(params);

    return {
        rsaPublicKey: rsa.publicKey,
        pqPublicKey: pq.publicKey,
        createdRsa: rsa.created,
        createdPq: pq.created,
    };
}

/**
 * Checks whether an error indicates that a master password prompt is required.
 *
 * @param error - Unknown thrown value
 * @returns true when the error requires master password input
 */
export function isMasterPasswordRequiredError(error: unknown): boolean {
    if (!error || typeof error !== 'object') {
        return false;
    }

    return (
        'code' in error &&
        (error as { code?: string }).code === KEY_MATERIAL_ERROR_MASTER_PASSWORD_REQUIRED
    );
}

// ============ Internal Helpers ============

function createKeyMaterialError(code: string, message: string): KeyMaterialError {
    const error = new Error(message) as KeyMaterialError;
    error.code = code;
    return error;
}

function isUniqueViolation(error: unknown): boolean {
    if (!error || typeof error !== 'object') {
        return false;
    }

    return (
        'code' in error &&
        (error as { code?: string }).code === '23505'
    );
}

// ============ Type Definitions ============

interface KeyMaterialError extends Error {
    code?: string;
}

export interface EnsureRsaKeyMaterialParams {
    userId: string;
    masterPassword?: string;
    /** When provided, new private keys are wrapped with the UserKey (USK format). */
    userKey?: CryptoKey;
}

export interface EnsureRsaKeyMaterialResult {
    publicKey: string;
    created: boolean;
}

export interface EnsurePqKeyMaterialParams {
    userId: string;
    masterPassword?: string;
    /** When provided, new private keys are wrapped with the UserKey (USK format). */
    userKey?: CryptoKey;
}

export interface EnsurePqKeyMaterialResult {
    publicKey: string;
    created: boolean;
    enforcedAtSet: boolean;
    securityStandardApplied: boolean;
}

export interface EnsureHybridKeyMaterialParams {
    userId: string;
    masterPassword?: string;
    /** When provided, new private keys are wrapped with the UserKey (USK format). */
    userKey?: CryptoKey;
}

export interface EnsureHybridKeyMaterialResult {
    rsaPublicKey: string;
    pqPublicKey: string;
    createdRsa: boolean;
    createdPq: boolean;
}
