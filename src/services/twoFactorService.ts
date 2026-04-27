// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 — see LICENSE
/**
 * @fileoverview Two-Factor Authentication Service
 * 
 * Provides TOTP-based 2FA functionality including:
 * - Secret generation and QR code URI
 * - TOTP code verification
 * - Backup code generation and verification
 * - 2FA enable/disable with security checks
 */

import * as OTPAuth from 'otpauth';
import { supabase } from '@/integrations/supabase/client';

// ============ Types ============

export interface TwoFactorStatus {
    isEnabled: boolean;
    vaultTwoFactorEnabled: boolean;
    lastVerifiedAt: string | null;
    backupCodesRemaining: number;
}

export type TwoFactorContext =
    | 'account_login'
    | 'account_security_change'
    | 'vault_unlock'
    | 'password_reset'
    | 'critical_action'
    | 'disable_2fa';

export type TwoFactorVerificationMethod = 'totp' | 'backup_code';

export interface TwoFactorRequirement {
    context: TwoFactorContext;
    required: boolean;
    status: 'loaded' | 'unavailable';
    reason?: 'account_2fa_enabled' | 'vault_2fa_enabled' | 'status_unavailable';
}

interface TwoFactorStatusLoadResult {
    status: 'loaded' | 'unavailable';
    data: Pick<TwoFactorStatus, 'isEnabled' | 'vaultTwoFactorEnabled' | 'lastVerifiedAt'> | null;
    error?: unknown;
}

export interface SetupData {
    secret: string;
    qrCodeUri: string;
    backupCodes: string[];
}

export type TwoFactorErrorCode =
    | 'RATE_LIMITED'
    | 'AUTH_REQUIRED'
    | 'FORBIDDEN'
    | 'SERVER_ERROR'
    | 'UNKNOWN';

export interface TwoFactorOperationResult {
    success: boolean;
    error?: string;
    errorCode?: TwoFactorErrorCode;
    retryAfterSeconds?: number;
    lockedUntil?: string | null;
}

// ============ Constants ============

const ISSUER = 'Singra Vault';
const BACKUP_CODE_COUNT = 5;
const BACKUP_CODE_LENGTH = 8;

// ============ Secret Generation ============

/**
 * Generates a new TOTP secret
 * @returns Base32 encoded secret
 */
export function generateTOTPSecret(): string {
    const secret = new OTPAuth.Secret({ size: 20 });
    return secret.base32;
}

/**
 * Generates the QR code URI for authenticator apps
 * @param secret - Base32 encoded secret
 * @param email - User's email for the label
 * @returns otpauth:// URI for QR code generation
 */
export function generateQRCodeUri(secret: string, email: string): string {
    const totp = new OTPAuth.TOTP({
        issuer: ISSUER,
        label: email,
        algorithm: 'SHA1',
        digits: 6,
        period: 30,
        secret: OTPAuth.Secret.fromBase32(secret),
    });

    return totp.toString();
}

/**
 * Formats secret for manual entry (with spaces for readability)
 * @param secret - Base32 encoded secret
 * @returns Formatted secret like "JBSW Y3DP EHPK 3PXP"
 */
export function formatSecretForDisplay(secret: string): string {
    return secret.match(/.{1,4}/g)?.join(' ') || secret;
}

// ============ TOTP Verification ============

/**
 * Verifies a TOTP code against a secret
 * @param secret - Base32 encoded secret
 * @param code - 6-digit code to verify
 * @returns true if code is valid
 */
export function verifyTOTPCode(secret: string, code: string): boolean {
    try {
        const totp = new OTPAuth.TOTP({
            issuer: ISSUER,
            algorithm: 'SHA1',
            digits: 6,
            period: 30,
            secret: OTPAuth.Secret.fromBase32(secret.replace(/\s/g, '')),
        });

        // Allow 1 period window (30 seconds) for clock drift
        const delta = totp.validate({ token: code.replace(/\s/g, ''), window: 1 });
        return delta !== null;
    } catch (error) {
        console.error('TOTP verification error:', error);
        return false;
    }
}

// ============ Backup Codes ============

/**
 * Generates random backup codes
 * @returns Array of backup codes (not hashed, for display to user)
 */
export function generateBackupCodes(): string[] {
    const codes: string[] = [];
    const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // Excluded similar chars (0, O, 1, I)

    for (let i = 0; i < BACKUP_CODE_COUNT; i++) {
        let code = '';
        for (let j = 0; j < BACKUP_CODE_LENGTH; j++) {
            const randomIndex = getSecureRandomInt(0, chars.length - 1);
            code += chars[randomIndex];
        }
        // Format as XXXX-XXXX
        codes.push(`${code.slice(0, 4)}-${code.slice(4)}`);
    }

    return codes;
}

/**
 * Generates a cryptographically secure random integer in range [min, max]
 * Uses rejection sampling to avoid modulo bias.
 *
 * @param min - Minimum value (inclusive)
 * @param max - Maximum value (inclusive)
 * @returns Secure random integer
 */
function getSecureRandomInt(min: number, max: number): number {
    const range = max - min + 1;
    const bytesNeeded = Math.ceil(Math.log2(range) / 8) || 1;
    const maxValid = Math.floor((256 ** bytesNeeded) / range) * range - 1;

    let randomValue: number;
    const randomBytes = new Uint8Array(bytesNeeded);

    do {
        crypto.getRandomValues(randomBytes);
        randomValue = 0;
        for (let i = 0; i < bytesNeeded; i++) {
            randomValue = (randomValue << 8) | randomBytes[i];
        }
    } while (randomValue > maxValid);

    return min + (randomValue % range);
}

/**
 * Hashes a backup code for secure storage using HMAC-SHA-256.
 * The user's encryption salt is used as the HMAC key so that
 * identical codes for different users produce different hashes.
 *
 * @param code - Plain backup code
 * @param salt - User's encryption_salt (base64) from profile
 * @returns Versioned hash string for backup code verification
 */
export async function hashBackupCode(code: string, salt?: string): Promise<string> {
    const normalizedCode = code.replace(/-/g, '').toUpperCase();
    void salt;

    // Version 3: Argon2id (new secure standard)
    // Generate unique salt for this backup code
    const codeSalt = crypto.getRandomValues(new Uint8Array(16));
    const saltBase64 = btoa(String.fromCharCode(...codeSalt));

    // Import argon2 for backup codes (lighter params than master password)
    const { argon2id } = await import('hash-wasm');

    // Use lighter Argon2 params for backup codes (still secure but faster)
    const hash = await argon2id({
        password: normalizedCode,
        salt: codeSalt,
        parallelism: 1,
        iterations: 2,
        memorySize: 16384, // 16 MiB - lighter than master password
        hashLength: 32,
        outputType: 'hex',
    });

    // Return versioned format for new codes
    return `v3:${saltBase64}:${hash}`;
}

/**
 * Legacy hash function for backward compatibility
 */
async function hashBackupCodeLegacy(code: string, salt?: string): Promise<string> {
    const normalizedCode = code.replace(/-/g, '').toUpperCase();
    const encoder = new TextEncoder();
    const data = encoder.encode(normalizedCode);

    if (salt) {
        const keyData = encoder.encode(salt);
        const hmacKey = await crypto.subtle.importKey(
            'raw',
            keyData,
            { name: 'HMAC', hash: 'SHA-256' },
            false,
            ['sign']
        );
        const signature = await crypto.subtle.sign('HMAC', hmacKey, data);
        const hashArray = Array.from(new Uint8Array(signature));
        return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    }

    // Legacy fallback: unsalted SHA-256
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Verifies a backup code against stored hashes.
 * Supports all hash versions for backward compatibility.
 */
export async function verifyBackupCodeHash(
    code: string,
    storedHash: string,
    userSalt?: string
): Promise<boolean> {
    const normalizedCode = code.replace(/-/g, '').toUpperCase();

    // Check if versioned format (Argon2id)
    if (storedHash.startsWith('v3:')) {
        const [, saltBase64, hash] = storedHash.split(':');
        const salt = new Uint8Array(atob(saltBase64).split('').map(c => c.charCodeAt(0)));

        const { argon2id } = await import('hash-wasm');
        const computedHash = await argon2id({
            password: normalizedCode,
            salt: salt,
            parallelism: 1,
            iterations: 2,
            memorySize: 16384,
            hashLength: 32,
            outputType: 'hex',
        });

        return computedHash === hash;
    }

    // Legacy verification (HMAC-SHA-256 when salt provided, SHA-256 otherwise)
    const legacyHash = await hashBackupCodeLegacy(code, userSalt);
    return legacyHash === storedHash;
}

// ============ Internal Helpers ============

/**
 * Fetches the encryption salt for a user from the profiles table.
 * This salt is used as the HMAC key for backup-code hashing so that
 * identical plaintext codes produce different hashes per user.
 *
 * @param userId - The user's auth UID
 * @returns The base64-encoded encryption salt, or null if not found
 */
async function getUserEncryptionSalt(userId: string): Promise<string | null> {
    const { data, error } = await supabase
        .from('profiles')
        .select('encryption_salt')
        .eq('user_id', userId)
        .single();

    if (error || !data?.encryption_salt) {
        return null;
    }

    return data.encryption_salt;
}

// ============ Database Operations ============

/**
 * Gets the current 2FA status for a user
 * @param userId - User ID
 * @returns 2FA status or null if not set up
 */
export async function get2FAStatus(userId: string): Promise<TwoFactorStatus | null> {
    const { data, error } = await supabase
        .from('user_2fa')
        .select('is_enabled, vault_2fa_enabled, last_verified_at')
        .eq('user_id', userId)
        .maybeSingle();

    if (error || !data) {
        return null;
    }

    // Count remaining backup codes
    const { count } = await supabase
        .from('backup_codes')
        .select('id', { count: 'exact', head: true })
        .eq('user_id', userId)
        .eq('is_used', false);

    return {
        isEnabled: data.is_enabled,
        vaultTwoFactorEnabled: data.vault_2fa_enabled,
        lastVerifiedAt: data.last_verified_at,
        backupCodesRemaining: count || 0,
    };
}

async function loadTwoFactorStatus(userId: string): Promise<TwoFactorStatusLoadResult> {
    const { data, error } = await supabase
        .from('user_2fa')
        .select('is_enabled, vault_2fa_enabled, last_verified_at')
        .eq('user_id', userId)
        .maybeSingle();

    if (error) {
        return { status: 'unavailable', data: null, error };
    }

    if (!data) {
        return { status: 'loaded', data: null };
    }

    return {
        status: 'loaded',
        data: {
            isEnabled: Boolean(data.is_enabled),
            vaultTwoFactorEnabled: Boolean(data.vault_2fa_enabled),
            lastVerifiedAt: data.last_verified_at,
        },
    };
}

interface Auth2FAInvokeError {
    message: string;
    status?: number;
    code: TwoFactorErrorCode;
    retryAfterSeconds?: number;
    lockedUntil?: string | null;
    details?: Record<string, unknown>;
}

interface FunctionsErrorContextLike {
    status?: number;
    headers?: {
        get: (name: string) => string | null;
    };
    json?: () => Promise<unknown>;
}

async function invokeAuth2FA<T = Record<string, unknown>>(body: Record<string, unknown>): Promise<{
    data: T | null;
    error: Auth2FAInvokeError | null;
}> {
    const { data, error } = await supabase.functions.invoke<T>('auth-2fa', { body });
    return { data: data ?? null, error: error ? await normalizeAuth2FAError(error) : null };
}

async function normalizeAuth2FAError(error: unknown): Promise<Auth2FAInvokeError> {
    const context = getFunctionsErrorContext(error);
    const status = context?.status;
    const details = context ? await readFunctionErrorDetails(context) : null;
    const retryAfterSeconds = getRetryAfterSeconds(details, context);
    const lockedUntil = getString(details?.lockedUntil) ?? null;
    const code = getTwoFactorErrorCode(status);

    if (code === 'RATE_LIMITED') {
        return {
            message: formatRateLimitedMessage(retryAfterSeconds, lockedUntil),
            status,
            code,
            retryAfterSeconds,
            lockedUntil,
            details: details ?? undefined,
        };
    }

    const detailMessage = getString(details?.error) ?? getString(details?.message);
    const fallbackMessage = error instanceof Error
        ? error.message
        : getString(isRecord(error) ? error.message : undefined) ?? '2FA verification failed.';
    return {
        message: detailMessage ?? fallbackMessage,
        status,
        code,
        retryAfterSeconds,
        lockedUntil,
        details: details ?? undefined,
    };
}

function getFunctionsErrorContext(error: unknown): FunctionsErrorContextLike | null {
    if (!isRecord(error) || !isRecord(error.context)) {
        return null;
    }

    return error.context as FunctionsErrorContextLike;
}

async function readFunctionErrorDetails(context: FunctionsErrorContextLike): Promise<Record<string, unknown> | null> {
    if (typeof context.json !== 'function') {
        return null;
    }

    try {
        const value = await context.json();
        return isRecord(value) ? value : null;
    } catch {
        return null;
    }
}

function getRetryAfterSeconds(
    details: Record<string, unknown> | null,
    context: FunctionsErrorContextLike | null,
): number | undefined {
    const bodyRetryAfter = getPositiveNumber(details?.retryAfterSeconds);
    if (bodyRetryAfter !== undefined) {
        return bodyRetryAfter;
    }

    const headerValue = context?.headers?.get('Retry-After');
    if (!headerValue) {
        return undefined;
    }

    const parsed = Number.parseInt(headerValue, 10);
    return Number.isFinite(parsed) && parsed > 0 ? parsed : undefined;
}

function getTwoFactorErrorCode(status: number | undefined): TwoFactorErrorCode {
    if (status === 429) return 'RATE_LIMITED';
    if (status === 401) return 'AUTH_REQUIRED';
    if (status === 403) return 'FORBIDDEN';
    if (status && status >= 500) return 'SERVER_ERROR';
    return 'UNKNOWN';
}

function formatRateLimitedMessage(retryAfterSeconds?: number, lockedUntil?: string | null): string {
    const seconds = retryAfterSeconds ?? secondsUntil(lockedUntil);
    if (seconds && seconds > 0) {
        return `Too many attempts. Try again in ${formatDuration(seconds)}.`;
    }

    return 'Too many attempts. Please try again later.';
}

function secondsUntil(lockedUntil?: string | null): number | undefined {
    if (!lockedUntil) {
        return undefined;
    }

    const millis = new Date(lockedUntil).getTime() - Date.now();
    if (!Number.isFinite(millis) || millis <= 0) {
        return undefined;
    }

    return Math.ceil(millis / 1000);
}

function formatDuration(seconds: number): string {
    if (seconds < 60) {
        return `${seconds} second${seconds === 1 ? '' : 's'}`;
    }

    const minutes = Math.ceil(seconds / 60);
    return `${minutes} minute${minutes === 1 ? '' : 's'}`;
}

function getPositiveNumber(value: unknown): number | undefined {
    return typeof value === 'number' && Number.isFinite(value) && value > 0 ? value : undefined;
}

function getString(value: unknown): string | undefined {
    return typeof value === 'string' && value.trim() ? value : undefined;
}

function isRecord(value: unknown): value is Record<string, unknown> {
    return typeof value === 'object' && value !== null;
}

export async function getTwoFactorRequirement(input: {
    userId: string;
    context: TwoFactorContext;
}): Promise<TwoFactorRequirement> {
    try {
        const { data, error } = await invokeAuth2FA<{
            required?: boolean;
            status?: 'loaded' | 'unavailable';
            reason?: TwoFactorRequirement['reason'];
        }>({
            action: 'requirement',
            context: input.context,
        });

        if (!error && data) {
            return {
                context: input.context,
                required: data.status === 'unavailable' ? true : Boolean(data.required),
                status: data.status === 'unavailable' ? 'unavailable' : 'loaded',
                reason: data.status === 'unavailable' ? 'status_unavailable' : data.reason,
            };
        }
    } catch {
        // Fall through to fail-closed for unlock-sensitive contexts.
    }

    if (input.context === 'vault_unlock') {
        return {
            context: input.context,
            required: true,
            status: 'unavailable',
            reason: 'status_unavailable',
        };
    }

    const loaded = await loadTwoFactorStatus(input.userId);

    if (loaded.status === 'unavailable') {
        return {
            context: input.context,
            required: true,
            status: 'unavailable',
            reason: 'status_unavailable',
        };
    }

    const status = loaded.data;
    if (!status?.isEnabled) {
        return {
            context: input.context,
            required: false,
            status: 'loaded',
        };
    }

    if (input.context === 'vault_unlock') {
        return {
            context: input.context,
            required: status.vaultTwoFactorEnabled,
            status: 'loaded',
            reason: status.vaultTwoFactorEnabled ? 'vault_2fa_enabled' : undefined,
        };
    }

    return {
        context: input.context,
        required: true,
        status: 'loaded',
        reason: 'account_2fa_enabled',
    };
}

/**
 * Gets the TOTP secret for a user (for verification)
 * @param userId - User ID
 * @returns Secret or null
 */
export async function getTOTPSecret(userId: string): Promise<string | null> {
    const { data, error } = await supabase.rpc('get_user_2fa_secret', {
        p_user_id: userId,
        p_require_enabled: true,
    });

    if (error || !data) {
        return null;
    }

    return data;
}

/**
 * Initializes 2FA setup (stores secret but not enabled yet)
 * @param userId - User ID
 * @param secret - TOTP secret
 * @returns Success status
 */
export async function initializeTwoFactorSetup(
    userId: string,
    secret: string
): Promise<{ success: boolean; error?: string }> {
    const { error } = await supabase.rpc('initialize_user_2fa_secret', {
        p_user_id: userId,
        p_secret: secret,
    });

    if (error) {
        console.error('Error initializing 2FA:', error);
        return { success: false, error: error.message };
    }

    return { success: true };
}

/**
 * Enables 2FA after successful code verification
 * @param userId - User ID
 * @param code - TOTP code for verification
 * @param backupCodes - Generated backup codes to store
 * @returns Success status
 */
export async function enableTwoFactor(
    userId: string,
    code: string,
    backupCodes: string[]
): Promise<{ success: boolean; error?: string }> {
    // Get the pending secret
    const { data: pendingSecret, error: fetchError } = await supabase.rpc('get_user_2fa_secret', {
        p_user_id: userId,
        p_require_enabled: false,
    });

    if (fetchError || !pendingSecret) {
        return { success: false, error: '2FA setup not found. Please start again.' };
    }

    // Verify the code
    if (!verifyTOTPCode(pendingSecret, code)) {
        return { success: false, error: 'Invalid code. Please try again.' };
    }

    // Enable 2FA
    const { error: updateError } = await supabase
        .from('user_2fa')
        .update({
            is_enabled: true,
            enabled_at: new Date().toISOString(),
            last_verified_at: new Date().toISOString(),
        })
        .eq('user_id', userId);

    if (updateError) {
        return { success: false, error: updateError.message };
    }

    // Store hashed backup codes with Argon2id (v3)
    const hashedCodes = await Promise.all(
        backupCodes.map(async (code) => ({
            user_id: userId,
            code_hash: await hashBackupCode(code), // Now uses Argon2id v3 by default
            hash_version: 3, // Track version for future migrations
        }))
    );

    const { error: codesError } = await supabase
        .from('backup_codes')
        .insert(hashedCodes);

    if (codesError) {
        console.error('Error storing backup codes:', codesError);
        // Don't fail the whole operation, 2FA is still enabled
    }

    return { success: true };
}

/**
 * Verifies a backup code and marks it as used.
 *
 * Uses a dual-verify strategy to support transparent migration from
 * legacy unsalted SHA-256 hashes to HMAC-SHA-256:
 *   1. Try HMAC-SHA-256 hash (current secure method)
 *   2. If no match, try legacy unsalted SHA-256
 *   3. If legacy matches, mark as used (the code is consumed anyway)
 *
 * @param userId - User ID
 * @param code - Backup code to verify
 * @returns Whether the code was valid
 */
export async function verifyAndConsumeBackupCode(
    userId: string,
    code: string
): Promise<boolean> {
    // Get all unused backup codes for this user
    const { data: codes, error: fetchError } = await supabase
        .from('backup_codes')
        .select('id, code_hash')
        .eq('user_id', userId)
        .eq('is_used', false);

    if (fetchError || !codes || codes.length === 0) {
        return false;
    }

    // Get user salt for legacy verification (HMAC path)
    const salt = await getUserEncryptionSalt(userId);
    const legacyHmacHash = salt ? await hashBackupCodeLegacy(code, salt) : null;
    const legacyShaHash = await hashBackupCodeLegacy(code);

    // Check each code
    for (const storedCode of codes) {
        let isMatch = false;

        // Check based on hash version
        if (storedCode.code_hash.startsWith('v3:')) {
            // Argon2id verification
            isMatch = await verifyBackupCodeHash(code, storedCode.code_hash);
        } else {
            // Legacy verification (HMAC-SHA-256 with salt, SHA-256 fallback)
            isMatch = storedCode.code_hash === legacyHmacHash || storedCode.code_hash === legacyShaHash;
        }

        if (isMatch) {
            // Mark as used
            const { error: updateError } = await supabase
                .from('backup_codes')
                .update({
                    is_used: true,
                    used_at: new Date().toISOString(),
                })
                .eq('id', storedCode.id);

            if (updateError) {
                console.error('Error consuming backup code:', updateError);
                return false;
            }

            // Update last verified timestamp for audit/UX consistency
            await supabase
                .from('user_2fa')
                .update({ last_verified_at: new Date().toISOString() })
                .eq('user_id', userId);

            return true;
        }
    }

    return false;
}

/**
 * Disables 2FA for a user (requires valid TOTP code)
 * @param userId - User ID
 * @param code - Current TOTP code (NOT backup code)
 * @returns Success status
 */
export async function disableTwoFactor(
    userId: string,
    code: string
): Promise<TwoFactorOperationResult> {
    void userId;
    const { data, error } = await invokeAuth2FA<{ success?: boolean; error?: string }>({
        action: 'disable-2fa',
        code,
        method: 'totp',
    });

    if (error || !data?.success) {
        return {
            success: false,
            error: data?.error || error?.message || 'Invalid code. Backup codes cannot be used to disable 2FA.',
            errorCode: error?.code,
            retryAfterSeconds: error?.retryAfterSeconds,
            lockedUntil: error?.lockedUntil,
        };
    }

    return { success: true };
}

/**
 * Toggles vault 2FA requirement
 * @param userId - User ID
 * @param enabled - Whether to require 2FA for vault unlock
 * @returns Success status
 */
export async function setVaultTwoFactor(
    userId: string,
    enabled: boolean
): Promise<{ success: boolean; error?: string }> {
    const { error } = await supabase
        .from('user_2fa')
        .update({ vault_2fa_enabled: enabled })
        .eq('user_id', userId)
        .eq('is_enabled', true);

    if (error) {
        return { success: false, error: error.message };
    }

    return { success: true };
}

/**
 * Regenerates backup codes (deletes old ones)
 * @param userId - User ID
 * @returns New backup codes or error
 */
export async function regenerateBackupCodes(
    userId: string
): Promise<{ success: boolean; codes?: string[]; error?: string }> {
    // Check if 2FA is enabled
    const status = await get2FAStatus(userId);
    if (!status?.isEnabled) {
        return { success: false, error: '2FA is not enabled.' };
    }

    // Delete old backup codes
    await supabase.from('backup_codes').delete().eq('user_id', userId);

    // Generate new codes
    const newCodes = generateBackupCodes();

    // Fetch the user's encryption salt for HMAC-based hashing
    const salt = await getUserEncryptionSalt(userId);

    // Store hashed codes (HMAC-SHA-256 when salt available, SHA-256 fallback)
    const hashedCodes = await Promise.all(
        newCodes.map(async (code) => ({
            user_id: userId,
            code_hash: await hashBackupCode(code),
            hash_version: 3,
        }))
    );

    const { error } = await supabase.from('backup_codes').insert(hashedCodes);

    if (error) {
        return { success: false, error: error.message };
    }

    return { success: true, codes: newCodes };
}

/**
 * Verifies 2FA for login (either TOTP or backup code)
 * @param userId - User ID
 * @param code - Code to verify
 * @param isBackupCode - Whether this is a backup code
 * @returns Whether verification succeeded
 */
export async function verifyTwoFactorForLogin(
    userId: string,
    code: string,
    isBackupCode: boolean
): Promise<boolean> {
    const result = await verifyTwoFactorCode({
        userId,
        context: 'account_login',
        code,
        method: isBackupCode ? 'backup_code' : 'totp',
    });

    return result.success;
}

export async function verifyTwoFactorCode(input: {
    userId: string;
    context: TwoFactorContext;
    code: string;
    method: TwoFactorVerificationMethod;
}): Promise<TwoFactorOperationResult> {
    const normalizedCode = input.code.trim();
    if (!normalizedCode) {
        return { success: false, error: 'Invalid verification code.' };
    }

    if (input.context === 'vault_unlock' || input.context === 'disable_2fa' || input.context === 'critical_action') {
        const result = await verifyTwoFactorChallenge(input);
        return { success: result.success, error: result.error };
    }

    if (input.method === 'backup_code') {
        if (input.context === 'disable_2fa') {
            return { success: false, error: 'Backup codes cannot be used for this action.' };
        }

        return {
            success: await verifyAndConsumeBackupCode(input.userId, normalizedCode),
        };
    }

    const secret = await getTOTPSecret(input.userId);
    if (!secret) {
        return { success: false, error: '2FA is not enabled.' };
    }

    const isValid = verifyTOTPCode(secret, normalizedCode);

    if (isValid) {
        // Update last verified timestamp
        await supabase
            .from('user_2fa')
            .update({ last_verified_at: new Date().toISOString() })
            .eq('user_id', input.userId);
    }

    return { success: isValid };
}

export async function verifyTwoFactorChallenge(input: {
    context: TwoFactorContext;
    code: string;
    method: TwoFactorVerificationMethod;
}): Promise<TwoFactorOperationResult & { challengeId?: string }> {
    const normalizedCode = input.code.trim();
    if (!normalizedCode) {
        return { success: false, error: 'Invalid verification code.' };
    }

    try {
        const challenge = await invokeAuth2FA<{
            required?: boolean;
            challengeId?: string;
            error?: string;
        }>({
            action: 'create-challenge',
            context: input.context,
        });

        if (challenge.error) {
            return {
                success: false,
                error: challenge.error.message || 'Invalid verification code.',
                errorCode: challenge.error.code,
                retryAfterSeconds: challenge.error.retryAfterSeconds,
                lockedUntil: challenge.error.lockedUntil,
            };
        }

        if (challenge.data?.required === false) {
            return { success: true };
        }

        const challengeId = challenge.data?.challengeId;
        if (!challengeId) {
            return { success: false, error: 'Invalid verification code.' };
        }

        const verified = await invokeAuth2FA<{ success?: boolean; verified?: boolean; error?: string }>({
            action: 'verify-challenge',
            context: input.context,
            challengeId,
            code: normalizedCode,
            method: input.method,
        });

        if (verified.error || !verified.data?.success || !verified.data?.verified) {
            return {
                success: false,
                error: verified.data?.error || verified.error?.message || 'Invalid verification code.',
                errorCode: verified.error?.code,
                retryAfterSeconds: verified.error?.retryAfterSeconds,
                lockedUntil: verified.error?.lockedUntil,
            };
        }

        return { success: true, challengeId };
    } catch {
        return { success: false, error: 'Invalid verification code.' };
    }
}
