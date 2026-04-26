// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 — see LICENSE
/**
 * @fileoverview TOTP (Time-based One-Time Password) Service
 * 
 * Implements RFC 6238 TOTP generation for 2FA codes.
 * Uses the otpauth library for reliable OTP handling.
 */

import * as OTPAuth from 'otpauth';

export const SUPPORTED_TOTP_ALGORITHMS = ['SHA1', 'SHA256', 'SHA512'] as const;
export const SUPPORTED_TOTP_DIGITS = [6, 8] as const;
export const MIN_TOTP_PERIOD = 15;
export const MAX_TOTP_PERIOD = 120;

export type TOTPAlgorithm = typeof SUPPORTED_TOTP_ALGORITHMS[number];
export type TOTPDigits = typeof SUPPORTED_TOTP_DIGITS[number];

/**
 * Normalizes user-provided TOTP secret input.
 *
 * Removes all whitespace and converts to uppercase.
 *
 * @param secret - Raw secret input from user or scanner
 * @returns Normalized base32-like secret string
 */
export function normalizeTOTPSecretInput(secret: string): string {
    return secret.replace(/\s/g, '').toUpperCase();
}

export interface TOTPConfig {
    algorithm?: TOTPAlgorithm;
    digits?: TOTPDigits;
    period?: number;
}

export function normalizeTOTPAlgorithm(value: string | null | undefined): TOTPAlgorithm | null {
    const normalized = (value || 'SHA1').replace(/[-_\s]/g, '').toUpperCase();
    return (SUPPORTED_TOTP_ALGORITHMS as readonly string[]).includes(normalized)
        ? normalized as TOTPAlgorithm
        : null;
}

export function normalizeTOTPDigits(value: string | number | null | undefined): TOTPDigits | null {
    const parsed = typeof value === 'number' ? value : parseInt(value || '6', 10);
    return (SUPPORTED_TOTP_DIGITS as readonly number[]).includes(parsed)
        ? parsed as TOTPDigits
        : null;
}

export function normalizeTOTPPeriod(value: string | number | null | undefined): number | null {
    const parsed = typeof value === 'number' ? value : parseInt(value || '30', 10);
    if (!Number.isInteger(parsed) || parsed < MIN_TOTP_PERIOD || parsed > MAX_TOTP_PERIOD) {
        return null;
    }
    return parsed;
}

export function normalizeTOTPConfig(config: TOTPConfig = {}): Required<TOTPConfig> | null {
    const algorithm = normalizeTOTPAlgorithm(config.algorithm);
    const digits = normalizeTOTPDigits(config.digits);
    const period = normalizeTOTPPeriod(config.period);

    if (!algorithm || !digits || !period) {
        return null;
    }

    return { algorithm, digits, period };
}

/**
 * Generates a TOTP code from a secret
 * 
 * @param secret - Base32 encoded TOTP secret
 * @returns Current TOTP code
 */
export function generateTOTP(secret: string, config: TOTPConfig = {}): string {
    try {
        const normalizedConfig = normalizeTOTPConfig(config);
        if (!normalizedConfig) {
            return '------';
        }

        const totp = new OTPAuth.TOTP({
            issuer: 'Singra Vault',
            algorithm: normalizedConfig.algorithm,
            digits: normalizedConfig.digits,
            period: normalizedConfig.period,
            secret: OTPAuth.Secret.fromBase32(normalizeTOTPSecretInput(secret)),
        });

        return totp.generate();
    } catch {
        console.error('TOTP generation error: invalid or unsupported secret');
        return '------';
    }
}

/**
 * Gets the remaining seconds until the next TOTP period
 * 
 * @returns Seconds remaining (0-29)
 */
export function getTimeRemaining(period = 30): number {
    const normalizedPeriod = normalizeTOTPPeriod(period) ?? 30;
    const now = Math.floor(Date.now() / 1000);
    return normalizedPeriod - (now % normalizedPeriod);
}

/**
 * Validates a TOTP secret format
 * 
 * @param secret - Secret to validate
 * @returns true if the secret is valid Base32
 */
export function isValidTOTPSecret(secret: string): boolean {
    const cleanSecret = normalizeTOTPSecretInput(secret);

    // Check if it's valid Base32 (A-Z and 2-7)
    const base32Regex = /^[A-Z2-7]+=*$/;

    if (!base32Regex.test(cleanSecret)) {
        return false;
    }

    // Should be at least 16 characters for security
    return cleanSecret.length >= 16;
}

/**
 * Validates a TOTP secret with detailed error messages
 * 
 * @param secret - Secret to validate
 * @returns Validation result with error message if invalid
 */
export function validateTOTPSecret(secret: string): { valid: boolean; error?: string } {
    const cleaned = normalizeTOTPSecretInput(secret);

    // Check length
    if (cleaned.length < 16) {
        return { valid: false, error: 'Secret zu kurz (mindestens 16 Zeichen)' };
    }

    // Check Base32 format (A-Z, 2-7, optional padding =)
    if (!/^[A-Z2-7]+=*$/.test(cleaned)) {
        return { valid: false, error: 'Ungültiges Format (nur A-Z und 2-7 erlaubt)' };
    }

    return { valid: true };
}

export function validateTOTPConfig(config: TOTPConfig): { valid: boolean; error?: string } {
    if (!normalizeTOTPAlgorithm(config.algorithm)) {
        return { valid: false, error: 'Unsupported TOTP algorithm' };
    }

    if (!normalizeTOTPDigits(config.digits)) {
        return { valid: false, error: 'Unsupported TOTP digit count' };
    }

    if (!normalizeTOTPPeriod(config.period)) {
        return { valid: false, error: `Unsupported TOTP period (${MIN_TOTP_PERIOD}-${MAX_TOTP_PERIOD} seconds)` };
    }

    return { valid: true };
}

/**
 * Parses an otpauth:// URI and extracts TOTP information
 * 
 * @param uri - otpauth:// URI from QR code
 * @returns Parsed data with secret, issuer, and label, or null if invalid
 */
export function parseOTPAuthUri(uri: string): {
    secret: string;
    issuer?: string;
    label?: string;
} | null {
    try {
        const url = new URL(uri);

        if (url.protocol !== 'otpauth:' || url.host !== 'totp') {
            return null;
        }

        const secret = url.searchParams.get('secret');
        if (!secret) return null;

        const issuer = url.searchParams.get('issuer') || undefined;
        const label = decodeURIComponent(url.pathname.slice(1)) || undefined;

        return { secret: secret.toUpperCase(), issuer, label };
    } catch {
        return null;
    }
}

/**
 * Formats a TOTP code for display (adds space in middle)
 * 
 * @param code - 6-digit code
 * @returns Formatted code like "123 456"
 */
export function formatTOTPCode(code: string): string {
    if (code.length !== 6) return code;
    return `${code.slice(0, 3)} ${code.slice(3)}`;
}

export function getTOTPDataValidationError(data: Pick<TOTPData, 'secret' | 'algorithm' | 'digits' | 'period'>): string | null {
    const secretValidation = validateTOTPSecret(data.secret);
    if (!secretValidation.valid) {
        return secretValidation.error || 'Invalid TOTP secret';
    }

    const configValidation = validateTOTPConfig({
        algorithm: data.algorithm,
        digits: data.digits,
        period: data.period,
    });

    return configValidation.valid ? null : configValidation.error || 'Unsupported TOTP parameters';
}

/**
 * Parses a TOTP URI (otpauth://totp/...) and extracts the secret
 * 
 * @param uri - TOTP URI from QR code
 * @returns Parsed TOTP data or null if invalid
 */
export function parseTOTPUri(uri: string): TOTPData | null {
    try {
        const url = new URL(uri);

        if (url.protocol !== 'otpauth:' || url.host !== 'totp') {
            return null;
        }

        const secret = url.searchParams.get('secret');
        if (!secret) return null;

        // Extract label (issuer:account or just account)
        const label = decodeURIComponent(url.pathname.slice(1));
        const issuer = url.searchParams.get('issuer') || '';

        const algorithm = normalizeTOTPAlgorithm(url.searchParams.get('algorithm'));
        const digits = normalizeTOTPDigits(url.searchParams.get('digits'));
        const period = normalizeTOTPPeriod(url.searchParams.get('period'));
        if (!algorithm || !digits || !period) {
            return null;
        }

        const data: TOTPData = {
            secret: normalizeTOTPSecretInput(secret),
            label,
            issuer,
            algorithm,
            digits,
            period,
        };

        return getTOTPDataValidationError(data) ? null : data;
    } catch {
        return null;
    }
}

/**
 * Generates a TOTP URI for QR code display
 * 
 * @param data - TOTP configuration data
 * @returns otpauth:// URI
 */
export function generateTOTPUri(data: TOTPData): string {
    const totp = new OTPAuth.TOTP({
        issuer: data.issuer,
        label: data.label,
        algorithm: data.algorithm || 'SHA1',
        digits: data.digits || 6,
        period: data.period || 30,
        secret: OTPAuth.Secret.fromBase32(data.secret),
    });

    return totp.toString();
}

// ============ Type Definitions ============

export interface TOTPData {
    secret: string;
    label: string;
    issuer: string;
    algorithm?: TOTPAlgorithm;
    digits?: TOTPDigits;
    period?: number;
}
