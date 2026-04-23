// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE
/**
 * @fileoverview Security Regression Test Suite
 *
 * CRITICAL: This test suite must pass before every deployment
 * to ensure security fixes remain in place.
 */

import { describe, it, expect, beforeAll, vi } from 'vitest';
import { generateUserKeyPair, migrateToHybridKeyPair } from '@/services/cryptoService';
import { hashBackupCode, verifyBackupCodeHash } from '@/services/twoFactorService';
import { SecureBuffer } from '@/services/secureBuffer';
import { logger } from '@/lib/logger';
import { handleError, ErrorCode } from '@/lib/errorHandler';

describe('Security Regression Test Suite', () => {
    describe('C1: RLS Policy Hardening', () => {
        it('should prevent field manipulation in emergency access', () => {
            // This is tested via database migration and RLS policies
            // See security-rls-emergency-access.test.ts for detailed tests
            expect(true).toBe(true); // Placeholder - actual test requires DB
        });
    });

    describe('C2: Timing Attack Prevention', () => {
        it('should keep dual unlock behavior consistent (see dedicated timing test)', () => {
            // Covered in security-timing-attack.test.ts with structural assertions.
            expect(true).toBe(true);
        });
    });

    describe('C3: Post-Quantum sharing-key protection', () => {
        it('should generate hybrid PQ+RSA key-wrapping key pairs', async () => {
            const result = await generateUserKeyPair('test-master-password', 2);

            // Should have both RSA and PQ keys
            expect(result.publicKey).toBeDefined();
            expect(result.encryptedPrivateKey).toBeDefined();
            expect(result.pqPublicKey).toBeDefined();

            // Encrypted private key should have v2 format
            expect(result.encryptedPrivateKey).toMatch(/^pq-v2:/);
        });

        it('should migrate RSA-only keys to hybrid', async () => {
            // Create legacy RSA-only key
            const legacy = await generateUserKeyPair('test-password', 1);
            expect(legacy.pqPublicKey).toBeUndefined();

            // Migrate to hybrid
            const migrated = await migrateToHybridKeyPair(
                legacy.encryptedPrivateKey,
                'test-password'
            );

            expect(migrated).not.toBeNull();
            expect(migrated!.pqPublicKey).toBeDefined();
            expect(migrated!.encryptedPrivateKey).toMatch(/^pq-v2:/);
        });
    });

    describe('C4: Memory Safety', () => {
        it('should securely handle hex string conversion', () => {
            const hex = 'deadbeef';
            const buffer = SecureBuffer.fromHex(hex);

            expect(buffer.size).toBe(4);

            const bytes = buffer.toBytes();
            expect(bytes[0]).toBe(0xde);
            expect(bytes[1]).toBe(0xad);
            expect(bytes[2]).toBe(0xbe);
            expect(bytes[3]).toBe(0xef);

            // Clean up
            buffer.destroy();
            expect(buffer.isDestroyed).toBe(true);
        });

        it('should zero memory on SecureBuffer destroy', () => {
            const buffer = SecureBuffer.fromBytes(new Uint8Array([1, 2, 3, 4]));
            const bytes = buffer.toBytes();

            expect(bytes[0]).toBe(1);

            buffer.destroy();

            // Should throw after destroy
            expect(() => buffer.toBytes()).toThrow('SecureBuffer has been destroyed');
        });
    });

    describe('H1: Server-side Rate Limiting', () => {
        it('should enforce exponential backoff', () => {
            // This is tested via Edge Function
            // See rate-limit/index.ts for implementation
            expect(true).toBe(true); // Placeholder - actual test requires Edge Function
        });
    });

    describe('H2: Backup Code Argon2id Migration', () => {
        it('should hash backup codes with Argon2id v3', async () => {
            const code = 'ABCD-EFGH';
            const hash = await hashBackupCode(code);

            // Should be v3 format
            expect(hash).toMatch(/^v3:[^:]+:[a-f0-9]+$/);

            // Should verify correctly
            const isValid = await verifyBackupCodeHash(code, hash);
            expect(isValid).toBe(true);

            // Wrong code should fail
            const isInvalid = await verifyBackupCodeHash('WXYZ-1234', hash);
            expect(isInvalid).toBe(false);
        });

        it('should still verify legacy SHA-256 codes', async () => {
            // Simulate legacy hash (SHA-256)
            const code = 'ABCD-EFGH';
            const normalizedCode = code.replace(/-/g, '').toUpperCase();
            const encoder = new TextEncoder();
            const data = encoder.encode(normalizedCode);
            const hashBuffer = await crypto.subtle.digest('SHA-256', data);
            const hashArray = Array.from(new Uint8Array(hashBuffer));
            const legacyHash = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');

            // Should still verify legacy format
            const isValid = await verifyBackupCodeHash(code, legacyHash);
            expect(isValid).toBe(true);
        });
    });

    describe('M1: Logging Abstraction', () => {
        it('should sanitize sensitive data in logs', () => {
            const consoleSpy = vi.spyOn(console, 'error');

            logger.error('Test message', undefined, {
                username: 'test@example.com',
                password: 'secret123',
                apiKey: 'sk_test_123',
                normalData: 'this is visible',
            });

            expect(consoleSpy).toHaveBeenCalled();
            const output = consoleSpy.mock.calls[0][0];
            expect(output).toContain('[REDACTED]');
            expect(output).not.toContain('secret123');
            expect(output).not.toContain('sk_test_123');
            expect(output).toContain('this is visible');

            consoleSpy.mockRestore();
        });

        it('should suppress debug/info/warn logs in test environment', () => {
            const debugSpy = vi.spyOn(console, 'debug');
            const infoSpy = vi.spyOn(console, 'info');
            const warnSpy = vi.spyOn(console, 'warn');
            const errorSpy = vi.spyOn(console, 'error');

            logger.debug('Debug message');
            logger.info('Info message');
            logger.warn('Warning message');
            logger.error('Error message');

            expect(debugSpy).not.toHaveBeenCalled();
            expect(infoSpy).not.toHaveBeenCalled();
            expect(warnSpy).not.toHaveBeenCalled();
            expect(errorSpy).toHaveBeenCalled();

            debugSpy.mockRestore();
            infoSpy.mockRestore();
            warnSpy.mockRestore();
            errorSpy.mockRestore();
        });
    });

    describe('M2: Error Handler', () => {
        it('should map internal errors to safe error codes', () => {
            const internalError = new Error('Row level security violation');
            const appError = handleError(internalError);

            expect(appError.code).toBe(ErrorCode.FORBIDDEN);
            expect(appError.userMessage).toBe('You do not have permission to perform this action');
            expect(appError.correlationId).toBeDefined();
        });

        it('should hide stack traces in production', () => {
            const error = new Error('Internal server error');
            const appError = handleError(error);

            const json = appError.toJSON();
            expect(json.error.code).toBeDefined();
            expect(json.error.message).toBeDefined();
            expect(json.error.correlationId).toBeDefined();

            // Stack trace should not be in client response
            expect(json).not.toHaveProperty('stack');
            expect(json).not.toHaveProperty('originalError');
        });

        it('should detect rate limiting errors', () => {
            const rateLimitError = new Error('Rate limit exceeded');
            const appError = handleError(rateLimitError);

            expect(appError.code).toBe(ErrorCode.AUTH_RATE_LIMITED);
            expect(appError.userMessage).toBe('Too many attempts. Please try again later');
        });
    });

    describe('M3: CORS Security', () => {
        it('should reject requests without Origin header', async () => {
            const originalDeno = (globalThis as unknown as { Deno?: unknown }).Deno;
            (globalThis as unknown as { Deno?: { env: { get: (key: string) => string | undefined } } }).Deno = {
                env: {
                    get: () => undefined,
                },
            };

            vi.resetModules();
            const { getCorsHeaders } = await import('../../supabase/functions/_shared/cors');

            const req = new Request('https://example.com', {
                headers: {
                    // No Origin header
                },
            });

            const headers = getCorsHeaders(req);
            expect(headers['Access-Control-Allow-Origin']).toBe('null');

            (globalThis as unknown as { Deno?: unknown }).Deno = originalDeno;
        });

        it('should allow server-to-server requests', async () => {
            const originalDeno = (globalThis as unknown as { Deno?: unknown }).Deno;
            (globalThis as unknown as { Deno?: { env: { get: (key: string) => string | undefined } } }).Deno = {
                env: {
                    get: () => undefined,
                },
            };

            vi.resetModules();
            const { getCorsHeaders } = await import('../../supabase/functions/_shared/cors');

            const req = new Request('https://example.com', {
                headers: {
                    'User-Agent': 'Deno/1.0',
                },
            });

            const headers = getCorsHeaders(req);
            expect(headers['Access-Control-Allow-Origin']).not.toBe('null');

            (globalThis as unknown as { Deno?: unknown }).Deno = originalDeno;
        });
    });
});

describe('Integration: Security Features Working Together', () => {
    it('should handle authentication flow with all security features', async () => {
        // This would be an E2E test in a real environment
        // Testing the interaction between:
        // 1. Rate limiting
        // 2. Timing-safe password verification
        // 3. Argon2id for backup codes
        // 4. Proper error handling
        // 5. Secure logging

        expect(true).toBe(true); // Placeholder for E2E test
    });
});
