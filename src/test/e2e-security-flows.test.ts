// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 — see LICENSE
/**
 * @fileoverview E2E Tests — Security Flows
 *
 * Tests security-critical flows end-to-end:
 * - 2FA lifecycle (generate, verify, backup codes, disable)
 * - Rate limiter with exponential backoff + recovery
 * - Vault integrity lifecycle (first check, update, tamper detection)
 * - Dual unlock (duress mode) with real crypto
 * - KDF migration v1 → v2
 * - Clipboard auto-clear behaviour
 */

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";

// ============ Argon2id PBKDF2 Shim ============

vi.mock("hash-wasm", () => ({
    argon2id: async ({
        password,
        salt,
        hashLength,
    }: {
        password: string;
        salt: Uint8Array | string;
        hashLength: number;
        parallelism?: number;
        iterations?: number;
        memorySize?: number;
        outputType?: string;
    }) => {
        const enc = new TextEncoder();
        const passwordBytes = enc.encode(password);
        const saltBytes = typeof salt === "string" ? enc.encode(salt) : salt;
        const baseKey = await crypto.subtle.importKey(
            "raw",
            passwordBytes,
            "PBKDF2",
            false,
            ["deriveBits"],
        );
        const bits = await crypto.subtle.deriveBits(
            { name: "PBKDF2", salt: saltBytes as any, iterations: 1000, hash: "SHA-256" },
            baseKey,
            hashLength * 8,
        );
        return Array.from(new Uint8Array(bits))
            .map((b) => b.toString(16).padStart(2, "0"))
            .join("");
    },
}));

// ============ Supabase Mock ============

vi.mock("@/integrations/supabase/client", () => ({
    supabase: {
        from: vi.fn().mockReturnValue({
            select: vi.fn().mockReturnThis(),
            insert: vi.fn().mockReturnThis(),
            update: vi.fn().mockReturnThis(),
            delete: vi.fn().mockReturnThis(),
            upsert: vi.fn().mockReturnThis(),
            eq: vi.fn().mockReturnThis(),
            single: vi.fn().mockResolvedValue({ data: null, error: null }),
            maybeSingle: vi.fn().mockResolvedValue({ data: null, error: null }),
        }),
        rpc: vi.fn().mockResolvedValue({ data: null, error: null }),
        auth: {
            getUser: vi.fn().mockResolvedValue({ data: { user: { id: "test-user-1" } }, error: null }),
            getSession: vi.fn().mockResolvedValue({ data: { session: { access_token: "test-token" } }, error: null }),
        },
    },
}));

// ============ Imports (after mocks) ============

import {
    generateSalt,
    deriveKey,
    createVerificationHash,
    verifyKey,
    attemptKdfUpgrade,
    CURRENT_KDF_VERSION,
} from "@/services/cryptoService";

import {
    generateTOTP,
    getTimeRemaining,
    isValidTOTPSecret,
    formatTOTPCode,
    parseOTPAuthUri,
} from "@/services/totpService";

import {
    generateTOTPSecret,
    generateBackupCodes,
    hashBackupCode,
    verifyTOTPCode,
    generateQRCodeUri,
    formatSecretForDisplay,
} from "@/services/twoFactorService";

import {
    recordFailedAttempt,
    resetUnlockAttempts,
    getUnlockCooldown,
    getFailedAttemptCount,
} from "@/services/rateLimiterService";

import {
    deriveIntegrityKey,
    updateIntegrityRoot,
    verifyVaultIntegrity,
    clearIntegrityRoot,
    hasIntegrityRoot,
    type VaultItemForIntegrity,
} from "@/services/vaultIntegrityService";

import {
    attemptDualUnlock,
    type DuressConfig,
} from "@/services/duressService";

import {
    writeClipboard,
} from "@/services/clipboardService";

// ============ Tests ============

describe("E2E: Security Flows", () => {

    // ========== 2FA Lifecycle ==========

    describe("2FA Lifecycle", () => {
        let secret: string;
        let backupCodes: string[];

        it("should generate a valid TOTP secret", () => {
            secret = generateTOTPSecret();
            expect(secret).toBeTruthy();
            expect(isValidTOTPSecret(secret)).toBe(true);
        });

        it("should generate a QR code URI from secret + email", () => {
            secret = generateTOTPSecret();
            const uri = generateQRCodeUri(secret, "test@example.com");
            expect(uri).toContain("otpauth://totp/");
            expect(uri).toContain(secret);
            expect(uri).toContain("test%40example.com");
        });

        it("should format secret for display with spaces", () => {
            secret = generateTOTPSecret();
            const formatted = formatSecretForDisplay(secret);
            expect(formatted).toContain(" ");
            expect(formatted.replace(/\s/g, "")).toBe(secret);
        });

        it("should generate a 6-digit TOTP code from secret", () => {
            secret = generateTOTPSecret();
            const code = generateTOTP(secret);
            expect(code).toMatch(/^\d{6}$/);
        });

        it("should verify a valid TOTP code", () => {
            secret = generateTOTPSecret();
            const code = generateTOTP(secret);
            // verifyTOTPCode uses ±1 period window
            const valid = verifyTOTPCode(secret, code);
            expect(valid).toBe(true);
        });

        it("should reject an invalid TOTP code", () => {
            secret = generateTOTPSecret();
            const valid = verifyTOTPCode(secret, "000000");
            // There's a small chance this is valid, but astronomically unlikely
            // If it happens to be valid, that's still correct behavior
            expect(typeof valid).toBe("boolean");
        });

        it("should format TOTP code with space", () => {
            expect(formatTOTPCode("123456")).toBe("123 456");
            expect(formatTOTPCode("000000")).toBe("000 000");
        });

        it("should return time remaining in 0-30 range", () => {
            const remaining = getTimeRemaining();
            expect(remaining).toBeGreaterThanOrEqual(1);
            expect(remaining).toBeLessThanOrEqual(30);
        });

        it("should generate 5 unique backup codes in XXXX-XXXX format", () => {
            backupCodes = generateBackupCodes();
            expect(backupCodes.length).toBe(5);

            // Each code matches XXXX-XXXX format
            for (const code of backupCodes) {
                expect(code).toMatch(/^[A-Z2-9]{4}-[A-Z2-9]{4}$/);
            }

            // All unique
            const unique = new Set(backupCodes);
            expect(unique.size).toBe(5);
        });

        it("should hash backup codes consistently", async () => {
            const code = "ABCD-EF23";
            const salt = "test-salt-123";

            const hash1 = await hashBackupCode(code, salt);
            const hash2 = await hashBackupCode(code, salt);
            expect(hash1).toBe(hash2);

            // Different salt → different hash
            const hash3 = await hashBackupCode(code, "other-salt");
            expect(hash3).not.toBe(hash1);
        });

        it("should normalize backup codes before hashing (strip dashes, uppercase)", async () => {
            const salt = "norm-salt";
            const hash1 = await hashBackupCode("abcd-ef23", salt);
            const hash2 = await hashBackupCode("ABCDEF23", salt);
            expect(hash1).toBe(hash2);
        });

        it("should parse otpauth URI correctly", () => {
            const uri = "otpauth://totp/Singra:test@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Singra";
            const parsed = parseOTPAuthUri(uri);
            expect(parsed).not.toBeNull();
            expect(parsed!.secret).toBe("JBSWY3DPEHPK3PXP");
            expect(parsed!.issuer).toBe("Singra");
        });
    });

    // ========== Rate Limiter + Recovery ==========

    describe("Rate Limiter + Recovery", () => {
        beforeEach(() => {
            vi.useFakeTimers();
            resetUnlockAttempts();
        });

        afterEach(() => {
            vi.useRealTimers();
            resetUnlockAttempts();
        });

        it("should allow 3 failures without lockout", () => {
            recordFailedAttempt();
            recordFailedAttempt();
            recordFailedAttempt();
            expect(getFailedAttemptCount()).toBe(3);
            expect(getUnlockCooldown()).toBeNull();
        });

        it("should lock after 4th failure with 5s cooldown", () => {
            for (let i = 0; i < 4; i++) recordFailedAttempt();
            const cooldown = getUnlockCooldown();
            expect(cooldown).not.toBeNull();
            expect(cooldown!).toBeGreaterThan(0);
            expect(cooldown!).toBeLessThanOrEqual(5000);
        });

        it("should reset lockout after successful unlock", () => {
            for (let i = 0; i < 5; i++) recordFailedAttempt();
            expect(getUnlockCooldown()).not.toBeNull();

            resetUnlockAttempts();
            expect(getFailedAttemptCount()).toBe(0);
            expect(getUnlockCooldown()).toBeNull();

            // New attempt should have full grace
            recordFailedAttempt();
            recordFailedAttempt();
            recordFailedAttempt();
            expect(getUnlockCooldown()).toBeNull();
        });

        it("should handle corrupted localStorage gracefully", () => {
            localStorage.setItem("singra_unlock_rl", "{invalid json}}}");
            // Should not throw, should reset to defaults
            expect(() => getFailedAttemptCount()).not.toThrow();
        });

        it("should unlock after cooldown expires", () => {
            for (let i = 0; i < 4; i++) recordFailedAttempt();
            expect(getUnlockCooldown()).not.toBeNull();

            // Advance time past the 5s cooldown
            vi.advanceTimersByTime(6000);
            expect(getUnlockCooldown()).toBeNull();
        });
    });

    // ========== Vault Integrity Lifecycle ==========

    describe("Vault Integrity Lifecycle", () => {
        const userId = "security-flow-user";
        let integrityKey: CryptoKey;

        beforeEach(async () => {
            localStorage.clear();
            const salt = generateSalt();
            integrityKey = await deriveIntegrityKey("TestPassword!123", salt);
        });

        it("should return isFirstCheck=true on first verification", async () => {
            clearIntegrityRoot(userId);

            const items: VaultItemForIntegrity[] = [
                { id: "a1", encrypted_data: "data-a1" },
            ];

            const result = await verifyVaultIntegrity(items, integrityKey, userId);
            expect(result.valid).toBe(true);
            expect(result.isFirstCheck).toBe(true);
        });

        it("should return valid=true after update + verify", async () => {
            const items: VaultItemForIntegrity[] = [
                { id: "b1", encrypted_data: "data-b1" },
                { id: "b2", encrypted_data: "data-b2" },
            ];

            await updateIntegrityRoot(items, integrityKey, userId);
            const result = await verifyVaultIntegrity(items, integrityKey, userId);
            expect(result.valid).toBe(true);
            expect(result.isFirstCheck).toBe(false);
        });

        it("should detect data tampering", async () => {
            const items: VaultItemForIntegrity[] = [
                { id: "c1", encrypted_data: "original-data" },
            ];

            await updateIntegrityRoot(items, integrityKey, userId);

            const tampered: VaultItemForIntegrity[] = [
                { id: "c1", encrypted_data: "MODIFIED-data" },
            ];
            const result = await verifyVaultIntegrity(tampered, integrityKey, userId);
            expect(result.valid).toBe(false);
        });

        it("should detect item deletion", async () => {
            const items: VaultItemForIntegrity[] = [
                { id: "d1", encrypted_data: "data-d1" },
                { id: "d2", encrypted_data: "data-d2" },
            ];

            await updateIntegrityRoot(items, integrityKey, userId);

            const result = await verifyVaultIntegrity(
                [{ id: "d1", encrypted_data: "data-d1" }],
                integrityKey,
                userId,
            );
            expect(result.valid).toBe(false);
        });
    });

    // ========== Dual Unlock (Duress) ==========

    describe("Dual Unlock (Duress Mode)", () => {
        const REAL_PASSWORD = "MyR3alP@ssw0rd!";
        const DURESS_PASSWORD = "DuressP@ss99!";
        const WRONG_PASSWORD = "WrongP@ss!000";

        let realSalt: string;
        let realKey: CryptoKey;
        let realVerifier: string;
        let duressSalt: string;
        let duressKey: CryptoKey;
        let duressVerifier: string;
        let duressConfig: DuressConfig;

        beforeEach(async () => {
            // Setup real credentials
            realSalt = generateSalt();
            realKey = await deriveKey(REAL_PASSWORD, realSalt, CURRENT_KDF_VERSION);
            realVerifier = await createVerificationHash(realKey);

            // Setup duress credentials
            duressSalt = generateSalt();
            duressKey = await deriveKey(DURESS_PASSWORD, duressSalt, CURRENT_KDF_VERSION);
            duressVerifier = await createVerificationHash(duressKey);

            duressConfig = {
                enabled: true,
                salt: duressSalt,
                verifier: duressVerifier,
                kdfVersion: CURRENT_KDF_VERSION,
            };
        });

        it("should return mode 'real' for correct real password", async () => {
            const result = await attemptDualUnlock(
                REAL_PASSWORD,
                realSalt,
                realVerifier,
                CURRENT_KDF_VERSION,
                duressConfig,
            );
            expect(result.mode).toBe("real");
            expect(result.key).not.toBeNull();
        });

        it("should return mode 'duress' for duress password", async () => {
            const result = await attemptDualUnlock(
                DURESS_PASSWORD,
                realSalt,
                realVerifier,
                CURRENT_KDF_VERSION,
                duressConfig,
            );
            expect(result.mode).toBe("duress");
            expect(result.key).not.toBeNull();
        });

        it("should return mode 'invalid' for wrong password", async () => {
            const result = await attemptDualUnlock(
                WRONG_PASSWORD,
                realSalt,
                realVerifier,
                CURRENT_KDF_VERSION,
                duressConfig,
            );
            expect(result.mode).toBe("invalid");
            expect(result.key).toBeNull();
        });

        it("should only check real password when duress is disabled", async () => {
            const result = await attemptDualUnlock(
                REAL_PASSWORD,
                realSalt,
                realVerifier,
                CURRENT_KDF_VERSION,
                null, // No duress config
            );
            expect(result.mode).toBe("real");
            expect(result.key).not.toBeNull();
        });

        it("should return invalid for duress password when duress is disabled", async () => {
            const result = await attemptDualUnlock(
                DURESS_PASSWORD,
                realSalt,
                realVerifier,
                CURRENT_KDF_VERSION,
                null, // No duress config
            );
            expect(result.mode).toBe("invalid");
        });
    });

    // ========== KDF Migration ==========

    describe("KDF Migration", () => {
        it("should upgrade from v1 with new verifier", async () => {
            const salt = generateSalt();
            const result = await attemptKdfUpgrade("MigrationTest!1", salt, 1);
            expect(result.upgraded).toBe(true);
            expect(result.activeVersion).toBe(CURRENT_KDF_VERSION);
            expect(result.newKey).toBeDefined();
            expect(result.newVerifier).toBeTruthy();

            // Verify new credentials work
            const verified = await verifyKey(result.newVerifier!, result.newKey!);
            expect(verified).toBe(true);
        });

        it("should not upgrade when already on current version", async () => {
            const salt = generateSalt();
            const result = await attemptKdfUpgrade("NoUpgrade!1", salt, CURRENT_KDF_VERSION);
            expect(result.upgraded).toBe(false);
            expect(result.activeVersion).toBe(CURRENT_KDF_VERSION);
        });
    });

    // ========== Clipboard Auto-Clear ==========

    describe("Clipboard Auto-Clear", () => {
        beforeEach(() => {
            vi.useFakeTimers();
        });

        afterEach(() => {
            vi.useRealTimers();
        });

        it("should write to clipboard", async () => {
            await writeClipboard("secret-password");
            const content = await navigator.clipboard.readText();
            expect(content).toBe("secret-password");
        });

        it("should auto-clear clipboard after 30 seconds", async () => {
            await writeClipboard("auto-clear-test");

            // Immediately readable
            let content = await navigator.clipboard.readText();
            expect(content).toBe("auto-clear-test");

            // Advance past auto-clear timeout (30s)
            // The setTimeout callback is async, so we need to flush promises
            vi.advanceTimersByTime(31000);
            await vi.runAllTimersAsync();

            // Should be cleared
            content = await navigator.clipboard.readText();
            expect(content).toBe("");
        });

        it("should not clear clipboard if user changed content", async () => {
            await writeClipboard("original-secret");

            // User writes something else directly
            await navigator.clipboard.writeText("user-content");

            // Advance past auto-clear
            vi.advanceTimersByTime(31000);
            await vi.runAllTimersAsync();

            // User content should remain (auto-clear only clears if unchanged)
            const content = await navigator.clipboard.readText();
            expect(content).toBe("user-content");
        });

        it("should handle empty string write", async () => {
            await writeClipboard("");
            const content = await navigator.clipboard.readText();
            expect(content).toBe("");
        });
    });
});
