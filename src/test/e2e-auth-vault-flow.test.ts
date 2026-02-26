// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 — see LICENSE
/**
 * @fileoverview E2E Tests — Auth & Vault Flow
 *
 * Tests the complete user journey from key derivation through vault
 * setup, unlock, lock, and KDF migration. Uses the real crypto pipeline
 * with a PBKDF2 shim for Argon2id. Supabase calls are mocked.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

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

const mockProfileData: Record<string, unknown> = {};
const mockSupabase = {
    from: vi.fn().mockReturnValue({
        select: vi.fn().mockReturnThis(),
        insert: vi.fn().mockReturnThis(),
        update: vi.fn().mockReturnThis(),
        delete: vi.fn().mockReturnThis(),
        upsert: vi.fn().mockReturnThis(),
        eq: vi.fn().mockReturnThis(),
        single: vi.fn().mockResolvedValue({ data: mockProfileData, error: null }),
        maybeSingle: vi.fn().mockResolvedValue({ data: mockProfileData, error: null }),
    }),
    rpc: vi.fn().mockResolvedValue({ data: null, error: null }),
    auth: {
        getUser: vi.fn().mockResolvedValue({ data: { user: { id: "test-user-1" } }, error: null }),
        getSession: vi.fn().mockResolvedValue({ data: { session: { access_token: "test-token" } }, error: null }),
        signUp: vi.fn(),
        signInWithPassword: vi.fn(),
        signOut: vi.fn().mockResolvedValue({ error: null }),
    },
};

vi.mock("@/integrations/supabase/client", () => ({
    supabase: mockSupabase,
}));

// ============ Imports (after mocks) ============

import {
    generateSalt,
    deriveKey,
    deriveRawKey,
    deriveRawKeySecure,
    encrypt,
    decrypt,
    createVerificationHash,
    verifyKey,
    encryptVaultItem,
    decryptVaultItem,
    attemptKdfUpgrade,
    CURRENT_KDF_VERSION,
    type VaultItemData,
} from "@/services/cryptoService";

import {
    recordFailedAttempt,
    resetUnlockAttempts,
    getUnlockCooldown,
    getFailedAttemptCount,
} from "@/services/rateLimiterService";

// ============ Tests ============

describe("E2E: Auth & Vault Flow", () => {
    const MASTER_PASSWORD = "MyStr0ng!P@ssw0rd#2026";
    const WRONG_PASSWORD = "WrongPassword123!";
    let salt: string;
    let key: CryptoKey;
    let verifier: string;

    beforeEach(() => {
        localStorage.clear();
        resetUnlockAttempts();
    });

    afterEach(() => {
        resetUnlockAttempts();
    });

    // ========== Master Password Setup ==========

    describe("Master Password Setup", () => {
        it("should generate a valid base64 salt", () => {
            salt = generateSalt();
            expect(salt).toBeTruthy();
            expect(typeof salt).toBe("string");
            // Base64 encoded 16 bytes = ~24 chars
            expect(salt.length).toBeGreaterThan(10);
        });

        it("should derive a CryptoKey from master password + salt", async () => {
            salt = generateSalt();
            key = await deriveKey(MASTER_PASSWORD, salt, CURRENT_KDF_VERSION);
            expect(key).toBeDefined();
            expect(key.type).toBe("secret");
            expect(key.algorithm).toHaveProperty("name", "AES-GCM");
        });

        it("should derive raw key bytes as Uint8Array", async () => {
            salt = generateSalt();
            const rawKey = await deriveRawKey(MASTER_PASSWORD, salt, CURRENT_KDF_VERSION);
            expect(rawKey).toBeInstanceOf(Uint8Array);
            expect(rawKey.length).toBe(32);
            // Not all zeros
            expect(rawKey.some((b) => b !== 0)).toBe(true);
            rawKey.fill(0); // cleanup
        });

        it("should derive raw key as SecureBuffer", async () => {
            salt = generateSalt();
            const secureBuf = await deriveRawKeySecure(MASTER_PASSWORD, salt, CURRENT_KDF_VERSION);
            expect(secureBuf.size).toBe(32);
            expect(secureBuf.isDestroyed).toBe(false);
            secureBuf.destroy();
            expect(secureBuf.isDestroyed).toBe(true);
        });

        it("should create a verification hash from derived key", async () => {
            salt = generateSalt();
            key = await deriveKey(MASTER_PASSWORD, salt, CURRENT_KDF_VERSION);
            verifier = await createVerificationHash(key);
            expect(verifier).toBeTruthy();
            expect(typeof verifier).toBe("string");
            // Verifier is a base64-encoded encrypted sentinel
            expect(verifier.length).toBeGreaterThan(20);
        });

        it("should store salt + verifier + kdfVersion as a complete profile", async () => {
            salt = generateSalt();
            key = await deriveKey(MASTER_PASSWORD, salt, CURRENT_KDF_VERSION);
            verifier = await createVerificationHash(key);

            // Simulate saving to profile
            const profile = {
                encryption_salt: salt,
                master_password_verifier: verifier,
                kdf_version: CURRENT_KDF_VERSION,
            };

            expect(profile.encryption_salt).toBe(salt);
            expect(profile.master_password_verifier).toBe(verifier);
            expect(profile.kdf_version).toBe(CURRENT_KDF_VERSION);
        });
    });

    // ========== Vault Unlock ==========

    describe("Vault Unlock", () => {
        beforeEach(async () => {
            salt = generateSalt();
            key = await deriveKey(MASTER_PASSWORD, salt, CURRENT_KDF_VERSION);
            verifier = await createVerificationHash(key);
        });

        it("should verify correct master password", async () => {
            const testKey = await deriveKey(MASTER_PASSWORD, salt, CURRENT_KDF_VERSION);
            const result = await verifyKey(verifier, testKey);
            expect(result).toBe(true);
        });

        it("should reject wrong master password", async () => {
            const wrongKey = await deriveKey(WRONG_PASSWORD, salt, CURRENT_KDF_VERSION);
            const result = await verifyKey(verifier, wrongKey);
            expect(result).toBe(false);
        });

        it("should verify repeatedly with same key (100x)", async () => {
            for (let i = 0; i < 100; i++) {
                const result = await verifyKey(verifier, key);
                expect(result).toBe(true);
            }
        });
    });

    // ========== Rate Limiter ==========

    describe("Rate Limiter Integration", () => {
        beforeEach(() => {
            vi.useFakeTimers();
            resetUnlockAttempts();
        });

        afterEach(() => {
            vi.useRealTimers();
            resetUnlockAttempts();
        });

        it("should allow 3 failed attempts without lockout (grace period)", () => {
            recordFailedAttempt();
            recordFailedAttempt();
            recordFailedAttempt();
            expect(getUnlockCooldown()).toBeNull();
            expect(getFailedAttemptCount()).toBe(3);
        });

        it("should lock out after 4th failed attempt", () => {
            recordFailedAttempt();
            recordFailedAttempt();
            recordFailedAttempt();
            recordFailedAttempt();
            const cooldown = getUnlockCooldown();
            expect(cooldown).not.toBeNull();
            expect(cooldown!).toBeGreaterThan(0);
            expect(cooldown!).toBeLessThanOrEqual(5000);
        });

        it("should escalate lockout exponentially", () => {
            // 4 failures = first lockout (5s)
            for (let i = 0; i < 4; i++) recordFailedAttempt();
            const first = getUnlockCooldown();

            // Advance past lockout
            vi.advanceTimersByTime(6000);

            // 5th failure = longer lockout (10s)
            recordFailedAttempt();
            const second = getUnlockCooldown();
            expect(second).not.toBeNull();
            expect(second!).toBeGreaterThan(first!);
        });

        it("should reset after successful unlock", () => {
            recordFailedAttempt();
            recordFailedAttempt();
            recordFailedAttempt();
            recordFailedAttempt();
            expect(getUnlockCooldown()).not.toBeNull();

            resetUnlockAttempts();
            expect(getUnlockCooldown()).toBeNull();
            expect(getFailedAttemptCount()).toBe(0);
        });
    });

    // ========== Lock + Re-Unlock ==========

    describe("Lock and Re-Unlock", () => {
        it("should re-derive same key from same password + salt", async () => {
            salt = generateSalt();
            const key1 = await deriveKey(MASTER_PASSWORD, salt, CURRENT_KDF_VERSION);
            const verifier1 = await createVerificationHash(key1);

            // Simulate lock (clear key reference)
            // Re-derive from same credentials
            const key2 = await deriveKey(MASTER_PASSWORD, salt, CURRENT_KDF_VERSION);
            const verified = await verifyKey(verifier1, key2);
            expect(verified).toBe(true);
        });

        it("should produce different keys from different salts", async () => {
            const salt1 = generateSalt();
            const salt2 = generateSalt();
            const key1 = await deriveKey(MASTER_PASSWORD, salt1, CURRENT_KDF_VERSION);
            const key2 = await deriveKey(MASTER_PASSWORD, salt2, CURRENT_KDF_VERSION);

            const verifier1 = await createVerificationHash(key1);
            // Key from salt2 should NOT verify salt1's verifier
            const crossVerify = await verifyKey(verifier1, key2);
            expect(crossVerify).toBe(false);
        });
    });

    // ========== KDF Migration ==========

    describe("KDF Migration", () => {
        it("should upgrade from v1 to v2", async () => {
            salt = generateSalt();
            // Start with v1
            const keyV1 = await deriveKey(MASTER_PASSWORD, salt, 1);
            const verifierV1 = await createVerificationHash(keyV1);

            // Attempt upgrade
            const result = await attemptKdfUpgrade(MASTER_PASSWORD, salt, 1);
            expect(result.upgraded).toBe(true);
            expect(result.activeVersion).toBe(CURRENT_KDF_VERSION);
            expect(result.newKey).toBeDefined();
            expect(result.newVerifier).toBeTruthy();
        });

        it("should not upgrade if already on current version", async () => {
            salt = generateSalt();
            const result = await attemptKdfUpgrade(MASTER_PASSWORD, salt, CURRENT_KDF_VERSION);
            expect(result.upgraded).toBe(false);
            expect(result.activeVersion).toBe(CURRENT_KDF_VERSION);
        });

        it("should produce a valid verifier after upgrade", async () => {
            salt = generateSalt();
            const result = await attemptKdfUpgrade(MASTER_PASSWORD, salt, 1);
            expect(result.upgraded).toBe(true);

            // New verifier should work with new key
            const verified = await verifyKey(result.newVerifier!, result.newKey!);
            expect(verified).toBe(true);

            // Re-derive v2 key from scratch — should also verify
            const freshV2Key = await deriveKey(MASTER_PASSWORD, salt, CURRENT_KDF_VERSION);
            const freshVerified = await verifyKey(result.newVerifier!, freshV2Key);
            expect(freshVerified).toBe(true);
        });
    });
});
