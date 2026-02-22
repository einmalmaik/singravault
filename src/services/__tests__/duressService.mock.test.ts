// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 — see LICENSE
/**
 * @fileoverview Unit tests for duressService with mocked Supabase
 *
 * Phase 4 tests: all DB-dependent functions in duressService.ts
 * Supabase and cryptoService are mocked to test control flow, error handling,
 * and data transformations without hitting a real database.
 */

// ============ Hoisted Mocks ============

const mockSupabase = vi.hoisted(() => {
    /**
     * Builds a chainable Supabase query object.
     * Terminal methods (`single`, `maybeSingle`) resolve the chain.
     * Call `_setResult(data, error, count?)` on the returned object
     * to configure the resolved value.
     */
    const createChainable = () => {
        let _result: { data: unknown; error: unknown; count?: number } = {
            data: null,
            error: null,
        };

        const chain: Record<string, (...args: unknown[]) => unknown> = {};
        const methods = [
            "select",
            "insert",
            "update",
            "delete",
            "eq",
            "in",
            "single",
            "maybeSingle",
            "limit",
            "order",
            "upsert",
            "head",
        ];

        for (const method of methods) {
            chain[method] = vi.fn().mockImplementation((..._args: unknown[]) => {
                // Terminal methods return the promise-like result
                if (method === "single" || method === "maybeSingle") {
                    return Promise.resolve(_result);
                }
                return chain;
            });
        }

        // Allow the chain itself to behave as a thenable so that
        // `await supabase.from('x').delete().eq(...)` resolves.
        chain.then = (
            resolve: (v: unknown) => void,
            reject?: (e: unknown) => void
        ) => Promise.resolve(_result).then(resolve, reject);

        // Helper used in tests to preset the resolved value
        chain._setResult = (
            data: unknown,
            error: unknown,
            count?: number
        ) => {
            _result = { data, error, count };
            return chain;
        };

        return chain;
    };

    return {
        from: vi.fn().mockImplementation(() => createChainable()),
        rpc: vi.fn(),
        auth: { getUser: vi.fn() },
        functions: { invoke: vi.fn() },
        storage: { from: vi.fn() },
        _createChainable: createChainable,
    };
});

vi.mock("@/integrations/supabase/client", () => ({
    supabase: mockSupabase,
}));

// Mock cryptoService functions
const mockCryptoService = vi.hoisted(() => ({
    deriveKey: vi.fn(),
    createVerificationHash: vi.fn(),
    verifyKey: vi.fn(),
    generateSalt: vi.fn(),
}));

vi.mock("../cryptoService", () => ({
    deriveKey: mockCryptoService.deriveKey,
    createVerificationHash: mockCryptoService.createVerificationHash,
    verifyKey: mockCryptoService.verifyKey,
    generateSalt: mockCryptoService.generateSalt,
    CURRENT_KDF_VERSION: 2,
}));

// ============ Imports (after mocks) ============

import { describe, it, expect, vi, beforeEach } from "vitest";
import {
    getDuressConfig,
    setupDuressPassword,
    attemptDualUnlock,
    disableDuressMode,
    changeDuressPassword,
} from "../duressService";

// ============ Test Suite ============

describe("duressService (DB-dependent functions)", () => {
    beforeEach(() => {
        vi.clearAllMocks();

        // Default mock implementations
        mockCryptoService.generateSalt.mockReturnValue("mock-salt-123");
        mockCryptoService.deriveKey.mockResolvedValue("mock-crypto-key" as unknown);
        mockCryptoService.createVerificationHash.mockResolvedValue("mock-verifier-hash");
        mockCryptoService.verifyKey.mockResolvedValue(true);
    });

    // ============ getDuressConfig() ============

    describe("getDuressConfig()", () => {
        it("returns config when duress mode is enabled", async () => {
            const chain = mockSupabase._createChainable();
            chain._setResult({
                duress_salt: "salt123",
                duress_password_verifier: "verifier456",
                duress_kdf_version: 2,
            }, null);
            mockSupabase.from.mockReturnValue(chain);

            const result = await getDuressConfig("user-1");

            expect(mockSupabase.from).toHaveBeenCalledWith("profiles");
            expect(chain.select).toHaveBeenCalledWith(
                "duress_salt, duress_password_verifier, duress_kdf_version"
            );
            expect(chain.eq).toHaveBeenCalledWith("user_id", "user-1");
            expect(result).toEqual({
                enabled: true,
                salt: "salt123",
                verifier: "verifier456",
                kdfVersion: 2,
            });
        });

        it("returns config with enabled=false when salt/verifier are null", async () => {
            const chain = mockSupabase._createChainable();
            chain._setResult({
                duress_salt: null,
                duress_password_verifier: null,
                duress_kdf_version: null,
            }, null);
            mockSupabase.from.mockReturnValue(chain);

            const result = await getDuressConfig("user-1");

            expect(result).toEqual({
                enabled: false,
                salt: null,
                verifier: null,
                kdfVersion: 2, // defaults to CURRENT_KDF_VERSION
            });
        });

        it("returns null on DB error", async () => {
            const chain = mockSupabase._createChainable();
            chain._setResult(null, { message: "DB error" });
            mockSupabase.from.mockReturnValue(chain);

            const result = await getDuressConfig("user-1");

            expect(result).toBeNull();
        });

        it("returns null when no profile exists", async () => {
            const chain = mockSupabase._createChainable();
            chain._setResult(null, null); // both null
            mockSupabase.from.mockReturnValue(chain);

            const result = await getDuressConfig("user-1");

            expect(result).toBeNull();
        });
    });

    // ============ setupDuressPassword() ============

    describe("setupDuressPassword()", () => {
        it("creates duress password successfully", async () => {
            mockCryptoService.generateSalt.mockReturnValue("new-duress-salt");
            const mockKey = { type: "secret" };
            mockCryptoService.deriveKey.mockResolvedValue(mockKey);
            mockCryptoService.createVerificationHash.mockResolvedValue("duress-verifier");

            const updateChain = mockSupabase._createChainable();
            updateChain._setResult({ user_id: "user-1" }, null);
            mockSupabase.from.mockReturnValue(updateChain);

            const result = await setupDuressPassword(
                "user-1",
                "duress-pass-123",
                "real-pass-456",
                "real-salt"
            );

            expect(result.success).toBe(true);
            expect(result.error).toBeUndefined();

            // Verify salt generation
            expect(mockCryptoService.generateSalt).toHaveBeenCalled();

            // Verify key derivation with duress password
            expect(mockCryptoService.deriveKey).toHaveBeenCalledWith("duress-pass-123", "new-duress-salt", 2);

            // Verify verifier creation
            expect(mockCryptoService.createVerificationHash).toHaveBeenCalledWith(mockKey);

            // Verify DB update
            expect(mockSupabase.from).toHaveBeenCalledWith("profiles");
            expect(updateChain.update).toHaveBeenCalledWith({
                duress_salt: "new-duress-salt",
                duress_password_verifier: "duress-verifier",
                duress_kdf_version: 2,
            });
            expect(updateChain.eq).toHaveBeenCalledWith("user_id", "user-1");
        });

        it("rejects when duress password equals real password", async () => {
            const result = await setupDuressPassword(
                "user-1",
                "same-password",
                "same-password",
                "real-salt"
            );

            expect(result.success).toBe(false);
            expect(result.error).toBe("Duress password must be different from your master password");
            expect(mockCryptoService.generateSalt).not.toHaveBeenCalled();
        });

        it("rejects when duress password is too short", async () => {
            const result = await setupDuressPassword(
                "user-1",
                "short",
                "real-pass-456",
                "real-salt"
            );

            expect(result.success).toBe(false);
            expect(result.error).toBe("Duress password must be at least 8 characters");
            expect(mockCryptoService.generateSalt).not.toHaveBeenCalled();
        });

        it("returns error when DB update fails", async () => {
            mockCryptoService.generateSalt.mockReturnValue("new-duress-salt");
            mockCryptoService.deriveKey.mockResolvedValue({ type: "secret" });
            mockCryptoService.createVerificationHash.mockResolvedValue("duress-verifier");

            const updateChain = mockSupabase._createChainable();
            updateChain._setResult(null, { message: "DB connection lost" });
            mockSupabase.from.mockReturnValue(updateChain);

            const result = await setupDuressPassword(
                "user-1",
                "duress-pass-123",
                "real-pass-456",
                "real-salt"
            );

            expect(result.success).toBe(false);
            expect(result.error).toBe("Failed to save duress password: DB connection lost");
        });

        it("handles exception during key derivation", async () => {
            mockCryptoService.generateSalt.mockReturnValue("new-duress-salt");
            mockCryptoService.deriveKey.mockRejectedValue(new Error("Crypto API failed"));

            const result = await setupDuressPassword(
                "user-1",
                "duress-pass-123",
                "real-pass-456",
                "real-salt"
            );

            expect(result.success).toBe(false);
            expect(result.error).toBe("Failed to set up duress password");
        });
    });

    // ============ attemptDualUnlock() ============

    describe("attemptDualUnlock()", () => {
        it("unlocks with real password when verifier matches", async () => {
            const realKey = { type: "real-key" };
            mockCryptoService.deriveKey.mockResolvedValueOnce(realKey); // real key
            mockCryptoService.verifyKey.mockResolvedValueOnce(true); // real verifier matches

            const result = await attemptDualUnlock(
                "real-password",
                "real-salt",
                "real-verifier",
                2,
                null // no duress config
            );

            expect(result.mode).toBe("real");
            expect(result.key).toBe(realKey);
            expect(result.error).toBeUndefined();
        });

        it("unlocks with duress password when duress verifier matches", async () => {
            const realKey = { type: "real-key" };
            const duressKey = { type: "duress-key" };

            mockCryptoService.deriveKey
                .mockResolvedValueOnce(realKey) // real key
                .mockResolvedValueOnce(duressKey); // duress key

            mockCryptoService.verifyKey
                .mockResolvedValueOnce(false) // real verifier fails
                .mockResolvedValueOnce(true); // duress verifier matches

            const duressConfig = {
                enabled: true,
                salt: "duress-salt",
                verifier: "duress-verifier",
                kdfVersion: 2,
            };

            const result = await attemptDualUnlock(
                "duress-password",
                "real-salt",
                "real-verifier",
                2,
                duressConfig
            );

            expect(result.mode).toBe("duress");
            expect(result.key).toBe(duressKey);
            expect(result.error).toBeUndefined();

            // Verify both keys were derived in parallel
            expect(mockCryptoService.deriveKey).toHaveBeenCalledTimes(2);
            expect(mockCryptoService.deriveKey).toHaveBeenNthCalledWith(1, "duress-password", "real-salt", 2);
            expect(mockCryptoService.deriveKey).toHaveBeenNthCalledWith(2, "duress-password", "duress-salt", 2);
        });

        it("returns invalid when neither password matches", async () => {
            const realKey = { type: "real-key" };
            const duressKey = { type: "duress-key" };

            mockCryptoService.deriveKey
                .mockResolvedValueOnce(realKey)
                .mockResolvedValueOnce(duressKey);

            mockCryptoService.verifyKey
                .mockResolvedValueOnce(false) // real fails
                .mockResolvedValueOnce(false); // duress fails

            const duressConfig = {
                enabled: true,
                salt: "duress-salt",
                verifier: "duress-verifier",
                kdfVersion: 2,
            };

            const result = await attemptDualUnlock(
                "wrong-password",
                "real-salt",
                "real-verifier",
                2,
                duressConfig
            );

            expect(result.mode).toBe("invalid");
            expect(result.key).toBeNull();
            expect(result.error).toBe("Invalid password");
        });

        it("only checks real password when duress config is null", async () => {
            const realKey = { type: "real-key" };
            const dummyKey = { type: "dummy-key" };
            mockCryptoService.deriveKey
                .mockResolvedValueOnce(realKey)
                .mockResolvedValueOnce(dummyKey);
            mockCryptoService.verifyKey.mockResolvedValueOnce(true);

            const result = await attemptDualUnlock(
                "real-password",
                "real-salt",
                "real-verifier",
                2,
                null // no duress
            );

            expect(result.mode).toBe("real");
            expect(mockCryptoService.deriveKey).toHaveBeenCalledTimes(2);
            expect(mockCryptoService.verifyKey).toHaveBeenCalledTimes(1);
        });

        it("only checks real password when duress config is disabled", async () => {
            const realKey = { type: "real-key" };
            const dummyKey = { type: "dummy-key" };
            mockCryptoService.deriveKey
                .mockResolvedValueOnce(realKey)
                .mockResolvedValueOnce(dummyKey);
            mockCryptoService.verifyKey.mockResolvedValueOnce(false);

            const duressConfig = {
                enabled: false,
                salt: null,
                verifier: null,
                kdfVersion: 2,
            };

            const result = await attemptDualUnlock(
                "wrong-password",
                "real-salt",
                "real-verifier",
                2,
                duressConfig
            );

            expect(result.mode).toBe("invalid");
            expect(mockCryptoService.deriveKey).toHaveBeenCalledTimes(2);
        });

        it("handles exception during unlock", async () => {
            mockCryptoService.deriveKey.mockRejectedValue(new Error("Crypto failure"));

            const result = await attemptDualUnlock(
                "password",
                "real-salt",
                "real-verifier",
                2,
                null
            );

            expect(result.mode).toBe("invalid");
            expect(result.key).toBeNull();
            expect(result.error).toBe("Unlock failed");
        });

        it("derives both keys in parallel for constant-time behavior", async () => {
            const realKey = { type: "real-key" };
            const duressKey = { type: "duress-key" };

            let realResolve: (value: unknown) => void;
            let duressResolve: (value: unknown) => void;

            const realPromise = new Promise(resolve => { realResolve = resolve; });
            const duressPromise = new Promise(resolve => { duressResolve = resolve; });

            mockCryptoService.deriveKey
                .mockReturnValueOnce(realPromise as unknown)
                .mockReturnValueOnce(duressPromise as unknown);

            mockCryptoService.verifyKey.mockResolvedValue(false);

            const duressConfig = {
                enabled: true,
                salt: "duress-salt",
                verifier: "duress-verifier",
                kdfVersion: 2,
            };

            const unlockPromise = attemptDualUnlock(
                "password",
                "real-salt",
                "real-verifier",
                2,
                duressConfig
            );

            // Verify both derivations started before either resolved
            expect(mockCryptoService.deriveKey).toHaveBeenCalledTimes(2);

            // Resolve them
            realResolve(realKey);
            duressResolve(duressKey);

            await unlockPromise;

            // Both should have been verified
            expect(mockCryptoService.verifyKey).toHaveBeenCalledTimes(2);
        });
    });

    // ============ disableDuressMode() ============

    describe("disableDuressMode()", () => {
        it("clears duress fields successfully", async () => {
            const updateChain = mockSupabase._createChainable();
            updateChain._setResult({ user_id: "user-1" }, null);
            mockSupabase.from.mockReturnValue(updateChain);

            const result = await disableDuressMode("user-1");

            expect(result.success).toBe(true);
            expect(result.error).toBeUndefined();

            expect(mockSupabase.from).toHaveBeenCalledWith("profiles");
            expect(updateChain.update).toHaveBeenCalledWith({
                duress_salt: null,
                duress_password_verifier: null,
                duress_kdf_version: null,
            });
            expect(updateChain.eq).toHaveBeenCalledWith("user_id", "user-1");
        });

        it("returns error when DB update fails", async () => {
            const updateChain = mockSupabase._createChainable();
            updateChain._setResult(null, { message: "Permission denied" });
            mockSupabase.from.mockReturnValue(updateChain);

            const result = await disableDuressMode("user-1");

            expect(result.success).toBe(false);
            expect(result.error).toBe("Permission denied");
        });

        it("handles exception during disable", async () => {
            mockSupabase.from.mockImplementation(() => {
                throw new Error("Network failure");
            });

            const result = await disableDuressMode("user-1");

            expect(result.success).toBe(false);
            expect(result.error).toBe("Failed to disable duress mode");
        });
    });

    // ============ changeDuressPassword() ============

    describe("changeDuressPassword()", () => {
        it("changes duress password successfully", async () => {
            // Mock getDuressConfig
            const selectChain = mockSupabase._createChainable();
            selectChain._setResult({
                duress_salt: "old-salt",
                duress_password_verifier: "old-verifier",
                duress_kdf_version: 2,
            }, null);

            const oldKey = { type: "old-key" };
            const newKey = { type: "new-key" };

            mockCryptoService.deriveKey
                .mockResolvedValueOnce(oldKey) // verify old password
                .mockResolvedValueOnce(newKey); // derive new key

            mockCryptoService.verifyKey.mockResolvedValueOnce(true); // old password verified
            mockCryptoService.createVerificationHash.mockResolvedValue("new-verifier");
            mockCryptoService.generateSalt.mockReturnValue("new-salt");

            const updateChain = mockSupabase._createChainable();
            updateChain._setResult({ user_id: "user-1" }, null);

            mockSupabase.from
                .mockReturnValueOnce(selectChain) // first call for getDuressConfig
                .mockReturnValueOnce(selectChain) // second call for verifier check
                .mockReturnValueOnce(updateChain); // third call for update

            const result = await changeDuressPassword(
                "user-1",
                "old-duress-pass",
                "new-duress-pass",
                "real-password"
            );

            expect(result.success).toBe(true);
            expect(result.newKey).toBe(newKey);
            expect(result.error).toBeUndefined();

            // Verify old key derivation
            expect(mockCryptoService.deriveKey).toHaveBeenNthCalledWith(1, "old-duress-pass", "old-salt", 2);

            // Verify new key derivation
            expect(mockCryptoService.deriveKey).toHaveBeenNthCalledWith(2, "new-duress-pass", "new-salt", 2);

            // Verify DB update
            expect(updateChain.update).toHaveBeenCalledWith({
                duress_salt: "new-salt",
                duress_password_verifier: "new-verifier",
                duress_kdf_version: 2,
            });
        });

        it("rejects when new password equals real password", async () => {
            const result = await changeDuressPassword(
                "user-1",
                "old-duress",
                "real-password",
                "real-password"
            );

            expect(result.success).toBe(false);
            expect(result.error).toBe("Duress password must be different from your master password");
        });

        it("returns error when duress mode is not enabled", async () => {
            const selectChain = mockSupabase._createChainable();
            selectChain._setResult({
                duress_salt: null,
                duress_password_verifier: null,
                duress_kdf_version: null,
            }, null);
            mockSupabase.from.mockReturnValue(selectChain);

            const result = await changeDuressPassword(
                "user-1",
                "old-duress",
                "new-duress",
                "real-password"
            );

            expect(result.success).toBe(false);
            expect(result.error).toBe("Duress mode is not enabled");
        });

        it("returns error when old duress password is incorrect", async () => {
            const selectChain = mockSupabase._createChainable();
            selectChain._setResult({
                duress_salt: "old-salt",
                duress_password_verifier: "old-verifier",
                duress_kdf_version: 2,
            }, null);

            const oldKey = { type: "old-key" };
            mockCryptoService.deriveKey.mockResolvedValueOnce(oldKey);
            mockCryptoService.verifyKey.mockResolvedValueOnce(false); // verification fails

            mockSupabase.from
                .mockReturnValueOnce(selectChain) // getDuressConfig
                .mockReturnValueOnce(selectChain); // verifier check

            const result = await changeDuressPassword(
                "user-1",
                "wrong-old-password",
                "new-duress",
                "real-password"
            );

            expect(result.success).toBe(false);
            expect(result.error).toBe("Current duress password is incorrect");
        });

        it("returns error when verifier not found in profile", async () => {
            const selectChain1 = mockSupabase._createChainable();
            selectChain1._setResult({
                duress_salt: "old-salt",
                duress_password_verifier: "old-verifier",
                duress_kdf_version: 2,
            }, null);

            const selectChain2 = mockSupabase._createChainable();
            selectChain2._setResult(null, null); // no data

            mockSupabase.from
                .mockReturnValueOnce(selectChain1) // getDuressConfig
                .mockReturnValueOnce(selectChain2); // verifier check

            const result = await changeDuressPassword(
                "user-1",
                "old-duress",
                "new-duress",
                "real-password"
            );

            expect(result.success).toBe(false);
            expect(result.error).toBe("Duress verifier not found");
        });

        it("returns error when DB update fails", async () => {
            const selectChain = mockSupabase._createChainable();
            selectChain._setResult({
                duress_salt: "old-salt",
                duress_password_verifier: "old-verifier",
                duress_kdf_version: 2,
            }, null);

            const oldKey = { type: "old-key" };
            const newKey = { type: "new-key" };

            mockCryptoService.deriveKey
                .mockResolvedValueOnce(oldKey)
                .mockResolvedValueOnce(newKey);

            mockCryptoService.verifyKey.mockResolvedValueOnce(true);
            mockCryptoService.createVerificationHash.mockResolvedValue("new-verifier");
            mockCryptoService.generateSalt.mockReturnValue("new-salt");

            const updateChain = mockSupabase._createChainable();
            updateChain._setResult(null, { message: "Constraint violation" });

            mockSupabase.from
                .mockReturnValueOnce(selectChain)
                .mockReturnValueOnce(selectChain)
                .mockReturnValueOnce(updateChain);

            const result = await changeDuressPassword(
                "user-1",
                "old-duress",
                "new-duress",
                "real-password"
            );

            expect(result.success).toBe(false);
            expect(result.error).toBe("Constraint violation");
        });

        it("handles exception during password change", async () => {
            // Mock getDuressConfig to succeed but subsequent operations to fail
            const selectChain1 = mockSupabase._createChainable();
            selectChain1._setResult({
                duress_salt: "old-salt",
                duress_password_verifier: "old-verifier",
                duress_kdf_version: 2,
            }, null);

            const selectChain2 = mockSupabase._createChainable();
            selectChain2._setResult({
                duress_password_verifier: "old-verifier",
            }, null);

            mockSupabase.from
                .mockReturnValueOnce(selectChain1) // getDuressConfig succeeds
                .mockReturnValueOnce(selectChain2) // verifier check succeeds
                .mockImplementationOnce(() => { // update throws
                    throw new Error("Unexpected DB error");
                });

            const oldKey = { type: "old-key" };
            const newKey = { type: "new-key" };

            mockCryptoService.deriveKey
                .mockResolvedValueOnce(oldKey)
                .mockResolvedValueOnce(newKey);

            mockCryptoService.verifyKey.mockResolvedValueOnce(true);
            mockCryptoService.createVerificationHash.mockResolvedValue("new-verifier");
            mockCryptoService.generateSalt.mockReturnValue("new-salt");

            const result = await changeDuressPassword(
                "user-1",
                "old-duress",
                "new-duress",
                "real-password"
            );

            expect(result.success).toBe(false);
            expect(result.error).toBe("Failed to change duress password");
        });
    });
});
