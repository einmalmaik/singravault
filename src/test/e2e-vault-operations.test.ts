// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 — see LICENSE
/**
 * @fileoverview E2E Tests — Vault Operations
 *
 * Tests the full vault item lifecycle: CRUD for password/note/TOTP items,
 * favourites, encryption round-trips with correct/wrong keys,
 * shared collection key wrapping, duress mode items, and integrity checks.
 */

import { describe, it, expect, beforeAll, vi } from "vitest";

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
        const saltBytes = typeof salt === "string" ? enc.encode(salt) : new Uint8Array(salt);
        const baseKey = await crypto.subtle.importKey(
            "raw",
            passwordBytes,
            "PBKDF2",
            false,
            ["deriveBits"],
        );
        const bits = await crypto.subtle.deriveBits(
            { name: "PBKDF2", salt: saltBytes, iterations: 1000, hash: "SHA-256" },
            baseKey,
            hashLength * 8,
        );
        return Array.from(new Uint8Array(bits))
            .map((b) => b.toString(16).padStart(2, "0"))
            .join("");
    },
}));

// ============ Imports (after mocks) ============

import {
    generateSalt,
    deriveKey,
    encrypt,
    decrypt,
    encryptVaultItem,
    decryptVaultItem,
    generateUserKeyPair,
    generateSharedKey,
    encryptWithSharedKey,
    decryptWithSharedKey,
    CURRENT_KDF_VERSION,
    type VaultItemData,
} from "@/services/cryptoService";

import {
    isDecoyItem,
    markAsDecoyItem,
    stripDecoyMarker,
    getDefaultDecoyItems,
    DURESS_MARKER_FIELD,
} from "@/services/duressService";

import {
    updateIntegrityRoot,
    verifyVaultIntegrity,
    clearIntegrityRoot,
    hasIntegrityRoot,
    deriveIntegrityKey,
    type VaultItemForIntegrity,
} from "@/services/vaultIntegrityService";

// ============ Test Helpers ============

const MASTER_PASSWORD = "E2E-Test-Master!99";
let masterSalt: string;
let masterKey: CryptoKey;

beforeAll(async () => {
    masterSalt = generateSalt();
    masterKey = await deriveKey(MASTER_PASSWORD, masterSalt, CURRENT_KDF_VERSION);
});

// ============ Tests ============

describe("E2E: Vault Operations", () => {

    // ========== Password Item CRUD ==========

    describe("Password Item CRUD", () => {
        const passwordItem: VaultItemData = {
            title: "GitHub Account",
            websiteUrl: "https://github.com",
            itemType: "password",
            username: "devuser@example.com",
            password: "Sup3rS3cur3!Pass",
            notes: "Work account",
            isFavorite: false,
        };

        let encryptedData: string;

        it("should encrypt a password item", async () => {
            encryptedData = await encryptVaultItem(passwordItem, masterKey);
            expect(encryptedData).toBeTruthy();
            expect(typeof encryptedData).toBe("string");
            // Encrypted data should not contain plaintext
            expect(encryptedData).not.toContain("GitHub Account");
            expect(encryptedData).not.toContain("Sup3rS3cur3!Pass");
        });

        it("should decrypt a password item with correct key", async () => {
            const decrypted = await decryptVaultItem(encryptedData, masterKey);
            expect(decrypted.title).toBe("GitHub Account");
            expect(decrypted.websiteUrl).toBe("https://github.com");
            expect(decrypted.username).toBe("devuser@example.com");
            expect(decrypted.password).toBe("Sup3rS3cur3!Pass");
            expect(decrypted.notes).toBe("Work account");
            expect(decrypted.itemType).toBe("password");
        });

        it("should update an encrypted item", async () => {
            const updated: VaultItemData = {
                ...passwordItem,
                password: "NewP@ssw0rd!2026",
                notes: "Updated notes",
            };
            const reEncrypted = await encryptVaultItem(updated, masterKey);
            expect(reEncrypted).not.toBe(encryptedData); // Different ciphertext (random IV)

            const decrypted = await decryptVaultItem(reEncrypted, masterKey);
            expect(decrypted.password).toBe("NewP@ssw0rd!2026");
            expect(decrypted.notes).toBe("Updated notes");
        });

        it("should fail to decrypt with wrong key", async () => {
            const wrongSalt = generateSalt();
            const wrongKey = await deriveKey("WrongPassword!", wrongSalt, CURRENT_KDF_VERSION);
            await expect(decryptVaultItem(encryptedData, wrongKey)).rejects.toThrow();
        });
    });

    // ========== Note Item ==========

    describe("Note Item", () => {
        it("should round-trip a note item", async () => {
            const noteItem: VaultItemData = {
                title: "Secret Diary",
                itemType: "note",
                notes: "This is a very private note with special chars: \u00E4\u00F6\u00FC\u00DF \u2603 \uD83D\uDD12",
            };

            const encrypted = await encryptVaultItem(noteItem, masterKey);
            const decrypted = await decryptVaultItem(encrypted, masterKey);
            expect(decrypted.title).toBe("Secret Diary");
            expect(decrypted.itemType).toBe("note");
            expect(decrypted.notes).toBe(noteItem.notes);
        });
    });

    // ========== TOTP Item ==========

    describe("TOTP Item", () => {
        it("should round-trip a TOTP item with secret", async () => {
            const totpItem: VaultItemData = {
                title: "AWS TOTP",
                itemType: "totp",
                totpSecret: "JBSWY3DPEHPK3PXP",
                username: "admin@aws.com",
            };

            const encrypted = await encryptVaultItem(totpItem, masterKey);
            const decrypted = await decryptVaultItem(encrypted, masterKey);
            expect(decrypted.title).toBe("AWS TOTP");
            expect(decrypted.itemType).toBe("totp");
            expect(decrypted.totpSecret).toBe("JBSWY3DPEHPK3PXP");
        });
    });

    // ========== Favourites ==========

    describe("Favourites", () => {
        it("should preserve favourite toggle through encrypt/decrypt", async () => {
            const item: VaultItemData = {
                title: "Favourite Item",
                isFavorite: true,
            };
            const encrypted = await encryptVaultItem(item, masterKey);
            const decrypted = await decryptVaultItem(encrypted, masterKey);
            expect(decrypted.isFavorite).toBe(true);

            // Toggle off
            const toggled: VaultItemData = { ...decrypted, isFavorite: false };
            const reEncrypted = await encryptVaultItem(toggled, masterKey);
            const reDecrypted = await decryptVaultItem(reEncrypted, masterKey);
            expect(reDecrypted.isFavorite).toBe(false);
        });
    });

    // ========== Encryption Round-Trip Edge Cases ==========

    describe("Encryption Round-Trip", () => {
        it("should preserve VaultItemData with all fields", async () => {
            const fullItem: VaultItemData = {
                title: "Complete Item",
                websiteUrl: "https://example.com",
                itemType: "password",
                isFavorite: true,
                categoryId: "cat-123",
                username: "user@example.com",
                password: "P@ss!Word123",
                notes: "Some notes here",
                totpSecret: "ABCDEF1234567890",
                customFields: { "Recovery Email": "recover@test.com", "PIN": "1234" },
            };

            const encrypted = await encryptVaultItem(fullItem, masterKey);
            const decrypted = await decryptVaultItem(encrypted, masterKey);

            expect(decrypted.title).toBe(fullItem.title);
            expect(decrypted.websiteUrl).toBe(fullItem.websiteUrl);
            expect(decrypted.itemType).toBe(fullItem.itemType);
            expect(decrypted.isFavorite).toBe(fullItem.isFavorite);
            expect(decrypted.categoryId).toBe(fullItem.categoryId);
            expect(decrypted.username).toBe(fullItem.username);
            expect(decrypted.password).toBe(fullItem.password);
            expect(decrypted.notes).toBe(fullItem.notes);
            expect(decrypted.totpSecret).toBe(fullItem.totpSecret);
            expect(decrypted.customFields).toEqual(fullItem.customFields);
        });

        it("should produce different ciphertext for same plaintext (random IV)", async () => {
            const item: VaultItemData = { title: "Test" };
            const enc1 = await encryptVaultItem(item, masterKey);
            const enc2 = await encryptVaultItem(item, masterKey);
            expect(enc1).not.toBe(enc2);
        });

        it("should handle raw string encrypt/decrypt round-trip", async () => {
            const plaintext = "Hello, World! \u00E4\u00F6\u00FC \uD83D\uDD10";
            const encrypted = await encrypt(plaintext, masterKey);
            const decrypted = await decrypt(encrypted, masterKey);
            expect(decrypted).toBe(plaintext);
        });
    });

    // ========== Shared Collection Key Wrapping ==========

    describe("Shared Collection E2E", () => {
        it("should encrypt and decrypt shared collection items with a generated shared key", async () => {
            // Step 1: Generate shared collection key
            const sharedKey = await generateSharedKey();
            expect(sharedKey).toBeTruthy();

            // Step 2: Encrypt/decrypt with shared key
            const itemData: VaultItemData = {
                title: "Shared Login",
                username: "team@example.com",
                password: "SharedP@ss123",
            };

            const aad = "shared-item-123";
            const encrypted = await encryptWithSharedKey(itemData, sharedKey, aad);
            const decrypted = await decryptWithSharedKey(encrypted, sharedKey, aad);
            expect(decrypted.title).toBe("Shared Login");
            expect(decrypted.username).toBe("team@example.com");
            expect(decrypted.password).toBe("SharedP@ss123");
        }, 30000);
    });

    // ========== Duress Mode Items ==========

    describe("Duress Mode Items", () => {
        it("should mark and detect decoy items through encrypt/decrypt", async () => {
            const itemData: VaultItemData = {
                title: "Decoy Bank Account",
                username: "fake@bank.com",
                password: "fake123",
            };

            // Mark as decoy
            const decoyData = markAsDecoyItem(itemData as unknown as Record<string, unknown>);
            expect(decoyData._duress).toBe(true);
            expect(isDecoyItem(decoyData)).toBe(true);

            // Encrypt and decrypt — duress marker should survive
            const encrypted = await encryptVaultItem(decoyData as unknown as VaultItemData, masterKey);
            const decrypted = await decryptVaultItem(encrypted, masterKey);
            expect(isDecoyItem(decrypted)).toBe(true);
            expect(decrypted.title).toBe("Decoy Bank Account");
        });

        it("should not detect non-duress items as decoy", () => {
            const normalItem: VaultItemData = { title: "Real Account" };
            expect(isDecoyItem(normalItem as unknown as Record<string, unknown>)).toBe(false);
        });

        it("should strip decoy marker", () => {
            const decoyData = markAsDecoyItem({ title: "Test", password: "123" } as unknown as Record<string, unknown>);
            const stripped = stripDecoyMarker(decoyData);
            expect(isDecoyItem(stripped as unknown as Record<string, unknown>)).toBe(false);
            expect((stripped as unknown as Record<string, unknown>)[DURESS_MARKER_FIELD]).toBeUndefined();
        });

        it("should provide default decoy items", () => {
            const decoys = getDefaultDecoyItems();
            expect(decoys.length).toBeGreaterThanOrEqual(3);
            expect(decoys[0].title).toBeTruthy();
            expect(decoys[0].password).toBeTruthy();
        });
    });

    // ========== Vault Integrity ==========

    describe("Vault Integrity Check", () => {
        const userId = "integrity-test-user";
        let integrityKey: CryptoKey;

        beforeAll(async () => {
            localStorage.clear();
            integrityKey = await deriveIntegrityKey(MASTER_PASSWORD, masterSalt);
        });

        it("should report isFirstCheck when no stored root exists", async () => {
            clearIntegrityRoot(userId);
            expect(hasIntegrityRoot(userId)).toBe(false);

            const items: VaultItemForIntegrity[] = [
                { id: "item-1", encrypted_data: "enc-data-1" },
                { id: "item-2", encrypted_data: "enc-data-2" },
            ];

            const result = await verifyVaultIntegrity(items, integrityKey, userId);
            expect(result.valid).toBe(true);
            expect(result.isFirstCheck).toBe(true);
            expect(result.itemCount).toBe(2);
        });

        it("should verify integrity after update", async () => {
            const items: VaultItemForIntegrity[] = [
                { id: "item-1", encrypted_data: "enc-data-1" },
                { id: "item-2", encrypted_data: "enc-data-2" },
            ];

            // Update root
            const root = await updateIntegrityRoot(items, integrityKey, userId);
            expect(root).toBeTruthy();
            expect(hasIntegrityRoot(userId)).toBe(true);

            // Verify — should match
            const result = await verifyVaultIntegrity(items, integrityKey, userId);
            expect(result.valid).toBe(true);
            expect(result.isFirstCheck).toBe(false);
            expect(result.computedRoot).toBe(root);
        });

        it("should detect tampering (data modification)", async () => {
            const items: VaultItemForIntegrity[] = [
                { id: "item-1", encrypted_data: "enc-data-1" },
                { id: "item-2", encrypted_data: "enc-data-2" },
            ];

            await updateIntegrityRoot(items, integrityKey, userId);

            // Tamper with data
            const tampered: VaultItemForIntegrity[] = [
                { id: "item-1", encrypted_data: "TAMPERED-DATA" },
                { id: "item-2", encrypted_data: "enc-data-2" },
            ];

            const result = await verifyVaultIntegrity(tampered, integrityKey, userId);
            expect(result.valid).toBe(false);
        });

        it("should detect tampering (item deletion)", async () => {
            const items: VaultItemForIntegrity[] = [
                { id: "item-1", encrypted_data: "enc-data-1" },
                { id: "item-2", encrypted_data: "enc-data-2" },
                { id: "item-3", encrypted_data: "enc-data-3" },
            ];

            await updateIntegrityRoot(items, integrityKey, userId);

            // Delete one item
            const partial: VaultItemForIntegrity[] = [
                { id: "item-1", encrypted_data: "enc-data-1" },
                { id: "item-3", encrypted_data: "enc-data-3" },
            ];

            const result = await verifyVaultIntegrity(partial, integrityKey, userId);
            expect(result.valid).toBe(false);
        });
    });
});
