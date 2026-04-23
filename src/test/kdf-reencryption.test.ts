// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 — see LICENSE
/**
 * @fileoverview Tests for KDF upgrade re-encryption logic.
 *
 * Verifies that:
 *   1. reEncryptVault correctly re-encrypts items and categories
 *   2. reEncryptString produces data decryptable with the new key
 *   3. Encrypted category prefix fields are handled correctly
 *   4. Partial failure aborts re-encryption (no partial writes)
 */
import { describe, it, expect } from "vitest";
import {
  encrypt,
  decrypt,
  deriveKey,
  encryptVaultItem,
  decryptVaultItem,
  reEncryptVault,
  reEncryptString,
  generateSalt,
  KDF_PARAMS,
  VAULT_ITEM_ENVELOPE_V1_PREFIX,
} from "@/services/cryptoService";

const ENCRYPTED_CATEGORY_PREFIX = "enc:cat:v1:";

describe("KDF Re-Encryption", () => {
  // Use two different salts to simulate two genuinely different keys
  // (In production, KDF v1 vs v2 produce different keys from same salt)
  const testPassword = "test-master-password-2025!";
  let keyA: CryptoKey;
  let keyB: CryptoKey;
  let saltA: string;
  let saltB: string;

  // Derive two distinct keys before all tests
  // We use different salts to guarantee different key material
  // (since in test environment KDF params may be mocked identically)
  it("should derive two distinct keys for testing", async () => {
    saltA = generateSalt();
    saltB = generateSalt();
    keyA = await deriveKey(testPassword, saltA, 1);
    keyB = await deriveKey(testPassword, saltB, 1);
    expect(keyA).toBeTruthy();
    expect(keyB).toBeTruthy();
  }, 60000);

  describe("reEncryptString", () => {
    it("should re-encrypt a string from oldKey to newKey", async () => {
      const original = "Hello, this is a secret!";
      const encryptedWithA = await encrypt(original, keyA);

      // Re-encrypt from A to B
      const reEncrypted = await reEncryptString(encryptedWithA, keyA, keyB);

      // Must be decryptable with keyB
      const decrypted = await decrypt(reEncrypted, keyB);
      expect(decrypted).toBe(original);

      // Must NOT be decryptable with keyA (different ciphertext)
      await expect(decrypt(reEncrypted, keyA)).rejects.toThrow();
    }, 30000);

    it("should fail if oldKey is wrong", async () => {
      const encryptedWithA = await encrypt("secret", keyA);

      // Try to re-encrypt with keyB as "old key" — should fail
      await expect(reEncryptString(encryptedWithA, keyB, keyA)).rejects.toThrow();
    }, 30000);
  });

  describe("reEncryptVault", () => {
    it("should re-encrypt vault items", async () => {
      const itemData = {
        title: "Netflix",
        username: "user@example.com",
        password: "s3cret!Pass",
        websiteUrl: "https://netflix.com",
        itemType: "password" as const,
      };

      const encryptedData = await encryptVaultItem(itemData, keyA, "item-1");

      const result = await reEncryptVault(
        [{ id: "item-1", encrypted_data: encryptedData }],
        [],
        keyA,
        keyB,
      );

      expect(result.itemsReEncrypted).toBe(1);
      expect(result.categoriesReEncrypted).toBe(0);
      expect(result.itemUpdates).toHaveLength(1);
      expect(result.itemUpdates[0].id).toBe("item-1");
      expect(result.itemUpdates[0].encrypted_data.startsWith(VAULT_ITEM_ENVELOPE_V1_PREFIX)).toBe(true);

      // Verify the re-encrypted data is decryptable with new key + entry ID as AAD
      const decrypted = await decryptVaultItem(result.itemUpdates[0].encrypted_data, keyB, "item-1");
      expect(decrypted.title).toBe("Netflix");
      expect(decrypted.username).toBe("user@example.com");
      expect(decrypted.password).toBe("s3cret!Pass");
    }, 30000);

    it("should re-encrypt encrypted category fields", async () => {
      const catName = "Social Media";
      const catIcon = "globe";
      const catColor = "#ff5733";

      const encName = await encrypt(catName, keyA);
      const encIcon = await encrypt(catIcon, keyA);
      const encColor = await encrypt(catColor, keyA);

      const categories = [
        {
          id: "cat-1",
          name: `${ENCRYPTED_CATEGORY_PREFIX}${encName}`,
          icon: `${ENCRYPTED_CATEGORY_PREFIX}${encIcon}`,
          color: `${ENCRYPTED_CATEGORY_PREFIX}${encColor}`,
        },
      ];

      const result = await reEncryptVault([], categories, keyA, keyB);

      expect(result.categoriesReEncrypted).toBe(1);
      expect(result.categoryUpdates).toHaveLength(1);

      const updated = result.categoryUpdates[0];
      expect(updated.name.startsWith(ENCRYPTED_CATEGORY_PREFIX)).toBe(true);
      expect(updated.icon!.startsWith(ENCRYPTED_CATEGORY_PREFIX)).toBe(true);
      expect(updated.color!.startsWith(ENCRYPTED_CATEGORY_PREFIX)).toBe(true);

      // Verify decryption with new key works
      const decName = await decrypt(updated.name.slice(ENCRYPTED_CATEGORY_PREFIX.length), keyB);
      const decIcon = await decrypt(updated.icon!.slice(ENCRYPTED_CATEGORY_PREFIX.length), keyB);
      const decColor = await decrypt(updated.color!.slice(ENCRYPTED_CATEGORY_PREFIX.length), keyB);

      expect(decName).toBe(catName);
      expect(decIcon).toBe(catIcon);
      expect(decColor).toBe(catColor);
    }, 30000);

    it("should skip plaintext category fields (no prefix)", async () => {
      const categories = [
        {
          id: "cat-2",
          name: "Work",
          icon: "briefcase",
          color: "#3b82f6",
        },
      ];

      const result = await reEncryptVault([], categories, keyA, keyB);

      // No encrypted fields = no updates needed
      expect(result.categoriesReEncrypted).toBe(0);
      expect(result.categoryUpdates).toHaveLength(0);
    }, 30000);

    it("should abort entirely if one item fails to decrypt", async () => {
      const goodData = await encryptVaultItem({ title: "Good" }, keyA, "good-1");
      const badData = await encryptVaultItem({ title: "Bad" }, keyB, "bad-1"); // encrypted with wrong key

      const items = [
        { id: "good-1", encrypted_data: goodData },
        { id: "bad-1", encrypted_data: badData },
      ];

      await expect(
        reEncryptVault(items, [], keyA, keyB),
      ).rejects.toThrow(/Failed to re-encrypt vault item/);
    }, 30000);

    it("should migrate legacy unversioned vault items to the versioned envelope", async () => {
      const itemData = {
        title: "Legacy",
        password: "old-format",
      };
      const legacyEncryptedData = await encrypt(JSON.stringify(itemData), keyA);

      const result = await reEncryptVault(
        [{ id: "legacy-1", encrypted_data: legacyEncryptedData }],
        [],
        keyA,
        keyB,
      );

      expect(result.legacyItemsFound).toBe(1);
      expect(result.itemUpdates[0].encrypted_data.startsWith(VAULT_ITEM_ENVELOPE_V1_PREFIX)).toBe(true);
      await expect(decryptVaultItem(result.itemUpdates[0].encrypted_data, keyB, "legacy-1")).resolves.toEqual(itemData);
    }, 30000);

    it("should handle empty vault gracefully", async () => {
      const result = await reEncryptVault([], [], keyA, keyB);

      expect(result.itemsReEncrypted).toBe(0);
      expect(result.categoriesReEncrypted).toBe(0);
      expect(result.itemUpdates).toHaveLength(0);
      expect(result.categoryUpdates).toHaveLength(0);
    }, 30000);
  });
});
