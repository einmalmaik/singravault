// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 — see LICENSE
/**
 * @fileoverview Integration Tests — Core Cryptographic Pipeline
 *
 * Tests the full encrypt/decrypt round-trip for the zero-knowledge vault,
 * including AES-256-GCM, RSA-4096-OAEP, verification hashes, vault item
 * serialisation, shared-collection key wrapping, and KDF upgrade logic.
 *
 * These tests exercise cryptoService functions end-to-end using the native
 * Web Crypto API provided by Node.js (no WASM required for the AES/RSA
 * portions). Argon2id-dependent functions are tested with a lightweight
 * shim that derives keys via PBKDF2 so we can validate the pipeline
 * without the WASM overhead.
 */

import { describe, it, expect, beforeAll, vi } from "vitest";

// ---------------------------------------------------------------------------
// Mock hash-wasm's argon2id with a PBKDF2 stand-in so we can test the full
// pipeline in a jsdom environment that lacks WASM support.
// ---------------------------------------------------------------------------
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
    const saltBytes =
      typeof salt === "string" ? enc.encode(salt) : new Uint8Array(salt);

    // Import password as a raw key for PBKDF2
    const baseKey = await crypto.subtle.importKey(
      "raw",
      passwordBytes,
      "PBKDF2",
      false,
      ["deriveBits"]
    );

    const bits = await crypto.subtle.deriveBits(
      { name: "PBKDF2", salt: saltBytes, iterations: 1000, hash: "SHA-256" },
      baseKey,
      hashLength * 8
    );

    // Return hex string (matching hash-wasm's outputType: 'hex')
    return Array.from(new Uint8Array(bits))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
  },
}));

// Import AFTER mocking
import {
  generateSalt,
  deriveKey,
  deriveRawKey,
  encrypt,
  decrypt,
  encryptVaultItem,
  decryptVaultItem,
  createVerificationHash,
  verifyKey,
  importMasterKey,
  attemptKdfUpgrade,
  secureClear,
  generateRSAKeyPair,
  exportPublicKey,
  importPublicKey,
  exportPrivateKey,
  importPrivateKey,
  encryptRSA,
  decryptRSA,
  generateUserKeyPair,
  generateSharedKey,

  encryptWithSharedKey,
  decryptWithSharedKey,
  CURRENT_KDF_VERSION,
  KDF_PARAMS,
} from "@/services/cryptoService";
import type { VaultItemData } from "@/services/cryptoService";

// ============ Helper ============

/** Generates a deterministic CryptoKey from a simple passphrase for test use */
async function testKey(passphrase = "test-master-password"): Promise<CryptoKey> {
  const salt = generateSalt();
  return deriveKey(passphrase, salt, 1);
}

// ============ Tests ============

describe("Integration: Core Cryptographic Pipeline", () => {
  // ------------------------------------------------------------------
  // Salt generation
  // ------------------------------------------------------------------
  describe("generateSalt", () => {
    it("should return a base64 string of correct length", () => {
      const salt = generateSalt();
      expect(typeof salt).toBe("string");
      // 16 bytes -> ~24 base64 chars (with padding)
      expect(salt.length).toBeGreaterThanOrEqual(20);
    });

    it("should produce unique salts on successive calls", () => {
      const salts = new Set(Array.from({ length: 50 }, () => generateSalt()));
      expect(salts.size).toBe(50);
    });
  });

  // ------------------------------------------------------------------
  // Key derivation
  // ------------------------------------------------------------------
  describe("deriveKey / deriveRawKey", () => {
    it("should derive a non-extractable CryptoKey", async () => {
      const salt = generateSalt();
      const key = await deriveKey("password123", salt, 1);
      expect(key).toBeDefined();
      expect(key.type).toBe("secret");
      expect(key.extractable).toBe(false);
      expect(key.algorithm).toMatchObject({ name: "AES-GCM" });
    });

    it("should derive 32-byte raw key", async () => {
      const salt = generateSalt();
      const raw = await deriveRawKey("password123", salt, 1);
      expect(raw).toBeInstanceOf(Uint8Array);
      expect(raw.length).toBe(32);
    });

    it("should produce same key for same inputs", async () => {
      const salt = generateSalt();
      const a = await deriveRawKey("same-password", salt, 1);
      const b = await deriveRawKey("same-password", salt, 1);
      expect(Array.from(a)).toEqual(Array.from(b));
      a.fill(0);
      b.fill(0);
    });

    it("should produce different keys for different passwords", async () => {
      const salt = generateSalt();
      const a = await deriveRawKey("password-a", salt, 1);
      const b = await deriveRawKey("password-b", salt, 1);
      expect(Array.from(a)).not.toEqual(Array.from(b));
      a.fill(0);
      b.fill(0);
    });

    it("should produce different keys for different salts", async () => {
      const s1 = generateSalt();
      const s2 = generateSalt();
      const a = await deriveRawKey("password", s1, 1);
      const b = await deriveRawKey("password", s2, 1);
      expect(Array.from(a)).not.toEqual(Array.from(b));
      a.fill(0);
      b.fill(0);
    });

    it("should throw for unknown KDF version", async () => {
      const salt = generateSalt();
      await expect(deriveRawKey("pw", salt, 999)).rejects.toThrow(
        "Unknown KDF version"
      );
    });
  });

  // ------------------------------------------------------------------
  // AES-256-GCM encrypt / decrypt round-trip
  // ------------------------------------------------------------------
  describe("encrypt / decrypt round-trip", () => {
    let key: CryptoKey;

    beforeAll(async () => {
      key = await testKey();
    });

    it("should round-trip a simple string", async () => {
      const plaintext = "Hello, Singra Vault!";
      const encrypted = await encrypt(plaintext, key);
      const decrypted = await decrypt(encrypted, key);
      expect(decrypted).toBe(plaintext);
    });

    it("should round-trip an empty string", async () => {
      const encrypted = await encrypt("", key);
      const decrypted = await decrypt(encrypted, key);
      expect(decrypted).toBe("");
    });

    it("should round-trip unicode / emoji content", async () => {
      const plaintext = "Passwort: 🔑 Sicherheit!  日本語テスト";
      const encrypted = await encrypt(plaintext, key);
      const decrypted = await decrypt(encrypted, key);
      expect(decrypted).toBe(plaintext);
    });

    it("should round-trip long strings (10 KB)", async () => {
      const plaintext = "A".repeat(10_000);
      const encrypted = await encrypt(plaintext, key);
      const decrypted = await decrypt(encrypted, key);
      expect(decrypted).toBe(plaintext);
    });

    it("should produce different ciphertexts for the same plaintext (random IV)", async () => {
      const plaintext = "same-data";
      const a = await encrypt(plaintext, key);
      const b = await encrypt(plaintext, key);
      expect(a).not.toBe(b);
      // But both decrypt to the same value
      expect(await decrypt(a, key)).toBe(plaintext);
      expect(await decrypt(b, key)).toBe(plaintext);
    });

    it("should fail to decrypt with a wrong key", async () => {
      const encrypted = await encrypt("secret", key);
      const wrongKey = await testKey("wrong-password");
      await expect(decrypt(encrypted, wrongKey)).rejects.toThrow();
    });

    it("should fail to decrypt tampered ciphertext", async () => {
      const encrypted = await encrypt("secret", key);
      // Flip a byte in the middle of the base64 string
      const chars = encrypted.split("");
      const mid = Math.floor(chars.length / 2);
      chars[mid] = chars[mid] === "A" ? "B" : "A";
      const tampered = chars.join("");
      await expect(decrypt(tampered, key)).rejects.toThrow();
    });
  });

  // ------------------------------------------------------------------
  // VaultItem encrypt / decrypt
  // ------------------------------------------------------------------
  describe("encryptVaultItem / decryptVaultItem", () => {
    let key: CryptoKey;

    beforeAll(async () => {
      key = await testKey();
    });

    it("should round-trip a full vault item", async () => {
      const item: VaultItemData = {
        title: "GitHub",
        username: "octocat",
        password: "super-secret-123!",
        websiteUrl: "https://github.com",
        notes: "Mein Konto",
        itemType: "password",
        isFavorite: true,
        categoryId: "cat-1",
        customFields: { "API Key": "ghp_abc123" },
      };

      const encrypted = await encryptVaultItem(item, key);
      expect(typeof encrypted).toBe("string");

      const decrypted = await decryptVaultItem(encrypted, key);
      expect(decrypted).toEqual(item);
    });

    it("should round-trip a minimal vault item", async () => {
      const item: VaultItemData = { title: "Note", itemType: "note" };
      const encrypted = await encryptVaultItem(item, key);
      const decrypted = await decryptVaultItem(encrypted, key);
      expect(decrypted).toEqual(item);
    });

    it("should round-trip a TOTP vault item", async () => {
      const item: VaultItemData = {
        title: "2FA Token",
        itemType: "totp",
        totpSecret: "JBSWY3DPEHPK3PXP",
      };
      const encrypted = await encryptVaultItem(item, key);
      const decrypted = await decryptVaultItem(encrypted, key);
      expect(decrypted).toEqual(item);
    });

    it("should round-trip a vault item with null categoryId", async () => {
      const item: VaultItemData = {
        title: "Test",
        categoryId: null,
      };
      const encrypted = await encryptVaultItem(item, key);
      const decrypted = await decryptVaultItem(encrypted, key);
      expect(decrypted.categoryId).toBeNull();
    });
  });

  // ------------------------------------------------------------------
  // Password verification hash
  // ------------------------------------------------------------------
  describe("createVerificationHash / verifyKey", () => {
    it("should verify correct key", async () => {
      const key = await testKey("my-password");
      const hash = await createVerificationHash(key);
      expect(hash.startsWith("v2:")).toBe(true);
      const result = await verifyKey(hash, key);
      expect(result).toBe(true);
    });

    it("should reject wrong key", async () => {
      const key = await testKey("my-password");
      const hash = await createVerificationHash(key);
      const wrongKey = await testKey("wrong-password");
      const result = await verifyKey(hash, wrongKey);
      expect(result).toBe(false);
    });

    it("should reject tampered hash", async () => {
      const key = await testKey("my-password");
      const hash = await createVerificationHash(key);
      const tampered = hash.slice(0, -4) + "XXXX";
      const result = await verifyKey(tampered, key);
      expect(result).toBe(false);
    });

    it("should verify legacy v1 verification hashes for backward compatibility", async () => {
      const key = await testKey("my-password");
      const legacyHash = await encrypt("SINGRA_PW_VERIFICATION", key);
      const result = await verifyKey(legacyHash, key);
      expect(result).toBe(true);
    });
  });

  // ------------------------------------------------------------------
  // KDF upgrade
  // ------------------------------------------------------------------
  describe("attemptKdfUpgrade", () => {
    it("should skip upgrade when already on latest version", async () => {
      const result = await attemptKdfUpgrade("pw", generateSalt(), CURRENT_KDF_VERSION);
      expect(result.upgraded).toBe(false);
      expect(result.activeVersion).toBe(CURRENT_KDF_VERSION);
    });

    it("should upgrade from v1 to latest and produce valid key", async () => {
      const salt = generateSalt();
      const result = await attemptKdfUpgrade("my-pass", salt, 1);
      expect(result.upgraded).toBe(true);
      expect(result.activeVersion).toBe(CURRENT_KDF_VERSION);
      expect(result.newKey).toBeDefined();
      expect(result.newVerifier).toBeDefined();

      // New verifier should be verifiable with the new key
      const valid = await verifyKey(result.newVerifier!, result.newKey!);
      expect(valid).toBe(true);
    });
  });

  // ------------------------------------------------------------------
  // secureClear
  // ------------------------------------------------------------------
  describe("secureClear", () => {
    it("should zero all sensitive fields", () => {
      const data: VaultItemData = {
        title: "Test",
        username: "user",
        password: "secret",
        notes: "notes",
        websiteUrl: "https://example.com",
        totpSecret: "ABCD",
        customFields: { key: "value" },
      };

      secureClear(data);

      expect(data.title).toBe("");
      expect(data.username).toBe("");
      expect(data.password).toBe("");
      expect(data.notes).toBe("");
      expect(data.websiteUrl).toBe("");
      expect(data.totpSecret).toBe("");
      expect(data.customFields!.key).toBe("");
    });
  });

  // ------------------------------------------------------------------
  // importMasterKey
  // ------------------------------------------------------------------
  describe("importMasterKey", () => {
    it("should import raw bytes into a non-extractable CryptoKey", async () => {
      const raw = crypto.getRandomValues(new Uint8Array(32));
      const key = await importMasterKey(raw);
      expect(key.type).toBe("secret");
      expect(key.extractable).toBe(false);
      expect(key.usages).toContain("encrypt");
      expect(key.usages).toContain("decrypt");
    });

    it("should produce a working key for encrypt/decrypt", async () => {
      const raw = crypto.getRandomValues(new Uint8Array(32));
      const key = await importMasterKey(raw);
      const encrypted = await encrypt("test", key);
      const decrypted = await decrypt(encrypted, key);
      expect(decrypted).toBe("test");
    });
  });

  // ------------------------------------------------------------------
  // RSA-4096-OAEP asymmetric encryption
  // ------------------------------------------------------------------
  describe("RSA-4096-OAEP encrypt / decrypt", () => {
    let publicKey: CryptoKey;
    let privateKey: CryptoKey;

    beforeAll(async () => {
      const keyPair = await generateRSAKeyPair();
      publicKey = keyPair.publicKey;
      privateKey = keyPair.privateKey;
    }, 30000);

    it("should round-trip a short string", async () => {
      const plaintext = "secret-vault-key-material";
      const encrypted = await encryptRSA(plaintext, publicKey);
      const decrypted = await decryptRSA(encrypted, privateKey);
      expect(decrypted).toBe(plaintext);
    });

    it("should fail with wrong private key", async () => {
      const encrypted = await encryptRSA("data", publicKey);
      const otherPair = await generateRSAKeyPair();
      await expect(decryptRSA(encrypted, otherPair.privateKey)).rejects.toThrow();
    }, 30000);

    it("should export and re-import keys correctly", async () => {
      const pubJwk = await exportPublicKey(publicKey);
      const privJwk = await exportPrivateKey(privateKey);

      const reimportedPub = await importPublicKey(pubJwk);
      const reimportedPriv = await importPrivateKey(privJwk);

      const encrypted = await encryptRSA("round-trip-test", reimportedPub);
      const decrypted = await decryptRSA(encrypted, reimportedPriv);
      expect(decrypted).toBe("round-trip-test");
    });
  });

  // ------------------------------------------------------------------
  // Shared collection key wrapping pipeline
  // ------------------------------------------------------------------
  describe("Shared collection key wrap / unwrap", () => {


    it("should encrypt and decrypt vault items with shared key", async () => {
      const sharedKey = await generateSharedKey();
      const aad = "vault-item-123";
      const item: VaultItemData = {
        title: "Shared Login",
        username: "team-user",
        password: "shared-pw-123",
      };

      const encrypted = await encryptWithSharedKey(item, sharedKey, aad);
      const decrypted = await decryptWithSharedKey(encrypted, sharedKey, aad);
      expect(decrypted).toEqual(item);
    });


  });

  // ------------------------------------------------------------------
  // KDF_PARAMS integrity
  // ------------------------------------------------------------------
  describe("KDF_PARAMS", () => {
    it("should have v1 with 64 MiB memory", () => {
      expect(KDF_PARAMS[1].memory).toBe(65536);
      expect(KDF_PARAMS[1].hashLength).toBe(32);
    });

    it("should have v2 with 128 MiB memory", () => {
      expect(KDF_PARAMS[2].memory).toBe(131072);
      expect(KDF_PARAMS[2].hashLength).toBe(32);
    });

    it("should have CURRENT_KDF_VERSION pointing to an existing version", () => {
      expect(KDF_PARAMS[CURRENT_KDF_VERSION]).toBeDefined();
    });
  });
});
