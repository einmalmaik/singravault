// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 — see LICENSE
/**
 * @fileoverview Integration Tests — Vault Integrity, TOTP, Password Generator, Vault Health
 *
 * Tests the remaining critical services:
 * - VaultIntegrityService: HMAC Merkle tree tamper detection
 * - TOTP Service: code generation, validation, URI parsing
 * - TwoFactorService: TOTP verification, backup code hashing
 * - PasswordGenerator: secure password/passphrase generation, strength analysis
 * - VaultHealthService: password health scoring and issue detection
 */

import { describe, it, expect, beforeEach, beforeAll, vi } from "vitest";

// ---------------------------------------------------------------------------
// Mock hash-wasm for vault integrity tests (Argon2id -> PBKDF2)
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
      typeof salt === "string" ? enc.encode(salt) : salt;

    const baseKey = await crypto.subtle.importKey(
      "raw",
      passwordBytes,
      "PBKDF2",
      false,
      ["deriveBits"]
    );

    const bits = await crypto.subtle.deriveBits(
      { name: "PBKDF2", salt: saltBytes as any, iterations: 1000, hash: "SHA-256" },
      baseKey,
      hashLength * 8
    );

    return Array.from(new Uint8Array(bits))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
  },
}));

// ============ Vault Integrity Service Tests ============

import {
  deriveIntegrityKey,
  verifyVaultIntegrity,
  updateIntegrityRoot,
  clearIntegrityRoot,
  hasIntegrityRoot,
} from "@/services/vaultIntegrityService";
import type { VaultItemForIntegrity } from "@/services/vaultIntegrityService";

describe("Integration: VaultIntegrityService — Tamper Detection", () => {
  const TEST_USER_ID = "test-integrity-user-001";
  const TEST_PASSWORD = "integrity-master-pw";
  const TEST_SALT = btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(16))));

  let integrityKey: CryptoKey;

  beforeAll(async () => {
    integrityKey = await deriveIntegrityKey(TEST_PASSWORD, TEST_SALT);
  });

  beforeEach(() => {
    clearIntegrityRoot(TEST_USER_ID);
  });

  it("should derive a valid HMAC key from master password", async () => {
    expect(integrityKey).toBeDefined();
    expect(integrityKey.type).toBe("secret");
    expect(integrityKey.algorithm).toMatchObject({ name: "HMAC" });
    expect(integrityKey.usages).toContain("sign");
  });

  it("should derive different keys for different passwords (domain separation)", async () => {
    const key1 = await deriveIntegrityKey("password-a", TEST_SALT);
    const key2 = await deriveIntegrityKey("password-b", TEST_SALT);

    // Sign the same data with both keys — results should differ
    const data = new TextEncoder().encode("test-data");
    const sig1 = await crypto.subtle.sign("HMAC", key1, data);
    const sig2 = await crypto.subtle.sign("HMAC", key2, data);

    expect(new Uint8Array(sig1)).not.toEqual(new Uint8Array(sig2));
  });

  it("should report first check with no stored root", async () => {
    const items: VaultItemForIntegrity[] = [
      { id: "item-1", encrypted_data: "encrypted-a" },
      { id: "item-2", encrypted_data: "encrypted-b" },
    ];

    const result = await verifyVaultIntegrity(items, integrityKey, TEST_USER_ID);
    expect(result.valid).toBe(true);
    expect(result.isFirstCheck).toBe(true);
    expect(result.computedRoot).toBeTruthy();
    expect(result.itemCount).toBe(2);
  });

  it("should verify integrity after storing root", async () => {
    const items: VaultItemForIntegrity[] = [
      { id: "item-1", encrypted_data: "data-a" },
      { id: "item-2", encrypted_data: "data-b" },
    ];

    // Store root
    const root = await updateIntegrityRoot(items, integrityKey, TEST_USER_ID);
    expect(root).toBeTruthy();
    expect(hasIntegrityRoot(TEST_USER_ID)).toBe(true);

    // Verify — should match
    const result = await verifyVaultIntegrity(items, integrityKey, TEST_USER_ID);
    expect(result.valid).toBe(true);
    expect(result.isFirstCheck).toBe(false);
  });

  it("should detect tampered item data", async () => {
    const items: VaultItemForIntegrity[] = [
      { id: "item-1", encrypted_data: "original-data-a" },
      { id: "item-2", encrypted_data: "original-data-b" },
    ];

    await updateIntegrityRoot(items, integrityKey, TEST_USER_ID);

    // Tamper with item data
    const tamperedItems: VaultItemForIntegrity[] = [
      { id: "item-1", encrypted_data: "TAMPERED-data-a" },
      { id: "item-2", encrypted_data: "original-data-b" },
    ];

    const result = await verifyVaultIntegrity(tamperedItems, integrityKey, TEST_USER_ID);
    expect(result.valid).toBe(false);
  });

  it("should detect deleted items", async () => {
    const items: VaultItemForIntegrity[] = [
      { id: "item-1", encrypted_data: "data-a" },
      { id: "item-2", encrypted_data: "data-b" },
      { id: "item-3", encrypted_data: "data-c" },
    ];

    await updateIntegrityRoot(items, integrityKey, TEST_USER_ID);

    // Remove an item (server-side deletion attack)
    const missingItem = items.slice(0, 2);
    const result = await verifyVaultIntegrity(missingItem, integrityKey, TEST_USER_ID);
    expect(result.valid).toBe(false);
  });

  it("should detect added items", async () => {
    const items: VaultItemForIntegrity[] = [
      { id: "item-1", encrypted_data: "data-a" },
    ];

    await updateIntegrityRoot(items, integrityKey, TEST_USER_ID);

    // Add a rogue item
    const extraItems: VaultItemForIntegrity[] = [
      ...items,
      { id: "item-rogue", encrypted_data: "rogue-data" },
    ];

    const result = await verifyVaultIntegrity(extraItems, integrityKey, TEST_USER_ID);
    expect(result.valid).toBe(false);
  });

  it("should handle empty vault deterministically", async () => {
    const empty: VaultItemForIntegrity[] = [];

    const root1 = await updateIntegrityRoot(empty, integrityKey, TEST_USER_ID);
    const result = await verifyVaultIntegrity(empty, integrityKey, TEST_USER_ID);

    expect(result.valid).toBe(true);
    expect(root1).toBe("EMPTY_VAULT_ROOT");
  });

  it("should produce deterministic roots regardless of item order", async () => {
    const items: VaultItemForIntegrity[] = [
      { id: "aaa", encrypted_data: "data-a" },
      { id: "bbb", encrypted_data: "data-b" },
      { id: "ccc", encrypted_data: "data-c" },
    ];

    const root1 = await updateIntegrityRoot(items, integrityKey, TEST_USER_ID);
    clearIntegrityRoot(TEST_USER_ID);

    // Reverse order
    const reversed = [...items].reverse();
    const root2 = await updateIntegrityRoot(reversed, integrityKey, TEST_USER_ID);

    // Roots must match because items are sorted by ID internally
    expect(root1).toBe(root2);
  });

  it("should clear and detect missing root", () => {
    localStorage.setItem("singra_integrity_root_" + TEST_USER_ID, "fake-root");
    expect(hasIntegrityRoot(TEST_USER_ID)).toBe(true);

    clearIntegrityRoot(TEST_USER_ID);
    expect(hasIntegrityRoot(TEST_USER_ID)).toBe(false);
  });
});

// ============ TOTP Service Tests ============

import {
  generateTOTP,
  getTimeRemaining,
  isValidTOTPSecret,
  normalizeTOTPSecretInput,
  validateTOTPSecret,
  parseOTPAuthUri,
  formatTOTPCode,
  parseTOTPUri,
  generateTOTPUri,
} from "@/services/totpService";

describe("Integration: TOTP Service — Code Generation & Validation", () => {
  const VALID_SECRET = "JBSWY3DPEHPK3PXP"; // Standard test secret

  describe("generateTOTP", () => {
    it("should generate a 6-digit code from a valid secret", () => {
      const code = generateTOTP(VALID_SECRET);
      expect(code).toMatch(/^\d{6}$/);
    });

    it("should handle secrets with spaces", () => {
      const code = generateTOTP("JBSW Y3DP EHPK 3PXP");
      expect(code).toMatch(/^\d{6}$/);
    });

    it("should handle lowercase secrets", () => {
      const code = generateTOTP("jbswy3dpehpk3pxp");
      expect(code).toMatch(/^\d{6}$/);
    });

    it("should return dashes for invalid secret", () => {
      const code = generateTOTP("INVALID!!!!");
      expect(code).toBe("------");
    });
  });

  describe("getTimeRemaining", () => {
    it("should return a number between 0 and 30", () => {
      const remaining = getTimeRemaining();
      expect(remaining).toBeGreaterThanOrEqual(0);
      expect(remaining).toBeLessThanOrEqual(30);
    });
  });

  describe("isValidTOTPSecret", () => {
    it("should accept valid base32 secrets", () => {
      expect(isValidTOTPSecret("JBSWY3DPEHPK3PXP")).toBe(true);
      expect(isValidTOTPSecret("ABCDEFGHIJKLMNOP")).toBe(true);
    });

    it("should accept secrets with spaces", () => {
      expect(isValidTOTPSecret("JBSW Y3DP EHPK 3PXP")).toBe(true);
    });

    it("should reject secrets shorter than 16 characters", () => {
      expect(isValidTOTPSecret("ABCD")).toBe(false);
      expect(isValidTOTPSecret("ABCDEFGHIJK")).toBe(false);
    });

    it("should reject non-base32 characters", () => {
      expect(isValidTOTPSecret("ABCDEFGH01890000")).toBe(false); // 0,1,8,9 not in base32
    });
  });

  describe("normalizeTOTPSecretInput", () => {
    it("should remove spaces and normalize to uppercase", () => {
      const input = "fdzert tretrefgd erttredfgfg terdfggfdt";
      const normalized = normalizeTOTPSecretInput(input);
      expect(normalized).toBe("FDZERTTRETREFGDERTTREDFGFGTERDFGGFDT");
    });

    it("should remove mixed whitespace characters", () => {
      const input = "ab cd\tef\ngh";
      const normalized = normalizeTOTPSecretInput(input);
      expect(normalized).toBe("ABCDEFGH");
    });
  });

  describe("validateTOTPSecret", () => {
    it("should return valid for correct secrets", () => {
      const result = validateTOTPSecret("JBSWY3DPEHPK3PXP");
      expect(result.valid).toBe(true);
      expect(result.error).toBeUndefined();
    });

    it("should return error for too-short secrets", () => {
      const result = validateTOTPSecret("ABC");
      expect(result.valid).toBe(false);
      expect(result.error).toBeTruthy();
    });

    it("should return error for invalid format", () => {
      const result = validateTOTPSecret("ABCDEFGH01890000");
      expect(result.valid).toBe(false);
      expect(result.error).toBeTruthy();
    });
  });

  describe("parseOTPAuthUri", () => {
    it("should parse a standard otpauth URI", () => {
      const uri = "otpauth://totp/GitHub:user@test.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub";
      const result = parseOTPAuthUri(uri);
      expect(result).not.toBeNull();
      expect(result!.secret).toBe("JBSWY3DPEHPK3PXP");
      expect(result!.issuer).toBe("GitHub");
      expect(result!.label).toContain("user@test.com");
    });

    it("should return null for invalid URIs", () => {
      expect(parseOTPAuthUri("not-a-uri")).toBeNull();
      expect(parseOTPAuthUri("https://example.com")).toBeNull();
      expect(parseOTPAuthUri("otpauth://hotp/test?secret=ABC")).toBeNull();
    });

    it("should return null when secret is missing", () => {
      expect(parseOTPAuthUri("otpauth://totp/test")).toBeNull();
    });
  });

  describe("formatTOTPCode", () => {
    it("should format 6-digit code with space", () => {
      expect(formatTOTPCode("123456")).toBe("123 456");
    });

    it("should return non-6-digit codes unformatted", () => {
      expect(formatTOTPCode("12345")).toBe("12345");
      expect(formatTOTPCode("1234567")).toBe("1234567");
    });

    it("should format 6-char dashes string with space (treats length=6 as valid)", () => {
      // "------" is 6 chars, so formatTOTPCode splits it: "--- ---"
      expect(formatTOTPCode("------")).toBe("--- ---");
    });
  });

  describe("parseTOTPUri / generateTOTPUri round-trip", () => {
    it("should round-trip a TOTP configuration", () => {
      const original = {
        secret: "JBSWY3DPEHPK3PXP",
        label: "test@example.com",
        issuer: "Singra Vault",
        algorithm: "SHA1",
        digits: 6,
        period: 30,
      };

      const uri = generateTOTPUri(original);
      expect(uri).toContain("otpauth://totp/");
      expect(uri).toContain("JBSWY3DPEHPK3PXP");

      const parsed = parseTOTPUri(uri);
      expect(parsed).not.toBeNull();
      expect(parsed!.secret).toBe("JBSWY3DPEHPK3PXP");
      expect(parsed!.issuer).toBe("Singra Vault");
      expect(parsed!.digits).toBe(6);
      expect(parsed!.period).toBe(30);
    });
  });
});

// ============ Two-Factor Service Tests (Pure Functions Only) ============

import {
  generateTOTPSecret,
  generateQRCodeUri,
  formatSecretForDisplay,
  verifyTOTPCode,
  generateBackupCodes,
  hashBackupCode,
} from "@/services/twoFactorService";

describe("Integration: TwoFactorService — Pure Functions", () => {
  describe("generateTOTPSecret", () => {
    it("should generate a valid base32 secret", () => {
      const secret = generateTOTPSecret();
      expect(secret).toBeTruthy();
      expect(secret.length).toBeGreaterThanOrEqual(16);
      expect(/^[A-Z2-7]+=*$/.test(secret)).toBe(true);
    });

    it("should generate unique secrets", () => {
      const secrets = new Set(Array.from({ length: 20 }, () => generateTOTPSecret()));
      expect(secrets.size).toBe(20);
    });
  });

  describe("generateQRCodeUri", () => {
    it("should generate valid otpauth URI", () => {
      const secret = generateTOTPSecret();
      const uri = generateQRCodeUri(secret, "test@example.com");
      expect(uri).toContain("otpauth://totp/");
      expect(uri).toContain("Singra%20PW");
      expect(uri).toContain(secret);
    });
  });

  describe("formatSecretForDisplay", () => {
    it("should group secret in 4-char blocks", () => {
      const formatted = formatSecretForDisplay("ABCDEFGHIJKLMNOP");
      expect(formatted).toBe("ABCD EFGH IJKL MNOP");
    });
  });

  describe("verifyTOTPCode", () => {
    it("should verify a freshly generated code", () => {
      const secret = generateTOTPSecret();
      const code = generateTOTP(secret);
      expect(verifyTOTPCode(secret, code)).toBe(true);
    });

    it("should reject invalid codes", () => {
      const secret = generateTOTPSecret();
      expect(verifyTOTPCode(secret, "000000")).toBe(false);
      expect(verifyTOTPCode(secret, "ABCDEF")).toBe(false);
    });

    it("should handle codes with spaces", () => {
      const secret = generateTOTPSecret();
      const code = generateTOTP(secret);
      const formatted = code.slice(0, 3) + " " + code.slice(3);
      expect(verifyTOTPCode(secret, formatted)).toBe(true);
    });
  });

  describe("generateBackupCodes", () => {
    it("should generate 5 backup codes", () => {
      const codes = generateBackupCodes();
      expect(codes.length).toBe(5);
    });

    it("should format codes as XXXX-XXXX", () => {
      const codes = generateBackupCodes();
      for (const code of codes) {
        expect(code).toMatch(/^[A-Z2-9]{4}-[A-Z2-9]{4}$/);
      }
    });

    it("should generate unique codes", () => {
      const codes = generateBackupCodes();
      const unique = new Set(codes);
      expect(unique.size).toBe(5);
    });

    it("should exclude ambiguous characters (0, O, 1, I)", () => {
      // Generate many sets to increase confidence
      for (let i = 0; i < 10; i++) {
        const codes = generateBackupCodes();
        for (const code of codes) {
          const clean = code.replace(/-/g, "");
          expect(clean).not.toMatch(/[01IO]/);
        }
      }
    });
  });

  describe("hashBackupCode", () => {
    it("should produce consistent hash for same input (unsalted)", async () => {
      const hash1 = await hashBackupCode("ABCD-EFGH");
      const hash2 = await hashBackupCode("ABCD-EFGH");
      expect(hash1).toBe(hash2);
    });

    it("should normalize dashes and case", async () => {
      const hash1 = await hashBackupCode("ABCD-EFGH");
      const hash2 = await hashBackupCode("abcdefgh"); // no dash, lowercase
      expect(hash1).toBe(hash2);
    });

    it("should produce different hashes with different salts (HMAC)", async () => {
      const hash1 = await hashBackupCode("ABCD-EFGH", "salt-a");
      const hash2 = await hashBackupCode("ABCD-EFGH", "salt-b");
      expect(hash1).not.toBe(hash2);
    });

    it("should produce different hashes for different codes", async () => {
      const hash1 = await hashBackupCode("AAAA-BBBB");
      const hash2 = await hashBackupCode("CCCC-DDDD");
      expect(hash1).not.toBe(hash2);
    });

    it("should produce hex-encoded hash of correct length", async () => {
      const hash = await hashBackupCode("TEST-CODE");
      // SHA-256 = 64 hex chars
      expect(hash).toMatch(/^[0-9a-f]{64}$/);
    });

    it("should produce HMAC hash of same length as SHA-256", async () => {
      const hash = await hashBackupCode("TEST-CODE", "my-salt");
      expect(hash).toMatch(/^[0-9a-f]{64}$/);
    });
  });
});

// ============ Password Generator Tests ============

import {
  generatePassword,
  generatePassphrase,
  calculateStrength,
  DEFAULT_PASSWORD_OPTIONS,
  DEFAULT_PASSPHRASE_OPTIONS,
} from "@/services/passwordGenerator";

describe("Integration: PasswordGenerator — Secure Generation", () => {
  describe("generatePassword", () => {
    it("should generate password of requested length", () => {
      const pw = generatePassword({ ...DEFAULT_PASSWORD_OPTIONS, length: 20 });
      expect(pw.length).toBe(20);
    });

    it("should include all requested character types", () => {
      // Generate many passwords to verify charset guarantees
      for (let i = 0; i < 20; i++) {
        const pw = generatePassword(DEFAULT_PASSWORD_OPTIONS);
        expect(pw).toMatch(/[A-Z]/);     // uppercase
        expect(pw).toMatch(/[a-z]/);     // lowercase
        expect(pw).toMatch(/[0-9]/);     // numbers
        expect(pw).toMatch(/[^a-zA-Z0-9]/); // symbols
      }
    });

    it("should respect uppercase-only option", () => {
      const pw = generatePassword({
        length: 20,
        uppercase: true,
        lowercase: false,
        numbers: false,
        symbols: false,
      });
      expect(pw).toMatch(/^[A-Z]+$/);
    });

    it("should respect numbers-only option", () => {
      const pw = generatePassword({
        length: 20,
        uppercase: false,
        lowercase: false,
        numbers: true,
        symbols: false,
      });
      expect(pw).toMatch(/^[0-9]+$/);
    });

    it("should fall back to lowercase when nothing selected", () => {
      const pw = generatePassword({
        length: 10,
        uppercase: false,
        lowercase: false,
        numbers: false,
        symbols: false,
      });
      expect(pw).toMatch(/^[a-z]+$/);
    });

    it("should generate unique passwords (CSPRNG)", () => {
      const passwords = new Set(
        Array.from({ length: 50 }, () => generatePassword(DEFAULT_PASSWORD_OPTIONS))
      );
      expect(passwords.size).toBe(50);
    });
  });

  describe("generatePassphrase", () => {
    it("should generate correct number of words", () => {
      const pp = generatePassphrase(DEFAULT_PASSPHRASE_OPTIONS);
      // With number: wordCount words + 1 number
      const parts = pp.split(DEFAULT_PASSPHRASE_OPTIONS.separator);
      expect(parts.length).toBe(DEFAULT_PASSPHRASE_OPTIONS.wordCount + 1);
    });

    it("should capitalize words when requested", () => {
      const pp = generatePassphrase({
        wordCount: 4,
        separator: "-",
        capitalize: true,
        includeNumber: false,
      });
      const words = pp.split("-");
      for (const word of words) {
        expect(word[0]).toMatch(/[A-Z]/);
      }
    });

    it("should use custom separator", () => {
      const pp = generatePassphrase({
        wordCount: 3,
        separator: ".",
        capitalize: false,
        includeNumber: false,
      });
      expect(pp.split(".").length).toBe(3);
    });

    it("should append a number when includeNumber is true", () => {
      const pp = generatePassphrase({
        wordCount: 3,
        separator: "-",
        capitalize: false,
        includeNumber: true,
      });
      const parts = pp.split("-");
      const lastPart = parts[parts.length - 1];
      expect(lastPart).toMatch(/^\d+$/);
    });
  });

  describe("calculateStrength", () => {
    it("should rate short passwords as weak (score 0)", () => {
      const result = calculateStrength("abc");
      expect(result.score).toBe(0);
      expect(result.label).toBe("weak");
    });

    it("should rate simple passwords as fair (score 1)", () => {
      const result = calculateStrength("abcdefghij");
      expect(result.score).toBeGreaterThanOrEqual(1);
    });

    it("should rate complex passwords as strong (score 3+)", () => {
      const result = calculateStrength("Tr0ub4dor&3!@SecurityPW");
      expect(result.score).toBeGreaterThanOrEqual(3);
    });

    it("should rate very long complex passwords as very strong (score 4)", () => {
      const result = calculateStrength("Xk9#mP2@qR7!nL5$vB3&wF8^hJ");
      expect(result.score).toBe(4);
      expect(result.label).toBe("veryStrong");
    });

    it("should calculate entropy correctly", () => {
      const result = calculateStrength("aaaa"); // 4 chars, 26 charset
      // entropy = 4 * log2(26) ≈ 18.8
      expect(result.entropy).toBeGreaterThan(15);
      expect(result.entropy).toBeLessThan(25);
    });

    it("should return color for UI display", () => {
      const result = calculateStrength("test");
      expect(result.color).toBeTruthy();
      expect(result.color).toContain("bg-");
    });
  });
});

// ============ Vault Health Service Tests ============

import { analyzeVaultHealth } from "@/services/vaultHealthService";
import type { DecryptedPasswordItem } from "@/services/vaultHealthService";

describe("Integration: VaultHealthService — Password Analysis", () => {
  const NOW = new Date().toISOString();
  const OLD_DATE = new Date(Date.now() - 120 * 24 * 60 * 60 * 1000).toISOString(); // 120 days ago

  it("should return perfect score for empty vault", () => {
    const report = analyzeVaultHealth([]);
    expect(report.score).toBe(100);
    expect(report.totalItems).toBe(0);
    expect(report.issues).toHaveLength(0);
  });

  it("should detect weak passwords", () => {
    const items: DecryptedPasswordItem[] = [
      { id: "1", title: "Short", password: "abc", updatedAt: NOW },
      { id: "2", title: "Strong", password: "X9k#mP2@qR7!nL5$", updatedAt: NOW },
    ];

    const report = analyzeVaultHealth(items);
    expect(report.stats.weak).toBeGreaterThanOrEqual(1);
    expect(report.issues.some((i) => i.type === "weak" && i.itemId === "1")).toBe(true);
  });

  it("should detect duplicate passwords", () => {
    const items: DecryptedPasswordItem[] = [
      { id: "1", title: "Site A", password: "SamePassword123!", updatedAt: NOW },
      { id: "2", title: "Site B", password: "SamePassword123!", updatedAt: NOW },
      { id: "3", title: "Site C", password: "UniquePassword456!", updatedAt: NOW },
    ];

    const report = analyzeVaultHealth(items);
    expect(report.stats.duplicate).toBeGreaterThanOrEqual(2);
    expect(report.issues.filter((i) => i.type === "duplicate").length).toBeGreaterThanOrEqual(2);
  });

  it("should detect old passwords (>90 days)", () => {
    const items: DecryptedPasswordItem[] = [
      { id: "1", title: "Old Login", password: "OldPassword123!@#", updatedAt: OLD_DATE },
      { id: "2", title: "Fresh Login", password: "FreshPass456!@#", updatedAt: NOW },
    ];

    const report = analyzeVaultHealth(items);
    expect(report.stats.old).toBe(1);
    expect(report.issues.some((i) => i.type === "old" && i.itemId === "1")).toBe(true);
  });

  it("should detect reused passwords across domains", () => {
    const items: DecryptedPasswordItem[] = [
      {
        id: "1",
        title: "GitHub",
        password: "SharedCrossDomain!1",
        websiteUrl: "https://github.com",
        updatedAt: NOW,
      },
      {
        id: "2",
        title: "GitLab",
        password: "SharedCrossDomain!1",
        websiteUrl: "https://gitlab.com",
        updatedAt: NOW,
      },
    ];

    const report = analyzeVaultHealth(items);
    expect(report.stats.reused).toBeGreaterThanOrEqual(2);
  });

  it("should score perfect vault near 100", () => {
    const items: DecryptedPasswordItem[] = [
      { id: "1", title: "A", password: "X9k#mP2@qR7!nL5$vB3", updatedAt: NOW },
      { id: "2", title: "B", password: "aZ4!bY5@cX6#dW7$eV8", updatedAt: NOW },
      { id: "3", title: "C", password: "Kj9&mN3!pQ7*sT5^wR2", updatedAt: NOW },
    ];

    const report = analyzeVaultHealth(items);
    expect(report.score).toBeGreaterThanOrEqual(90);
    expect(report.stats.strong).toBe(3);
  });

  it("should score unhealthy vault near 0", () => {
    const items: DecryptedPasswordItem[] = [
      { id: "1", title: "Bad1", password: "123", updatedAt: OLD_DATE },
      { id: "2", title: "Bad2", password: "123", updatedAt: OLD_DATE },
      { id: "3", title: "Bad3", password: "abc", updatedAt: OLD_DATE },
    ];

    const report = analyzeVaultHealth(items);
    expect(report.score).toBeLessThan(30);
  });

  it("should count strong passwords correctly", () => {
    const items: DecryptedPasswordItem[] = [
      { id: "1", title: "Strong", password: "Xk9#mP2@qR7!nL5$vB3&wF8", updatedAt: NOW },
      { id: "2", title: "Weak", password: "123", updatedAt: NOW },
    ];

    const report = analyzeVaultHealth(items);
    expect(report.stats.strong).toBe(1);
    expect(report.stats.weak).toBe(1);
  });
});
