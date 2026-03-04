// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 — see LICENSE
/**
 * @fileoverview Integration Tests - TOTP, Two-Factor, Password Generator
 *
 * Tests the remaining critical services:
 * - TOTP Service: code generation, validation, URI parsing
 * - TwoFactorService: TOTP verification, backup code hashing
 * - PasswordGenerator: secure password/passphrase generation, strength analysis
 */

import { describe, it, expect, vi } from "vitest";

// ---------------------------------------------------------------------------
// Mock hash-wasm Argon2id with PBKDF2 for deterministic test execution.
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
  verifyBackupCodeHash,
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
      expect(uri).toContain("Singra%20Vault");
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
    it("should produce v3 versioned hash with Argon2id", async () => {
      const hash = await hashBackupCode("ABCD-EFGH");
      expect(hash).toMatch(/^v3:[A-Za-z0-9+/=]+:[0-9a-f]{64}$/);
    });

    it("should verify hash via verifyBackupCodeHash", async () => {
      const hash = await hashBackupCode("ABCD-EFGH");
      const valid = await verifyBackupCodeHash("ABCD-EFGH", hash);
      expect(valid).toBe(true);
    });

    it("should normalize dashes and case during verification", async () => {
      const hash = await hashBackupCode("ABCD-EFGH");
      const valid = await verifyBackupCodeHash("abcdefgh", hash);
      expect(valid).toBe(true);
    });

    it("should produce different hashes for different codes (unique salt)", async () => {
      const hash1 = await hashBackupCode("AAAA-BBBB");
      const hash2 = await hashBackupCode("CCCC-DDDD");
      // Different codes → different hash portion
      const hex1 = hash1.split(':')[2];
      const hex2 = hash2.split(':')[2];
      expect(hex1).not.toBe(hex2);
    });

    it("should reject wrong code during verification", async () => {
      const hash = await hashBackupCode("ABCD-EFGH");
      const valid = await verifyBackupCodeHash("XXXX-YYYY", hash);
      expect(valid).toBe(false);
    });

    it("should produce non-deterministic hashes (random salt per call)", async () => {
      const hash1 = await hashBackupCode("ABCD-EFGH");
      const hash2 = await hashBackupCode("ABCD-EFGH");
      // Same code but different random salts → different full hash strings
      expect(hash1).not.toBe(hash2);
      // But both should verify
      expect(await verifyBackupCodeHash("ABCD-EFGH", hash1)).toBe(true);
      expect(await verifyBackupCodeHash("ABCD-EFGH", hash2)).toBe(true);
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

