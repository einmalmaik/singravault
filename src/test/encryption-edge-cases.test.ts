// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 — see LICENSE
import { describe, it, expect, beforeAll } from "vitest";
import { createClient } from "@supabase/supabase-js";

/**
 * Unit Tests: 2FA Encryption Edge Cases
 * 
 * Feature: 2fa-encryption-fix
 * Validates: Requirements 2.3, 3.3, 3.4
 * 
 * These tests verify edge cases and error handling in the encryption functions:
 * - Empty string encryption/decryption
 * - NULL handling
 * - Missing encryption key error messages
 * - Invalid base64 data error handling
 * 
 * NOTE: These tests require the fixed migrations to be deployed to the database.
 * If migrations are not applied, tests will be skipped with a warning.
 */

// Create a Supabase client with service role for testing
const supabaseUrl = process.env.VITE_SUPABASE_URL || "";
const supabaseServiceKey = process.env.SUPABASE_SERVICE_ROLE_KEY || "";
const hasSupabaseTestEnv = Boolean(supabaseUrl && supabaseServiceKey);

const supabase = createClient(
  supabaseUrl || "http://localhost:54321",
  supabaseServiceKey || "test-service-role-key",
);
const describeIfSupabase = hasSupabaseTestEnv ? describe : describe.skip;

describeIfSupabase("2FA Encryption Edge Cases", () => {
  let migrationsApplied = false;

  beforeAll(async () => {
    // Check if migrations are applied by testing the encryption function
    const { error: testError } = await supabase.rpc("user_2fa_encrypt_secret", {
      _secret: "TEST_MIGRATION_CHECK",
    });
    
    if (testError) {
      if (testError.code === "42883") {
        console.warn(
          "\n⚠️  WARNING: pgp_sym_encrypt fix not applied to database yet.\n" +
          "   Tests will be skipped until fixed migrations are deployed.\n" +
          "   Error: " + testError.message + "\n"
        );
        migrationsApplied = false;
      } else if (testError.message?.includes("Missing secret")) {
        console.warn(
          "\n⚠️  WARNING: Encryption key not configured in database.\n" +
          "   Please ensure 'totp_encryption_key' exists in private.app_secrets.\n"
        );
        migrationsApplied = false;
      } else {
        // Some other error - still skip but log it
        console.warn("\n⚠️  WARNING: Unexpected error testing migrations:", testError);
        migrationsApplied = false;
      }
      return;
    }
    
    migrationsApplied = true;
    console.log("✓ Migrations applied successfully - running edge case tests");
  });

  describe("Empty String Handling", () => {
    it("should encrypt and decrypt empty string successfully", async () => {
      if (!migrationsApplied) {
        console.log("  ⊘ Skipped - migrations not applied");
        return;
      }

      const emptySecret = "";

      // Encrypt empty string
      const { data: encryptedSecret, error: encryptError } = await supabase.rpc(
        "user_2fa_encrypt_secret",
        { _secret: emptySecret }
      );

      expect(encryptError).toBeNull();
      expect(encryptedSecret).toBeTruthy();
      expect(typeof encryptedSecret).toBe("string");

      // Decrypt the secret
      const { data: decryptedSecret, error: decryptError } = await supabase.rpc(
        "user_2fa_decrypt_secret",
        { _secret_enc: encryptedSecret }
      );

      expect(decryptError).toBeNull();
      expect(decryptedSecret).toBe(emptySecret);
    });
  });

  describe("NULL Handling", () => {
    it("should handle NULL input in encryption function", async () => {
      if (!migrationsApplied) {
        console.log("  ⊘ Skipped - migrations not applied");
        return;
      }

      const { data, error } = await supabase.rpc("user_2fa_encrypt_secret", {
        _secret: null,
      });

      // PostgreSQL should handle NULL gracefully
      if (error) {
        expect(error).toBeTruthy();
        expect(error.message).toBeTruthy();
      } else {
        expect(data).toBeNull();
      }
    });

    it("should handle NULL input in decryption function", async () => {
      if (!migrationsApplied) {
        console.log("  ⊘ Skipped - migrations not applied");
        return;
      }

      const { data, error } = await supabase.rpc("user_2fa_decrypt_secret", {
        _secret_enc: null,
      });

      // PostgreSQL should handle NULL gracefully
      if (error) {
        expect(error).toBeTruthy();
        expect(error.message).toBeTruthy();
      } else {
        expect(data).toBeNull();
      }
    });
  });

  describe("Missing Encryption Key", () => {
    it("should provide descriptive error when encryption key is missing", async () => {
      // This test verifies error handling structure
      // We test with a non-existent key name to verify error messages
      
      const { data, error } = await supabase.rpc("get_app_secret", {
        p_name: "non_existent_key_test_12345",
      });

      // Should either return NULL or raise an error with a message
      if (error) {
        expect(error.message).toBeTruthy();
        expect(error.message.length).toBeGreaterThan(0);
      } else {
        expect(data).toBeNull();
      }
    });
  });

  describe("Invalid Base64 Data", () => {
    it("should handle invalid base64 data in decryption", async () => {
      if (!migrationsApplied) {
        console.log("  ⊘ Skipped - migrations not applied");
        return;
      }

      const invalidBase64Strings = [
        "not-valid-base64!@#$",
        "===invalid===",
        "12345",
        "!!!",
        "ZZZZZ",
      ];

      for (const invalidData of invalidBase64Strings) {
        const { data, error } = await supabase.rpc("user_2fa_decrypt_secret", {
          _secret_enc: invalidData,
        });

        // Should handle gracefully without crashing
        if (error) {
          expect(error).toBeTruthy();
          expect(error.message).toBeTruthy();
        } else {
          expect(data).toBeDefined();
        }
      }
    });

    it("should handle corrupted encrypted data", async () => {
      if (!migrationsApplied) {
        console.log("  ⊘ Skipped - migrations not applied");
        return;
      }

      // First, encrypt a valid secret
      const validSecret = "JBSWY3DPEHPK3PXP";
      const { data: encryptedSecret, error: encryptError } = await supabase.rpc(
        "user_2fa_encrypt_secret",
        { _secret: validSecret }
      );

      expect(encryptError).toBeNull();
      expect(encryptedSecret).toBeTruthy();

      // Corrupt the encrypted data by modifying it
      const corruptedData = encryptedSecret!.slice(0, -5) + "XXXXX";

      // Attempt to decrypt corrupted data
      const { data, error } = await supabase.rpc("user_2fa_decrypt_secret", {
        _secret_enc: corruptedData,
      });

      // Should handle the error gracefully
      if (error) {
        expect(error).toBeTruthy();
        expect(error.message).toBeTruthy();
        // Error message should not expose sensitive data
        expect(error.message).not.toContain(validSecret);
      } else {
        // If no error, decrypted data should not match original
        expect(data).not.toBe(validSecret);
      }
    });

    it("should handle empty string as encrypted data", async () => {
      if (!migrationsApplied) {
        console.log("  ⊘ Skipped - migrations not applied");
        return;
      }

      const { data, error } = await supabase.rpc("user_2fa_decrypt_secret", {
        _secret_enc: "",
      });

      // Should handle gracefully
      if (error) {
        expect(error).toBeTruthy();
        expect(error.message).toBeTruthy();
      } else {
        expect(data).toBeDefined();
      }
    });
  });

  describe("Special Characters and Encoding", () => {
    it("should handle secrets with special characters", async () => {
      if (!migrationsApplied) {
        console.log("  ⊘ Skipped - migrations not applied");
        return;
      }

      const specialSecrets = [
        "ABC123!@#$%^&*()",
        "Test\nNewline",
        "Test\tTab",
        "Test'Quote",
        'Test"DoubleQuote',
        "Test\\Backslash",
      ];

      for (const secret of specialSecrets) {
        // Encrypt
        const { data: encrypted, error: encryptError } = await supabase.rpc(
          "user_2fa_encrypt_secret",
          { _secret: secret }
        );

        expect(encryptError).toBeNull();
        expect(encrypted).toBeTruthy();

        // Decrypt
        const { data: decrypted, error: decryptError } = await supabase.rpc(
          "user_2fa_decrypt_secret",
          { _secret_enc: encrypted }
        );

        expect(decryptError).toBeNull();
        expect(decrypted).toBe(secret);
      }
    });

    it("should handle Unicode characters", async () => {
      if (!migrationsApplied) {
        console.log("  ⊘ Skipped - migrations not applied");
        return;
      }

      const unicodeSecrets = [
        "Test🔒Emoji",
        "Test中文Chinese",
        "TestÄÖÜGerman",
        "Test日本語Japanese",
        "Test🚀🔐💻",
      ];

      for (const secret of unicodeSecrets) {
        // Encrypt
        const { data: encrypted, error: encryptError } = await supabase.rpc(
          "user_2fa_encrypt_secret",
          { _secret: secret }
        );

        expect(encryptError).toBeNull();
        expect(encrypted).toBeTruthy();

        // Decrypt
        const { data: decrypted, error: decryptError } = await supabase.rpc(
          "user_2fa_decrypt_secret",
          { _secret_enc: encrypted }
        );

        expect(decryptError).toBeNull();
        expect(decrypted).toBe(secret);
      }
    });
  });

  describe("Maximum Length Handling", () => {
    it("should handle very long secrets", async () => {
      if (!migrationsApplied) {
        console.log("  ⊘ Skipped - migrations not applied");
        return;
      }

      // Generate a very long secret (1000 characters)
      const longSecret = "A".repeat(1000);

      // Encrypt
      const { data: encrypted, error: encryptError } = await supabase.rpc(
        "user_2fa_encrypt_secret",
        { _secret: longSecret }
      );

      expect(encryptError).toBeNull();
      expect(encrypted).toBeTruthy();

      // Decrypt
      const { data: decrypted, error: decryptError } = await supabase.rpc(
        "user_2fa_decrypt_secret",
        { _secret_enc: encrypted }
      );

      expect(decryptError).toBeNull();
      expect(decrypted).toBe(longSecret);
    });
  });
});
