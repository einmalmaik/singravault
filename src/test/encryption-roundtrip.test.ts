// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 — see LICENSE
import { describe, it, expect, beforeAll } from "vitest";
import * as fc from "fast-check";
import { createClient } from "@supabase/supabase-js";

/**
 * Property-Based Test: Encryption Round-Trip
 * 
 * Feature: 2fa-encryption-fix
 * Property 2: Round-Trip Encryption Preserves Data
 * Validates: Requirements 3.1, 3.2
 * 
 * This test verifies that for any TOTP secret, encrypting with user_2fa_encrypt_secret
 * then decrypting with user_2fa_decrypt_secret returns the original secret value.
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

// Base32 alphabet (used for TOTP secrets)
const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

// Generator for Base32 strings (16-32 characters)
const base32StringArbitrary = fc
  .integer({ min: 16, max: 32 })
  .chain((length) =>
    fc
      .array(fc.constantFrom(...BASE32_ALPHABET.split("")), {
        minLength: length,
        maxLength: length,
      })
      .map((chars) => chars.join(""))
  );

describeIfSupabase("2FA Encryption Round-Trip Property Tests", () => {
  beforeAll(async () => {
    // Verify that the encryption key exists in the database
    const { data, error } = await supabase.rpc("get_totp_encryption_key");
    
    if (error) {
      console.error("Failed to get encryption key:", error);
      throw new Error(
        "Encryption key not found. Please ensure the database migrations have been applied."
      );
    }
    
    expect(data).toBeTruthy();
  });

  it("should preserve data through encrypt-decrypt round-trip (100+ iterations)", async () => {
    await fc.assert(
      fc.asyncProperty(base32StringArbitrary, async (totpSecret) => {
        // Encrypt the secret
        const { data: encryptedSecret, error: encryptError } = await supabase.rpc(
          "user_2fa_encrypt_secret",
          { _secret: totpSecret }
        );

        // Verify encryption succeeded
        expect(encryptError).toBeNull();
        expect(encryptedSecret).toBeTruthy();
        expect(typeof encryptedSecret).toBe("string");

        // Decrypt the secret
        const { data: decryptedSecret, error: decryptError } = await supabase.rpc(
          "user_2fa_decrypt_secret",
          { _secret_enc: encryptedSecret }
        );

        // Verify decryption succeeded
        expect(decryptError).toBeNull();
        expect(decryptedSecret).toBeTruthy();

        // Verify round-trip preserves the original value
        expect(decryptedSecret).toBe(totpSecret);
      }),
      {
        numRuns: 100, // Run minimum 100 iterations as specified
        verbose: true,
      }
    );
  }, 60000); // 60 second timeout for 100+ database calls

  it("should produce different ciphertext for the same secret", async () => {
    const testSecret = "JBSWY3DPEHPK3PXP"; // Example Base32 TOTP secret

    // Encrypt the same secret twice
    const { data: encrypted1, error: error1 } = await supabase.rpc(
      "user_2fa_encrypt_secret",
      { _secret: testSecret }
    );

    const { data: encrypted2, error: error2 } = await supabase.rpc(
      "user_2fa_encrypt_secret",
      { _secret: testSecret }
    );

    expect(error1).toBeNull();
    expect(error2).toBeNull();
    expect(encrypted1).toBeTruthy();
    expect(encrypted2).toBeTruthy();

    // Ciphertext should differ due to random IV
    expect(encrypted1).not.toBe(encrypted2);

    // But both should decrypt to the same original value
    const { data: decrypted1 } = await supabase.rpc("user_2fa_decrypt_secret", {
      _secret_enc: encrypted1,
    });

    const { data: decrypted2 } = await supabase.rpc("user_2fa_decrypt_secret", {
      _secret_enc: encrypted2,
    });

    expect(decrypted1).toBe(testSecret);
    expect(decrypted2).toBe(testSecret);
  });
});
