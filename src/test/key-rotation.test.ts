// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 — see LICENSE
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import * as fc from "fast-check";
import { createClient } from "@supabase/supabase-js";

/**
 * Property-Based Test: Key Rotation Preserves Data
 * 
 * Feature: 2fa-encryption-fix
 * Property 2: Round-Trip Encryption Preserves Data
 * Validates: Requirements 3.1, 3.2
 * 
 * This test verifies that for any set of TOTP secrets encrypted with key A,
 * rotating to key B and then decrypting with key B returns the original values.
 * 
 * Real auth.users are created via the Admin API to satisfy the foreign key
 * constraint on user_2fa.user_id -> auth.users(id).
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

// Generator for 64-character hex keys (32 bytes)
const hexKeyArbitrary = fc
  .array(fc.integer({ min: 0, max: 15 }), {
    minLength: 64,
    maxLength: 64,
  })
  .map((nums) => nums.map((n) => n.toString(16)).join(""));

// Maximum number of test users needed (matches maxLength of secrets array)
const MAX_TEST_USERS = 10;

// Store original key for restoration
let originalKey: string | null = null;

// Pre-created test user IDs (real auth.users entries)
const testUserIds: string[] = [];

describeIfSupabase("2FA Key Rotation Property Tests", () => {
  beforeAll(async () => {
    // 1. Store the original encryption key
    const { data, error } = await supabase.rpc("get_totp_encryption_key");
    
    if (error) {
      console.error("Failed to get encryption key:", error);
      throw new Error(
        "Encryption key not found. Please ensure the database migrations have been applied."
      );
    }
    
    originalKey = data;
    expect(originalKey).toBeTruthy();

    // 2. Create real test users in auth.users to satisfy FK constraints
    for (let i = 0; i < MAX_TEST_USERS; i++) {
      const email = `test-keyrot-${Date.now()}-${i}@example.com`;
      const { data: userData, error: userError } = await supabase.auth.admin.createUser({
        email,
        password: "TestKeyRotation123!@#",
        email_confirm: true,
      });

      if (userError || !userData.user) {
        throw new Error(`Failed to create test user ${i}: ${userError?.message}`);
      }

      testUserIds.push(userData.user.id);
    }

    expect(testUserIds.length).toBe(MAX_TEST_USERS);
  }, 60000); // 60s timeout for user creation

  afterAll(async () => {
    // 1. Clean up user_2fa records for all test users
    if (testUserIds.length > 0) {
      await supabase.from("user_2fa").delete().in("user_id", testUserIds);
    }

    // 2. Restore original encryption key
    if (originalKey) {
      try {
        await supabase.rpc("rotate_totp_encryption_key", {
          p_new_key: originalKey,
        });
      } catch (error) {
        console.error("Failed to restore original key:", error);
      }
    }

    // 3. Delete test users from auth.users
    for (const userId of testUserIds) {
      try {
        await supabase.auth.admin.deleteUser(userId);
      } catch {
        // Best-effort cleanup
      }
    }
  }, 30000);

  it("should preserve all secrets through key rotation (100+ iterations)", async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.array(base32StringArbitrary, { minLength: 1, maxLength: MAX_TEST_USERS }),
        hexKeyArbitrary,
        async (totpSecrets, newKey) => {
          // Use pre-created real user IDs (sliced to match secrets count)
          const userIds = testUserIds.slice(0, totpSecrets.length);

          try {
            // Step 1: Clean up any existing 2FA data for these users
            await supabase
              .from("user_2fa")
              .delete()
              .in("user_id", userIds);

            // Step 2: Encrypt secrets with current key (key A)
            const encryptedSecrets: string[] = [];
            for (const secret of totpSecrets) {
              const { data: encrypted, error: encErr } = await supabase.rpc(
                "user_2fa_encrypt_secret",
                { _secret: secret }
              );
              
              expect(encErr).toBeNull();
              expect(encrypted).toBeTruthy();
              encryptedSecrets.push(encrypted as string);
            }

            // Step 3: Insert 2FA records for real users
            const insertData = userIds.map((userId, index) => ({
              user_id: userId,
              totp_secret_enc: encryptedSecrets[index],
              is_enabled: true,
            }));

            const { error: insertError } = await supabase
              .from("user_2fa")
              .insert(insertData);

            expect(insertError).toBeNull();

            // Step 4: Rotate to new key (key B)
            const { data: rotatedCount, error: rotateError } = await supabase.rpc(
              "rotate_totp_encryption_key",
              { p_new_key: newKey }
            );

            expect(rotateError).toBeNull();
            // rotatedCount >= totpSecrets.length (may be more if other rows exist)
            expect(rotatedCount).toBeGreaterThanOrEqual(totpSecrets.length);

            // Step 5: Decrypt all secrets with new key and verify
            for (let i = 0; i < totpSecrets.length; i++) {
              const { data: userRecord, error: fetchError } = await supabase
                .from("user_2fa")
                .select("totp_secret_enc")
                .eq("user_id", userIds[i])
                .single();

              expect(fetchError).toBeNull();
              expect(userRecord).toBeTruthy();
              expect(userRecord.totp_secret_enc).toBeTruthy();

              // Decrypt with new key
              const { data: decrypted, error: decryptError } = await supabase.rpc(
                "user_2fa_decrypt_secret",
                { _secret_enc: userRecord.totp_secret_enc }
              );

              expect(decryptError).toBeNull();
              expect(decrypted).toBe(totpSecrets[i]);
            }

            // Step 6: Restore original key for next iteration
            if (originalKey) {
              await supabase.rpc("rotate_totp_encryption_key", {
                p_new_key: originalKey,
              });
            }
          } finally {
            // Clean up 2FA data for this iteration
            await supabase
              .from("user_2fa")
              .delete()
              .in("user_id", userIds);
          }
        }
      ),
      {
        numRuns: 100, // Run minimum 100 iterations as specified
        verbose: true,
      }
    );
  }, 300000); // 5 minute timeout for 100+ iterations with database operations

  it("should handle single secret rotation correctly", async () => {
    const testSecret = "JBSWY3DPEHPK3PXP"; // Example Base32 TOTP secret
    const testUserId = testUserIds[0]; // Use first pre-created real user
    const newKey = "a".repeat(64); // Simple test key

    try {
      // Clean up
      await supabase.from("user_2fa").delete().eq("user_id", testUserId);

      // Encrypt with current key
      const { data: encrypted, error: encryptError } = await supabase.rpc(
        "user_2fa_encrypt_secret",
        { _secret: testSecret }
      );

      expect(encryptError).toBeNull();
      expect(encrypted).toBeTruthy();

      // Insert 2FA record for real user
      const { error: insertError } = await supabase.from("user_2fa").insert({
        user_id: testUserId,
        totp_secret_enc: encrypted,
        is_enabled: true,
      });

      expect(insertError).toBeNull();

      // Rotate to new key
      const { data: rotatedCount, error: rotateError } = await supabase.rpc(
        "rotate_totp_encryption_key",
        { p_new_key: newKey }
      );

      expect(rotateError).toBeNull();
      expect(rotatedCount).toBeGreaterThanOrEqual(1);

      // Fetch and decrypt with new key
      const { data: userRecord } = await supabase
        .from("user_2fa")
        .select("totp_secret_enc")
        .eq("user_id", testUserId)
        .single();

      expect(userRecord).toBeTruthy();

      const { data: decrypted, error: decryptError } = await supabase.rpc(
        "user_2fa_decrypt_secret",
        { _secret_enc: userRecord.totp_secret_enc }
      );

      expect(decryptError).toBeNull();
      expect(decrypted).toBe(testSecret);

      // Restore original key
      if (originalKey) {
        await supabase.rpc("rotate_totp_encryption_key", {
          p_new_key: originalKey,
        });
      }
    } finally {
      // Clean up
      await supabase.from("user_2fa").delete().eq("user_id", testUserId);
    }
  });
});
