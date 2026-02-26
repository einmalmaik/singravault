// @ts-nocheck — RPC type inference broken for DB functions with params
// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 — see LICENSE
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { createClient } from "@supabase/supabase-js";

/**
 * Integration Test: 2FA Setup Flow
 * 
 * Feature: 2fa-encryption-fix
 * Validates: Requirements 1.4, 3.1, 3.2
 * 
 * This test verifies the complete 2FA setup flow:
 * 1. Create test user account
 * 2. Initialize 2FA secret using initialize_user_2fa_secret
 * 3. Retrieve secret using get_user_2fa_secret
 * 4. Verify retrieved secret matches original
 * 5. Test with p_require_enabled both true and false
 */

// Create a Supabase client with service role for testing
const supabaseUrl = process.env.VITE_SUPABASE_URL || "";
const supabaseServiceKey = process.env.SUPABASE_SERVICE_ROLE_KEY || "";

const supabase = createClient(supabaseUrl, supabaseServiceKey);

// Test user credentials
const TEST_USER_EMAIL = `test-2fa-${Date.now()}@example.com`;
const TEST_USER_PASSWORD = "TestPassword123!@#";
const TEST_TOTP_SECRET = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"; // Base32 TOTP secret

describe("2FA Setup Flow Integration Tests", () => {
  let testUserId: string | null = null;
  let testUserClient: ReturnType<typeof createClient> | null = null;

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

  afterAll(async () => {
    // Clean up test user
    if (testUserId) {
      try {
        // Delete user_2fa record
        await supabase
          .from("user_2fa")
          .delete()
          .eq("user_id", testUserId);

        // Delete user from auth.users (requires service role)
        await supabase.auth.admin.deleteUser(testUserId);
      } catch (error) {
        console.error("Failed to clean up test user:", error);
      }
    }
  });

  describe("Complete 2FA Setup Flow", () => {
    it("should create test user account", async () => {
      // Create a new user account
      const { data, error } = await supabase.auth.admin.createUser({
        email: TEST_USER_EMAIL,
        password: TEST_USER_PASSWORD,
        email_confirm: true,
      });

      expect(error).toBeNull();
      expect(data.user).toBeTruthy();
      expect(data.user?.id).toBeTruthy();

      testUserId = data.user!.id;

      // Create a client for the test user
      const anonKey = process.env.VITE_SUPABASE_ANON_KEY || process.env.SUPABASE_ANON_KEY || process.env.VITE_SUPABASE_PUBLISHABLE_KEY || "";
      testUserClient = createClient(supabaseUrl, anonKey);
      
      // Sign in as the test user
      const { data: signInData, error: signInError } = await testUserClient.auth.signInWithPassword({
        email: TEST_USER_EMAIL,
        password: TEST_USER_PASSWORD,
      });

      expect(signInError).toBeNull();
      expect(signInData.user).toBeTruthy();
      expect(signInData.session).toBeTruthy();
    });

    it("should initialize 2FA secret with initialize_user_2fa_secret", async () => {
      expect(testUserId).toBeTruthy();
      expect(testUserClient).toBeTruthy();

      // Call initialize_user_2fa_secret as the authenticated user
      const { data, error } = await testUserClient!.rpc("initialize_user_2fa_secret", {
        p_user_id: testUserId,
        p_secret: TEST_TOTP_SECRET,
      });

      expect(error).toBeNull();
      expect(data).toBeNull(); // Function returns void

      // Verify the record was created in user_2fa table
      const { data: userRecord, error: fetchError } = await supabase
        .from("user_2fa")
        .select("user_id, totp_secret_enc, is_enabled")
        .eq("user_id", testUserId)
        .single();

      expect(fetchError).toBeNull();
      expect(userRecord).toBeTruthy();
      expect(userRecord.user_id).toBe(testUserId);
      expect(userRecord.totp_secret_enc).toBeTruthy();
      expect(userRecord.is_enabled).toBe(false); // Should be disabled initially
    });

    it("should retrieve secret with get_user_2fa_secret when p_require_enabled is false", async () => {
      expect(testUserId).toBeTruthy();
      expect(testUserClient).toBeTruthy();

      // Retrieve the secret with p_require_enabled = false
      const { data: retrievedSecret, error } = await testUserClient!.rpc("get_user_2fa_secret", {
        p_user_id: testUserId,
        p_require_enabled: false,
      });

      expect(error).toBeNull();
      expect(retrievedSecret).toBeTruthy();
      expect(retrievedSecret).toBe(TEST_TOTP_SECRET);
    });

    it("should return NULL when p_require_enabled is true and 2FA is not enabled", async () => {
      expect(testUserId).toBeTruthy();
      expect(testUserClient).toBeTruthy();

      // Retrieve the secret with p_require_enabled = true (default)
      const { data: retrievedSecret, error } = await testUserClient!.rpc("get_user_2fa_secret", {
        p_user_id: testUserId,
        p_require_enabled: true,
      });

      expect(error).toBeNull();
      expect(retrievedSecret).toBeNull(); // Should be NULL because is_enabled is false
    });

    it("should retrieve secret after enabling 2FA", async () => {
      expect(testUserId).toBeTruthy();
      expect(testUserClient).toBeTruthy();

      // Enable 2FA for the test user
      const { error: updateError } = await supabase
        .from("user_2fa")
        .update({ is_enabled: true })
        .eq("user_id", testUserId);

      expect(updateError).toBeNull();

      // Now retrieve the secret with p_require_enabled = true
      const { data: retrievedSecret, error } = await testUserClient!.rpc("get_user_2fa_secret", {
        p_user_id: testUserId,
        p_require_enabled: true,
      });

      expect(error).toBeNull();
      expect(retrievedSecret).toBeTruthy();
      expect(retrievedSecret).toBe(TEST_TOTP_SECRET);
    });

    it("should prevent unauthorized access to another user's secret", async () => {
      expect(testUserId).toBeTruthy();
      expect(testUserClient).toBeTruthy();

      // Create a second test user
      const secondUserEmail = `test-2fa-second-${Date.now()}@example.com`;
      const { data: secondUserData, error: createError } = await supabase.auth.admin.createUser({
        email: secondUserEmail,
        password: TEST_USER_PASSWORD,
        email_confirm: true,
      });

      expect(createError).toBeNull();
      expect(secondUserData.user).toBeTruthy();

      const secondUserId = secondUserData.user!.id;

      try {
        // Try to access the first user's secret as the first user but with second user's ID
        const { data, error } = await testUserClient!.rpc("get_user_2fa_secret", {
          p_user_id: secondUserId, // Different user ID
          p_require_enabled: false,
        });

        // Should fail with Forbidden error
        expect(error).toBeTruthy();
        expect(error?.message).toContain("Forbidden");
        expect(data).toBeNull();
      } finally {
        // Clean up second user
        await supabase.auth.admin.deleteUser(secondUserId);
      }
    });
  });

  describe("Multiple Secret Initialization", () => {
    it("should replace existing disabled secret when initializing again", async () => {
      expect(testUserId).toBeTruthy();
      expect(testUserClient).toBeTruthy();

      const newSecret = "NEWBASE32SECRETNEWBASE32SECRETNEW";

      // Disable 2FA first
      await supabase
        .from("user_2fa")
        .update({ is_enabled: false })
        .eq("user_id", testUserId);

      // Initialize with a new secret
      const { error: initError } = await testUserClient!.rpc("initialize_user_2fa_secret", {
        p_user_id: testUserId,
        p_secret: newSecret,
      });

      expect(initError).toBeNull();

      // Retrieve the new secret
      const { data: retrievedSecret, error: getError } = await testUserClient!.rpc("get_user_2fa_secret", {
        p_user_id: testUserId,
        p_require_enabled: false,
      });

      expect(getError).toBeNull();
      expect(retrievedSecret).toBe(newSecret);
      expect(retrievedSecret).not.toBe(TEST_TOTP_SECRET);
    });
  });

  describe("Edge Cases", () => {
    it("should handle empty secret string", async () => {
      expect(testUserId).toBeTruthy();
      expect(testUserClient).toBeTruthy();

      const emptySecret = "";

      // Disable 2FA first
      await supabase
        .from("user_2fa")
        .update({ is_enabled: false })
        .eq("user_id", testUserId);

      // Initialize with empty secret
      const { error: initError } = await testUserClient!.rpc("initialize_user_2fa_secret", {
        p_user_id: testUserId,
        p_secret: emptySecret,
      });

      expect(initError).toBeNull();

      // Retrieve the empty secret
      const { data: retrievedSecret, error: getError } = await testUserClient!.rpc("get_user_2fa_secret", {
        p_user_id: testUserId,
        p_require_enabled: false,
      });

      expect(getError).toBeNull();
      expect(retrievedSecret).toBe(emptySecret);
    });

    it("should handle very long secret", async () => {
      expect(testUserId).toBeTruthy();
      expect(testUserClient).toBeTruthy();

      const longSecret = "A".repeat(500);

      // Disable 2FA first
      await supabase
        .from("user_2fa")
        .update({ is_enabled: false })
        .eq("user_id", testUserId);

      // Initialize with long secret
      const { error: initError } = await testUserClient!.rpc("initialize_user_2fa_secret", {
        p_user_id: testUserId,
        p_secret: longSecret,
      });

      expect(initError).toBeNull();

      // Retrieve the long secret
      const { data: retrievedSecret, error: getError } = await testUserClient!.rpc("get_user_2fa_secret", {
        p_user_id: testUserId,
        p_require_enabled: false,
      });

      expect(getError).toBeNull();
      expect(retrievedSecret).toBe(longSecret);
    });

    it("should handle special characters in secret", async () => {
      expect(testUserId).toBeTruthy();
      expect(testUserClient).toBeTruthy();

      const specialSecret = "Test!@#$%^&*()_+-=[]{}|;:',.<>?/~`";

      // Disable 2FA first
      await supabase
        .from("user_2fa")
        .update({ is_enabled: false })
        .eq("user_id", testUserId);

      // Initialize with special characters
      const { error: initError } = await testUserClient!.rpc("initialize_user_2fa_secret", {
        p_user_id: testUserId,
        p_secret: specialSecret,
      });

      expect(initError).toBeNull();

      // Retrieve the special secret
      const { data: retrievedSecret, error: getError } = await testUserClient!.rpc("get_user_2fa_secret", {
        p_user_id: testUserId,
        p_require_enabled: false,
      });

      expect(getError).toBeNull();
      expect(retrievedSecret).toBe(specialSecret);
    });
  });
});
