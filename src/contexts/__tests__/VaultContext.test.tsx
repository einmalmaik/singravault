// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 — see LICENSE
/**
 * @fileoverview Tests for VaultContext
 *
 * Tests vault state management, encryption/decryption, and locking.
 * Note: This file tests the core context functionality. Full integration
 * tests for crypto operations are in src/test/integration-*.test.ts
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { renderHook, act, waitFor } from "@testing-library/react";
import { VaultProvider, useVault } from "../VaultContext";
import type { ReactNode } from "react";

// ============ Mock Setup ============

// Mock AuthContext
const mockUser = { id: "test-user-123", email: "test@example.com" };
const mockUseAuth = vi.fn();
vi.mock("../AuthContext", () => ({
  useAuth: () => mockUseAuth(),
}));

// Mock Supabase client - use vi.hoisted() to avoid initialization errors
const mockSupabase = vi.hoisted(() => ({
  from: vi.fn(),
  auth: {
    onAuthStateChange: vi.fn(() => ({
      data: { subscription: { unsubscribe: vi.fn() } },
    })),
  },
}));
vi.mock("@/integrations/supabase/client", () => ({
  supabase: mockSupabase,
}));

// Mock crypto service
const mockDeriveKey = vi.fn();
const mockDeriveRawKey = vi.fn();
const mockImportMasterKey = vi.fn();
const mockGenerateSalt = vi.fn();
const mockCreateVerificationHash = vi.fn();
const mockVerifyKey = vi.fn();
const mockEncrypt = vi.fn();
const mockDecrypt = vi.fn();
const mockEncryptVaultItem = vi.fn();
const mockDecryptVaultItem = vi.fn();
const mockAttemptKdfUpgrade = vi.fn();

vi.mock("@/services/cryptoService", () => ({
  deriveKey: (...args: unknown[]) => mockDeriveKey(...args),
  deriveRawKey: (...args: unknown[]) => mockDeriveRawKey(...args),
  generateSalt: () => mockGenerateSalt(),
  encrypt: (...args: unknown[]) => mockEncrypt(...args),
  decrypt: (...args: unknown[]) => mockDecrypt(...args),
  importMasterKey: (...args: unknown[]) => mockImportMasterKey(...args),
  createVerificationHash: (...args: unknown[]) => mockCreateVerificationHash(...args),
  verifyKey: (...args: unknown[]) => mockVerifyKey(...args),
  encryptVaultItem: (...args: unknown[]) => mockEncryptVaultItem(...args),
  decryptVaultItem: (...args: unknown[]) => mockDecryptVaultItem(...args),
  clearReferences: vi.fn(),
  secureClear: vi.fn(),
  attemptKdfUpgrade: (...args: unknown[]) => mockAttemptKdfUpgrade(...args),
  CURRENT_KDF_VERSION: 2,
}));

// Mock offline vault service
vi.mock("@/services/offlineVaultService", () => ({
  isAppOnline: vi.fn(() => true),
  isLikelyOfflineError: vi.fn(() => false),
  getOfflineCredentials: vi.fn(() => Promise.resolve(null)),
  saveOfflineCredentials: vi.fn(() => Promise.resolve()),
}));

// Mock passkey service
const mockAuthenticatePasskey = vi.fn();
vi.mock("@/services/passkeyService", () => ({
  authenticatePasskey: () => mockAuthenticatePasskey(),
  isWebAuthnAvailable: vi.fn(() => false),
}));

// Mock duress service
vi.mock("@/services/duressService", () => ({
  getDuressConfig: vi.fn(() => Promise.resolve(null)),
  attemptDualUnlock: vi.fn(),
  isDecoyItem: vi.fn(() => false),
}));

// Mock rate limiter service
const mockGetUnlockCooldown = vi.fn(() => null);
const mockRecordFailedAttempt = vi.fn();
const mockResetUnlockAttempts = vi.fn();
vi.mock("@/services/rateLimiterService", () => ({
  getUnlockCooldown: () => mockGetUnlockCooldown(),
  recordFailedAttempt: () => mockRecordFailedAttempt(),
  resetUnlockAttempts: () => mockResetUnlockAttempts(),
}));

// Mock vault integrity service
vi.mock("@/services/vaultIntegrityService", () => ({
  deriveIntegrityKey: vi.fn(() => Promise.resolve({} as CryptoKey)),
  verifyVaultIntegrity: vi.fn(),
  updateIntegrityRoot: vi.fn(),
  clearIntegrityRoot: vi.fn(),
}));

// ============ Test Helpers ============

function createWrapper() {
  return function Wrapper({ children }: { children: ReactNode }) {
    return <VaultProvider>{children}</VaultProvider>;
  };
}

// ============ Test Suite ============

describe("VaultContext", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    sessionStorage.clear();
    localStorage.clear();

    // Default auth mock
    mockUseAuth.mockReturnValue({ user: mockUser, authReady: true });
    mockDeriveRawKey.mockResolvedValue(new Uint8Array(32));
    mockImportMasterKey.mockResolvedValue({} as CryptoKey);
    mockAuthenticatePasskey.mockResolvedValue({ success: true, encryptionKey: {} as CryptoKey });
    mockGetUnlockCooldown.mockReturnValue(null);

    // Default Supabase profile response - no vault setup yet
    // Support chained .eq() calls with proper mock structure
    const mockEqChain = {
      eq: vi.fn().mockReturnValue({
        single: vi.fn().mockResolvedValue({ data: null, error: null }),
      }),
      single: vi.fn().mockResolvedValue({ data: null, error: null }),
      limit: vi.fn().mockResolvedValue({ data: [], error: null }),
    };

    mockSupabase.from.mockReturnValue({
      select: vi.fn().mockReturnValue({
        eq: vi.fn().mockReturnValue(mockEqChain),
      }),
      insert: vi.fn().mockReturnValue({
        select: vi.fn().mockResolvedValue({ data: [{ id: "vault-123" }], error: null }),
      }),
      update: vi.fn().mockReturnValue({
        eq: vi.fn().mockResolvedValue({ data: null, error: null }),
      }),
    });
  });

  afterEach(() => {
    vi.clearAllTimers();
  });

  describe("Hook error handling", () => {
    it("should throw error when useVault is called outside VaultProvider", () => {
      expect(() => {
        renderHook(() => useVault());
      }).toThrow("useVault must be used within a VaultProvider");
    });
  });

  describe("Initial state", () => {
    it("should start with vault locked", async () => {
      const { result } = renderHook(() => useVault(), { wrapper: createWrapper() });

      await waitFor(() => {
        expect(result.current.isLoading).toBe(false);
      });

      expect(result.current.isLocked).toBe(true);
      expect(result.current.isDuressMode).toBe(false);
    });

    it("should detect setup is required when no profile exists", async () => {
      const { result } = renderHook(() => useVault(), { wrapper: createWrapper() });

      await waitFor(() => {
        expect(result.current.isLoading).toBe(false);
      });

      expect(result.current.isSetupRequired).toBe(true);
    });

    it("should load existing vault setup from profile", async () => {
      // Mock existing profile with vault setup
      mockSupabase.from.mockReturnValue({
        select: vi.fn().mockReturnValue({
          eq: vi.fn().mockReturnValue({
            single: vi.fn().mockResolvedValue({
              data: {
                encryption_salt: "test-salt-123",
                master_password_verifier: "test-verifier-456",
                kdf_version: 2,
              },
              error: null,
            }),
            limit: vi.fn().mockResolvedValue({
              data: [],
              error: null,
            }),
          }),
        }),
      });

      const { result } = renderHook(() => useVault(), { wrapper: createWrapper() });

      await waitFor(() => {
        expect(result.current.isLoading).toBe(false);
      });

      expect(result.current.isSetupRequired).toBe(false);
      expect(result.current.isLocked).toBe(true);
    });

    it("should run checkSetup when authReady transitions from false to true", async () => {
      // Regression test for stale-closure P1 bug (Commit 19bb7e8):
      // authReady was missing from the useEffect dep array, so checkSetup() never
      // re-ran when authReady became true without a simultaneous user change.

      // Start: user present but authReady=false (INITIAL_SESSION window).
      // Case B guard fires: early return WITHOUT setting isLoading=false.
      // isLoading stays true — spinner shown, no stale-defaults flash (Bug 4 fix).
      mockUseAuth.mockReturnValue({ user: mockUser, authReady: false });

      const { result, rerender } = renderHook(() => useVault(), {
        wrapper: createWrapper(),
      });

      // isLoading must remain TRUE — setup is pending, not yet aborted.
      // Supabase must NOT be called yet (auth not ready).
      await waitFor(() => {
        expect(result.current.isLoading).toBe(true);
      });
      expect(mockSupabase.from).not.toHaveBeenCalledWith("profiles");

      // Now auth becomes ready (Supabase session synchronized) without user changing.
      mockUseAuth.mockReturnValue({ user: mockUser, authReady: true });
      rerender();

      // With the dep-array fix, the useEffect re-runs and calls checkSetup().
      // The default mock returns no profile → isSetupRequired becomes true.
      await waitFor(() => {
        expect(result.current.isSetupRequired).toBe(true);
      });
      // isLoading must be false after checkSetup() completes (finally block)
      expect(result.current.isLoading).toBe(false);
      // Verify Supabase was actually called (proof that checkSetup ran)
      expect(mockSupabase.from).toHaveBeenCalledWith("profiles");
    });

    it("should keep isLoading true when user is set but authReady is false", async () => {
      // Regression test for Bug 4 (premature isLoading=false in INITIAL_SESSION window):
      // Before the guard split, both (!user) and (!authReady) paths called
      // setIsLoading(false). Now Case B (user set, authReady=false) returns
      // immediately without touching isLoading, preserving the spinner.
      mockUseAuth.mockReturnValue({ user: mockUser, authReady: false });

      const { result } = renderHook(() => useVault(), {
        wrapper: createWrapper(),
      });

      // Spin for 100ms — isLoading must remain true the entire time.
      // (waitFor with negation: give it time and confirm it never went false.)
      await new Promise((r) => setTimeout(r, 100));
      expect(result.current.isLoading).toBe(true);

      // hasPasskeyUnlock must NOT have been cleared — user exists, data unknown.
      // (Only cleared when user is definitively absent.)
      expect(result.current.isLoading).toBe(true);
    });

    it("should set isLoading false and clear passkeys when user is null", async () => {
      // Regression test for Bug 4 (Case A guard):
      // When there is no user, isLoading must end immediately so the UI
      // can show the sign-in screen without waiting.
      mockUseAuth.mockReturnValue({ user: null, authReady: false });

      const { result } = renderHook(() => useVault(), {
        wrapper: createWrapper(),
      });

      await waitFor(() => {
        expect(result.current.isLoading).toBe(false);
      });
      // Supabase must never have been touched — no user, no fetch.
      expect(mockSupabase.from).not.toHaveBeenCalledWith("profiles");
    });
  });

  describe("setupMasterPassword", () => {
    it("should set up master password for first-time users", async () => {
      mockGenerateSalt.mockReturnValue("new-salt-789");
      mockDeriveKey.mockResolvedValue({} as CryptoKey);
      mockCreateVerificationHash.mockResolvedValue("new-verifier-abc");

      const { result } = renderHook(() => useVault(), { wrapper: createWrapper() });

      await waitFor(() => {
        expect(result.current.isLoading).toBe(false);
      });

      let setupResult: { error: Error | null } | undefined;
      await act(async () => {
        setupResult = await result.current.setupMasterPassword("SecurePassword123!");
      });

      expect(setupResult?.error).toBeNull();
      expect(mockGenerateSalt).toHaveBeenCalled();
      expect(mockDeriveKey).toHaveBeenCalledWith("SecurePassword123!", "new-salt-789", 2);
      expect(mockCreateVerificationHash).toHaveBeenCalled();

      // Vault should be unlocked after setup
      expect(result.current.isLocked).toBe(false);
      expect(result.current.isSetupRequired).toBe(false);
    });

    it("should return error when user is not logged in", async () => {
      mockUseAuth.mockReturnValue({ user: null, authReady: true });

      const { result } = renderHook(() => useVault(), { wrapper: createWrapper() });

      await waitFor(() => {
        expect(result.current.isLoading).toBe(false);
      });

      let setupResult: { error: Error | null } | undefined;
      await act(async () => {
        setupResult = await result.current.setupMasterPassword("password");
      });

      expect(setupResult?.error).toBeInstanceOf(Error);
      expect(setupResult?.error?.message).toBe("No user logged in");
    });
  });

  describe("unlock", () => {
    beforeEach(() => {
      // Mock existing profile
      mockSupabase.from.mockReturnValue({
        select: vi.fn().mockReturnValue({
          eq: vi.fn().mockReturnValue({
            single: vi.fn().mockResolvedValue({
              data: {
                encryption_salt: "existing-salt",
                master_password_verifier: "existing-verifier",
                kdf_version: 2,
              },
              error: null,
            }),
            limit: vi.fn().mockResolvedValue({
              data: [],
              error: null,
            }),
          }),
        }),
        update: vi.fn().mockReturnValue({
          eq: vi.fn().mockResolvedValue({ data: null, error: null }),
        }),
      });
    });

    it("should unlock vault with correct password", async () => {
      mockDeriveKey.mockResolvedValue({} as CryptoKey);
      mockVerifyKey.mockResolvedValue(true);
      mockAttemptKdfUpgrade.mockResolvedValue({ upgraded: false });

      const { result } = renderHook(() => useVault(), { wrapper: createWrapper() });

      await waitFor(() => {
        expect(result.current.isLoading).toBe(false);
      });

      expect(result.current.isLocked).toBe(true);

      let unlockResult: { error: Error | null } | undefined;
      await act(async () => {
        unlockResult = await result.current.unlock("CorrectPassword!");
      });

      expect(unlockResult?.error).toBeNull();
      expect(mockDeriveKey).toHaveBeenCalledWith("CorrectPassword!", "existing-salt", 2, undefined);
      expect(mockVerifyKey).toHaveBeenCalled();
      expect(result.current.isLocked).toBe(false);
    });

    it("should return error with incorrect password", async () => {
      mockDeriveKey.mockResolvedValue({} as CryptoKey);
      mockVerifyKey.mockResolvedValue(false);

      const { result } = renderHook(() => useVault(), { wrapper: createWrapper() });

      await waitFor(() => {
        expect(result.current.isLoading).toBe(false);
      });

      let unlockResult: { error: Error | null } | undefined;
      await act(async () => {
        unlockResult = await result.current.unlock("WrongPassword");
      });

      expect(unlockResult?.error).toBeInstanceOf(Error);
      expect(unlockResult?.error?.message).toBe("Invalid master password");
      expect(result.current.isLocked).toBe(true);
    });
  });

  describe("unlockWithPasskey", () => {
    it("should return explicit NO_PRF error for non-unlock-capable passkeys", async () => {
      mockAuthenticatePasskey.mockResolvedValue({ success: false, error: "NO_PRF" });

      const { result } = renderHook(() => useVault(), { wrapper: createWrapper() });

      await waitFor(() => {
        expect(result.current.isLoading).toBe(false);
      });

      let unlockResult: { error: Error | null } | undefined;
      await act(async () => {
        unlockResult = await result.current.unlockWithPasskey();
      });

      expect(unlockResult?.error?.message).toContain("does not support vault unlock");
    });

    it("should respect cooldown before passkey authentication", async () => {
      mockGetUnlockCooldown.mockReturnValue(5000);

      const { result } = renderHook(() => useVault(), { wrapper: createWrapper() });

      await waitFor(() => {
        expect(result.current.isLoading).toBe(false);
      });

      let unlockResult: { error: Error | null } | undefined;
      await act(async () => {
        unlockResult = await result.current.unlockWithPasskey();
      });

      expect(unlockResult?.error?.message).toContain("Too many attempts");
      expect(mockAuthenticatePasskey).not.toHaveBeenCalled();
    });

    it("should record failed attempts for passkey verification errors", async () => {
      mockAuthenticatePasskey.mockResolvedValue({ success: false, error: "Server verification failed" });

      const { result } = renderHook(() => useVault(), { wrapper: createWrapper() });

      await waitFor(() => {
        expect(result.current.isLoading).toBe(false);
      });

      await act(async () => {
        await result.current.unlockWithPasskey();
      });

      expect(mockRecordFailedAttempt).toHaveBeenCalledTimes(1);
    });
  });

  describe("getRawKeyForPasskey", () => {
    it("should reject wrong master password and wipe derived raw key bytes", async () => {
      const rawBytes = new Uint8Array(32).fill(7);
      mockDeriveRawKey.mockResolvedValue(rawBytes);
      mockDeriveKey.mockResolvedValue({} as CryptoKey);
      mockAttemptKdfUpgrade.mockResolvedValue({ upgraded: false });
      mockVerifyKey
        .mockResolvedValueOnce(true)  // unlock()
        .mockResolvedValueOnce(false); // getRawKeyForPasskey()

      // Mock existing profile with vault setup
      mockSupabase.from.mockReturnValue({
        select: vi.fn().mockReturnValue({
          eq: vi.fn().mockReturnValue({
            single: vi.fn().mockResolvedValue({
              data: {
                encryption_salt: "existing-salt",
                master_password_verifier: "existing-verifier",
                kdf_version: 2,
              },
              error: null,
            }),
            limit: vi.fn().mockResolvedValue({
              data: [],
              error: null,
            }),
          }),
        }),
        update: vi.fn().mockReturnValue({
          eq: vi.fn().mockResolvedValue({ data: null, error: null }),
        }),
      });

      const { result } = renderHook(() => useVault(), { wrapper: createWrapper() });

      await waitFor(() => {
        expect(result.current.isLoading).toBe(false);
      });

      await act(async () => {
        await result.current.unlock("CorrectPassword!");
      });

      let rawKey: Uint8Array | null = null;
      await act(async () => {
        rawKey = await result.current.getRawKeyForPasskey("WrongPassword!");
      });

      expect(rawKey).toBeNull();
      expect(Array.from(rawBytes).every((value) => value === 0)).toBe(true);
    });
  });

  describe("lock", () => {
    it("should lock the vault and clear encryption key", async () => {
      // Setup unlocked vault
      mockGenerateSalt.mockReturnValue("salt");
      mockDeriveKey.mockResolvedValue({} as CryptoKey);
      mockCreateVerificationHash.mockResolvedValue("verifier");

      const { result } = renderHook(() => useVault(), { wrapper: createWrapper() });

      await waitFor(() => {
        expect(result.current.isLoading).toBe(false);
      });

      // Setup and unlock
      await act(async () => {
        await result.current.setupMasterPassword("password");
      });

      expect(result.current.isLocked).toBe(false);

      // Lock
      act(() => {
        result.current.lock();
      });

      expect(result.current.isLocked).toBe(true);
      expect(result.current.isDuressMode).toBe(false);
    });
  });

  describe("Encryption helpers", () => {
    beforeEach(async () => {
      // Setup unlocked vault for encryption tests
      mockGenerateSalt.mockReturnValue("salt");
      mockDeriveKey.mockResolvedValue({} as CryptoKey);
      mockCreateVerificationHash.mockResolvedValue("verifier");
    });

    it("should encrypt data when vault is unlocked", async () => {
      mockEncrypt.mockResolvedValue("encrypted-data-xyz");

      const { result } = renderHook(() => useVault(), { wrapper: createWrapper() });

      await waitFor(() => {
        expect(result.current.isLoading).toBe(false);
      });

      await act(async () => {
        await result.current.setupMasterPassword("password");
      });

      let encrypted: string | undefined;
      await act(async () => {
        encrypted = await result.current.encryptData("plaintext");
      });

      expect(encrypted).toBe("encrypted-data-xyz");
      expect(mockEncrypt).toHaveBeenCalledWith("plaintext", expect.anything());
    });

    it("should decrypt data when vault is unlocked", async () => {
      mockDecrypt.mockResolvedValue("decrypted-plaintext");

      const { result } = renderHook(() => useVault(), { wrapper: createWrapper() });

      await waitFor(() => {
        expect(result.current.isLoading).toBe(false);
      });

      await act(async () => {
        await result.current.setupMasterPassword("password");
      });

      let decrypted: string | undefined;
      await act(async () => {
        decrypted = await result.current.decryptData("encrypted-data");
      });

      expect(decrypted).toBe("decrypted-plaintext");
      expect(mockDecrypt).toHaveBeenCalledWith("encrypted-data", expect.anything());
    });

    it("should throw error when trying to encrypt with locked vault", async () => {
      const { result } = renderHook(() => useVault(), { wrapper: createWrapper() });

      await waitFor(() => {
        expect(result.current.isLoading).toBe(false);
      });

      // Vault is locked, attempt encrypt
      await expect(async () => {
        await act(async () => {
          await result.current.encryptData("plaintext");
        });
      }).rejects.toThrow("Vault is locked");
    });

    it("should throw error when trying to decrypt with locked vault", async () => {
      const { result } = renderHook(() => useVault(), { wrapper: createWrapper() });

      await waitFor(() => {
        expect(result.current.isLoading).toBe(false);
      });

      // Vault is locked, attempt decrypt
      await expect(async () => {
        await act(async () => {
          await result.current.decryptData("encrypted-data");
        });
      }).rejects.toThrow("Vault is locked");
    });

    it("should encrypt vault item when unlocked", async () => {
      mockEncryptVaultItem.mockResolvedValue("encrypted-item-json");

      const { result } = renderHook(() => useVault(), { wrapper: createWrapper() });

      await waitFor(() => {
        expect(result.current.isLoading).toBe(false);
      });

      await act(async () => {
        await result.current.setupMasterPassword("password");
      });

      const itemData = {
        title: "Test Login",
        username: "user@example.com",
        password: "secret123",
        type: "password" as const,
      };

      let encrypted: string | undefined;
      await act(async () => {
        encrypted = await result.current.encryptItem(itemData);
      });

      expect(encrypted).toBe("encrypted-item-json");
      expect(mockEncryptVaultItem).toHaveBeenCalledWith(itemData, expect.anything(), undefined);
    });

    it("should decrypt vault item when unlocked", async () => {
      const decryptedItem = {
        title: "Test Login",
        username: "user@example.com",
        password: "secret123",
        type: "password" as const,
      };
      mockDecryptVaultItem.mockResolvedValue(decryptedItem);

      const { result } = renderHook(() => useVault(), { wrapper: createWrapper() });

      await waitFor(() => {
        expect(result.current.isLoading).toBe(false);
      });

      await act(async () => {
        await result.current.setupMasterPassword("password");
      });

      let decrypted: unknown;
      await act(async () => {
        decrypted = await result.current.decryptItem("encrypted-item-data");
      });

      expect(decrypted).toEqual(decryptedItem);
      expect(mockDecryptVaultItem).toHaveBeenCalledWith("encrypted-item-data", expect.anything(), undefined);
    });
  });

  describe("Auto-lock settings", () => {
    it("should allow setting auto-lock timeout", async () => {
      // Mock cookie consent
      localStorage.setItem("singra-cookie-consent", JSON.stringify({ optional: true }));

      const { result } = renderHook(() => useVault(), { wrapper: createWrapper() });

      await waitFor(() => {
        expect(result.current.isLoading).toBe(false);
      });

      expect(result.current.autoLockTimeout).toBe(15 * 60 * 1000); // Default 15 minutes

      act(() => {
        result.current.setAutoLockTimeout(30 * 60 * 1000); // 30 minutes
      });

      expect(result.current.autoLockTimeout).toBe(30 * 60 * 1000);
      expect(localStorage.getItem("singra_autolock")).toBe("1800000");
    });

    it("should not persist auto-lock timeout without cookie consent", async () => {
      // No cookie consent
      localStorage.removeItem("singra-cookie-consent");

      const { result } = renderHook(() => useVault(), { wrapper: createWrapper() });

      await waitFor(() => {
        expect(result.current.isLoading).toBe(false);
      });

      act(() => {
        result.current.setAutoLockTimeout(30 * 60 * 1000);
      });

      expect(result.current.autoLockTimeout).toBe(30 * 60 * 1000);
      expect(localStorage.getItem("singra_autolock")).toBeNull();
    });
  });

  describe("WebAuthn availability", () => {
    it("should indicate WebAuthn is not available by default", async () => {
      const { result } = renderHook(() => useVault(), { wrapper: createWrapper() });

      await waitFor(() => {
        expect(result.current.isLoading).toBe(false);
      });

      expect(result.current.webAuthnAvailable).toBe(false);
      expect(result.current.hasPasskeyUnlock).toBe(false);
    });
  });
});
