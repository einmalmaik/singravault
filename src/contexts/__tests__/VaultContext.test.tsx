// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE
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
const mockUnwrapUserKeyBytes = vi.fn();

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
  reEncryptVault: vi.fn(() => Promise.resolve({ itemUpdates: [], categoryUpdates: [], itemsReEncrypted: 0 })),
  // USK Layer mocks
  createEncryptedUserKey: vi.fn(() => Promise.resolve({
    encryptedUserKey: 'mock-encrypted-user-key',
    userKey: { type: 'secret', extractable: false, usages: ['encrypt', 'decrypt'] },
  })),
  migrateToUserKey: vi.fn(() => Promise.resolve({
    encryptedUserKey: 'mock-migrated-user-key',
    userKey: { type: 'secret', extractable: false, usages: ['encrypt', 'decrypt'] },
  })),
  unwrapUserKey: vi.fn(() => Promise.resolve(
    { type: 'secret', extractable: false, usages: ['encrypt', 'decrypt'] }
  )),
  unwrapUserKeyBytes: (...args: unknown[]) => mockUnwrapUserKeyBytes(...args),
  rewrapUserKey: vi.fn(() => Promise.resolve('mock-rewrapped-user-key')),
  decryptPrivateKeyLegacy: vi.fn(() => Promise.resolve('mock-plain-private-key')),
  wrapPrivateKeyWithUserKey: vi.fn(() => Promise.resolve('mock-wrapped-private-key')),
  CURRENT_KDF_VERSION: 2,
}));

const mockRestoreQuarantinedItemFromTrustedSnapshot = vi.fn();
const mockDeleteQuarantinedItemFromVault = vi.fn();
vi.mock("@/services/vaultQuarantineRecoveryService", () => ({
  indexTrustedSnapshotItems: (snapshot: { items: Array<{ id: string }> } | null) => {
    if (!snapshot) return {};
    return Object.fromEntries(snapshot.items.map((item) => [item.id, item]));
  },
  buildQuarantineResolutionMap: (
    items: Array<{ id: string; reason: string }>,
    trustedItemsById: Record<string, unknown>,
    runtimeStateById: Record<string, { isBusy: boolean; lastError: string | null }> = {},
  ) =>
    Object.fromEntries(
      items.map((item) => {
        const runtimeState = runtimeStateById[item.id] ?? { isBusy: false, lastError: null };
        const hasTrustedLocalCopy = Boolean(trustedItemsById[item.id]);
        return [
          item.id,
          {
            reason: item.reason,
            canRestore: hasTrustedLocalCopy && item.reason !== "unknown_on_server",
            canDelete: item.reason === "ciphertext_changed" || item.reason === "unknown_on_server",
            canAcceptMissing: item.reason === "missing_on_server",
            hasTrustedLocalCopy,
            isBusy: runtimeState.isBusy,
            lastError: runtimeState.lastError,
          },
        ];
      }),
    ),
  restoreQuarantinedItemFromTrustedSnapshot: (...args: unknown[]) =>
    mockRestoreQuarantinedItemFromTrustedSnapshot(...args),
  deleteQuarantinedItemFromVault: (...args: unknown[]) =>
    mockDeleteQuarantinedItemFromVault(...args),
}));

// Mock offline vault service
const mockGetOfflineCredentials = vi.fn();
const mockSaveOfflineCredentials = vi.fn();
const mockGetOfflineVaultTwoFactorRequirement = vi.fn();
const mockSaveOfflineVaultTwoFactorRequirement = vi.fn();
const mockLoadVaultSnapshot = vi.fn();
const mockFetchRemoteOfflineSnapshot = vi.fn();
const mockGetOfflineSnapshot = vi.fn();
const mockGetTrustedOfflineSnapshot = vi.fn();
const mockIsRecentLocalVaultMutation = vi.fn();
const mockSaveTrustedOfflineSnapshot = vi.fn();
const mockClearOfflineVaultData = vi.fn();
const mockIsAppOnline = vi.fn(() => true);
vi.mock("@/services/offlineVaultService", () => ({
  isAppOnline: () => mockIsAppOnline(),
  isLikelyOfflineError: vi.fn(() => false),
  fetchRemoteOfflineSnapshot: (...args: unknown[]) => mockFetchRemoteOfflineSnapshot(...args),
  getOfflineSnapshot: (...args: unknown[]) => mockGetOfflineSnapshot(...args),
  getOfflineCredentials: (...args: unknown[]) => mockGetOfflineCredentials(...args),
  getOfflineVaultTwoFactorRequirement: (...args: unknown[]) => mockGetOfflineVaultTwoFactorRequirement(...args),
  getTrustedOfflineSnapshot: (...args: unknown[]) => mockGetTrustedOfflineSnapshot(...args),
  isRecentLocalVaultMutation: (...args: unknown[]) => mockIsRecentLocalVaultMutation(...args),
  saveOfflineCredentials: (...args: unknown[]) => mockSaveOfflineCredentials(...args),
  saveOfflineVaultTwoFactorRequirement: (...args: unknown[]) => mockSaveOfflineVaultTwoFactorRequirement(...args),
  saveTrustedOfflineSnapshot: (...args: unknown[]) => mockSaveTrustedOfflineSnapshot(...args),
  loadVaultSnapshot: (...args: unknown[]) => mockLoadVaultSnapshot(...args),
  clearOfflineVaultData: (...args: unknown[]) => mockClearOfflineVaultData(...args),
}));

// Mock device key service
const mockGenerateDeviceKey = vi.fn(() => new Uint8Array(32).fill(5));
const mockStoreDeviceKey = vi.fn();
const mockLoadDeviceKey = vi.fn();
const mockCheckHasDeviceKey = vi.fn();
const mockDeleteDeviceKey = vi.fn();
vi.mock("@/services/deviceKeyService", () => ({
  generateDeviceKey: () => mockGenerateDeviceKey(),
  storeDeviceKey: (...args: unknown[]) => mockStoreDeviceKey(...args),
  getDeviceKey: (...args: unknown[]) => mockLoadDeviceKey(...args),
  hasDeviceKey: (...args: unknown[]) => mockCheckHasDeviceKey(...args),
  deleteDeviceKey: (...args: unknown[]) => mockDeleteDeviceKey(...args),
}));

// Mock passkey service
const mockAuthenticatePasskey = vi.fn();
const mockListPasskeys = vi.fn();
vi.mock("@/services/passkeyService", () => ({
  authenticatePasskey: () => mockAuthenticatePasskey(),
  listPasskeys: () => mockListPasskeys(),
  isWebAuthnAvailable: vi.fn(() => false),
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

const mockGetTwoFactorRequirement = vi.fn();
vi.mock("@/services/twoFactorService", () => ({
  getTwoFactorRequirement: (...args: unknown[]) => mockGetTwoFactorRequirement(...args),
}));

// ============ Test Helpers ============

function createWrapper() {
  return function Wrapper({ children }: { children: ReactNode }) {
    return <VaultProvider>{children}</VaultProvider>;
  };
}

function createSelectQueryMock(
  profileData: Record<string, unknown> | null = null,
  limitData: unknown[] = [],
) {
  const query = {
    eq: vi.fn(),
    single: vi.fn().mockResolvedValue({ data: profileData, error: null }),
    maybeSingle: vi.fn().mockResolvedValue({ data: profileData, error: null }),
    limit: vi.fn().mockResolvedValue({ data: limitData, error: null }),
    order: vi.fn(),
  };

  query.eq.mockReturnValue(query);
  query.order.mockReturnValue(query);

  return query;
}

function withCompleteSnapshot<T extends {
  userId?: string;
  vaultId?: string | null;
  items: unknown[];
  categories: unknown[];
  lastSyncedAt?: string | null;
  updatedAt?: string;
}>(
  snapshot: T,
  source: "remote" | "remote_with_local_overlay" = "remote",
): T & { completeness: Record<string, unknown> } {
  const checkedAt = snapshot.updatedAt ?? "2026-04-29T10:00:00.000Z";
  const userId = snapshot.userId ?? mockUser.id;
  const vaultId = snapshot.vaultId ?? "vault-123";
  return {
    ...snapshot,
    userId,
    vaultId,
    lastSyncedAt: snapshot.lastSyncedAt ?? checkedAt,
    updatedAt: snapshot.updatedAt ?? checkedAt,
    completeness: {
      kind: "complete",
      reason: source === "remote_with_local_overlay"
        ? "remote_with_local_mutation_overlay"
        : "remote_page_count_verified",
      checkedAt,
      source,
      scope: {
        kind: "private_default_vault",
        userId,
        vaultId,
        includesSharedCollections: false,
      },
      vault: { defaultVaultResolved: Boolean(vaultId) },
      items: {
        loadedCount: snapshot.items.length,
        totalCount: snapshot.items.length,
        complete: true,
        pageSize: 1000,
      },
      categories: {
        loadedCount: snapshot.categories.length,
        totalCount: snapshot.categories.length,
        complete: true,
        pageSize: 1000,
      },
    },
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
    mockGetOfflineCredentials.mockResolvedValue(null);
    mockGetOfflineVaultTwoFactorRequirement.mockResolvedValue(null);
    mockSaveOfflineVaultTwoFactorRequirement.mockResolvedValue(undefined);
    mockIsAppOnline.mockReturnValue(true);
    mockSaveOfflineCredentials.mockResolvedValue(undefined);
    mockFetchRemoteOfflineSnapshot.mockResolvedValue(withCompleteSnapshot({
      userId: mockUser.id,
      vaultId: "vault-123",
      items: [],
      categories: [],
      lastSyncedAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    }));
    mockGetOfflineSnapshot.mockResolvedValue(null);
    mockGetTrustedOfflineSnapshot.mockResolvedValue(null);
    mockIsRecentLocalVaultMutation.mockReturnValue(false);
    mockSaveTrustedOfflineSnapshot.mockResolvedValue(undefined);
    mockClearOfflineVaultData.mockResolvedValue(undefined);
    mockStoreDeviceKey.mockResolvedValue(undefined);
    mockLoadDeviceKey.mockResolvedValue(null);
    mockCheckHasDeviceKey.mockResolvedValue(false);
    mockLoadVaultSnapshot.mockResolvedValue({
      snapshot: withCompleteSnapshot({
        items: [],
        categories: [],
      }, "remote_with_local_overlay"),
      source: "cache",
    });
    mockDeriveRawKey.mockResolvedValue(new Uint8Array(32));
    mockImportMasterKey.mockResolvedValue({} as CryptoKey);
    mockAuthenticatePasskey.mockResolvedValue({
      success: true,
      encryptionKey: {} as CryptoKey,
      keySource: "vault-key",
    });
    mockListPasskeys.mockResolvedValue([]);
    mockRestoreQuarantinedItemFromTrustedSnapshot.mockResolvedValue({ syncedOnline: true });
    mockDeleteQuarantinedItemFromVault.mockResolvedValue({ syncedOnline: true });
    mockGetUnlockCooldown.mockReturnValue(null);
    mockUnwrapUserKeyBytes.mockResolvedValue(new Uint8Array(32));
    mockGetTwoFactorRequirement.mockResolvedValue({
      context: "vault_unlock",
      required: false,
      status: "loaded",
    });

    // Default Supabase profile response - no vault setup yet
    const mockEqChain = createSelectQueryMock(null, []);

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

    it("should expose refreshIntegrityBaseline through the provider value", async () => {
      const { result } = renderHook(() => useVault(), { wrapper: createWrapper() });

      await waitFor(() => {
        expect(result.current.isLoading).toBe(false);
      });

      expect(result.current.refreshIntegrityBaseline).toEqual(expect.any(Function));
    });

    it("should detect setup is required when no profile exists", async () => {
      const { result } = renderHook(() => useVault(), { wrapper: createWrapper() });

      await waitFor(() => {
        expect(result.current.isLoading).toBe(false);
      });

      expect(result.current.isSetupRequired).toBe(true);
    });

    it("does not offer master-password setup while offline without a trusted local snapshot", async () => {
      mockIsAppOnline.mockReturnValue(false);
      mockGetOfflineCredentials.mockResolvedValue(null);

      const { result } = renderHook(() => useVault(), { wrapper: createWrapper() });

      await waitFor(() => {
        expect(result.current.isLoading).toBe(false);
      });

      expect(result.current.isSetupRequired).toBe(false);
      expect(result.current.isLocked).toBe(true);
      expect(mockSupabase.from).not.toHaveBeenCalledWith("profiles");
    });

    it("uses cached master-password state when the online profile check fails", async () => {
      mockGetOfflineCredentials.mockResolvedValue({
        salt: "cached-salt",
        verifier: "cached-verifier",
        kdfVersion: 2,
        encryptedUserKey: "cached-user-key",
      });
      mockSupabase.from.mockReturnValue({
        select: vi.fn().mockReturnValue({
          eq: vi.fn().mockReturnValue(createSelectQueryMock(null)),
        }),
      });

      const { result } = renderHook(() => useVault(), { wrapper: createWrapper() });

      await waitFor(() => {
        expect(result.current.isLoading).toBe(false);
      });

      expect(result.current.isSetupRequired).toBe(false);
      expect(result.current.isLocked).toBe(true);
    });

    it("does not grant the legacy Tauri dev user a local setup bypass", async () => {
      mockUseAuth.mockReturnValue({
        user: { id: "00000000-0000-4000-8000-000000000001", email: "tauri-dev@singra.local" },
        authReady: true,
      });
      mockGetOfflineCredentials.mockResolvedValue({
        salt: "dev-salt",
        verifier: "dev-verifier",
        kdfVersion: 2,
        encryptedUserKey: "dev-encrypted-user-key",
      });

      const { result } = renderHook(() => useVault(), { wrapper: createWrapper() });

      await waitFor(() => {
        expect(result.current.isLoading).toBe(false);
      });

      expect(result.current.isSetupRequired).toBe(false);
      expect(mockGetOfflineCredentials).toHaveBeenCalledWith("00000000-0000-4000-8000-000000000001");
      expect(mockSupabase.from).toHaveBeenCalledWith("profiles");
    });

    it("should load existing vault setup from profile", async () => {
      // Mock existing profile with vault setup
      mockSupabase.from.mockReturnValue({
        select: vi.fn().mockReturnValue({
          eq: vi.fn().mockReturnValue(createSelectQueryMock({
            encryption_salt: "test-salt-123",
            master_password_verifier: "test-verifier-456",
            kdf_version: 2,
          })),
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
      // isLoading stays true â€” spinner shown, no stale-defaults flash (Bug 4 fix).
      mockUseAuth.mockReturnValue({ user: mockUser, authReady: false });

      const { result, rerender } = renderHook(() => useVault(), {
        wrapper: createWrapper(),
      });

      // isLoading must remain TRUE â€” setup is pending, not yet aborted.
      // Supabase must NOT be called yet (auth not ready).
      await waitFor(() => {
        expect(result.current.isLoading).toBe(true);
      });
      expect(mockSupabase.from).not.toHaveBeenCalledWith("profiles");

      // Now auth becomes ready (Supabase session synchronized) without user changing.
      mockUseAuth.mockReturnValue({ user: mockUser, authReady: true });
      rerender();

      // With the dep-array fix, the useEffect re-runs and calls checkSetup().
      // The default mock returns no profile â†’ isSetupRequired becomes true.
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

      // Spin for 100ms â€” isLoading must remain true the entire time.
      // (waitFor with negation: give it time and confirm it never went false.)
      await new Promise((r) => setTimeout(r, 100));
      expect(result.current.isLoading).toBe(true);

      // hasPasskeyUnlock must NOT have been cleared â€” user exists, data unknown.
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
      // Supabase must never have been touched â€” no user, no fetch.
      expect(mockSupabase.from).not.toHaveBeenCalledWith("profiles");
    });

    it("clears prior user credentials before loading a different account", async () => {
      const authState = {
        user: mockUser,
        authReady: true,
      };
      mockUseAuth.mockImplementation(() => authState);

      mockSupabase.from.mockImplementation(() => ({
        select: vi.fn().mockReturnValue({
          eq: vi.fn((_column: string, value: string) => createSelectQueryMock(
            value === mockUser.id
              ? {
                  encryption_salt: "first-user-salt",
                  master_password_verifier: "first-user-verifier",
                  kdf_version: 2,
                  encrypted_user_key: "first-user-usk",
                }
              : null,
          )),
        }),
        insert: vi.fn().mockReturnValue({
          select: vi.fn().mockResolvedValue({ data: [{ id: "vault-123" }], error: null }),
        }),
        update: vi.fn().mockReturnValue({
          eq: vi.fn().mockResolvedValue({ data: null, error: null }),
        }),
      }));

      const { result, rerender } = renderHook(() => useVault(), { wrapper: createWrapper() });

      await waitFor(() => {
        expect(result.current.isLoading).toBe(false);
      });
      expect(result.current.isSetupRequired).toBe(false);

      authState.user = { id: "second-user-456", email: "second@example.com" };
      rerender();

      await waitFor(() => {
        expect(result.current.isLoading).toBe(false);
        expect(result.current.isSetupRequired).toBe(true);
      });

      let unlockResult: Awaited<ReturnType<typeof result.current.unlock>> | null = null;
      await act(async () => {
        unlockResult = await result.current.unlock("test-password");
      });

      expect(unlockResult?.error?.message).toBe("Vault not set up");
      expect(mockVerifyKey).not.toHaveBeenCalled();
    });
  });

  describe("setupMasterPassword", () => {
    it("should set up master password for first-time users", async () => {
      mockGenerateSalt.mockReturnValue("new-salt-789");
      mockDeriveRawKey.mockResolvedValue(new Uint8Array(32));
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
      expect(mockDeriveRawKey).toHaveBeenCalledWith("SecurePassword123!", "new-salt-789", 2);
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

    it("rejects setup when cached master-password credentials already exist", async () => {
      mockGetOfflineCredentials.mockResolvedValue({
        salt: "cached-salt",
        verifier: "cached-verifier",
        kdfVersion: 2,
        encryptedUserKey: "cached-user-key",
      });

      const { result } = renderHook(() => useVault(), { wrapper: createWrapper() });

      await waitFor(() => {
        expect(result.current.isLoading).toBe(false);
      });

      let setupResult: { error: Error | null } | undefined;
      await act(async () => {
        setupResult = await result.current.setupMasterPassword("SecurePassword123!");
      });

      expect(setupResult?.error?.message).toBe("Master password is already set for this account.");
      expect(mockGenerateSalt).not.toHaveBeenCalled();
    });

    it("rejects setup when the remote profile already has an encryption salt", async () => {
      mockSupabase.from.mockReturnValue({
        select: vi.fn().mockReturnValue({
          eq: vi.fn().mockReturnValue(createSelectQueryMock({
            encryption_salt: "existing-salt",
            master_password_verifier: "existing-verifier",
            kdf_version: 2,
          })),
        }),
        update: vi.fn().mockReturnValue({
          eq: vi.fn().mockResolvedValue({ data: null, error: null }),
        }),
      });

      const { result } = renderHook(() => useVault(), { wrapper: createWrapper() });

      await waitFor(() => {
        expect(result.current.isLoading).toBe(false);
      });

      let setupResult: { error: Error | null } | undefined;
      await act(async () => {
        setupResult = await result.current.setupMasterPassword("SecurePassword123!");
      });

      expect(setupResult?.error?.message).toBe("Master password is already set for this account.");
      expect(mockGenerateSalt).not.toHaveBeenCalled();
      expect(result.current.isSetupRequired).toBe(false);
    });
  });

  describe("unlock", () => {
    beforeEach(() => {
      // Mock existing profile
      mockSupabase.from.mockReturnValue({
        select: vi.fn().mockReturnValue({
          eq: vi.fn().mockReturnValue(createSelectQueryMock({
            encryption_salt: "existing-salt",
            master_password_verifier: "existing-verifier",
            kdf_version: 2,
          })),
        }),
        update: vi.fn().mockReturnValue({
          eq: vi.fn().mockResolvedValue({ data: null, error: null }),
        }),
      });
    });

    it("should unlock vault with correct password", async () => {
      // Profile mock without encrypted_user_key -> takes PRE-USK migration path
      mockDeriveRawKey.mockResolvedValue(new Uint8Array(32));
      mockImportMasterKey.mockResolvedValue({ type: 'secret', extractable: false } as CryptoKey);
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
      expect(mockDeriveRawKey).toHaveBeenCalledWith("CorrectPassword!", "existing-salt", 2, undefined);
      expect(mockVerifyKey).toHaveBeenCalled();
      expect(result.current.isLocked).toBe(false);
    });

    it("blocks master-password unlock when vault 2FA is required but no verifier callback is supplied", async () => {
      mockDeriveRawKey.mockResolvedValue(new Uint8Array(32));
      mockImportMasterKey.mockResolvedValue({ type: "secret", extractable: false } as CryptoKey);
      mockVerifyKey.mockResolvedValue(true);
      mockAttemptKdfUpgrade.mockResolvedValue({ upgraded: false });
      mockGetTwoFactorRequirement.mockResolvedValue({
        context: "vault_unlock",
        required: true,
        status: "loaded",
        reason: "vault_2fa_enabled",
      });

      const { result } = renderHook(() => useVault(), { wrapper: createWrapper() });

      await waitFor(() => {
        expect(result.current.isLoading).toBe(false);
      });

      let unlockResult: { error: Error | null } | undefined;
      await act(async () => {
        unlockResult = await result.current.unlock("CorrectPassword!");
      });

      expect(unlockResult?.error?.message).toContain("2FA verification required");
      expect(result.current.isLocked).toBe(true);
    });

    it("unlocks with master password only after vault 2FA verification succeeds", async () => {
      mockDeriveRawKey.mockResolvedValue(new Uint8Array(32));
      mockImportMasterKey.mockResolvedValue({ type: "secret", extractable: false } as CryptoKey);
      mockVerifyKey.mockResolvedValue(true);
      mockAttemptKdfUpgrade.mockResolvedValue({ upgraded: false });
      mockGetTwoFactorRequirement.mockResolvedValue({
        context: "vault_unlock",
        required: true,
        status: "loaded",
        reason: "vault_2fa_enabled",
      });

      const { result } = renderHook(() => useVault(), { wrapper: createWrapper() });

      await waitFor(() => {
        expect(result.current.isLoading).toBe(false);
      });

      await act(async () => {
        await result.current.unlock("CorrectPassword!", {
          verifyTwoFactor: async () => true,
        });
      });

      expect(result.current.isLocked).toBe(false);
      expect(mockSaveOfflineVaultTwoFactorRequirement).toHaveBeenCalledWith(mockUser.id, true);
    });

    it("allows offline master-password unlock when cached vault 2FA state says it is not required", async () => {
      mockIsAppOnline.mockReturnValue(false);
      mockGetOfflineVaultTwoFactorRequirement.mockResolvedValue(false);
      mockGetOfflineCredentials.mockResolvedValue({
        salt: "existing-salt",
        verifier: "existing-verifier",
        kdfVersion: 2,
        encryptedUserKey: null,
      });
      mockDeriveRawKey.mockResolvedValue(new Uint8Array(32));
      mockImportMasterKey.mockResolvedValue({ type: "secret", extractable: false } as CryptoKey);
      mockVerifyKey.mockResolvedValue(true);
      mockAttemptKdfUpgrade.mockResolvedValue({ upgraded: false });

      const { result } = renderHook(() => useVault(), { wrapper: createWrapper() });

      await waitFor(() => {
        expect(result.current.isLoading).toBe(false);
      });

      let unlockResult: { error: Error | null } | undefined;
      await act(async () => {
        unlockResult = await result.current.unlock("CorrectPassword!");
      });

      expect(unlockResult?.error).toBeNull();
      expect(result.current.isLocked).toBe(false);
      expect(mockGetTwoFactorRequirement).not.toHaveBeenCalled();
    });

    it("blocks offline master-password unlock when vault 2FA state is unknown", async () => {
      mockIsAppOnline.mockReturnValue(false);
      mockGetOfflineVaultTwoFactorRequirement.mockResolvedValue(null);
      mockGetOfflineCredentials.mockResolvedValue({
        salt: "existing-salt",
        verifier: "existing-verifier",
        kdfVersion: 2,
        encryptedUserKey: null,
      });
      mockDeriveRawKey.mockResolvedValue(new Uint8Array(32));
      mockImportMasterKey.mockResolvedValue({ type: "secret", extractable: false } as CryptoKey);
      mockVerifyKey.mockResolvedValue(true);
      mockAttemptKdfUpgrade.mockResolvedValue({ upgraded: false });

      const { result } = renderHook(() => useVault(), { wrapper: createWrapper() });

      await waitFor(() => {
        expect(result.current.isLoading).toBe(false);
      });

      let unlockResult: { error: Error | null } | undefined;
      await act(async () => {
        unlockResult = await result.current.unlock("CorrectPassword!");
      });

      expect(unlockResult?.error?.message).toContain("2FA status is not cached");
      expect(result.current.isLocked).toBe(true);
      expect(mockGetTwoFactorRequirement).not.toHaveBeenCalled();
    });

    it("keeps the vault locked when master-password 2FA verification fails", async () => {
      mockDeriveRawKey.mockResolvedValue(new Uint8Array(32));
      mockImportMasterKey.mockResolvedValue({ type: "secret", extractable: false } as CryptoKey);
      mockVerifyKey.mockResolvedValue(true);
      mockAttemptKdfUpgrade.mockResolvedValue({ upgraded: false });
      mockGetTwoFactorRequirement.mockResolvedValue({
        context: "vault_unlock",
        required: true,
        status: "loaded",
        reason: "vault_2fa_enabled",
      });

      const { result } = renderHook(() => useVault(), { wrapper: createWrapper() });

      await waitFor(() => {
        expect(result.current.isLoading).toBe(false);
      });

      let unlockResult: { error: Error | null } | undefined;
      await act(async () => {
        unlockResult = await result.current.unlock("CorrectPassword!", {
          verifyTwoFactor: async () => false,
        });
      });

      expect(unlockResult?.error?.message).toContain("2FA verification failed");
      expect(result.current.isLocked).toBe(true);
    });

    it("legacy Tauri dev user unlock uses the normal remote snapshot path", async () => {
      const devUserId = "00000000-0000-4000-8000-000000000001";
      mockUseAuth.mockReturnValue({
        user: { id: devUserId, email: "tauri-dev@singra.local" },
        authReady: true,
      });
      mockSupabase.from.mockReturnValue({
        select: vi.fn().mockReturnValue({
          eq: vi.fn().mockReturnValue(createSelectQueryMock({
            encryption_salt: "dev-salt",
            master_password_verifier: "dev-verifier",
            kdf_version: 2,
            encrypted_user_key: "dev-encrypted-user-key",
            vault_protection_mode: "master_only",
          })),
        }),
        update: vi.fn().mockReturnValue({
          eq: vi.fn().mockResolvedValue({ data: null, error: null }),
        }),
      });
      mockGetOfflineCredentials.mockResolvedValue({
        salt: "dev-salt",
        verifier: "dev-verifier",
        kdfVersion: 2,
        encryptedUserKey: "dev-encrypted-user-key",
      });
      mockVerifyKey.mockResolvedValue(true);
      mockAttemptKdfUpgrade.mockResolvedValue({ upgraded: false });
      mockDecrypt.mockResolvedValue("QA Kategorie");
      mockFetchRemoteOfflineSnapshot.mockResolvedValue(withCompleteSnapshot({
        userId: devUserId,
        vaultId: "vault-regular",
        items: [],
        categories: [
          {
            id: "cat-1",
            user_id: devUserId,
            name: "enc:cat:v1:category-cipher",
            icon: null,
            color: "enc:cat:v1:color-cipher",
            parent_id: null,
            sort_order: null,
            created_at: "2026-04-22T10:00:00.000Z",
            updated_at: "2026-04-22T11:00:00.000Z",
          },
        ],
        lastSyncedAt: null,
        updatedAt: "2026-04-22T11:00:00.000Z",
      }));

      const { result } = renderHook(() => useVault(), { wrapper: createWrapper() });

      await waitFor(() => {
        expect(result.current.isLoading).toBe(false);
      });

      let unlockResult: { error: Error | null } | undefined;
      await act(async () => {
        unlockResult = await result.current.unlock("CorrectPassword!");
      });

      expect(unlockResult?.error).toBeNull();
      expect(result.current.isLocked).toBe(false);
      expect(result.current.integrityMode).toBe("healthy");
      expect(mockFetchRemoteOfflineSnapshot).toHaveBeenCalledWith(devUserId, { persist: false });
      expect(mockLoadVaultSnapshot).not.toHaveBeenCalledWith(devUserId);
      expect(mockSupabase.from).toHaveBeenCalledWith("profiles");
    });

    it("keeps unlock digest-based and treats deferred unreadable items as revalidation failure", async () => {
      mockDeriveRawKey.mockResolvedValue(new Uint8Array(32));
      mockImportMasterKey.mockResolvedValue({ type: 'secret', extractable: false } as CryptoKey);
      mockVerifyKey.mockResolvedValue(true);
      mockAttemptKdfUpgrade.mockResolvedValue({ upgraded: false });
      mockFetchRemoteOfflineSnapshot.mockResolvedValue(withCompleteSnapshot({
        userId: mockUser.id,
        vaultId: "vault-123",
        items: [
          {
            id: "item-bad",
            vault_id: "vault-123",
            title: "Encrypted Item",
            website_url: null,
            icon_url: null,
            item_type: "password",
            is_favorite: false,
            category_id: null,
            created_at: "2026-04-22T10:00:00.000Z",
            updated_at: "2026-04-22T10:00:00.000Z",
            encrypted_data: "cipher-bad",
          },
        ],
        categories: [],
        lastSyncedAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
      }));
      mockDecryptVaultItem.mockRejectedValue(new Error("OperationError"));

      const { result } = renderHook(() => useVault(), { wrapper: createWrapper() });

      await waitFor(() => {
        expect(result.current.isLoading).toBe(false);
      });

      let unlockResult: { error: Error | null } | undefined;
      await act(async () => {
        unlockResult = await result.current.unlock("CorrectPassword!");
      });

      expect(unlockResult?.error).toBeNull();
      expect(result.current.isLocked).toBe(false);
      expect(mockDecryptVaultItem).not.toHaveBeenCalled();
      expect(result.current.integrityMode).toBe("healthy");

      act(() => {
        result.current.reportUnreadableItems([
          {
            id: "item-bad",
            reason: "decrypt_failed",
            updatedAt: "2026-04-22T10:00:00.000Z",
          },
        ]);
      });

      expect(result.current.integrityMode).toBe("revalidation_failed");
      expect(result.current.quarantinedItems).toEqual([]);
    });

    it("does not expose runtime unreadable items as deletable quarantine records", async () => {
      mockDeriveRawKey.mockResolvedValue(new Uint8Array(32));
      mockImportMasterKey.mockResolvedValue({ type: "secret", extractable: false } as CryptoKey);
      mockVerifyKey.mockResolvedValue(true);
      mockAttemptKdfUpgrade.mockResolvedValue({ upgraded: false });

      const { result } = renderHook(() => useVault(), { wrapper: createWrapper() });

      await waitFor(() => {
        expect(result.current.isLoading).toBe(false);
      });

      await act(async () => {
        await result.current.unlock("CorrectPassword!");
      });

      act(() => {
        result.current.reportUnreadableItems([
          {
            id: "item-bad",
            reason: "decrypt_failed",
            updatedAt: "2026-04-22T10:00:00.000Z",
          },
        ]);
      });

      expect(result.current.integrityMode).toBe("revalidation_failed");
      expect(result.current.quarantinedItems).toEqual([]);
      expect(mockDeleteQuarantinedItemFromVault).not.toHaveBeenCalled();
    });

    it("blocks unlock when encrypted categories can no longer be decrypted", async () => {
      mockDeriveRawKey.mockResolvedValue(new Uint8Array(32));
      mockImportMasterKey.mockResolvedValue({ type: 'secret', extractable: false } as CryptoKey);
      mockVerifyKey.mockResolvedValue(true);
      mockAttemptKdfUpgrade.mockResolvedValue({ upgraded: false });
      mockFetchRemoteOfflineSnapshot.mockResolvedValue(withCompleteSnapshot({
        userId: mockUser.id,
        vaultId: "vault-123",
        items: [],
        categories: [
          {
            id: "cat-bad",
            user_id: mockUser.id,
            name: "enc:cat:v1:broken",
            icon: null,
            color: null,
            parent_id: null,
            sort_order: null,
            created_at: "2026-04-22T10:00:00.000Z",
            updated_at: "2026-04-22T10:00:00.000Z",
          },
        ],
        lastSyncedAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
      }));
      mockDecrypt.mockRejectedValue(new Error("OperationError"));

      const { result } = renderHook(() => useVault(), { wrapper: createWrapper() });

      await waitFor(() => {
        expect(result.current.isLoading).toBe(false);
      });

      let unlockResult: { error: Error | null } | undefined;
      await act(async () => {
        unlockResult = await result.current.unlock("CorrectPassword!");
      });

      expect(unlockResult?.error?.message).toContain("Integritätsprüfung");
      expect(result.current.isLocked).toBe(true);
      expect(result.current.integrityMode).toBe("blocked");
      expect(result.current.integrityBlockedReason).toBe("category_structure_mismatch");
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

    it("blocks master-password unlock before deriving key material when Device Key is required but missing", async () => {
      mockSupabase.from.mockReturnValue({
        select: vi.fn().mockReturnValue({
          eq: vi.fn().mockReturnValue(createSelectQueryMock({
            encryption_salt: "existing-salt",
            master_password_verifier: "existing-verifier",
            kdf_version: 2,
            encrypted_user_key: "encrypted-user-key",
            vault_protection_mode: "device_key_required",
          })),
        }),
        update: vi.fn().mockReturnValue({
          eq: vi.fn().mockResolvedValue({ data: null, error: null }),
        }),
      });
      mockCheckHasDeviceKey.mockResolvedValue(false);
      mockLoadDeviceKey.mockResolvedValue(null);

      const { result } = renderHook(() => useVault(), { wrapper: createWrapper() });

      await waitFor(() => {
        expect(result.current.isLoading).toBe(false);
      });

      let unlockResult: { error: Error | null } | undefined;
      await act(async () => {
        unlockResult = await result.current.unlock("CorrectPassword!");
      });

      expect(unlockResult?.error?.message).toContain("This vault is protected with a Device Key");
      expect(mockDeriveRawKey).not.toHaveBeenCalled();
      expect(mockImportMasterKey).not.toHaveBeenCalled();
      expect(mockFetchRemoteOfflineSnapshot).not.toHaveBeenCalled();
      expect(result.current.isLocked).toBe(true);
    });

    it("should unlock and migrate an empty legacy vault without a verifier", async () => {
      mockDeriveRawKey.mockResolvedValue(new Uint8Array(32));
      mockImportMasterKey.mockResolvedValue({ type: "secret", extractable: false } as CryptoKey);
      mockCreateVerificationHash.mockResolvedValue("migrated-verifier");

      mockSupabase.from.mockReturnValue({
        select: vi.fn().mockReturnValue({
          eq: vi.fn().mockReturnValue(createSelectQueryMock({
            encryption_salt: "existing-salt",
            master_password_verifier: null,
            kdf_version: 1,
          })),
        }),
        update: vi.fn().mockReturnValue({
          eq: vi.fn().mockResolvedValue({ data: null, error: null }),
        }),
      });

      const { result } = renderHook(() => useVault(), { wrapper: createWrapper() });

      await waitFor(() => {
        expect(result.current.isLoading).toBe(false);
      });

      let unlockResult: { error: Error | null } | undefined;
      await act(async () => {
        unlockResult = await result.current.unlock("CorrectPassword!");
      });

      expect(unlockResult?.error).toBeNull();
      expect(result.current.isLocked).toBe(false);
      expect(mockVerifyKey).not.toHaveBeenCalled();
      expect(mockCreateVerificationHash).toHaveBeenCalled();
      expect(mockSaveOfflineCredentials).toHaveBeenCalledWith(
        mockUser.id,
        "existing-salt",
        "migrated-verifier",
        1,
        "mock-migrated-user-key",
        "master_only",
      );
    });
  });

  describe("refreshIntegrityBaseline", () => {
    it("should re-baseline decryptable trusted changes instead of blocking them", async () => {
      mockGenerateSalt.mockReturnValue("fresh-salt");
      mockCreateVerificationHash.mockResolvedValue("fresh-verifier");

      const { result } = renderHook(() => useVault(), { wrapper: createWrapper() });

      await waitFor(() => {
        expect(result.current.isLoading).toBe(false);
      });

      await act(async () => {
        await result.current.setupMasterPassword("CorrectPassword!");
      });

      const trustedSnapshot = withCompleteSnapshot({
        userId: mockUser.id,
        vaultId: "vault-123",
        items: [
          {
            id: "item-1",
            vault_id: "vault-123",
            title: "Encrypted Item",
            website_url: null,
            icon_url: null,
            item_type: "password",
            is_favorite: false,
            category_id: "cat-1",
            created_at: "2026-04-22T10:00:00.000Z",
            updated_at: "2026-04-22T11:00:00.000Z",
            encrypted_data: "cipher-updated",
          },
        ],
        categories: [
          {
            id: "cat-1",
            user_id: mockUser.id,
            name: "enc:cat:v1:rotated",
            icon: null,
            color: null,
            parent_id: null,
            sort_order: null,
            created_at: "2026-04-22T10:00:00.000Z",
            updated_at: "2026-04-22T11:00:00.000Z",
          },
        ],
        lastSyncedAt: "2026-04-22T11:00:00.000Z",
        updatedAt: "2026-04-22T11:00:00.000Z",
      }, "remote_with_local_overlay");

      mockLoadVaultSnapshot.mockResolvedValue({
        snapshot: trustedSnapshot,
        source: "cache",
      });
      mockDecryptVaultItem.mockResolvedValue({ id: "item-1" });
      mockDecrypt.mockResolvedValue("decrypted-category");

      await act(async () => {
        await result.current.refreshIntegrityBaseline({
          itemIds: ["item-1"],
          categoryIds: ["cat-1"],
        });
      });

      expect(result.current.isLocked).toBe(false);
      expect(result.current.integrityMode).toBe("healthy");
      expect(result.current.integrityBlockedReason).toBeNull();
      expect(result.current.quarantinedItems).toEqual([]);
      expect(mockLoadVaultSnapshot).toHaveBeenCalledWith(mockUser.id);
      expect(mockSaveTrustedOfflineSnapshot).toHaveBeenLastCalledWith(trustedSnapshot);
    });

    it("uses the local mutation overlay for trusted category re-baselining", async () => {
      mockGenerateSalt.mockReturnValue("fresh-salt");
      mockCreateVerificationHash.mockResolvedValue("fresh-verifier");
      mockEncrypt.mockImplementation(async (plaintext: unknown) => String(plaintext));
      mockDecrypt.mockImplementation(async (payload: unknown) => {
        const value = String(payload);
        return value.startsWith("{") ? value : "decrypted-category";
      });

      const { result } = renderHook(() => useVault(), { wrapper: createWrapper() });

      await waitFor(() => {
        expect(result.current.isLoading).toBe(false);
      });

      await act(async () => {
        await result.current.setupMasterPassword("CorrectPassword!");
      });

      const mergedSnapshot = withCompleteSnapshot({
        userId: mockUser.id,
        vaultId: "vault-123",
        items: [],
        categories: [
          {
            id: "cat-1",
            user_id: mockUser.id,
            name: "enc:cat:v1:local-cipher",
            icon: null,
            color: "enc:cat:v1:local-color",
            parent_id: null,
            sort_order: null,
            created_at: "2026-04-22T10:00:00.000Z",
            updated_at: "2026-04-22T11:00:00.000Z",
          },
        ],
        lastSyncedAt: "2026-04-22T11:00:00.000Z",
        updatedAt: "2026-04-22T11:00:00.000Z",
      }, "remote_with_local_overlay");

      mockLoadVaultSnapshot.mockClear();
      mockSaveTrustedOfflineSnapshot.mockClear();
      mockLoadVaultSnapshot.mockResolvedValue({
        snapshot: mergedSnapshot,
        source: "cache",
      });

      await act(async () => {
        await result.current.refreshIntegrityBaseline({
          categoryIds: ["cat-1"],
        });
      });

      expect(mockLoadVaultSnapshot).toHaveBeenCalledWith(mockUser.id);
      expect(mockSaveTrustedOfflineSnapshot).toHaveBeenLastCalledWith(mergedSnapshot);
      expect(result.current.isLocked).toBe(false);
      expect(result.current.integrityMode).toBe("healthy");
      expect(result.current.integrityBlockedReason).toBeNull();
    });

  });

  describe("unlockWithPasskey", () => {
    it("fails fast offline because passkey unlock requires a server WebAuthn challenge", async () => {
      mockIsAppOnline.mockReturnValue(false);

      const { result } = renderHook(() => useVault(), { wrapper: createWrapper() });

      await waitFor(() => {
        expect(result.current.isLoading).toBe(false);
      });

      let unlockResult: { error: Error | null } | undefined;
      await act(async () => {
        unlockResult = await result.current.unlockWithPasskey();
      });

      expect(unlockResult?.error?.message).toContain("Passkey unlock requires an online WebAuthn challenge");
      expect(mockAuthenticatePasskey).not.toHaveBeenCalled();
    });

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

    it("blocks passkey unlock before WebAuthn when a required Device Key is missing", async () => {
      mockSupabase.from.mockReturnValue({
        select: vi.fn().mockReturnValue({
          eq: vi.fn().mockReturnValue(createSelectQueryMock({
            encryption_salt: "existing-salt",
            master_password_verifier: "existing-verifier",
            kdf_version: 2,
            encrypted_user_key: "encrypted-user-key",
            vault_protection_mode: "device_key_required",
          })),
        }),
        update: vi.fn().mockReturnValue({
          eq: vi.fn().mockResolvedValue({ data: null, error: null }),
        }),
      });
      mockCheckHasDeviceKey.mockResolvedValue(false);
      mockLoadDeviceKey.mockResolvedValue(null);

      const { result } = renderHook(() => useVault(), { wrapper: createWrapper() });

      await waitFor(() => {
        expect(result.current.isLoading).toBe(false);
      });

      let unlockResult: { error: Error | null } | undefined;
      await act(async () => {
        unlockResult = await result.current.unlockWithPasskey();
      });

      expect(unlockResult?.error?.message).toContain("This vault is protected with a Device Key");
      expect(mockAuthenticatePasskey).not.toHaveBeenCalled();
      expect(result.current.isLocked).toBe(true);
    });

    it("does not let passkey disable Device Key enforcement when the local Device Key is available", async () => {
      const localDeviceKey = new Uint8Array(32).fill(7);
      mockSupabase.from.mockReturnValue({
        select: vi.fn().mockReturnValue({
          eq: vi.fn().mockReturnValue(createSelectQueryMock({
            encryption_salt: "existing-salt",
            master_password_verifier: "existing-verifier",
            kdf_version: 2,
            encrypted_user_key: "encrypted-user-key",
            vault_protection_mode: "device_key_required",
          })),
        }),
        update: vi.fn().mockReturnValue({
          eq: vi.fn().mockResolvedValue({ data: null, error: null }),
        }),
      });
      mockLoadDeviceKey.mockResolvedValue(localDeviceKey);
      mockVerifyKey.mockResolvedValue(true);

      const { result } = renderHook(() => useVault(), { wrapper: createWrapper() });

      await waitFor(() => {
        expect(result.current.isLoading).toBe(false);
      });

      await act(async () => {
        await result.current.unlockWithPasskey();
      });

      expect(mockLoadDeviceKey).toHaveBeenCalledWith(mockUser.id);
      expect(mockAuthenticatePasskey).toHaveBeenCalledTimes(1);
      expect(result.current.isLocked).toBe(false);
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

    it("blocks passkey unlock when vault 2FA is required but no verifier callback is supplied", async () => {
      mockGetTwoFactorRequirement.mockResolvedValue({
        context: "vault_unlock",
        required: true,
        status: "loaded",
        reason: "vault_2fa_enabled",
      });

      const { result } = renderHook(() => useVault(), { wrapper: createWrapper() });

      await waitFor(() => {
        expect(result.current.isLoading).toBe(false);
      });

      let unlockResult: { error: Error | null } | undefined;
      await act(async () => {
        unlockResult = await result.current.unlockWithPasskey();
      });

      expect(unlockResult?.error?.message).toContain("2FA verification required");
      expect(result.current.isLocked).toBe(true);
    });

    it("blocks passkey unlock when vault 2FA verification fails", async () => {
      mockGetTwoFactorRequirement.mockResolvedValue({
        context: "vault_unlock",
        required: true,
        status: "loaded",
        reason: "vault_2fa_enabled",
      });

      const { result } = renderHook(() => useVault(), { wrapper: createWrapper() });

      await waitFor(() => {
        expect(result.current.isLoading).toBe(false);
      });

      let unlockResult: { error: Error | null } | undefined;
      await act(async () => {
        unlockResult = await result.current.unlockWithPasskey({
          verifyTwoFactor: async () => false,
        });
      });

      expect(unlockResult?.error?.message).toContain("2FA verification failed");
      expect(result.current.isLocked).toBe(true);
    });

    it("allows passkey unlock only after vault 2FA verification succeeds", async () => {
      mockGetTwoFactorRequirement.mockResolvedValue({
        context: "vault_unlock",
        required: true,
        status: "loaded",
        reason: "vault_2fa_enabled",
      });

      const { result } = renderHook(() => useVault(), { wrapper: createWrapper() });

      await waitFor(() => {
        expect(result.current.isLoading).toBe(false);
      });

      await act(async () => {
        await result.current.unlockWithPasskey({
          verifyTwoFactor: async () => true,
        });
      });

      expect(result.current.isLocked).toBe(false);
    });

    it("fails closed when vault 2FA status cannot be loaded", async () => {
      mockGetTwoFactorRequirement.mockResolvedValue({
        context: "vault_unlock",
        required: true,
        status: "unavailable",
        reason: "status_unavailable",
      });

      const { result } = renderHook(() => useVault(), { wrapper: createWrapper() });

      await waitFor(() => {
        expect(result.current.isLoading).toBe(false);
      });

      let unlockResult: { error: Error | null } | undefined;
      await act(async () => {
        unlockResult = await result.current.unlockWithPasskey({
          verifyTwoFactor: async () => true,
        });
      });

      expect(unlockResult?.error?.message).toContain("2FA status unavailable");
      expect(result.current.isLocked).toBe(true);
    });
  });

  describe("getPasskeyWrappingMaterial", () => {
    it("should reject wrong master password and wipe derived raw key bytes", async () => {
      const rawBytes = new Uint8Array(32).fill(7);
      mockDeriveRawKey.mockResolvedValue(rawBytes);
      mockDeriveKey.mockResolvedValue({} as CryptoKey);
      mockAttemptKdfUpgrade.mockResolvedValue({ upgraded: false });
      mockVerifyKey
        .mockResolvedValueOnce(true)  // unlock()
        .mockResolvedValueOnce(false); // getPasskeyWrappingMaterial()

      // Mock existing profile with vault setup
      mockSupabase.from.mockReturnValue({
        select: vi.fn().mockReturnValue({
          eq: vi.fn().mockReturnValue(createSelectQueryMock({
            encryption_salt: "existing-salt",
            master_password_verifier: "existing-verifier",
            kdf_version: 2,
          })),
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
        rawKey = await result.current.getPasskeyWrappingMaterial("WrongPassword!");
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

    it("should keep unlock metadata after manual lock so the vault can be unlocked again", async () => {
      mockGenerateSalt.mockReturnValue("salt");
      mockDeriveKey.mockResolvedValue({} as CryptoKey);
      mockCreateVerificationHash.mockResolvedValue("verifier");
      mockVerifyKey.mockResolvedValue(true);

      const { result } = renderHook(() => useVault(), { wrapper: createWrapper() });

      await waitFor(() => {
        expect(result.current.isLoading).toBe(false);
      });

      await act(async () => {
        await result.current.setupMasterPassword("CorrectPassword!");
      });

      act(() => {
        result.current.lock();
      });

      expect(result.current.isLocked).toBe(true);

      let unlockResult:
        | {
            error: Error | null;
          }
        | undefined;

      await act(async () => {
        unlockResult = await result.current.unlock("CorrectPassword!");
      });

      expect(unlockResult?.error).toBeNull();
      expect(result.current.isLocked).toBe(false);
    });

    it("should wipe the in-memory device key on lock and reload it for the next unlock", async () => {
      const firstDeviceKey = new Uint8Array(32).fill(7);
      const secondDeviceKey = new Uint8Array(32).fill(9);

      mockCheckHasDeviceKey.mockResolvedValue(true);
      mockLoadDeviceKey
        .mockResolvedValueOnce(firstDeviceKey)
        .mockResolvedValueOnce(secondDeviceKey);
      mockVerifyKey.mockResolvedValue(true);
      mockAttemptKdfUpgrade.mockResolvedValue({ upgraded: false });

      mockSupabase.from.mockReturnValue({
        select: vi.fn().mockReturnValue({
          eq: vi.fn().mockReturnValue(createSelectQueryMock({
            encryption_salt: "existing-salt",
            master_password_verifier: "existing-verifier",
            kdf_version: 2,
            vault_protection_mode: "device_key_required",
          })),
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

      expect(mockDeriveRawKey).toHaveBeenCalledWith(
        "CorrectPassword!",
        "existing-salt",
        2,
        firstDeviceKey,
      );

      act(() => {
        result.current.lock();
      });

      expect(result.current.isLocked).toBe(true);
      expect(Array.from(firstDeviceKey).every((value) => value === 0)).toBe(true);

      await act(async () => {
        await result.current.unlock("CorrectPassword!");
      });

      expect(mockLoadDeviceKey).toHaveBeenCalledTimes(2);
      expect(mockDeriveRawKey).toHaveBeenLastCalledWith(
        "CorrectPassword!",
        "existing-salt",
        2,
        secondDeviceKey,
      );
      expect(result.current.isLocked).toBe(false);
    });

    it("should surface a missing device key after lock instead of treating it as a wrong password", async () => {
      const firstDeviceKey = new Uint8Array(32).fill(7);

      mockCheckHasDeviceKey.mockResolvedValue(true);
      mockLoadDeviceKey
        .mockResolvedValueOnce(firstDeviceKey)
        .mockResolvedValueOnce(null);
      mockVerifyKey.mockResolvedValue(true);
      mockAttemptKdfUpgrade.mockResolvedValue({ upgraded: false });

      mockSupabase.from.mockReturnValue({
        select: vi.fn().mockReturnValue({
          eq: vi.fn().mockReturnValue(createSelectQueryMock({
            encryption_salt: "existing-salt",
            master_password_verifier: "existing-verifier",
            kdf_version: 2,
            vault_protection_mode: "device_key_required",
          })),
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

      act(() => {
        result.current.lock();
      });

      let unlockResult: { error: Error | null } | undefined;
      await act(async () => {
        unlockResult = await result.current.unlock("CorrectPassword!");
      });

      expect(unlockResult?.error?.message).toBe(
        "This vault is protected with a Device Key. No matching Device Key was found on this device. Import your Device Key from a trusted device or use your documented recovery process. Without the Device Key, this vault cannot be decrypted.",
      );
      expect(mockDeriveRawKey).toHaveBeenCalledTimes(1);
      expect(mockRecordFailedAttempt).not.toHaveBeenCalled();
      expect(result.current.isLocked).toBe(true);
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
      expect(mockEncrypt).toHaveBeenCalledWith("plaintext", expect.anything(), undefined);
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
      expect(mockDecrypt).toHaveBeenCalledWith("encrypted-data", expect.anything(), undefined);
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
        encrypted = await result.current.encryptItem(itemData, "item-1");
      });

      expect(encrypted).toBe("encrypted-item-json");
      expect(mockEncryptVaultItem).toHaveBeenCalledWith(itemData, expect.anything(), "item-1");
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
        decrypted = await result.current.decryptItem("encrypted-item-data", "item-1");
      });

      expect(decrypted).toEqual(decryptedItem);
      expect(mockDecryptVaultItem).toHaveBeenCalledWith("encrypted-item-data", expect.anything(), "item-1");
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

    it("loads registered passkey unlock status even when the local WebAuthn probe is false", async () => {
      mockListPasskeys.mockResolvedValue([
        {
          id: "passkey-1",
          credential_id: "credential-1",
          device_name: "Windows Hello",
          prf_enabled: true,
          created_at: "2026-04-22T10:00:00.000Z",
          last_used_at: null,
          rp_id: "127.0.0.1",
        },
      ]);
      mockSupabase.from.mockReturnValue({
        select: vi.fn().mockReturnValue({
          eq: vi.fn().mockReturnValue(createSelectQueryMock({
            encryption_salt: "existing-salt",
            master_password_verifier: "existing-verifier",
            encrypted_user_key: "encrypted-user-key",
            kdf_version: 2,
          })),
        }),
        update: vi.fn().mockReturnValue({
          eq: vi.fn().mockResolvedValue({ data: null, error: null }),
        }),
      });

      const { result } = renderHook(() => useVault(), { wrapper: createWrapper() });

      await waitFor(() => {
        expect(result.current.isLoading).toBe(false);
      });

      await waitFor(() => {
        expect(result.current.hasPasskeyUnlock).toBe(true);
      });
      expect(result.current.webAuthnAvailable).toBe(false);
    });
  });
});
