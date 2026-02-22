// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 — see LICENSE
/**
 * @fileoverview Unit tests for twoFactorService with mocked DB and OTPAuth
 *
 * Phase 2 tests: every Supabase call and the OTPAuth library are mocked so
 * we can verify control flow, error handling, and data transformations
 * without hitting a real database.
 */

// ============ Hoisted Mocks ============

const mockSupabase = vi.hoisted(() => {
  /**
   * Builds a chainable Supabase query object.
   * Terminal methods (`single`, `maybeSingle`) resolve the chain.
   * Call `_setResult(data, error, count?)` on the returned object
   * to configure the resolved value.
   */
  const createChainable = () => {
    let _result: { data: unknown; error: unknown; count?: number } = {
      data: null,
      error: null,
    };

    type MockFn = ReturnType<typeof vi.fn>;
    const chain: Record<string, MockFn> = {};
    const methods = [
      "select",
      "insert",
      "update",
      "delete",
      "eq",
      "in",
      "single",
      "maybeSingle",
      "limit",
      "order",
      "upsert",
      "head",
    ];

    for (const method of methods) {
      chain[method] = vi.fn().mockImplementation((..._args: unknown[]) => {
        // Terminal methods return the promise-like result
        if (method === "single" || method === "maybeSingle") {
          return Promise.resolve(_result);
        }
        return chain;
      });
    }

    // Allow the chain itself to behave as a thenable so that
    // `await supabase.from('x').delete().eq(...)` resolves.
    chain.then = ((
      resolve: (v: unknown) => void,
      reject?: (e: unknown) => void
    ) => Promise.resolve(_result).then(resolve, reject)) as unknown as MockFn;

    // Helper used in tests to preset the resolved value
    chain._setResult = ((
      data: unknown,
      error: unknown,
      count?: number
    ) => {
      _result = { data, error, count };
      return chain;
    }) as unknown as MockFn;

    return chain;
  };

  return {
    from: vi.fn().mockImplementation(() => createChainable()),
    rpc: vi.fn(),
    auth: { getUser: vi.fn() },
    functions: { invoke: vi.fn() },
    storage: { from: vi.fn() },
    _createChainable: createChainable,
  };
});

vi.mock("@/integrations/supabase/client", () => ({
  supabase: mockSupabase,
}));

// Mock OTPAuth so we can control TOTP validation results
const mockValidate = vi.hoisted(() => vi.fn().mockReturnValue(0));

vi.mock("otpauth", () => ({
  TOTP: vi.fn().mockImplementation(() => ({
    validate: mockValidate,
    toString: vi.fn().mockReturnValue("otpauth://totp/test"),
  })),
  Secret: Object.assign(vi.fn().mockImplementation(() => ({ base32: "MOCKSECRETBASE32" })), {
    fromBase32: vi.fn().mockReturnValue({ base32: "JBSWY3DPEHPK3PXP" }),
  }),
}));

// ============ Imports (after mocks) ============

import { describe, it, expect, vi, beforeEach } from "vitest";
import {
  get2FAStatus,
  getTOTPSecret,
  initializeTwoFactorSetup,
  enableTwoFactor,
  verifyAndConsumeBackupCode,
  disableTwoFactor,
  setVaultTwoFactor,
  regenerateBackupCodes,
  verifyTwoFactorForLogin,
  hashBackupCode,
} from "../twoFactorService";

// ============ Helpers ============

const TEST_USER_ID = "user-abc-123";
const TEST_SECRET = "JBSWY3DPEHPK3PXP";
const TEST_CODE = "123456";
const TEST_SALT = "dGVzdC1zYWx0LWJhc2U2NA=="; // base64

/**
 * Configures `mockSupabase.from` so that successive calls to `from(tableName)`
 * each get their own pre-configured chainable mock.
 *
 * Pass an array of `{ table, data, error, count? }` objects in the order
 * the service will call `supabase.from(...)`.
 */
function setupFromChain(
  calls: Array<{
    table: string;
    data?: unknown;
    error?: unknown;
    count?: number;
  }>
) {
  const chains = calls.map((c) => {
    const chain = mockSupabase._createChainable();
    chain._setResult(c.data ?? null, c.error ?? null, c.count);
    return { table: c.table, chain };
  });

  let callIndex = 0;
  mockSupabase.from.mockImplementation((table: string) => {
    // Find the next matching chain for this table
    for (let i = callIndex; i < chains.length; i++) {
      if (chains[i].table === table) {
        callIndex = i + 1;
        return chains[i].chain;
      }
    }
    // Fallback: return a default chain with null data
    const fallback = mockSupabase._createChainable();
    fallback._setResult(null, null);
    return fallback;
  });

  return chains;
}

// ============ Test Suites ============

beforeEach(() => {
  vi.clearAllMocks();
  // Default: validate returns 0 (valid)
  mockValidate.mockReturnValue(0);
});

describe("get2FAStatus", () => {
  it("returns status when 2FA is enabled", async () => {
    setupFromChain([
      {
        table: "user_2fa",
        data: {
          is_enabled: true,
          vault_2fa_enabled: true,
          last_verified_at: "2025-01-01T00:00:00Z",
        },
      },
      {
        table: "backup_codes",
        data: null,
        error: null,
        count: 3,
      },
    ]);

    const result = await get2FAStatus(TEST_USER_ID);

    expect(result).toEqual({
      isEnabled: true,
      vaultTwoFactorEnabled: true,
      lastVerifiedAt: "2025-01-01T00:00:00Z",
      backupCodesRemaining: 3,
    });
  });

  it("returns null on DB error", async () => {
    setupFromChain([
      {
        table: "user_2fa",
        data: null,
        error: { message: "DB connection failed" },
      },
    ]);

    const result = await get2FAStatus(TEST_USER_ID);
    expect(result).toBeNull();
  });

  it("returns null when no entry found", async () => {
    setupFromChain([
      {
        table: "user_2fa",
        data: null,
        error: null,
      },
    ]);

    const result = await get2FAStatus(TEST_USER_ID);
    expect(result).toBeNull();
  });
});

describe("getTOTPSecret", () => {
  it("returns secret string via RPC", async () => {
    mockSupabase.rpc.mockResolvedValueOnce({
      data: TEST_SECRET,
      error: null,
    });

    const result = await getTOTPSecret(TEST_USER_ID);

    expect(result).toBe(TEST_SECRET);
    expect(mockSupabase.rpc).toHaveBeenCalledWith("get_user_2fa_secret", {
      p_user_id: TEST_USER_ID,
      p_require_enabled: true,
    });
  });

  it("returns null on RPC error", async () => {
    mockSupabase.rpc.mockResolvedValueOnce({
      data: null,
      error: { message: "RPC failed" },
    });

    const result = await getTOTPSecret(TEST_USER_ID);
    expect(result).toBeNull();
  });
});

describe("initializeTwoFactorSetup", () => {
  it("returns success on successful RPC", async () => {
    mockSupabase.rpc.mockResolvedValueOnce({ data: null, error: null });

    const result = await initializeTwoFactorSetup(TEST_USER_ID, TEST_SECRET);
    expect(result).toEqual({ success: true });
  });

  it("returns error on RPC failure", async () => {
    mockSupabase.rpc.mockResolvedValueOnce({
      data: null,
      error: { message: "Duplicate entry" },
    });

    const result = await initializeTwoFactorSetup(TEST_USER_ID, TEST_SECRET);
    expect(result).toEqual({
      success: false,
      error: "Duplicate entry",
    });
  });

  it("calls correct RPC with userId and secret params", async () => {
    mockSupabase.rpc.mockResolvedValueOnce({ data: null, error: null });

    await initializeTwoFactorSetup(TEST_USER_ID, TEST_SECRET);

    expect(mockSupabase.rpc).toHaveBeenCalledWith("initialize_user_2fa_secret", {
      p_user_id: TEST_USER_ID,
      p_secret: TEST_SECRET,
    });
  });
});

describe("enableTwoFactor", () => {
  const backupCodes = ["ABCD-1234", "EFGH-5678", "JKLM-9012"];

  it("succeeds: fetches secret, verifies code, enables 2FA, stores hashed codes", async () => {
    // 1. RPC to get pending secret
    mockSupabase.rpc.mockResolvedValueOnce({
      data: TEST_SECRET,
      error: null,
    });

    // 2. from('user_2fa').update(...)  — enable 2FA
    // 3. from('profiles').select(...)  — getUserEncryptionSalt
    // 4. from('backup_codes').insert(...) — store codes
    const chains = setupFromChain([
      { table: "user_2fa", data: null, error: null },
      { table: "backup_codes", data: null, error: null },
    ]);

    mockValidate.mockReturnValue(0); // valid code

    const result = await enableTwoFactor(TEST_USER_ID, TEST_CODE, backupCodes);

    expect(result).toEqual({ success: true });
    expect(mockSupabase.rpc).toHaveBeenCalledWith("get_user_2fa_secret", {
      p_user_id: TEST_USER_ID,
      p_require_enabled: false,
    });

    // Verify backup_codes insert was called
    expect(chains[1].chain.insert).toHaveBeenCalled();
  });

  it("returns error when code is invalid", async () => {
    mockSupabase.rpc.mockResolvedValueOnce({
      data: TEST_SECRET,
      error: null,
    });

    mockValidate.mockReturnValue(null); // invalid code

    const result = await enableTwoFactor(TEST_USER_ID, "000000", backupCodes);

    expect(result).toEqual({
      success: false,
      error: "Invalid code. Please try again.",
    });
  });

  it("returns error when no pending setup found", async () => {
    mockSupabase.rpc.mockResolvedValueOnce({
      data: null,
      error: null,
    });

    const result = await enableTwoFactor(TEST_USER_ID, TEST_CODE, backupCodes);

    expect(result).toEqual({
      success: false,
      error: "2FA setup not found. Please start again.",
    });
  });

  it("hashes backup codes before storing", async () => {
    mockSupabase.rpc.mockResolvedValueOnce({
      data: TEST_SECRET,
      error: null,
    });

    const chains = setupFromChain([
      { table: "user_2fa", data: null, error: null },
      { table: "backup_codes", data: null, error: null },
    ]);

    mockValidate.mockReturnValue(0);

    await enableTwoFactor(TEST_USER_ID, TEST_CODE, backupCodes);

    const insertCall = chains[1].chain.insert.mock.calls[0][0];
    expect(insertCall).toHaveLength(backupCodes.length);

    // Each inserted item should have user_id and code_hash (hex string, not plaintext)
    for (const item of insertCall) {
      expect(item.user_id).toBe(TEST_USER_ID);
      expect(item.code_hash).toBeDefined();
      expect(typeof item.code_hash).toBe("string");
      // Must be a v3 hash string (v3:salt:hex)
      expect(item.code_hash).toMatch(/^v3:[A-Za-z0-9+/=]+:[0-9a-f]+$/);
      // Must NOT be the plaintext code
      expect(backupCodes).not.toContain(item.code_hash);
    }
  });
});

describe("verifyAndConsumeBackupCode", () => {
  const PLAIN_CODE = "ABCD-1234";

  it("returns true and marks code as used when valid", async () => {
    const hmacHash = await hashBackupCode(PLAIN_CODE, TEST_SALT);

    const chains = setupFromChain([
      // 1. backup_codes — fetch unused codes
      { table: "backup_codes", data: [{ id: "code-1", code_hash: hmacHash, hash_version: 2 }] },
      // 2. profiles — getUserEncryptionSalt
      { table: "profiles", data: { encryption_salt: TEST_SALT } },
      // 3. backup_codes — mark as used
      { table: "backup_codes", data: null, error: null },
      // 4. user_2fa — update last_verified_at
      { table: "user_2fa", data: null, error: null },
    ]);

    const result = await verifyAndConsumeBackupCode(TEST_USER_ID, PLAIN_CODE);

    expect(result).toBe(true);
    // Verify update was called to mark the code as used
    expect(chains[2].chain.update).toHaveBeenCalled();
    const updateArg = chains[2].chain.update.mock.calls[0][0];
    expect(updateArg.is_used).toBe(true);
    expect(updateArg.used_at).toBeDefined();
  });

  it("returns false when code is invalid", async () => {
    setupFromChain([
      // 1. backup_codes — fetch unused codes (no codes)
      { table: "backup_codes", data: [], error: null },
      // 2. profiles — getUserEncryptionSalt
      { table: "profiles", data: { encryption_salt: TEST_SALT } },
    ]);

    const result = await verifyAndConsumeBackupCode(TEST_USER_ID, "ZZZZ-0000");
    expect(result).toBe(false);
  });

  it("checks both HMAC and legacy SHA-256 hashes (dual-verify)", async () => {
    // Compute both hashes for the same code
    const hmacHash = await hashBackupCode(PLAIN_CODE, TEST_SALT);
    const legacyHash = await hashBackupCode(PLAIN_CODE);

    // They should differ since one uses a salt key
    expect(hmacHash).not.toBe(legacyHash);

    const chains = setupFromChain([
      // 1. backup_codes — fetch unused codes
      { table: "backup_codes", data: [{ id: "code-legacy", code_hash: legacyHash, hash_version: 2 }] },
      // 2. profiles — returns salt
      { table: "profiles", data: { encryption_salt: TEST_SALT } },
      // 3. backup_codes — mark as used
      { table: "backup_codes", data: null, error: null },
      // 4. user_2fa — update last_verified_at
      { table: "user_2fa", data: null, error: null },
    ]);

    const result = await verifyAndConsumeBackupCode(TEST_USER_ID, PLAIN_CODE);

    expect(result).toBe(true);
  });
});

describe("disableTwoFactor", () => {
  it("succeeds with valid TOTP code", async () => {
    // getTOTPSecret → RPC
    mockSupabase.rpc.mockResolvedValueOnce({
      data: TEST_SECRET,
      error: null,
    });

    mockValidate.mockReturnValue(0); // valid

    setupFromChain([
      // 1. user_2fa delete
      { table: "user_2fa", data: null, error: null },
      // 2. backup_codes delete
      { table: "backup_codes", data: null, error: null },
    ]);

    const result = await disableTwoFactor(TEST_USER_ID, TEST_CODE);
    expect(result).toEqual({ success: true });
  });

  it("returns error with wrong code", async () => {
    mockSupabase.rpc.mockResolvedValueOnce({
      data: TEST_SECRET,
      error: null,
    });

    mockValidate.mockReturnValue(null); // invalid

    const result = await disableTwoFactor(TEST_USER_ID, "000000");

    expect(result).toEqual({
      success: false,
      error: "Invalid code. Backup codes cannot be used to disable 2FA.",
    });
  });

  it("deletes user_2fa and backup_codes on success", async () => {
    mockSupabase.rpc.mockResolvedValueOnce({
      data: TEST_SECRET,
      error: null,
    });

    mockValidate.mockReturnValue(0);

    const chains = setupFromChain([
      { table: "user_2fa", data: null, error: null },
      { table: "backup_codes", data: null, error: null },
    ]);

    await disableTwoFactor(TEST_USER_ID, TEST_CODE);

    // Both chains should have had .delete() called
    expect(chains[0].chain.delete).toHaveBeenCalled();
    expect(chains[1].chain.delete).toHaveBeenCalled();
  });
});

describe("setVaultTwoFactor", () => {
  it("activates vault 2FA", async () => {
    const chains = setupFromChain([
      { table: "user_2fa", data: null, error: null },
    ]);

    const result = await setVaultTwoFactor(TEST_USER_ID, true);

    expect(result).toEqual({ success: true });
    expect(chains[0].chain.update).toHaveBeenCalledWith({
      vault_2fa_enabled: true,
    });
  });

  it("deactivates vault 2FA", async () => {
    const chains = setupFromChain([
      { table: "user_2fa", data: null, error: null },
    ]);

    const result = await setVaultTwoFactor(TEST_USER_ID, false);

    expect(result).toEqual({ success: true });
    expect(chains[0].chain.update).toHaveBeenCalledWith({
      vault_2fa_enabled: false,
    });
  });
});

describe("regenerateBackupCodes", () => {
  it("generates 5 new codes", async () => {
    // get2FAStatus needs: user_2fa + backup_codes count
    setupFromChain([
      // 1. user_2fa (get2FAStatus)
      { table: "user_2fa", data: { is_enabled: true, vault_2fa_enabled: false, last_verified_at: null } },
      // 2. backup_codes count (get2FAStatus)
      { table: "backup_codes", data: null, count: 3 },
      // 3. backup_codes delete (old codes)
      { table: "backup_codes", data: null, error: null },
      // 4. profiles (getUserEncryptionSalt)
      { table: "profiles", data: { encryption_salt: TEST_SALT } },
      // 5. backup_codes insert (new codes)
      { table: "backup_codes", data: null, error: null },
    ]);

    const result = await regenerateBackupCodes(TEST_USER_ID);

    expect(result.success).toBe(true);
    expect(result.codes).toBeDefined();
    expect(result.codes).toHaveLength(5);
    // Each code should be formatted as XXXX-XXXX
    for (const code of result.codes!) {
      expect(code).toMatch(/^[A-Z0-9]{4}-[A-Z0-9]{4}$/);
    }
  });

  it("deletes old codes first", async () => {
    const chains = setupFromChain([
      { table: "user_2fa", data: { is_enabled: true, vault_2fa_enabled: false, last_verified_at: null } },
      { table: "backup_codes", data: null, count: 3 },
      { table: "backup_codes", data: null, error: null },
      { table: "profiles", data: { encryption_salt: TEST_SALT } },
      { table: "backup_codes", data: null, error: null },
    ]);

    await regenerateBackupCodes(TEST_USER_ID);

    // The 3rd chain (index 2) is the delete call for old backup codes
    expect(chains[2].chain.delete).toHaveBeenCalled();
  });

  it("returns error when 2FA is not active", async () => {
    setupFromChain([
      // user_2fa returns not enabled
      {
        table: "user_2fa",
        data: { is_enabled: false, vault_2fa_enabled: false, last_verified_at: null },
      },
      { table: "backup_codes", data: null, count: 0 },
    ]);

    const result = await regenerateBackupCodes(TEST_USER_ID);

    expect(result).toEqual({
      success: false,
      error: "2FA is not enabled.",
    });
  });
});

describe("verifyTwoFactorForLogin", () => {
  it("TOTP mode: delegates to getTOTPSecret + verifyTOTPCode", async () => {
    // getTOTPSecret → RPC
    mockSupabase.rpc.mockResolvedValueOnce({
      data: TEST_SECRET,
      error: null,
    });

    mockValidate.mockReturnValue(0); // valid

    // from('user_2fa').update last_verified_at
    setupFromChain([
      { table: "user_2fa", data: null, error: null },
    ]);

    const result = await verifyTwoFactorForLogin(TEST_USER_ID, TEST_CODE, false);

    expect(result).toBe(true);
    expect(mockSupabase.rpc).toHaveBeenCalledWith("get_user_2fa_secret", {
      p_user_id: TEST_USER_ID,
      p_require_enabled: true,
    });
  });

  it("backup mode: delegates to verifyAndConsumeBackupCode", async () => {
    const PLAIN_CODE = "ABCD-1234";
    const hmacHash = await hashBackupCode(PLAIN_CODE, TEST_SALT);

    setupFromChain([
      // 1. backup_codes — fetch unused codes
      { table: "backup_codes", data: [{ id: "code-1", code_hash: hmacHash, hash_version: 2 }] },
      // 2. profiles — getUserEncryptionSalt
      { table: "profiles", data: { encryption_salt: TEST_SALT } },
      // 3. backup_codes — mark as used
      { table: "backup_codes", data: null, error: null },
      // 4. user_2fa — update last_verified_at
      { table: "user_2fa", data: null, error: null },
    ]);

    const result = await verifyTwoFactorForLogin(TEST_USER_ID, PLAIN_CODE, true);

    expect(result).toBe(true);
    // Should NOT have called the RPC for getSecret — backup path is different
    expect(mockSupabase.rpc).not.toHaveBeenCalled();
  });

  it("updates last_verified_at on successful TOTP verification", async () => {
    mockSupabase.rpc.mockResolvedValueOnce({
      data: TEST_SECRET,
      error: null,
    });

    mockValidate.mockReturnValue(0);

    const chains = setupFromChain([
      { table: "user_2fa", data: null, error: null },
    ]);

    await verifyTwoFactorForLogin(TEST_USER_ID, TEST_CODE, false);

    // The user_2fa chain should have update called with last_verified_at
    expect(chains[0].chain.update).toHaveBeenCalled();
    const updateArg = chains[0].chain.update.mock.calls[0][0];
    expect(updateArg).toHaveProperty("last_verified_at");
    expect(typeof updateArg.last_verified_at).toBe("string");
  });
});
