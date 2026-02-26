// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 — see LICENSE
/**
 * @fileoverview Phase 2 — Unit-Tests für emergencyAccessService mit DB-Mocks
 *
 * Testet alle Methoden des emergencyAccessService-Objekts mit gemocktem Supabase.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";

// ---------------------------------------------------------------------------
// Supabase Mock
// ---------------------------------------------------------------------------
function createChainable(resolvedValue: unknown = { data: null, error: null }) {
  const chain: Record<string, (...args: unknown[]) => unknown> = {};
  const methods = ["select", "insert", "update", "delete", "eq", "in", "single", "maybeSingle", "limit", "order", "or"];
  for (const m of methods) {
    chain[m] = vi.fn().mockReturnValue(chain);
  }
  chain.then = (resolve: (v: unknown) => unknown) => resolve(resolvedValue);
  return chain;
}

const mockSupabase = vi.hoisted(() => {
  const chains: unknown[] = [];
  let chainIndex = 0;

  return {
    from: vi.fn().mockImplementation(() => {
      const idx = chainIndex++;
      return chains[idx] || createChainable();
    }),
    rpc: vi.fn(),
    auth: {
      getUser: vi.fn().mockResolvedValue({
        data: { user: { id: "user-123", email: "test@example.com" } },
      }),
      getSession: vi.fn().mockResolvedValue({
        data: { session: { access_token: "test-token" } },
        error: null,
      }),
      refreshSession: vi.fn().mockResolvedValue({
        data: { session: { access_token: "test-token", user: { id: "user-123" } } },
        error: null,
      }),
    },
    functions: { invoke: vi.fn() },
    storage: { from: vi.fn() },
    _setChains: (newChains: unknown[]) => { chains.length = 0; chains.push(...newChains); chainIndex = 0; },
    _reset: () => { chains.length = 0; chainIndex = 0; },
  };
});

vi.mock("@/integrations/supabase/client", () => ({ supabase: mockSupabase }));
const mockInvokeAuthedFunction = vi.hoisted(() => vi.fn());
vi.mock("@/services/edgeFunctionService", () => ({
  invokeAuthedFunction: mockInvokeAuthedFunction,
}));

// Mock pqCryptoService
vi.mock("@/services/pqCryptoService", () => ({
  generatePQKeyPair: vi.fn(),
  hybridEncrypt: vi.fn().mockResolvedValue("hybrid-ciphertext"),
  hybridDecrypt: vi.fn().mockResolvedValue("decrypted-master-key"),
  isHybridEncrypted: vi.fn().mockReturnValue(false),
}));

// ---------------------------------------------------------------------------
// Import after mocks
// ---------------------------------------------------------------------------
import { emergencyAccessService } from "@/services/emergencyAccessService";
import * as pqCryptoService from "@/services/pqCryptoService";

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

beforeEach(() => {
  vi.clearAllMocks();
  mockSupabase._reset();
  mockInvokeAuthedFunction.mockReset();
  mockSupabase.auth.getUser.mockResolvedValue({
    data: { user: { id: "user-123", email: "test@example.com" } },
  });
});

describe("getTrustees()", () => {
  it("returns trustees with profiles", async () => {
    const rows = [
      { id: "ea1", grantor_id: "user-123", trusted_user_id: "t1", trusted_email: "t@e.com", status: "accepted", created_at: "2026-01-01" },
    ];
    const profiles = [{ user_id: "t1", display_name: "Trustee", avatar_url: null }];

    // Chain 1: emergency_access query
    const eaChain = createChainable({ data: rows, error: null });
    // Chain 2: profiles query
    const profileChain = createChainable({ data: profiles, error: null });
    mockSupabase._setChains([eaChain, profileChain]);

    const result = await emergencyAccessService.getTrustees();
    expect(result).toHaveLength(1);
    expect(result[0].trustee).toEqual({ display_name: "Trustee", avatar_url: null });
  });

  it("returns empty array when no user", async () => {
    mockSupabase.auth.getUser.mockResolvedValueOnce({ data: { user: null } });
    const result = await emergencyAccessService.getTrustees();
    expect(result).toEqual([]);
  });
});

describe("getGrantors()", () => {
  it("returns grantors with profiles", async () => {
    const rows = [
      { id: "ea2", grantor_id: "g1", trusted_user_id: "user-123", trusted_email: "test@example.com", status: "accepted", created_at: "2026-01-01" },
    ];
    const profiles = [{ user_id: "g1", display_name: "Grantor", avatar_url: null }];

    const eaChain = createChainable({ data: rows, error: null });
    const profileChain = createChainable({ data: profiles, error: null });
    mockSupabase._setChains([eaChain, profileChain]);

    const result = await emergencyAccessService.getGrantors();
    expect(result).toHaveLength(1);
    expect(result[0].grantor).toEqual({ display_name: "Grantor", avatar_url: null });
  });

  it("returns empty array when no user email", async () => {
    mockSupabase.auth.getUser.mockResolvedValueOnce({ data: { user: { id: "user-123" } } });
    const result = await emergencyAccessService.getGrantors();
    expect(result).toEqual([]);
  });
});

describe("inviteTrustee()", () => {
  it("invokes edge function with correct params", async () => {
    mockInvokeAuthedFunction.mockResolvedValue(undefined);

    const result = await emergencyAccessService.inviteTrustee("trustee@e.com", 7);
    expect(mockInvokeAuthedFunction).toHaveBeenCalledWith("invite-emergency-access", {
      email: "trustee@e.com",
      wait_days: 7,
    });
    expect(result.trusted_email).toBe("trustee@e.com");
    expect(result.wait_days).toBe(7);
    expect(result.status).toBe("invited");
  });

  it("throws on edge function error", async () => {
    mockInvokeAuthedFunction.mockRejectedValue(new Error("Failed"));

    await expect(emergencyAccessService.inviteTrustee("bad@e.com", 3)).rejects.toMatchObject({ message: "Failed" });
  });

  it("throws when session token is missing", async () => {
    mockInvokeAuthedFunction.mockRejectedValue(new Error("Authentication required"));

    await expect(emergencyAccessService.inviteTrustee("trustee@e.com", 3)).rejects.toMatchObject({
      message: "Authentication required",
    });
  });
});

describe("revokeAccess()", () => {
  it("deletes the access entry", async () => {
    const chain = createChainable({ data: null, error: null });
    mockSupabase._setChains([chain]);

    await emergencyAccessService.revokeAccess("ea1");
    expect(mockSupabase.from).toHaveBeenCalledWith("emergency_access");
    expect(chain.delete).toHaveBeenCalled();
    expect(chain.eq).toHaveBeenCalledWith("id", "ea1");
  });
});

describe("requestAccess()", () => {
  it("sets status to pending and starts timer", async () => {
    const chain = createChainable({
      data: { id: "ea1", status: "pending", requested_at: "2026-01-01" },
      error: null,
    });
    mockSupabase._setChains([chain]);

    const result = await emergencyAccessService.requestAccess("ea1");
    expect(chain.update).toHaveBeenCalledWith(
      expect.objectContaining({ status: "pending" })
    );
    expect(result.status).toBe("pending");
  });
});

describe("rejectAccess()", () => {
  it("setzt Status auf 'rejected' und löscht den Timer (Anfrage abgelehnt)", async () => {
    const chain = createChainable({
      data: { id: "ea1", status: "rejected", requested_at: null },
      error: null,
    });
    mockSupabase._setChains([chain]);

    const result = await emergencyAccessService.rejectAccess("ea1");
    expect(chain.update).toHaveBeenCalledWith(
      expect.objectContaining({ status: "rejected", requested_at: null })
    );
    expect(result.status).toBe("rejected");
  });
});

describe("approveAccess()", () => {
  it("sets status to granted", async () => {
    const chain = createChainable({
      data: { id: "ea1", status: "granted", granted_at: "2026-01-01" },
      error: null,
    });
    mockSupabase._setChains([chain]);

    const result = await emergencyAccessService.approveAccess("ea1");
    expect(chain.update).toHaveBeenCalledWith(
      expect.objectContaining({ status: "granted" })
    );
    expect(result.status).toBe("granted");
  });
});

describe("acceptInviteWithPQ()", () => {
  it("accepts with RSA + PQ public keys", async () => {
    const chain = createChainable({
      data: { id: "ea1", status: "accepted", trustee_public_key: "rsa-key", trustee_pq_public_key: "pq-key" },
      error: null,
    });
    mockSupabase._setChains([chain]);

    const result = await emergencyAccessService.acceptInviteWithPQ("ea1", "rsa-key", "pq-key");
    expect(chain.update).toHaveBeenCalledWith(
      expect.objectContaining({
        status: "accepted",
        trusted_user_id: "user-123",
        trustee_public_key: "rsa-key",
        trustee_pq_public_key: "pq-key",
      })
    );
    expect(result.status).toBe("accepted");
  });

  it("throws when not authenticated", async () => {
    mockSupabase.auth.getUser.mockResolvedValueOnce({ data: { user: null } });
    await expect(emergencyAccessService.acceptInviteWithPQ("ea1", "rsa", "pq")).rejects.toThrow("Not authenticated");
  });
});

describe("setHybridEncryptedMasterKey()", () => {
  it("encrypts and stores hybrid ciphertext", async () => {
    const chain = createChainable({ data: null, error: null });
    mockSupabase._setChains([chain]);

    await emergencyAccessService.setHybridEncryptedMasterKey("ea1", "master-key", "pq-pub", "rsa-pub");
    expect(chain.update).toHaveBeenCalledWith(
      expect.objectContaining({ pq_encrypted_master_key: "hybrid-ciphertext" })
    );
  });
});

describe("decryptHybridMasterKey()", () => {
  it("decrypts hybrid encrypted key", async () => {
    const result = await emergencyAccessService.decryptHybridMasterKey("encrypted", "pq-secret", "rsa-private");
    expect(result).toBe("decrypted-master-key");
  });
});

describe("hasPQEncryption()", () => {
  it("returns true when both PQ fields are present", () => {
    vi.mocked(pqCryptoService.isHybridEncrypted).mockReturnValueOnce(true);

    const access = {
      id: "ea1", grantor_id: "g1", trusted_email: "t@e.com", trusted_user_id: null,
      status: "accepted" as const, wait_days: 7, requested_at: null, granted_at: null,
      created_at: "2026-01-01", trustee_public_key: "rsa",
      encrypted_master_key: null,
      trustee_pq_public_key: "pq-pub",
      pq_encrypted_master_key: "pq-enc",
    };
    expect(emergencyAccessService.hasPQEncryption(access)).toBe(true);
  });

  it("returns false when PQ fields are missing", () => {
    const access = {
      id: "ea1", grantor_id: "g1", trusted_email: "t@e.com", trusted_user_id: null,
      status: "accepted" as const, wait_days: 7, requested_at: null, granted_at: null,
      created_at: "2026-01-01", trustee_public_key: "rsa",
      encrypted_master_key: "enc",
      trustee_pq_public_key: null,
      pq_encrypted_master_key: null,
    };
    expect(emergencyAccessService.hasPQEncryption(access)).toBe(false);
  });
});
