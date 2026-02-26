// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 — see LICENSE
/**
 * @fileoverview Phase 2 — Unit-Tests für familyService mit DB-Mocks
 *
 * Testet alle exportierten Funktionen des familyService mit gemocktem Supabase.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";

// ---------------------------------------------------------------------------
// Supabase Mock
// ---------------------------------------------------------------------------
function createChainable(resolvedValue: unknown = { data: null, error: null }) {
  const chain: Record<string, (...args: unknown[]) => unknown> = {};
  const methods = ["select", "insert", "update", "delete", "eq", "in", "single", "maybeSingle", "limit", "order", "upsert", "or"];
  for (const m of methods) {
    chain[m] = vi.fn().mockReturnValue(chain);
  }
  // Terminal methods also return the chain but resolve as a promise
  chain.then = (resolve: (v: unknown) => unknown) => resolve(resolvedValue);
  chain._result = () => resolvedValue;
  return chain;
}

const mockSupabase = vi.hoisted(() => {
  const chains: unknown[] = [];
  let chainIndex = 0;

  const mock = {
    from: vi.fn().mockImplementation(() => {
      const idx = chainIndex++;
      return chains[idx] || createChainable();
    }),
    rpc: vi.fn(),
    auth: {
      getUser: vi.fn().mockResolvedValue({ data: { user: { id: "user-123", email: "test@example.com" } } }),
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
  return mock;
});

vi.mock("@/integrations/supabase/client", () => ({ supabase: mockSupabase }));
const mockInvokeAuthedFunction = vi.hoisted(() => vi.fn());
vi.mock("@/services/edgeFunctionService", () => ({
  invokeAuthedFunction: mockInvokeAuthedFunction,
}));

// ---------------------------------------------------------------------------
// Import after mocks
// ---------------------------------------------------------------------------
import {
  getFamilyMembers,
  inviteFamilyMember,
  removeFamilyMember,
  getSharedCollections,
  createSharedCollection,
  deleteSharedCollection,
  getPendingInvitations,
  acceptFamilyInvitation,
  declineFamilyInvitation,
} from "@/services/familyService";

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

beforeEach(() => {
  vi.clearAllMocks();
  mockSupabase._reset();
  mockInvokeAuthedFunction.mockReset();
});

describe("getFamilyMembers()", () => {
  it("returns family members from DB", async () => {
    const members = [
      { id: "m1", family_owner_id: "user-1", member_email: "a@b.com", role: "member", status: "active", invited_at: "2026-01-01" },
    ];
    const chain = createChainable({ data: members, error: null });
    mockSupabase._setChains([chain]);

    const result = await getFamilyMembers("user-1");
    expect(result).toEqual(members);
    expect(mockSupabase.from).toHaveBeenCalledWith("family_members");
  });

  it("returns empty array when no members", async () => {
    const chain = createChainable({ data: [], error: null });
    mockSupabase._setChains([chain]);

    const result = await getFamilyMembers("user-1");
    expect(result).toEqual([]);
  });

  it("throws on DB error", async () => {
    const chain = createChainable({ data: null, error: { message: "DB error" } });
    mockSupabase._setChains([chain]);

    await expect(getFamilyMembers("user-1")).rejects.toEqual({ message: "DB error" });
  });
});

describe("inviteFamilyMember()", () => {
  it("invokes edge function with email", async () => {
    mockInvokeAuthedFunction.mockResolvedValue(undefined);

    await inviteFamilyMember("user-1", "invite@example.com");
    expect(mockInvokeAuthedFunction).toHaveBeenCalledWith("invite-family-member", {
      email: "invite@example.com",
    });
  });

  it("throws on edge function error", async () => {
    mockInvokeAuthedFunction.mockRejectedValue(new Error("Invalid email"));

    await expect(inviteFamilyMember("user-1", "bad")).rejects.toMatchObject({ message: "Invalid email" });
  });

  it("throws when session token is missing", async () => {
    mockInvokeAuthedFunction.mockRejectedValue(new Error("Authentication required"));

    await expect(inviteFamilyMember("user-1", "invite@example.com")).rejects.toMatchObject({
      message: "Authentication required",
    });
  });
});

describe("removeFamilyMember()", () => {
  it("deletes member by ID", async () => {
    const chain = createChainable({ data: null, error: null });
    mockSupabase._setChains([chain]);

    await removeFamilyMember("m1");
    expect(mockSupabase.from).toHaveBeenCalledWith("family_members");
    expect(chain.delete).toHaveBeenCalled();
    expect(chain.eq).toHaveBeenCalledWith("id", "m1");
  });

  it("throws on DB error", async () => {
    const chain = createChainable({ data: null, error: { message: "Not found" } });
    mockSupabase._setChains([chain]);

    await expect(removeFamilyMember("invalid-id")).rejects.toEqual({ message: "Not found" });
  });
});

describe("getSharedCollections()", () => {
  it("returns collections for owner", async () => {
    const collections = [{ id: "c1", owner_id: "user-1", name: "Family", description: null, created_at: "2026-01-01", updated_at: "2026-01-01" }];
    const chain = createChainable({ data: collections, error: null });
    mockSupabase._setChains([chain]);

    const result = await getSharedCollections("user-1");
    expect(result).toEqual(collections);
    expect(mockSupabase.from).toHaveBeenCalledWith("shared_collections");
  });

  it("returns empty array when no collections", async () => {
    const chain = createChainable({ data: [], error: null });
    mockSupabase._setChains([chain]);

    const result = await getSharedCollections("user-1");
    expect(result).toEqual([]);
  });
});

describe("createSharedCollection()", () => {
  it("inserts collection with name and description", async () => {
    const chain = createChainable({ data: null, error: null });
    mockSupabase._setChains([chain]);

    await createSharedCollection("user-1", "Shared", "A collection");
    expect(mockSupabase.from).toHaveBeenCalledWith("shared_collections");
    expect(chain.insert).toHaveBeenCalledWith({
      owner_id: "user-1",
      name: "Shared",
      description: "A collection",
    });
  });

  it("throws on duplicate name error", async () => {
    const chain = createChainable({ data: null, error: { message: "duplicate key" } });
    mockSupabase._setChains([chain]);

    await expect(createSharedCollection("user-1", "Dup", undefined)).rejects.toEqual({ message: "duplicate key" });
  });
});

describe("deleteSharedCollection()", () => {
  it("deletes collection by ID", async () => {
    const chain = createChainable({ data: null, error: null });
    mockSupabase._setChains([chain]);

    await deleteSharedCollection("c1");
    expect(mockSupabase.from).toHaveBeenCalledWith("shared_collections");
    expect(chain.delete).toHaveBeenCalled();
  });
});

describe("getPendingInvitations()", () => {
  it("returns pending invitations for current user", async () => {
    const invitations = [{ id: "inv1", member_email: "test@example.com", status: "invited" }];
    const chain = createChainable({ data: invitations, error: null });
    mockSupabase._setChains([chain]);

    const result = await getPendingInvitations();
    expect(result).toEqual(invitations);
    expect(chain.eq).toHaveBeenCalledWith("member_email", "test@example.com");
    expect(chain.eq).toHaveBeenCalledWith("status", "invited");
  });

  it("returns empty array when no user", async () => {
    mockSupabase.auth.getUser.mockResolvedValueOnce({ data: { user: null } });

    const result = await getPendingInvitations();
    expect(result).toEqual([]);
  });
});

describe("acceptFamilyInvitation()", () => {
  it("updates invitation to active status", async () => {
    const chain = createChainable({ data: null, error: null });
    mockSupabase._setChains([chain]);

    await acceptFamilyInvitation("inv1");
    expect(mockSupabase.from).toHaveBeenCalledWith("family_members");
    expect(chain.update).toHaveBeenCalledWith(
      expect.objectContaining({
        member_user_id: "user-123",
        status: "active",
      })
    );
    expect(chain.eq).toHaveBeenCalledWith("id", "inv1");
    expect(chain.eq).toHaveBeenCalledWith("status", "invited");
  });

  it("throws when not authenticated", async () => {
    mockSupabase.auth.getUser.mockResolvedValueOnce({ data: { user: null } });

    await expect(acceptFamilyInvitation("inv1")).rejects.toThrow("Not authenticated");
  });
});

describe("declineFamilyInvitation()", () => {
  it("deletes the invitation", async () => {
    const chain = createChainable({ data: null, error: null });
    mockSupabase._setChains([chain]);

    await declineFamilyInvitation("inv1");
    expect(mockSupabase.from).toHaveBeenCalledWith("family_members");
    expect(chain.delete).toHaveBeenCalled();
    expect(chain.eq).toHaveBeenCalledWith("id", "inv1");
    expect(chain.eq).toHaveBeenCalledWith("status", "invited");
  });

  it("throws when not authenticated", async () => {
    mockSupabase.auth.getUser.mockResolvedValueOnce({ data: { user: null } });

    await expect(declineFamilyInvitation("inv1")).rejects.toThrow("Not authenticated");
  });
});
