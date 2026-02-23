// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 — see LICENSE
import { beforeEach, describe, expect, it, vi } from "vitest";

const {
  mockGetUser,
  mockFrom,
  mockSelect,
  mockEq,
  mockSingle,
  mockInvoke,
  supabaseMock,
} = vi.hoisted(() => {
  const mockGetUser = vi.fn();
  const mockSingle = vi.fn();
  const mockEq = vi.fn(() => ({ single: mockSingle }));
  const mockSelect = vi.fn(() => ({ eq: mockEq }));
  const mockFrom = vi.fn(() => ({ select: mockSelect }));
  const mockInvoke = vi.fn();

  const supabaseMock = {
    auth: { getUser: mockGetUser },
    from: mockFrom,
    functions: { invoke: mockInvoke },
  };

  return {
    mockGetUser,
    mockFrom,
    mockSelect,
    mockEq,
    mockSingle,
    mockInvoke,
    supabaseMock,
  };
});

vi.mock("@/integrations/supabase/client", () => ({
  supabase: supabaseMock,
}));

vi.mock("@/services/edgeFunctionService", () => ({
  invokeAuthedFunction: mockInvoke,
}));

import {
  cancelSubscription,
  createCheckoutSession,
  createPortalSession,
  getSubscription,
} from "@/services/subscriptionService";

describe("subscriptionService", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("returns null when there is no authenticated user", async () => {
    mockGetUser.mockResolvedValue({ data: { user: null } });

    const result = await getSubscription();

    expect(result).toBeNull();
    expect(mockFrom).not.toHaveBeenCalled();
  });

  it("returns subscription data for the authenticated user", async () => {
    mockGetUser.mockResolvedValue({ data: { user: { id: "user-1" } } });
    mockSingle.mockResolvedValue({
      data: {
        id: "sub-1",
        user_id: "user-1",
        tier: "premium",
        status: "active",
      },
      error: null,
    });

    const result = await getSubscription();

    expect(mockFrom).toHaveBeenCalledWith("subscriptions");
    expect(mockSelect).toHaveBeenCalledWith("*");
    expect(mockEq).toHaveBeenCalledWith("user_id", "user-1");
    expect(result).toMatchObject({
      id: "sub-1",
      user_id: "user-1",
      tier: "premium",
      status: "active",
    });
  });

  it("blocks checkout when mandatory Widerruf consent is missing", async () => {
    const result = await createCheckoutSession("premium_monthly", {
      execution: true,
      loss: false,
    });

    expect(result).toEqual({
      url: null,
      error: "WIDERRUF_CONSENT_REQUIRED",
    });
    expect(mockInvoke).not.toHaveBeenCalled();
  });

  it("creates checkout session through edge function", async () => {
    mockInvoke.mockResolvedValue({
      data: { url: "https://stripe.example/session" },
      error: null,
    });

    const result = await createCheckoutSession("families_yearly", {
      execution: true,
      loss: true,
    });

    expect(mockInvoke).toHaveBeenCalledWith("create-checkout-session", {
      body: {
        plan_key: "families_yearly",
        widerruf_consent_execution: true,
        widerruf_consent_loss: true,
      },
    });
    expect(result).toEqual({
      url: "https://stripe.example/session",
      error: null,
    });
  });

  it("returns function error for portal session failures", async () => {
    mockInvoke.mockResolvedValue({
      data: null,
      error: { message: "portal failed" },
    });

    const result = await createPortalSession();

    expect(result).toEqual({
      url: null,
      error: "portal failed",
    });
  });

  it("returns normalized cancel result on failures", async () => {
    mockInvoke.mockResolvedValue({
      data: null,
      error: { message: "cancel failed" },
    });

    const result = await cancelSubscription();

    expect(result).toEqual({
      success: false,
      error: "cancel failed",
    });
  });

  it("returns cancel metadata on success", async () => {
    mockInvoke.mockResolvedValue({
      data: {
        success: true,
        cancel_at_period_end: true,
        current_period_end: "2026-12-31T00:00:00.000Z",
      },
      error: null,
    });

    const result = await cancelSubscription();

    expect(result).toEqual({
      success: true,
      cancel_at_period_end: true,
      current_period_end: "2026-12-31T00:00:00.000Z",
    });
  });
});
