// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE
/**
 * @fileoverview Unit tests for edgeFunctionService.
 */

import { beforeEach, describe, expect, it, vi } from "vitest";
import { FunctionsHttpError } from "@supabase/supabase-js";

const { mockInvoke, mockGetSession, mockRefreshSession, mockSetSession, supabaseMock, validTestToken } = vi.hoisted(() => {
  const validTestToken = [
    "header",
    btoa(JSON.stringify({
      sub: "user-1",
      aud: "authenticated",
      role: "authenticated",
      exp: 4102444800,
      iss: "https://example.supabase.co/auth/v1",
    })),
    "signature",
  ].join(".");

  const mockInvoke = vi.fn();
  const mockGetSession = vi.fn().mockResolvedValue({
    data: { session: { access_token: validTestToken, refresh_token: 'mock-refresh-token' } },
    error: null
  });
  const mockRefreshSession = vi.fn().mockResolvedValue({
    data: { session: null },
    error: null,
  });
  const mockSetSession = vi.fn().mockResolvedValue({
    data: { session: { access_token: 'rehydrated-token', refresh_token: 'rehydrated-refresh-token' } },
    error: null,
  });

  const supabaseMock = {
    functions: {
      invoke: mockInvoke,
    },
    auth: {
      getSession: mockGetSession,
      refreshSession: mockRefreshSession,
      setSession: mockSetSession,
    }
  };

  return {
    mockInvoke,
    mockGetSession,
    mockRefreshSession,
    mockSetSession,
    supabaseMock,
    validTestToken,
  };
});

vi.mock("@/integrations/supabase/client", () => ({
  supabase: supabaseMock,
}));

import {
  invokeAuthedFunction,
  isEdgeFunctionServiceError,
} from "@/services/edgeFunctionService";

describe("edgeFunctionService", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("fetch not mocked")));
  });

  it("invokes function securely using supabase.functions.invoke", async () => {
    mockInvoke.mockResolvedValueOnce({
      data: { success: true },
      error: null,
    });

    const result = await invokeAuthedFunction<{ success: boolean }>("invite-family-member", {
      email: "a@example.com",
    });

    expect(mockInvoke).toHaveBeenCalledWith("invite-family-member", {
      body: { email: "a@example.com" },
      headers: { Authorization: `Bearer ${validTestToken}` }
    });
    expect(result.success).toBe(true);
  });

  it("throws AUTH_REQUIRED when status is 401", async () => {
    const error = new FunctionsHttpError("Edge Function returned a non-2xx status code");
    (error as any).context = {
      status: 401,
      json: vi.fn().mockResolvedValue({ error: "Unauthorized" }),
    };

    mockInvoke.mockResolvedValueOnce({
      data: null,
      error,
    });

    await expect(
      invokeAuthedFunction("invite-family-member", { email: "a@example.com" }),
    ).rejects.toMatchObject({
      code: "AUTH_REQUIRED",
      status: 401,
      message: "Authentication required",
    });
  });

  it("normalizes 403 function responses", async () => {
    const error = new FunctionsHttpError("Edge Function returned a non-2xx status code");
    (error as any).context = {
      status: 403,
      json: vi.fn().mockResolvedValue({ error: "Families subscription required" }),
    };

    mockInvoke.mockResolvedValueOnce({
      data: null,
      error,
    });

    await expect(
      invokeAuthedFunction("invite-family-member", { email: "a@example.com" }),
    ).rejects.toMatchObject({
      code: "FORBIDDEN",
      status: 403,
      message: "Forbidden",
    });
  });

  it("exposes backend message on 400 responses using json() method", async () => {
    const error = new FunctionsHttpError("Edge Function returned a non-2xx status code");
    (error as any).context = {
      status: 400,
      json: vi.fn().mockResolvedValue({ details: "Invalid email address format" }),
    };

    mockInvoke.mockResolvedValueOnce({
      data: null,
      error,
    });

    try {
      await invokeAuthedFunction("invite-family-member", { email: "" });
      throw new Error("Expected invokeAuthedFunction to throw");
    } catch (err) {
      expect(isEdgeFunctionServiceError(err)).toBe(true);
      expect((err as { code: string }).code).toBe("BAD_REQUEST");
      expect((err as Error).message).toBe("Invalid email address format");
    }
  });

  it("falls back to generic message string if parsing fails", async () => {
    const error = new Error("status code: 500");
    mockInvoke.mockResolvedValueOnce({
      data: null,
      error,
    });

    await expect(
      invokeAuthedFunction("invite-family-member", { email: "a@example.com" }),
    ).rejects.toMatchObject({
      code: "SERVER_ERROR",
      status: 500,
      message: "Internal server error",
    });
  });

  it("rehydrates the session from auth-session and retries once after a 401", async () => {
    const error = new FunctionsHttpError("Edge Function returned a non-2xx status code");
    (error as any).context = {
      status: 401,
      json: vi.fn().mockResolvedValue({ error: "Unauthorized" }),
    };

    mockInvoke
      .mockResolvedValueOnce({
        data: null,
        error,
      })
      .mockResolvedValueOnce({
        data: { success: true },
        error: null,
      });

    vi.mocked(fetch).mockResolvedValue({
      ok: true,
      json: vi.fn().mockResolvedValue({
        session: {
          access_token: "rehydrated-token",
          refresh_token: "rehydrated-refresh-token",
        },
      }),
    } as unknown as Response);

    const result = await invokeAuthedFunction<{ success: boolean }>("admin-team", {
      action: "get_access",
    });

    expect(fetch).toHaveBeenCalledWith(
      expect.stringContaining("/functions/v1/auth-session"),
      expect.objectContaining({
        method: "GET",
        credentials: "include",
      }),
    );
    expect(mockSetSession).toHaveBeenCalledWith({
      access_token: "rehydrated-token",
      refresh_token: "rehydrated-refresh-token",
    });
    expect(mockInvoke).toHaveBeenNthCalledWith(2, "admin-team", {
      body: { action: "get_access" },
      headers: { Authorization: "Bearer rehydrated-token" },
    });
    expect(result.success).toBe(true);
  });
});
