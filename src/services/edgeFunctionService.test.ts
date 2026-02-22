// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE
/**
 * @fileoverview Unit tests for edgeFunctionService.
 */

import { beforeEach, describe, expect, it, vi } from "vitest";
import { FunctionsHttpError } from "@supabase/supabase-js";

const { mockInvoke, mockGetUser, supabaseMock } = vi.hoisted(() => {
  const mockInvoke = vi.fn();
  const mockGetUser = vi.fn().mockResolvedValue({ data: { user: { id: 'test-user' } }, error: null });

  const supabaseMock = {
    functions: {
      invoke: mockInvoke,
    },
    auth: {
      getUser: mockGetUser,
    }
  };

  return {
    mockInvoke,
    mockGetUser,
    supabaseMock,
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
});
