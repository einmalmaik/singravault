// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 — see LICENSE
import { beforeEach, describe, expect, it, vi } from "vitest";

const { mockGetUser, mockInvoke, supabaseMock } = vi.hoisted(() => {
  const mockInvoke = vi.fn();
  const mockGetUser = vi.fn();

  const supabaseMock = {
    auth: {
      getUser: mockGetUser,
    },
    functions: {
      invoke: mockInvoke,
    },
  };

  return {
    mockGetUser,
    mockInvoke,
    supabaseMock,
  };
});

vi.mock("@/integrations/supabase/client", () => ({
  supabase: supabaseMock,
}));

import {
  assignUserSubscription,
  getAdminSupportTicket,
  getTeamAccess,
  listAdminSupportTickets,
  listRolePermissions,
  listTeamMembers,
  setRolePermission,
  setTeamMemberRole,
} from "@/services/adminService";

describe("adminService", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockGetUser.mockResolvedValue({
      data: {
        user: {
          id: "test-user",
        },
      },
      error: null,
    });
  });

  it("loads team access from admin-team function", async () => {
    mockInvoke.mockResolvedValue({
      data: {
        success: true,
        access: {
          roles: ["admin"],
          permissions: ["support.admin.access"],
          is_admin: true,
          can_access_admin: true,
        },
      },
      error: null,
    });

    const result = await getTeamAccess();

    expect(mockInvoke).toHaveBeenCalledWith("admin-team", {
      body: {
        action: "get_access",
      },
    });
    expect(result.error).toBeNull();
    expect(result.access?.can_access_admin).toBe(true);
  });

  it("lists support tickets with filter payload", async () => {
    mockInvoke.mockResolvedValue({
      data: {
        success: true,
        tickets: [{ id: "ticket-1", subject: "Issue" }],
      },
      error: null,
    });

    const result = await listAdminSupportTickets({
      status: "open",
      search: "Issue",
      limit: 10,
    });

    expect(mockInvoke).toHaveBeenCalledWith("admin-support", {
      body: {
        action: "list_tickets",
        status: "open",
        search: "Issue",
        limit: 10,
      },
    });
    expect(result.error).toBeNull();
    expect(result.tickets).toHaveLength(1);
  });

  it("returns normalized error when role update fails", async () => {
    mockInvoke.mockResolvedValue({
      data: null,
      error: { message: "role update failed" },
    });

    const result = await setTeamMemberRole("user-1", "moderator");

    expect(result.success).toBe(false);
    expect(result.error?.message).toBe("role update failed");
  });

  it("updates role permission via admin-team function", async () => {
    mockInvoke.mockResolvedValue({
      data: {
        success: true,
      },
      error: null,
    });

    const result = await setRolePermission("moderator", "support.tickets.status", true);

    expect(mockInvoke).toHaveBeenCalledWith("admin-team", {
      body: {
        action: "set_role_permission",
        role: "moderator",
        permission_key: "support.tickets.status",
        enabled: true,
      },
    });
    expect(result.success).toBe(true);
    expect(result.error).toBeNull();
  });

  it("handles ticket detail payload", async () => {
    mockInvoke.mockResolvedValue({
      data: {
        success: true,
        ticket: { id: "ticket-1", subject: "Issue" },
        messages: [{ id: "msg-1", body: "Hi" }],
        permissions: {
          can_reply: true,
          can_read_internal: true,
          can_update_status: true,
        },
      },
      error: null,
    });

    const result = await getAdminSupportTicket("ticket-1");

    expect(mockInvoke).toHaveBeenCalledWith("admin-support", {
      body: {
        action: "get_ticket",
        ticket_id: "ticket-1",
      },
    });
    expect(result.error).toBeNull();
    expect(result.detail?.messages).toHaveLength(1);
  });

  it("loads team lists from their edge functions", async () => {
    mockInvoke
      .mockResolvedValueOnce({
        data: {
          success: true,
          members: [{ user_id: "u1", primary_role: "admin" }],
        },
        error: null,
      })
      .mockResolvedValueOnce({
        data: {
          success: true,
          permissions: [{ permission_key: "support.tickets.read" }],
        },
        error: null,
      });

    const membersResult = await listTeamMembers();
    const permissionsResult = await listRolePermissions();

    expect(membersResult.members).toHaveLength(1);
    expect(permissionsResult.permissions).toHaveLength(1);
  });

  it("assigns user subscription via admin-support function", async () => {
    mockInvoke.mockResolvedValue({
      data: {
        success: true,
      },
      error: null,
    });

    const result = await assignUserSubscription({
      userId: "user-1",
      tier: "premium",
      reason: "Manual support upgrade",
      ticketId: "ticket-1",
    });

    expect(mockInvoke).toHaveBeenCalledWith("admin-support", {
      body: {
        action: "assign_subscription",
        user_id: "user-1",
        tier: "premium",
        reason: "Manual support upgrade",
        ticket_id: "ticket-1",
      },
    });
    expect(result.success).toBe(true);
    expect(result.error).toBeNull();
  });
});
