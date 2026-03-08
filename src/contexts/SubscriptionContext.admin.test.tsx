// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE
import { ReactNode } from "react";
import { render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

const { useAuthMock, getSubscriptionMock, getTeamAccessMock } = vi.hoisted(() => ({
  useAuthMock: vi.fn(),
  getSubscriptionMock: vi.fn(),
  getTeamAccessMock: vi.fn(),
}));

vi.mock("@/contexts/AuthContext", () => ({
  useAuth: useAuthMock,
}));

vi.mock("@/extensions/registry", () => ({
  getServiceHooks: () => ({
    getSubscription: getSubscriptionMock,
  }),
}));

vi.mock("@/services/adminService", () => ({
  getTeamAccess: getTeamAccessMock,
}));

let SubscriptionProvider: ({ children }: { children: ReactNode }) => JSX.Element;
let useSubscriptionHook: () => {
  tier: string;
  loading: boolean;
  hasFeature: (feature: "file_attachments" | "family_members") => boolean;
};

async function loadContextModule() {
  vi.resetModules();
  const module = await import("@/contexts/SubscriptionContext");
  SubscriptionProvider = module.SubscriptionProvider;
  useSubscriptionHook = module.useSubscription;
}

function Probe() {
  const state = useSubscriptionHook();

  return (
    <pre data-testid="subscription-state">
      {JSON.stringify({
        tier: state.tier,
        loading: state.loading,
        hasAttachments: state.hasFeature("file_attachments"),
        hasFamily: state.hasFeature("family_members"),
      })}
    </pre>
  );
}

function readState() {
  return JSON.parse(screen.getByTestId("subscription-state").textContent || "{}");
}

describe("SubscriptionContext admin override", () => {
  beforeEach(async () => {
    vi.clearAllMocks();
    await loadContextModule();
  });

  it("unlocks families-only features for internal team users without changing their stored tier", async () => {
    useAuthMock.mockReturnValue({
      user: { id: "admin-user" },
      authReady: true,
    });
    getSubscriptionMock.mockResolvedValue({
      id: "sub-1",
      user_id: "admin-user",
      tier: "premium",
      status: "active",
      current_period_end: null,
      cancel_at_period_end: false,
      has_used_intro_discount: false,
    });
    getTeamAccessMock.mockResolvedValue({
      access: {
        roles: ["moderator"],
        permissions: ["support.admin.access"],
        is_admin: false,
        can_access_admin: true,
      },
      error: null,
    });

    render(
      <SubscriptionProvider>
        <Probe />
      </SubscriptionProvider>
    );

    await waitFor(() => expect(readState().loading).toBe(false));
    expect(readState()).toMatchObject({
      tier: "premium",
      hasAttachments: true,
      hasFamily: true,
    });
  });

  it("preserves paid subscription access when team access lookup fails", async () => {
    useAuthMock.mockReturnValue({
      user: { id: "paid-user" },
      authReady: true,
    });
    getSubscriptionMock.mockResolvedValue({
      id: "sub-2",
      user_id: "paid-user",
      tier: "premium",
      status: "active",
      current_period_end: null,
      cancel_at_period_end: false,
      has_used_intro_discount: false,
    });
    getTeamAccessMock.mockRejectedValue(new Error("admin-team unavailable"));

    render(
      <SubscriptionProvider>
        <Probe />
      </SubscriptionProvider>
    );

    await waitFor(() => expect(readState().loading).toBe(false));
    expect(readState()).toMatchObject({
      tier: "premium",
      hasAttachments: true,
      hasFamily: false,
    });
  });
});
