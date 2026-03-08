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

  it("unlocks families-only features for admin users without changing their stored tier", async () => {
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
        roles: ["admin"],
        permissions: ["support.admin.access"],
        is_admin: true,
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
});
