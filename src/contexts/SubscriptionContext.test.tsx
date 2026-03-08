// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 — see LICENSE
import { ReactNode } from "react";
import { render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

const { useAuthMock, getSubscriptionMock, getFeatureAccessOverrideMock } = vi.hoisted(() => ({
  useAuthMock: vi.fn(),
  getSubscriptionMock: vi.fn(),
  getFeatureAccessOverrideMock: vi.fn(),
}));

vi.mock("@/contexts/AuthContext", () => ({
  useAuth: useAuthMock,
}));

vi.mock("@/extensions/registry", () => ({
  getServiceHooks: () => ({
    getSubscription: getSubscriptionMock,
    getFeatureAccessOverride: getFeatureAccessOverrideMock,
  }),
}));

let SubscriptionProvider: ({ children }: { children: ReactNode }) => JSX.Element;
let useSubscriptionHook: () => {
  tier: string;
  status: string | null;
  loading: boolean;
  isActive: boolean;
  hasFeature: (feature: "file_attachments" | "family_members") => boolean;
  subscription: unknown | null;
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
        status: state.status,
        loading: state.loading,
        isActive: state.isActive,
        hasAttachments: state.hasFeature("file_attachments"),
        hasFamily: state.hasFeature("family_members"),
        hasSubObject: state.subscription !== null,
      })}
    </pre>
  );
}

function readState() {
  return JSON.parse(screen.getByTestId("subscription-state").textContent || "{}");
}

describe("SubscriptionContext", () => {
  beforeEach(async () => {
    vi.clearAllMocks();
    getFeatureAccessOverrideMock.mockResolvedValue({ hasFullAccess: false });

    await loadContextModule();
  });

  it("loads and exposes active premium subscription feature access", async () => {
    useAuthMock.mockReturnValue({ user: { id: "user-1" }, loading: false, authReady: true });
    getSubscriptionMock.mockResolvedValue({
      id: "sub-1",
      user_id: "user-1",
      tier: "premium",
      status: "active",
      current_period_end: null,
      cancel_at_period_end: false,
      has_used_intro_discount: true,
    });

    render(
      <SubscriptionProvider>
        <Probe />
      </SubscriptionProvider>
    );

    await waitFor(() => expect(readState().loading).toBe(false));
    expect(readState()).toMatchObject({
      tier: "premium",
      status: "active",
      isActive: true,
      hasAttachments: true,
      hasFamily: false,
      hasSubObject: true,
    });
  });

  it("denies paid features for inactive paid subscriptions", async () => {
    useAuthMock.mockReturnValue({ user: { id: "user-2" }, loading: false, authReady: true });
    getSubscriptionMock.mockResolvedValue({
      id: "sub-2",
      user_id: "user-2",
      tier: "premium",
      status: "canceled",
      current_period_end: null,
      cancel_at_period_end: false,
      has_used_intro_discount: false,
    });

    render(
      <SubscriptionProvider>
        <Probe />
      </SubscriptionProvider>
    );

    await waitFor(() => expect(readState().loading).toBe(false));
    expect(readState()).toMatchObject({
      tier: "premium",
      status: "canceled",
      isActive: false,
      hasAttachments: false,
      hasSubObject: true,
    });
  });

  it("resets subscription state after logout to avoid stale paid access", async () => {
    const authState: { user: { id: string } | null; loading: boolean; authReady: boolean } = {
      user: { id: "user-3" },
      loading: false,
      authReady: true,
    };

    useAuthMock.mockImplementation(() => authState);
    getSubscriptionMock.mockResolvedValue({
      id: "sub-3",
      user_id: "user-3",
      tier: "premium",
      status: "active",
      current_period_end: null,
      cancel_at_period_end: false,
      has_used_intro_discount: false,
    });

    const view = render(
      <SubscriptionProvider>
        <Probe />
      </SubscriptionProvider>
    );

    await waitFor(() => expect(readState().tier).toBe("premium"));

    authState.user = null;
    view.rerender(
      <SubscriptionProvider>
        <Probe />
      </SubscriptionProvider>
    );

    await waitFor(() => expect(readState().loading).toBe(false));
    expect(readState()).toMatchObject({
      tier: "free",
      status: null,
      isActive: true,
      hasAttachments: false,
      hasSubObject: false,
    });
  });

  it("unlocks family-only features when premium provides a feature override", async () => {
    useAuthMock.mockReturnValue({ user: { id: "staff-1" }, loading: false, authReady: true });
    getSubscriptionMock.mockResolvedValue({
      id: "sub-4",
      user_id: "staff-1",
      tier: "premium",
      status: "active",
      current_period_end: null,
      cancel_at_period_end: false,
      has_used_intro_discount: false,
    });
    getFeatureAccessOverrideMock.mockResolvedValue({ hasFullAccess: true });

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
      hasSubObject: true,
    });
  });

  it("preserves paid access when feature override resolution fails", async () => {
    useAuthMock.mockReturnValue({ user: { id: "paid-user" }, loading: false, authReady: true });
    getSubscriptionMock.mockResolvedValue({
      id: "sub-5",
      user_id: "paid-user",
      tier: "premium",
      status: "active",
      current_period_end: null,
      cancel_at_period_end: false,
      has_used_intro_discount: false,
    });
    getFeatureAccessOverrideMock.mockRejectedValue(new Error("entitlement lookup failed"));

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
      hasSubObject: true,
    });
  });
});
