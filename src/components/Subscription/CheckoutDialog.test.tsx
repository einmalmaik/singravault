// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 — see LICENSE
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { CheckoutDialog } from "@/components/Subscription/CheckoutDialog";

const { createCheckoutSessionMock, useSubscriptionMock } = vi.hoisted(() => ({
  createCheckoutSessionMock: vi.fn(),
  useSubscriptionMock: vi.fn(),
}));

vi.mock("react-i18next", () => ({
  useTranslation: () => ({
    t: (key: string) => key,
  }),
}));

vi.mock("@/services/subscriptionService", () => ({
  createCheckoutSession: createCheckoutSessionMock,
}));

vi.mock("@/contexts/SubscriptionContext", () => ({
  useSubscription: useSubscriptionMock,
}));

describe("CheckoutDialog", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    useSubscriptionMock.mockReturnValue({
      hasUsedIntroDiscount: false,
    });
  });

  it("requires both consent checkboxes before enabling checkout", async () => {
    createCheckoutSessionMock.mockResolvedValue({ url: null, error: "NO_URL" });

    render(
      <CheckoutDialog
        planKey="premium_monthly"
        open={true}
        onClose={() => undefined}
      />
    );

    const proceedButton = screen.getByRole("button", {
      name: "subscription.proceed_checkout",
    });
    expect(proceedButton).toBeDisabled();

    fireEvent.click(screen.getByLabelText("subscription.widerruf_consent_execution"));
    expect(proceedButton).toBeDisabled();

    fireEvent.click(screen.getByLabelText("subscription.widerruf_consent_loss"));
    expect(proceedButton).toBeEnabled();

    fireEvent.click(proceedButton);

    await waitFor(() => {
      expect(createCheckoutSessionMock).toHaveBeenCalledWith("premium_monthly", {
        execution: true,
        loss: true,
      });
    });
  });

  it("shows intro discount only for monthly plans", () => {
    const { rerender } = render(
      <CheckoutDialog
        planKey="premium_monthly"
        open={true}
        onClose={() => undefined}
      />
    );

    expect(
      screen.getByText("subscription.first_month_discount")
    ).toBeInTheDocument();

    rerender(
      <CheckoutDialog
        planKey="premium_yearly"
        open={true}
        onClose={() => undefined}
      />
    );

    expect(
      screen.queryByText("subscription.first_month_discount")
    ).not.toBeInTheDocument();
  });

  it("renders service errors from checkout creation", async () => {
    createCheckoutSessionMock.mockResolvedValue({
      url: null,
      error: "CHECKOUT_FAILED",
    });

    render(
      <CheckoutDialog
        planKey="families_monthly"
        open={true}
        onClose={() => undefined}
      />
    );

    fireEvent.click(screen.getByLabelText("subscription.widerruf_consent_execution"));
    fireEvent.click(screen.getByLabelText("subscription.widerruf_consent_loss"));
    fireEvent.click(
      screen.getByRole("button", { name: "subscription.proceed_checkout" })
    );

    await waitFor(() => {
      expect(screen.getByText("CHECKOUT_FAILED")).toBeInTheDocument();
    });
  });
});
