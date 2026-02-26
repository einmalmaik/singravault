// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 — see LICENSE
/**
 * @fileoverview Tests for FeatureGate Component
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";
import { FeatureGate } from "../FeatureGate";

// ============ Mocks ============

const mockNavigate = vi.fn();
vi.mock("react-router-dom", () => ({
  useNavigate: () => mockNavigate,
}));

vi.mock("react-i18next", () => ({
  useTranslation: () => ({
    t: (key: string, params?: Record<string, string>) => {
      if (key === "subscription.feature_locked_title") return "Feature locked";
      if (key === "subscription.feature_locked_description")
        return `${params?.feature} requires ${params?.tier}`;
      if (key === "subscription.upgrade_now") return "Upgrade now";
      if (key.startsWith("subscription.features.")) return key.split(".").pop();
      return key;
    },
  }),
}));

const mockUseFeatureGate = vi.fn();
vi.mock("@/hooks/useFeatureGate", () => ({
  useFeatureGate: (...args: unknown[]) => mockUseFeatureGate(...args),
}));

// ============ Tests ============

describe("FeatureGate", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("should render children when feature is allowed", () => {
    mockUseFeatureGate.mockReturnValue({
      allowed: true,
      requiredTier: "free",
    });

    render(
      <FeatureGate feature="unlimited_passwords">
        <div data-testid="child-content">Protected Content</div>
      </FeatureGate>
    );

    expect(screen.getByTestId("child-content")).toBeInTheDocument();
    expect(screen.queryByText("Feature locked")).not.toBeInTheDocument();
  });

  it("should render lock card when feature is not allowed", () => {
    mockUseFeatureGate.mockReturnValue({
      allowed: false,
      requiredTier: "premium",
    });

    render(
      <FeatureGate feature="file_attachments">
        <div data-testid="child-content">Protected Content</div>
      </FeatureGate>
    );

    expect(screen.queryByTestId("child-content")).not.toBeInTheDocument();
    expect(screen.getByText("Feature locked")).toBeInTheDocument();
    expect(screen.getByText("Upgrade now")).toBeInTheDocument();
  });

  it("should render compact lock when compact=true", () => {
    mockUseFeatureGate.mockReturnValue({
      allowed: false,
      requiredTier: "premium",
    });

    const { container } = render(
      <FeatureGate feature="file_attachments" compact>
        <div data-testid="child-content">Protected Content</div>
      </FeatureGate>
    );

    expect(screen.queryByTestId("child-content")).not.toBeInTheDocument();
    expect(screen.queryByText("Upgrade now")).not.toBeInTheDocument();
    expect(container.querySelector(".cursor-not-allowed")).not.toBeNull();
    expect(screen.getByText("premium")).toBeInTheDocument();
  });

  it("should navigate to /pricing when Upgrade button is clicked", () => {
    mockUseFeatureGate.mockReturnValue({
      allowed: false,
      requiredTier: "premium",
    });

    render(
      <FeatureGate feature="file_attachments">
        <div>Protected Content</div>
      </FeatureGate>
    );

    fireEvent.click(screen.getByText("Upgrade now"));
    expect(mockNavigate).toHaveBeenCalledWith("/pricing");
  });
});
