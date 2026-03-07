// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 — see LICENSE
/**
 * @fileoverview Tests for CookieConsent Component
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, fireEvent, act } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { CookieConsent } from "../CookieConsent";

// ============ Mocks ============

vi.mock("react-i18next", () => ({
  useTranslation: () => ({
    i18n: { language: "en" },
    t: (key: string) => key,
  }),
}));

vi.mock("@/lib/utils", () => ({
  cn: (...args: unknown[]) => args.filter(Boolean).join(" "),
}));

// ============ Tests ============

describe("CookieConsent", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.useFakeTimers();
    localStorage.clear();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  const renderCookieConsent = () =>
    render(
      <MemoryRouter>
        <CookieConsent />
      </MemoryRouter>
    );

  it("should show banner after a short delay when no consent exists", async () => {
    renderCookieConsent();

    const banner = screen.getByRole("dialog", { name: "Cookie consent" });
    expect(banner).toHaveClass("opacity-0");
    expect(banner).toHaveClass("translate-y-4");

    // Advance past the entry delay
    act(() => {
      vi.advanceTimersByTime(100);
    });

    expect(banner).toHaveClass("opacity-100");
    expect(banner).toHaveClass("translate-y-0");
  });

  it("should not show banner when consent already exists", () => {
    localStorage.setItem(
      "singra-cookie-consent",
      JSON.stringify({ necessary: true, optional: false })
    );

    renderCookieConsent();

    act(() => {
      vi.advanceTimersByTime(100);
    });

    expect(screen.queryByRole("button", { name: "Accept all" })).not.toBeInTheDocument();
  });

  it("should save consent and hide banner when Accept All is clicked", () => {
    renderCookieConsent();

    act(() => {
      vi.advanceTimersByTime(100);
    });

    fireEvent.click(screen.getByRole("button", { name: "Accept all" }));

    act(() => {
      vi.advanceTimersByTime(300);
    });

    const consent = JSON.parse(localStorage.getItem("singra-cookie-consent")!);
    expect(consent.optional).toBe(true);
    expect(consent.necessary).toBe(true);
    expect(screen.queryByRole("button", { name: "Accept all" })).not.toBeInTheDocument();
  });

  it("should save essential-only consent when Essential only is clicked", () => {
    renderCookieConsent();

    act(() => {
      vi.advanceTimersByTime(100);
    });

    fireEvent.click(screen.getByRole("button", { name: "Essential only" }));

    act(() => {
      vi.advanceTimersByTime(300);
    });

    const consent = JSON.parse(localStorage.getItem("singra-cookie-consent")!);
    expect(consent.optional).toBe(false);
    expect(consent.necessary).toBe(true);
  });

  it("should open settings dialog when Customize is clicked", () => {
    renderCookieConsent();

    act(() => {
      vi.advanceTimersByTime(100);
    });

    fireEvent.click(screen.getByRole("button", { name: "Customize" }));

    expect(screen.getByText("Cookie Settings")).toBeInTheDocument();
  });

  it("should have necessary switch always on and disabled", () => {
    renderCookieConsent();

    act(() => {
      vi.advanceTimersByTime(100);
    });

    fireEvent.click(screen.getByRole("button", { name: "Customize" }));

    const [necessarySwitch] = screen.getAllByRole("switch");
    expect(necessarySwitch).toBeChecked();
    expect(necessarySwitch).toBeDisabled();
  });

  it("should save the functional preference from the settings dialog", () => {
    localStorage.setItem(
      "singra-cookie-consent",
      JSON.stringify({ necessary: true, optional: false })
    );

    renderCookieConsent();

    act(() => {
      window.dispatchEvent(new Event("singra:open-cookie-settings"));
    });

    fireEvent.click(screen.getByRole("switch", { name: /functional cookies/i }));
    fireEvent.click(screen.getByRole("button", { name: "Save Preferences" }));

    const consent = JSON.parse(localStorage.getItem("singra-cookie-consent")!);
    expect(consent.optional).toBe(true);
    expect(consent.necessary).toBe(true);
  });

  it("should open dialog via custom event singra:open-cookie-settings", () => {
    localStorage.setItem(
      "singra-cookie-consent",
      JSON.stringify({ necessary: true, optional: false })
    );

    renderCookieConsent();

    // Dispatch custom event
    act(() => {
      window.dispatchEvent(new Event("singra:open-cookie-settings"));
    });

    expect(screen.getByText("Cookie Settings")).toBeInTheDocument();
  });
});
