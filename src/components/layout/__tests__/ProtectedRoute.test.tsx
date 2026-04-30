// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE

import { render, screen } from "@testing-library/react";
import { MemoryRouter, Route, Routes, useLocation } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { ProtectedRoute } from "../ProtectedRoute";

const mockUseAuth = vi.fn();

vi.mock("@/contexts/AuthContext", () => ({
  useAuth: () => mockUseAuth(),
}));

vi.mock("react-i18next", () => ({
  useTranslation: () => ({
    t: (key: string, options?: { defaultValue?: string }) => options?.defaultValue ?? key,
  }),
}));

function LocationProbe() {
  const location = useLocation();
  return (
    <div data-testid="location">
      {location.pathname}
      {location.search}
      {location.hash}
    </div>
  );
}

function renderProtectedSettings(initialEntry = "/settings?tab=security#profile-device-key") {
  return render(
    <MemoryRouter initialEntries={[initialEntry]}>
      <Routes>
        <Route
          path="/settings"
          element={(
            <ProtectedRoute>
              <div>Account security settings</div>
              <LocationProbe />
            </ProtectedRoute>
          )}
        />
        <Route path="/auth" element={<LocationProbe />} />
      </Routes>
    </MemoryRouter>,
  );
}

describe("ProtectedRoute", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("allows account settings for an authenticated account even before vault unlock", () => {
    mockUseAuth.mockReturnValue({
      user: { id: "user-1", email: "user@example.com" },
      loading: false,
      authReady: true,
      isOfflineSession: false,
    });

    renderProtectedSettings();

    expect(screen.getByText("Account security settings")).toBeInTheDocument();
    expect(screen.getByTestId("location")).toHaveTextContent("/settings?tab=security#profile-device-key");
  });

  it("keeps the full target URL when unauthenticated users are redirected to auth", () => {
    mockUseAuth.mockReturnValue({
      user: null,
      loading: false,
      authReady: true,
      isOfflineSession: false,
    });

    renderProtectedSettings();

    const location = screen.getByTestId("location").textContent ?? "";
    expect(location).toContain("/auth?redirect=");
    expect(decodeURIComponent(location)).toContain("/settings?tab=security#profile-device-key");
  });
});
