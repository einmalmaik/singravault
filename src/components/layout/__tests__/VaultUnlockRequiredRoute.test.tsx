// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE

import { render, screen } from "@testing-library/react";
import { MemoryRouter, Route, Routes, useLocation } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { VaultUnlockRequiredRoute } from "../VaultUnlockRequiredRoute";

const mockUseVault = vi.fn();

vi.mock("@/contexts/VaultContext", () => ({
  useVault: () => mockUseVault(),
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

function renderVaultSettingsRoute() {
  return render(
    <MemoryRouter initialEntries={["/vault/settings?tab=security#mfa"]}>
      <Routes>
        <Route path="/vault" element={<LocationProbe />} />
        <Route
          path="/vault/settings"
          element={(
            <VaultUnlockRequiredRoute>
              <div>Vault settings</div>
            </VaultUnlockRequiredRoute>
          )}
        />
      </Routes>
    </MemoryRouter>,
  );
}

describe("VaultUnlockRequiredRoute", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("redirects locked vault settings back to the vault shell", () => {
    mockUseVault.mockReturnValue({
      isLocked: true,
      isSetupRequired: false,
      isLoading: false,
    });

    renderVaultSettingsRoute();

    expect(screen.queryByText("Vault settings")).not.toBeInTheDocument();
    expect(screen.getByTestId("location")).toHaveTextContent("/vault");
  });

  it("renders vault settings only after vault unlock", () => {
    mockUseVault.mockReturnValue({
      isLocked: false,
      isSetupRequired: false,
      isLoading: false,
    });

    renderVaultSettingsRoute();

    expect(screen.getByText("Vault settings")).toBeInTheDocument();
  });
});
