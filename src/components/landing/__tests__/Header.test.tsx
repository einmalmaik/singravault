// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE
/**
 * @fileoverview Tests for landing Header admin access visibility.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";

import { Header } from "../Header";

const translations: Record<string, string> = {
  "landing.footer.security": "Security",
  "subscription.pricing_title": "Pricing",
  "pwa.install": "Install app",
  "nav.vault": "Vault",
  "nav.account": "Account",
  "nav.settings": "Settings",
  "nav.logout": "Logout",
  "nav.login": "Login",
  "nav.signup": "Sign up",
  "admin.title": "Admin",
};

vi.mock("react-i18next", () => ({
  useTranslation: () => ({
    t: (key: string, fallback?: string) => translations[key] || fallback || key,
  }),
}));

const mockSignOut = vi.fn();
const mockGetTeamAccess = vi.fn();

let mockUser: { id: string } | null = { id: "user-1" };
let mockAuthReady = true;
let mockPremiumActive = true;

vi.mock("@/contexts/AuthContext", () => ({
  useAuth: () => ({
    user: mockUser,
    signOut: mockSignOut,
    authReady: mockAuthReady,
  }),
}));

vi.mock("@/extensions/registry", () => ({
  isPremiumActive: () => mockPremiumActive,
  getServiceHooks: () => ({
    getTeamAccess: mockGetTeamAccess,
  }),
}));

describe("Header", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockUser = { id: "user-1" };
    mockAuthReady = true;
    mockPremiumActive = true;
    mockGetTeamAccess.mockResolvedValue({
      access: {
        is_admin: true,
        can_access_admin: true,
      },
      error: null,
    });
  });

  it("shows the admin button next to the vault entry for admin accounts", async () => {
    render(
      <MemoryRouter>
        <Header />
      </MemoryRouter>,
    );

    await waitFor(() => {
      expect(screen.getAllByText("Admin")[0]).toBeInTheDocument();
    });
  });

  it("keeps the admin button hidden for non-admin accounts", async () => {
    mockGetTeamAccess.mockResolvedValue({
      access: {
        is_admin: false,
        can_access_admin: false,
      },
      error: null,
    });

    render(
      <MemoryRouter>
        <Header />
      </MemoryRouter>,
    );

    await waitFor(() => {
      expect(mockGetTeamAccess).toHaveBeenCalledTimes(1);
    });

    expect(screen.queryByText("Admin")).not.toBeInTheDocument();
  });
});
