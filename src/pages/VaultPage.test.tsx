// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE
/**
 * @fileoverview Tests for VaultPage deep-link editing behavior.
 */

import { render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter, Route, Routes, useLocation } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

import VaultPage from "./VaultPage";

const mockSyncOfflineMutations = vi.fn();

vi.mock("react-i18next", () => ({
  useTranslation: () => ({
    t: (key: string, options?: { defaultValue?: string }) => options?.defaultValue || key,
  }),
}));

vi.mock("@/hooks/use-toast", () => ({
  useToast: () => ({ toast: vi.fn() }),
}));

vi.mock("@/hooks/use-mobile", () => ({
  useIsMobile: () => false,
}));

vi.mock("@/contexts/AuthContext", () => ({
  useAuth: () => ({
    user: { id: "user-1" },
    loading: false,
    authReady: true,
  }),
}));

vi.mock("@/contexts/VaultContext", () => ({
  useVault: () => ({
    isLocked: false,
    isSetupRequired: false,
    isLoading: false,
  }),
}));

vi.mock("@/extensions/registry", () => ({
  isPremiumActive: () => false,
  getServiceHooks: () => ({}),
}));

vi.mock("@/services/offlineVaultService", () => ({
  syncOfflineMutations: (...args: unknown[]) => mockSyncOfflineMutations(...args),
}));

vi.mock("@/components/vault/MasterPasswordSetup", () => ({
  MasterPasswordSetup: () => <div>master-password-setup</div>,
}));

vi.mock("@/components/vault/VaultUnlock", () => ({
  VaultUnlock: () => <div>vault-unlock</div>,
}));

vi.mock("@/components/vault/VaultSidebar", () => ({
  VaultSidebar: () => <div>vault-sidebar</div>,
}));

vi.mock("@/components/vault/VaultItemList", () => ({
  VaultItemList: () => <div>vault-item-list</div>,
}));

vi.mock("@/components/vault/VaultItemDialog", () => ({
  VaultItemDialog: ({
    open,
    itemId,
    allowedTypes,
  }: {
    open: boolean;
    itemId: string | null;
    allowedTypes?: string[];
  }) => (
    <div data-testid="vault-item-dialog">
      {`open:${String(open)};item:${itemId ?? "null"};types:${allowedTypes?.join("|") ?? "all"}`}
    </div>
  ),
}));

vi.mock("@/components/ui/sheet", () => ({
  Sheet: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
  SheetContent: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
}));

function LocationProbe() {
  const location = useLocation();

  return <div data-testid="location-search">{location.search}</div>;
}

describe("VaultPage", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockSyncOfflineMutations.mockResolvedValue({
      processed: 0,
      remaining: 0,
      errors: 0,
    });
  });

  it("opens the editor from the edit query param and removes the deep-link params", async () => {
    render(
      <MemoryRouter initialEntries={["/vault?edit=item-123&source=vault-health"]}>
        <Routes>
          <Route
            path="/vault"
            element={
              <>
                <LocationProbe />
                <VaultPage />
              </>
            }
          />
        </Routes>
      </MemoryRouter>,
    );

    await waitFor(() => {
      expect(screen.getByTestId("vault-item-dialog")).toHaveTextContent("open:true;item:item-123");
    });

    expect(screen.getByTestId("vault-item-dialog")).toHaveTextContent("types:password|note");

    await waitFor(() => {
      expect(screen.getByTestId("location-search")).toBeEmptyDOMElement();
    });
  });
});
