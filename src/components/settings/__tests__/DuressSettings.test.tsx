// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 — see LICENSE
/**
 * @fileoverview Tests for DuressSettings Component
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { DuressSettings } from "../DuressSettings";

// ============ Mocks ============

vi.mock("react-i18next", () => ({
  useTranslation: () => ({
    t: (key: string) => {
      // Return the key itself — we'll search for the actual key strings
      return key;
    },
  }),
}));

const mockToast = vi.fn();
vi.mock("@/hooks/use-toast", () => ({
  useToast: () => ({ toast: mockToast }),
}));

const mockNavigate = vi.fn();
vi.mock("react-router-dom", () => ({
  useNavigate: () => mockNavigate,
}));

vi.mock("@/contexts/AuthContext", () => ({
  useAuth: () => ({
    user: { id: "user-1", email: "test@test.com" },
  }),
}));

const mockVaultContext = {
  isLocked: false,
};
vi.mock("@/contexts/VaultContext", () => ({
  useVault: () => mockVaultContext,
}));

const mockFeatureGate = { allowed: true };
vi.mock("@/hooks/useFeatureGate", () => ({
  useFeatureGate: () => mockFeatureGate,
}));

const mockGetDuressConfig = vi.fn();

vi.mock("@/services/duressService", () => ({
  getDuressConfig: (...args: unknown[]) => mockGetDuressConfig(...args),
  setupDuressPassword: vi.fn().mockResolvedValue({ success: true }),
  disableDuressMode: vi.fn().mockResolvedValue({ success: true }),
  changeDuressPassword: vi.fn(),
  getDefaultDecoyItems: vi.fn().mockReturnValue([]),
  markAsDecoyItem: vi.fn((item: unknown) => item),
}));

vi.mock("@/services/cryptoService", () => ({
  deriveKey: vi.fn().mockResolvedValue({} as CryptoKey),
  encryptVaultItem: vi.fn().mockResolvedValue("encrypted"),
}));

const mockSupabase = vi.hoisted(() => ({
  from: vi.fn().mockReturnValue({
    insert: vi.fn().mockResolvedValue({ error: null }),
    select: vi.fn().mockReturnValue({
      eq: vi.fn().mockReturnValue({
        single: vi.fn().mockResolvedValue({ data: null, error: null }),
      }),
    }),
  }),
}));
vi.mock("@/integrations/supabase/client", () => ({
  supabase: mockSupabase,
}));

// ============ Tests ============

describe("DuressSettings", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockVaultContext.isLocked = false;
    mockFeatureGate.allowed = true;
  });

  it("should show upgrade prompt for free users without access", async () => {
    mockFeatureGate.allowed = false;
    mockGetDuressConfig.mockResolvedValue(null);

    render(<DuressSettings />);

    await waitFor(() => {
      // Upgrade button uses t('duress.upgradeNow')
      expect(screen.getByText("duress.upgradeNow")).toBeInTheDocument();
    });
  });

  it("should show unlock required warning when vault is locked", async () => {
    mockVaultContext.isLocked = true;
    mockGetDuressConfig.mockResolvedValue(null);

    render(<DuressSettings />);

    await waitFor(() => {
      expect(screen.getByText("duress.unlockRequired")).toBeInTheDocument();
    });
  });

  it("should show enable button when duress is not configured", async () => {
    mockGetDuressConfig.mockResolvedValue(null);

    render(<DuressSettings />);

    await waitFor(() => {
      expect(screen.getByText("duress.enable")).toBeInTheDocument();
    });
  });

  it("should open setup dialog when enable is clicked", async () => {
    mockGetDuressConfig.mockResolvedValue(null);

    render(<DuressSettings />);

    await waitFor(() => {
      expect(screen.getByText("duress.enable")).toBeInTheDocument();
    });

    fireEvent.click(screen.getByText("duress.enable"));

    await waitFor(() => {
      expect(screen.getByText("duress.setupTitle")).toBeInTheDocument();
    });
  });

  it("should show Active badge when duress is enabled", async () => {
    mockGetDuressConfig.mockResolvedValue({ enabled: true, salt: "s", verifier: "v" });

    render(<DuressSettings />);

    await waitFor(() => {
      expect(screen.getByText("duress.active")).toBeInTheDocument();
    });
  });

  it("should show disable button when duress is enabled", async () => {
    mockGetDuressConfig.mockResolvedValue({ enabled: true, salt: "s", verifier: "v" });

    render(<DuressSettings />);

    await waitFor(() => {
      expect(screen.getByText("duress.disable")).toBeInTheDocument();
    });
  });

  it("should show change password button when duress is enabled", async () => {
    mockGetDuressConfig.mockResolvedValue({ enabled: true, salt: "s", verifier: "v" });

    render(<DuressSettings />);

    await waitFor(() => {
      expect(screen.getByText("duress.changePassword")).toBeInTheDocument();
    });
  });
});
