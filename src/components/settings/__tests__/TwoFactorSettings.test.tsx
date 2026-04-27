// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 — see LICENSE
/**
 * @fileoverview Tests for TwoFactorSettings Component
 *
 * Tests the multi-step 2FA setup flow:
 * 1. Loading state
 * 2. Enable/disable states
 * 3. Setup flow (QR code -> verify -> backup codes)
 * 4. Vault 2FA toggle
 * 5. Backup codes regeneration
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent, waitFor, within } from "@testing-library/react";
import { TwoFactorSettings } from "../TwoFactorSettings";

// ============ Mocks ============

vi.mock("react-i18next", () => ({
  useTranslation: () => ({
    t: (key: string) => key,
  }),
}));

const mockToast = vi.fn();
vi.mock("@/hooks/use-toast", () => ({
  useToast: () => ({ toast: mockToast }),
}));

vi.mock("@/contexts/AuthContext", () => ({
  useAuth: () => ({
    user: { id: "user-1", email: "test@example.com" },
  }),
}));

const mockGet2FAStatus = vi.fn();
const mockInitializeTwoFactorSetup = vi.fn();
const mockEnableTwoFactor = vi.fn();
const mockDisableTwoFactor = vi.fn();

vi.mock("@/services/twoFactorService", () => ({
  get2FAStatus: (...args: unknown[]) => mockGet2FAStatus(...args),
  generateTOTPSecret: vi.fn().mockReturnValue("JBSWY3DPEHPK3PXP"),
  generateQRCodeUri: vi.fn().mockReturnValue("otpauth://totp/test?secret=JBSWY3DPEHPK3PXP"),
  formatSecretForDisplay: vi.fn().mockReturnValue("JBSW Y3DP EHPK 3PXP"),
  generateBackupCodes: vi.fn().mockReturnValue(["CODE-0001", "CODE-0002", "CODE-0003", "CODE-0004", "CODE-0005"]),
  initializeTwoFactorSetup: (...args: unknown[]) => mockInitializeTwoFactorSetup(...args),
  enableTwoFactor: (...args: unknown[]) => mockEnableTwoFactor(...args),
  disableTwoFactor: (...args: unknown[]) => mockDisableTwoFactor(...args),
  setVaultTwoFactor: vi.fn().mockResolvedValue({ success: true }),
  regenerateBackupCodes: vi.fn().mockResolvedValue({ success: true, codes: ["NEW-0001", "NEW-0002"] }),
}));

vi.mock("@/services/clipboardService", () => ({
  writeClipboard: vi.fn().mockResolvedValue(undefined),
}));

vi.mock("qrcode", () => ({
  default: {
    toDataURL: vi.fn().mockResolvedValue("data:image/png;base64,fakeqrcode"),
  },
}));

// ============ Tests ============

describe("TwoFactorSettings", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockInitializeTwoFactorSetup.mockResolvedValue({ success: true });
    mockEnableTwoFactor.mockResolvedValue({ success: true });
    mockDisableTwoFactor.mockResolvedValue({ success: true });
  });

  it("should show loading state initially", () => {
    mockGet2FAStatus.mockReturnValue(new Promise(() => {})); // Never resolves
    const { container } = render(<TwoFactorSettings />);
    expect(container.querySelector(".animate-spin")).not.toBeNull();
  });

  it("should show enable button when 2FA is disabled", async () => {
    mockGet2FAStatus.mockResolvedValue({
      isEnabled: false,
      vaultTwoFactorEnabled: false,
      backupCodesRemaining: 0,
    });

    render(<TwoFactorSettings />);

    await waitFor(() => {
      expect(screen.getByText("settings.security.twoFactor.enable")).toBeInTheDocument();
    });
  });

  it("should show disable button when 2FA is enabled", async () => {
    mockGet2FAStatus.mockResolvedValue({
      isEnabled: true,
      vaultTwoFactorEnabled: false,
      backupCodesRemaining: 5,
    });

    render(<TwoFactorSettings />);

    await waitFor(() => {
      expect(screen.getByText("settings.security.twoFactor.disable")).toBeInTheDocument();
    });
  });

  it("should start setup flow when enable is clicked", async () => {
    mockGet2FAStatus.mockResolvedValue({
      isEnabled: false,
      vaultTwoFactorEnabled: false,
      backupCodesRemaining: 0,
    });

    render(<TwoFactorSettings />);

    await waitFor(() => {
      expect(screen.getByText("settings.security.twoFactor.enable")).toBeInTheDocument();
    });

    fireEvent.click(screen.getByText("settings.security.twoFactor.enable"));

    // QR code step should show
    await waitFor(() => {
      expect(screen.getByText("settings.security.twoFactor.setup.step1Title")).toBeInTheDocument();
    });
  });

  it("should navigate to step 2 from step 1", async () => {
    mockGet2FAStatus.mockResolvedValue({
      isEnabled: false,
      vaultTwoFactorEnabled: false,
      backupCodesRemaining: 0,
    });

    render(<TwoFactorSettings />);

    await waitFor(() => {
      expect(screen.getByText("settings.security.twoFactor.enable")).toBeInTheDocument();
    });

    fireEvent.click(screen.getByText("settings.security.twoFactor.enable"));

    await waitFor(() => {
      expect(screen.getByText("common.next")).toBeInTheDocument();
    });

    fireEvent.click(screen.getByText("common.next"));

    await waitFor(() => {
      expect(screen.getByText("settings.security.twoFactor.setup.step2Title")).toBeInTheDocument();
    });
  });

  it("should show vault 2FA toggle when enabled", async () => {
    mockGet2FAStatus.mockResolvedValue({
      isEnabled: true,
      vaultTwoFactorEnabled: false,
      backupCodesRemaining: 5,
    });

    render(<TwoFactorSettings />);

    await waitFor(() => {
      expect(screen.getByText("settings.security.twoFactor.vault.title")).toBeInTheDocument();
    });
  });

  it("should show regenerate backup codes button when enabled", async () => {
    mockGet2FAStatus.mockResolvedValue({
      isEnabled: true,
      vaultTwoFactorEnabled: false,
      backupCodesRemaining: 3,
    });

    render(<TwoFactorSettings />);

    await waitFor(() => {
      expect(screen.getByText("settings.security.twoFactor.regenerateCodes")).toBeInTheDocument();
    });
  });

  it("should show backup codes remaining count", async () => {
    mockGet2FAStatus.mockResolvedValue({
      isEnabled: true,
      vaultTwoFactorEnabled: false,
      backupCodesRemaining: 3,
    });

    render(<TwoFactorSettings />);

    await waitFor(() => {
      const text = document.body.textContent;
      expect(text).toContain("settings.security.twoFactor.backupCodesRemaining");
    });
  });

  it("should show a visible rate-limit message when disabling 2FA is throttled", async () => {
    mockGet2FAStatus.mockResolvedValue({
      isEnabled: true,
      vaultTwoFactorEnabled: false,
      backupCodesRemaining: 5,
    });
    mockDisableTwoFactor.mockResolvedValue({
      success: false,
      error: "Zu viele Versuche. Bitte versuche es in 2 Minuten erneut.",
    });

    render(<TwoFactorSettings />);

    await waitFor(() => {
      expect(screen.getByText("settings.security.twoFactor.disable")).toBeInTheDocument();
    });

    fireEvent.click(screen.getByText("settings.security.twoFactor.disable"));
    const dialog = screen.getByRole("dialog");
    fireEvent.change(screen.getByPlaceholderText("000000"), {
      target: { value: "123456" },
    });
    fireEvent.click(within(dialog).getByRole("button", { name: "settings.security.twoFactor.disable" }));

    await waitFor(() => {
      expect(mockDisableTwoFactor).toHaveBeenCalledWith("user-1", "123456");
      expect(screen.getByText("Zu viele Versuche. Bitte versuche es in 2 Minuten erneut.")).toBeInTheDocument();
    });
  });
});
