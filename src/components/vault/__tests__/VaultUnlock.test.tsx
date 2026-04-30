// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 — see LICENSE
/**
 * @fileoverview Tests for VaultUnlock Component
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { MemoryRouter, useLocation } from "react-router-dom";
import { VaultUnlock } from "../VaultUnlock";

// ============ Mocks ============

vi.mock("react-i18next", () => ({
  useTranslation: () => ({
    t: (key: string, fallback?: string) => fallback || key,
  }),
}));

const mockToast = vi.fn();
vi.mock("@/hooks/use-toast", () => ({
  useToast: () => ({ toast: mockToast }),
}));

const mockUnlock = vi.fn().mockResolvedValue({ error: null });
const mockUnlockWithPasskey = vi.fn().mockResolvedValue({ error: null });
const mockVaultContext = {
  unlock: (...args: unknown[]) => mockUnlock(...args),
  unlockWithPasskey: (...args: unknown[]) => mockUnlockWithPasskey(...args),
  pendingSessionRestore: false,
  webAuthnAvailable: false,
  hasPasskeyUnlock: false,
  deviceKeyActive: false,
  vaultProtectionMode: "master_only",
};

vi.mock("@/contexts/VaultContext", () => ({
  useVault: () => mockVaultContext,
}));

const mockSignOut = vi.fn().mockResolvedValue(undefined);
vi.mock("@/contexts/AuthContext", () => ({
  useAuth: () => ({
    signOut: mockSignOut,
    user: { id: "user-1", email: "test@test.com" },
  }),
}));

const mockVerifyTwoFactorCode = vi.fn().mockResolvedValue({ success: true });
vi.mock("@/services/twoFactorService", () => ({
  verifyTwoFactorCode: (...args: unknown[]) => mockVerifyTwoFactorCode(...args),
}));

vi.mock("@/components/auth/TwoFactorVerificationModal", () => ({
  TwoFactorVerificationModal: ({
    open,
    onVerify,
    onCancel,
  }: {
    open: boolean;
    onVerify: (code: string, isBackupCode: boolean) => Promise<boolean>;
    onCancel: () => void;
  }) =>
    open ? (
      <div data-testid="2fa-modal">
        2FA Modal
        <button type="button" onClick={() => void onVerify("123456", false)}>
          verify-totp
        </button>
        <button type="button" onClick={() => void onVerify("BACKUP-1", true)}>
          verify-backup
        </button>
        <button type="button" onClick={onCancel}>
          cancel-2fa
        </button>
      </div>
    ) : null,
}));

function renderVaultUnlock(initialEntries = ["/vault"]) {
  return render(
    <MemoryRouter initialEntries={initialEntries}>
      <VaultUnlock />
    </MemoryRouter>,
  );
}

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

// ============ Tests ============

describe("VaultUnlock", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockVaultContext.pendingSessionRestore = false;
    mockVaultContext.webAuthnAvailable = false;
    mockVaultContext.hasPasskeyUnlock = false;
    mockVaultContext.deviceKeyActive = false;
    mockVaultContext.vaultProtectionMode = "master_only";
    mockVerifyTwoFactorCode.mockResolvedValue({ success: true });
    mockUnlock.mockResolvedValue({ error: null });
    mockUnlockWithPasskey.mockResolvedValue({ error: null });
  });

  it("should render password input and unlock button", () => {
    renderVaultUnlock();

    expect(screen.getByLabelText("auth.unlock.password")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /auth\.unlock\.submit/i })).toBeInTheDocument();
  });

  it("should call unlock with entered password and a 2FA callback on submit", async () => {
    renderVaultUnlock();

    const input = screen.getByLabelText("auth.unlock.password");
    fireEvent.change(input, { target: { value: "MyMasterPassword!" } });

    const form = input.closest("form")!;
    fireEvent.submit(form);

    await waitFor(() => {
      expect(mockUnlock).toHaveBeenCalledWith(
        "MyMasterPassword!",
        expect.objectContaining({ verifyTwoFactor: expect.any(Function) }),
      );
    });
  });

  it("should show passkey button when passkey unlock credentials exist", () => {
    mockVaultContext.webAuthnAvailable = false;
    mockVaultContext.hasPasskeyUnlock = false;
    const { rerender } = render(
      <MemoryRouter>
        <VaultUnlock />
      </MemoryRouter>,
    );

    expect(screen.queryByText("Unlock with Passkey")).not.toBeInTheDocument();

    mockVaultContext.webAuthnAvailable = false;
    mockVaultContext.hasPasskeyUnlock = true;
    rerender(
      <MemoryRouter>
        <VaultUnlock />
      </MemoryRouter>,
    );

    expect(screen.getByText("Unlock with Passkey")).toBeInTheDocument();
  });

  it("should call unlockWithPasskey with a 2FA callback when passkey button clicked", async () => {
    mockVaultContext.webAuthnAvailable = true;
    mockVaultContext.hasPasskeyUnlock = true;
    renderVaultUnlock();

    fireEvent.click(screen.getByText("Unlock with Passkey"));

    await waitFor(() => {
      expect(mockUnlockWithPasskey).toHaveBeenCalledWith(
        expect.objectContaining({ verifyTwoFactor: expect.any(Function) }),
      );
    });
  });

  it("should show 2FA modal when the vault context requires it", async () => {
    mockUnlock.mockImplementationOnce(async (_password, options) => {
      await options.verifyTwoFactor();
      return { error: null };
    });
    renderVaultUnlock();

    const input = screen.getByLabelText("auth.unlock.password");
    fireEvent.change(input, { target: { value: "password123" } });

    const form = input.closest("form")!;
    fireEvent.submit(form);

    await waitFor(() => {
      expect(screen.getByTestId("2fa-modal")).toBeInTheDocument();
    });
  });

  it("should verify vault 2FA through the central service", async () => {
    mockUnlock.mockImplementationOnce(async (_password, options) => {
      const verified = await options.verifyTwoFactor();
      return verified ? { error: null } : { error: new Error("Vault 2FA verification failed.") };
    });
    renderVaultUnlock();

    const input = screen.getByLabelText("auth.unlock.password");
    fireEvent.change(input, { target: { value: "password123" } });
    fireEvent.submit(input.closest("form")!);

    await waitFor(() => {
      expect(screen.getByTestId("2fa-modal")).toBeInTheDocument();
    });

    fireEvent.click(screen.getByText("verify-totp"));

    await waitFor(() => {
      expect(mockVerifyTwoFactorCode).toHaveBeenCalledWith({
        userId: "user-1",
        context: "vault_unlock",
        code: "123456",
        method: "totp",
      });
    });
  });

  it("should not finish passkey unlock until central vault 2FA succeeds", async () => {
    mockVaultContext.webAuthnAvailable = true;
    mockVaultContext.hasPasskeyUnlock = true;
    mockUnlockWithPasskey.mockImplementationOnce(async (options) => {
      const verified = await options.verifyTwoFactor();
      return verified ? { error: null } : { error: new Error("Vault 2FA verification failed.") };
    });
    renderVaultUnlock();

    fireEvent.click(screen.getByText("Unlock with Passkey"));

    await waitFor(() => {
      expect(screen.getByTestId("2fa-modal")).toBeInTheDocument();
    });

    fireEvent.click(screen.getByText("verify-backup"));

    await waitFor(() => {
      expect(mockVerifyTwoFactorCode).toHaveBeenCalledWith({
        userId: "user-1",
        context: "vault_unlock",
        code: "BACKUP-1",
        method: "backup_code",
      });
    });
  });

  it("should show the actual vault unlock error instead of generic auth credentials text", async () => {
    mockUnlock.mockResolvedValue({ error: new Error("Vault not set up") });
    renderVaultUnlock();

    const input = screen.getByLabelText("auth.unlock.password");
    fireEvent.change(input, { target: { value: "MyMasterPassword!" } });

    const form = input.closest("form")!;
    fireEvent.submit(form);

    await waitFor(() => {
      expect(mockToast).toHaveBeenCalledWith(
        expect.objectContaining({
          description: "Vault not set up",
        }),
      );
    });
  });

  it("should call signOut when logout button is clicked", async () => {
    renderVaultUnlock();

    fireEvent.click(screen.getByText("auth.unlock.logout"));

    await waitFor(() => {
      expect(mockSignOut).toHaveBeenCalled();
    });
  });

  it("should toggle password visibility", () => {
    renderVaultUnlock();

    const input = screen.getByLabelText("auth.unlock.password");
    expect(input).toHaveAttribute("type", "password");

    // Find toggle button (the eye icon button inside the input wrapper)
    const toggleButtons = screen.getAllByRole("button");
    const eyeToggle = toggleButtons.find(
      (btn) => btn.classList.contains("absolute")
    );
    if (eyeToggle) {
      fireEvent.click(eyeToggle);
      expect(input).toHaveAttribute("type", "text");
    }
  });

  it("should show session restore banner when pendingSessionRestore is true", () => {
    mockVaultContext.pendingSessionRestore = true;
    renderVaultUnlock();

    expect(
      screen.getByText("Please re-enter your master password to continue your session.")
    ).toBeInTheDocument();
  });

  it("shows a pre-unlock Device Key import action when this protected vault has no local key", () => {
    mockVaultContext.vaultProtectionMode = "device_key_required";
    mockVaultContext.deviceKeyActive = false;

    render(
      <MemoryRouter initialEntries={["/vault"]}>
        <VaultUnlock />
        <LocationProbe />
      </MemoryRouter>,
    );

    expect(screen.getByText("Device Key required")).toBeInTheDocument();
    const importLink = screen.getByRole("link", { name: /Import Device Key/i });
    expect(importLink).toHaveAttribute("href", "/settings?tab=security#profile-device-key");
    fireEvent.click(importLink);
    expect(screen.getByTestId("location")).toHaveTextContent("/settings?tab=security#profile-device-key");
  });
});
