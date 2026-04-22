// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 — see LICENSE
/**
 * @fileoverview Tests for VaultUnlock Component
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
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
  unlockWithPasskey: () => mockUnlockWithPasskey(),
  pendingSessionRestore: false,
  webAuthnAvailable: false,
  hasPasskeyUnlock: false,
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

const mockGet2FAStatus = vi.fn().mockResolvedValue(null);
vi.mock("@/services/twoFactorService", () => ({
  get2FAStatus: (...args: unknown[]) => mockGet2FAStatus(...args),
  verifyTwoFactorForLogin: vi.fn(),
}));

vi.mock("@/components/auth/TwoFactorVerificationModal", () => ({
  TwoFactorVerificationModal: ({ open }: { open: boolean }) =>
    open ? <div data-testid="2fa-modal">2FA Modal</div> : null,
}));

// ============ Tests ============

describe("VaultUnlock", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockVaultContext.pendingSessionRestore = false;
    mockVaultContext.webAuthnAvailable = false;
    mockVaultContext.hasPasskeyUnlock = false;
    mockGet2FAStatus.mockResolvedValue(null);
    mockUnlock.mockResolvedValue({ error: null });
  });

  it("should render password input and unlock button", () => {
    render(<VaultUnlock />);

    expect(screen.getByLabelText("auth.unlock.password")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /auth\.unlock\.submit/i })).toBeInTheDocument();
  });

  it("should call unlock with entered password on submit", async () => {
    render(<VaultUnlock />);

    const input = screen.getByLabelText("auth.unlock.password");
    fireEvent.change(input, { target: { value: "MyMasterPassword!" } });

    const form = input.closest("form")!;
    fireEvent.submit(form);

    await waitFor(() => {
      expect(mockUnlock).toHaveBeenCalledWith("MyMasterPassword!");
    });
  });

  it("should show passkey button only when webAuthn available and hasPasskeyUnlock", () => {
    mockVaultContext.webAuthnAvailable = false;
    mockVaultContext.hasPasskeyUnlock = false;
    const { rerender } = render(<VaultUnlock />);

    expect(screen.queryByText("Unlock with Passkey")).not.toBeInTheDocument();

    mockVaultContext.webAuthnAvailable = true;
    mockVaultContext.hasPasskeyUnlock = true;
    rerender(<VaultUnlock />);

    expect(screen.getByText("Unlock with Passkey")).toBeInTheDocument();
  });

  it("should call unlockWithPasskey when passkey button clicked", async () => {
    mockVaultContext.webAuthnAvailable = true;
    mockVaultContext.hasPasskeyUnlock = true;
    render(<VaultUnlock />);

    fireEvent.click(screen.getByText("Unlock with Passkey"));

    await waitFor(() => {
      expect(mockUnlockWithPasskey).toHaveBeenCalled();
    });
  });

  it("should show 2FA modal when vault 2FA is active", async () => {
    mockGet2FAStatus.mockResolvedValue({ vaultTwoFactorEnabled: true });
    render(<VaultUnlock />);

    const input = screen.getByLabelText("auth.unlock.password");
    fireEvent.change(input, { target: { value: "password123" } });

    const form = input.closest("form")!;
    fireEvent.submit(form);

    await waitFor(() => {
      expect(screen.getByTestId("2fa-modal")).toBeInTheDocument();
    });
  });

  it("should show the actual vault unlock error instead of generic auth credentials text", async () => {
    mockUnlock.mockResolvedValue({ error: new Error("Vault not set up") });
    render(<VaultUnlock />);

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
    render(<VaultUnlock />);

    fireEvent.click(screen.getByText("auth.unlock.logout"));

    await waitFor(() => {
      expect(mockSignOut).toHaveBeenCalled();
    });
  });

  it("should toggle password visibility", () => {
    render(<VaultUnlock />);

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
    render(<VaultUnlock />);

    expect(
      screen.getByText("Please re-enter your master password to continue your session.")
    ).toBeInTheDocument();
  });
});
