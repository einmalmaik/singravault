// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 â€” see LICENSE
/**
 * @fileoverview Tests for PasskeySettings Component
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { PasskeySettings } from "../PasskeySettings";

vi.mock("react-i18next", () => ({
  useTranslation: () => ({
    t: (key: string, fallback?: string) => fallback || key,
  }),
}));

const mockToast = vi.fn();
let mockUser: { id: string } | null = { id: "user-1" };
vi.mock("@/hooks/use-toast", () => ({
  useToast: () => ({ toast: mockToast }),
}));
vi.mock("@/contexts/AuthContext", () => ({
  useAuth: () => ({
    user: mockUser,
    authReady: true,
  }),
}));

const mockGetPasskeyWrappingMaterial = vi.fn();
const mockRefreshPasskeyUnlockStatus = vi.fn().mockResolvedValue(undefined);
vi.mock("@/contexts/VaultContext", () => ({
  useVault: () => ({
    webAuthnAvailable: true,
    isLocked: false,
    getPasskeyWrappingMaterial: mockGetPasskeyWrappingMaterial,
    refreshPasskeyUnlockStatus: mockRefreshPasskeyUnlockStatus,
  }),
}));

const mockRegisterPasskey = vi.fn();
const mockActivatePasskeyPrf = vi.fn();
const mockListPasskeys = vi.fn();
const mockDeletePasskey = vi.fn();
const mockGetPasskeyClientSupport = vi.fn();

vi.mock("@/services/passkeyService", () => ({
  registerPasskey: (...args: unknown[]) => mockRegisterPasskey(...args),
  activatePasskeyPrf: (...args: unknown[]) => mockActivatePasskeyPrf(...args),
  listPasskeys: (...args: unknown[]) => mockListPasskeys(...args),
  deletePasskey: (...args: unknown[]) => mockDeletePasskey(...args),
  getPasskeyClientSupport: (...args: unknown[]) => mockGetPasskeyClientSupport(...args),
  isWebAuthnAvailable: vi.fn().mockReturnValue(true),
}));

vi.mock("@/services/edgeFunctionService", () => ({
  isEdgeFunctionServiceError: (error: unknown) =>
    error instanceof Error && error.name === "EdgeFunctionServiceError",
}));

describe("PasskeySettings", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockUser = { id: "user-1" };
    mockListPasskeys.mockResolvedValue([]);
    mockDeletePasskey.mockResolvedValue({ success: true });
    mockGetPasskeyWrappingMaterial.mockResolvedValue(new Uint8Array(32));
    mockRefreshPasskeyUnlockStatus.mockResolvedValue(undefined);
    mockGetPasskeyClientSupport.mockResolvedValue({
      webAuthnAvailable: true,
      platformAuthenticatorAvailable: true,
      clientCapabilitiesAvailable: true,
      prfExtensionSupported: true,
    });
  });

  it("activates PRF when registration requires a second ceremony", async () => {
    mockRegisterPasskey.mockResolvedValue({
      success: true,
      credentialId: "cred-1",
      prfEnabled: true,
      needsPrfActivation: true,
    });
    mockActivatePasskeyPrf.mockResolvedValue({ success: true, credentialId: "cred-1" });

    render(<PasskeySettings />);

    await waitFor(() => {
      expect(screen.getByRole("button", { name: "Add Passkey" })).toBeInTheDocument();
    });

    fireEvent.click(screen.getByRole("button", { name: "Add Passkey" }));

    fireEvent.change(screen.getByLabelText("Confirm master password"), {
      target: { value: "MasterPassword123!" },
    });

    fireEvent.click(screen.getByRole("button", { name: "Register Passkey" }));

    await waitFor(() => {
      expect(mockRegisterPasskey).toHaveBeenCalledTimes(1);
      expect(mockActivatePasskeyPrf).toHaveBeenCalledTimes(1);
      expect(mockActivatePasskeyPrf.mock.calls[0][1]).toBe("cred-1");
    });
  });

  it("shows a session error when passkey listing returns 401", async () => {
    const authError = Object.assign(new Error("Authentication required"), {
      name: "EdgeFunctionServiceError",
      status: 401,
      code: "AUTH_REQUIRED",
    });
    mockListPasskeys.mockRejectedValueOnce(authError);

    render(<PasskeySettings />);

    await waitFor(() => {
      expect(mockToast).toHaveBeenCalledWith(
        expect.objectContaining({
          variant: "destructive",
          description: "Your session has expired. Please sign in again.",
        }),
      );
    });
  });

  it("does not load passkeys when no authenticated user exists", async () => {
    mockUser = null;

    render(<PasskeySettings />);

    await waitFor(() => {
      expect(screen.getByRole("button", { name: "Add Passkey" })).toBeInTheDocument();
    });

    expect(mockListPasskeys).not.toHaveBeenCalled();
  });

  it("calls listPasskeys when authReady and user are set (stale closure regression)", async () => {
    // Regression test for loadPasskeys useCallback stale closure bug (P1):
    // authReady was missing from useCallback dep array. This test verifies that
    // passkeys load and render when authReady=true, proving loadPasskeys runs
    // past the `if (!authReady || !user) return` guard.
    mockListPasskeys.mockResolvedValue([
      {
        id: "pk-1",
        device_name: "Touch ID",
        created_at: "2024-01-01T00:00:00Z",
        last_used_at: null,
        prf_enabled: true,
      },
    ]);

    render(<PasskeySettings />);

    // If loadPasskeys ran to completion, the passkey name will appear.
    // A stale closure returning early would leave the list empty.
    await waitFor(() => {
      expect(screen.getByText("Touch ID")).toBeInTheDocument();
    });
  });

  it("shows a PRF warning when the current client does not support the extension", async () => {
    mockGetPasskeyClientSupport.mockResolvedValue({
      webAuthnAvailable: true,
      platformAuthenticatorAvailable: true,
      clientCapabilitiesAvailable: true,
      prfExtensionSupported: false,
    });

    render(<PasskeySettings />);

    await waitFor(() => {
      expect(
        screen.getByText(/does not expose the PRF extension required for vault unlock/i),
      ).toBeInTheDocument();
    });
  });
});
