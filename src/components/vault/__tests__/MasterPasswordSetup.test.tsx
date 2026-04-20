// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 — see LICENSE
/**
 * @fileoverview Tests for MasterPasswordSetup Component
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { MasterPasswordSetup } from "../MasterPasswordSetup";

// ============ Mocks ============

vi.mock("react-i18next", () => ({
  useTranslation: () => ({
    t: (key: string) => key,
  }),
}));

const mockNavigate = vi.fn();
vi.mock("react-router-dom", () => ({
  useNavigate: () => mockNavigate,
}));

const mockToast = vi.fn();
vi.mock("@/hooks/use-toast", () => ({
  useToast: () => ({ toast: mockToast }),
}));

const mockSetupMasterPassword = vi.fn().mockResolvedValue({ error: null });
vi.mock("@/contexts/VaultContext", () => ({
  useVault: () => ({
    setupMasterPassword: (...args: unknown[]) => mockSetupMasterPassword(...args),
  }),
}));

const mockSignOut = vi.fn().mockResolvedValue(undefined);
vi.mock("@/contexts/AuthContext", () => ({
  useAuth: () => ({
    signOut: mockSignOut,
  }),
}));

vi.mock("@/platform/runtime", () => ({
  isTauriRuntime: () => false,
}));

vi.mock("@/services/passwordGenerator", () => ({
  generatePassword: () => "Xy9!kL#mP2qR@wZv8nBj",
}));

// Mock usePasswordCheck hook
const mockOnPasswordChange = vi.fn();
const mockOnFieldFocus = vi.fn();
const mockOnPasswordBlur = vi.fn();
const mockOnPasswordSubmit = vi.fn().mockResolvedValue({
  score: 4,
  isStrong: true,
  isPwned: false,
  pwnedCount: 0,
  feedback: [],
  crackTimeDisplay: "centuries",
  isAcceptable: true,
});

vi.mock("@/hooks/usePasswordCheck", () => ({
  usePasswordCheck: () => ({
    strengthResult: { score: 4, isStrong: true, feedback: [], crackTimeDisplay: "centuries" },
    pwnedResult: { isPwned: false, pwnedCount: 0 },
    isChecking: false,
    isZxcvbnReady: true,
    onFieldFocus: mockOnFieldFocus,
    onPasswordChange: mockOnPasswordChange,
    onPasswordBlur: mockOnPasswordBlur,
    onPasswordSubmit: mockOnPasswordSubmit,
  }),
}));

// ============ Tests ============

describe("MasterPasswordSetup", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockSetupMasterPassword.mockResolvedValue({ error: null });
    mockSignOut.mockResolvedValue(undefined);
    mockOnPasswordSubmit.mockResolvedValue({
      score: 4, isStrong: true, isPwned: false, pwnedCount: 0,
      feedback: [], crackTimeDisplay: "centuries", isAcceptable: true,
    });
  });

  it("should render password input, confirm input, and submit button", () => {
    render(<MasterPasswordSetup />);

    expect(screen.getByLabelText("auth.masterPassword.password")).toBeInTheDocument();
    expect(screen.getByLabelText("auth.masterPassword.confirmPassword")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /auth\.masterPassword\.submit/i })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Zur Startseite/i })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Anderes Konto verwenden/i })).toBeInTheDocument();
  });

  it("should disable submit when password is empty", () => {
    render(<MasterPasswordSetup />);

    const submitBtn = screen.getByRole("button", { name: /auth\.masterPassword\.submit/i });
    expect(submitBtn).toBeDisabled();
  });

  it("should disable submit when passwords do not match", () => {
    render(<MasterPasswordSetup />);

    fireEvent.change(screen.getByLabelText("auth.masterPassword.password"), {
      target: { value: "Abcdef123456!" },
    });
    fireEvent.change(screen.getByLabelText("auth.masterPassword.confirmPassword"), {
      target: { value: "DifferentPassword" },
    });

    const submitBtn = screen.getByRole("button", { name: /auth\.masterPassword\.submit/i });
    expect(submitBtn).toBeDisabled();
  });

  it("should show mismatch error when confirm password differs", () => {
    render(<MasterPasswordSetup />);

    fireEvent.change(screen.getByLabelText("auth.masterPassword.password"), {
      target: { value: "TestPassword1!" },
    });
    fireEvent.change(screen.getByLabelText("auth.masterPassword.confirmPassword"), {
      target: { value: "Different" },
    });

    expect(screen.getByText("auth.errors.passwordMismatch")).toBeInTheDocument();
  });

  it("should reject weak passwords with toast", async () => {
    render(<MasterPasswordSetup />);

    // Short password (< 12 chars)
    fireEvent.change(screen.getByLabelText("auth.masterPassword.password"), {
      target: { value: "short" },
    });
    fireEvent.change(screen.getByLabelText("auth.masterPassword.confirmPassword"), {
      target: { value: "short" },
    });

    const form = screen.getByLabelText("auth.masterPassword.password").closest("form")!;
    fireEvent.submit(form);

    await waitFor(() => {
      expect(mockToast).toHaveBeenCalledWith(
        expect.objectContaining({ variant: "destructive" })
      );
    });
    expect(mockSetupMasterPassword).not.toHaveBeenCalled();
  });

  it("should fill both fields when generate strong password button is clicked", () => {
    render(<MasterPasswordSetup />);

    const genBtn = screen.getByText("Starkes Passwort generieren");
    fireEvent.click(genBtn);

    const passwordInput = screen.getByLabelText("auth.masterPassword.password") as HTMLInputElement;
    const confirmInput = screen.getByLabelText("auth.masterPassword.confirmPassword") as HTMLInputElement;

    expect(passwordInput.value).toBe("Xy9!kL#mP2qR@wZv8nBj");
    expect(confirmInput.value).toBe("Xy9!kL#mP2qR@wZv8nBj");
  });

  it("should call setupMasterPassword on valid submit", async () => {
    render(<MasterPasswordSetup />);

    // Use the generate button for a guaranteed strong password
    fireEvent.click(screen.getByText("Starkes Passwort generieren"));

    const form = screen.getByLabelText("auth.masterPassword.password").closest("form")!;
    fireEvent.submit(form);

    await waitFor(() => {
      expect(mockSetupMasterPassword).toHaveBeenCalledWith("Xy9!kL#mP2qR@wZv8nBj");
    });
  });

  it("should navigate to the landing page when home button is clicked", () => {
    render(<MasterPasswordSetup />);

    fireEvent.click(screen.getByRole("button", { name: /Zur Startseite/i }));

    expect(mockNavigate).toHaveBeenCalledWith("/", { replace: true });
  });

  it("should sign out and navigate to login when another account is requested", async () => {
    render(<MasterPasswordSetup />);

    fireEvent.click(screen.getByRole("button", { name: /Anderes Konto verwenden/i }));

    await waitFor(() => {
      expect(mockSignOut).toHaveBeenCalled();
      expect(mockNavigate).toHaveBeenCalledWith("/auth?mode=login", { replace: true });
    });
  });

  it("should block submit when password check returns not acceptable", async () => {
    mockOnPasswordSubmit.mockResolvedValue({
      score: 1, isStrong: false, isPwned: true, pwnedCount: 500,
      feedback: ["Too common"], crackTimeDisplay: "3 hours", isAcceptable: false,
    });

    render(<MasterPasswordSetup />);

    // A password that passes regex checks but fails zxcvbn/HIBP
    fireEvent.change(screen.getByLabelText("auth.masterPassword.password"), {
      target: { value: "ValidFormat1!Aa" },
    });
    fireEvent.change(screen.getByLabelText("auth.masterPassword.confirmPassword"), {
      target: { value: "ValidFormat1!Aa" },
    });

    const form = screen.getByLabelText("auth.masterPassword.password").closest("form")!;
    fireEvent.submit(form);

    await waitFor(() => {
      expect(mockToast).toHaveBeenCalledWith(
        expect.objectContaining({ variant: "destructive" })
      );
    });
    expect(mockSetupMasterPassword).not.toHaveBeenCalled();
  });
});
