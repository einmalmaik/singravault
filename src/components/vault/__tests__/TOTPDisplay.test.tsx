// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 — see LICENSE
/**
 * @fileoverview Tests for TOTPDisplay Component
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";
import { TOTPDisplay } from "../TOTPDisplay";

// ============ Mocks ============

vi.mock("react-i18next", () => ({
  useTranslation: () => ({
    t: (key: string) => key,
  }),
}));

vi.mock("@/hooks/use-toast", () => ({
  useToast: () => ({ toast: vi.fn() }),
}));

const mockWriteClipboard = vi.fn().mockResolvedValue(undefined);
vi.mock("@/services/clipboardService", () => ({
  writeClipboard: (...args: unknown[]) => mockWriteClipboard(...args),
}));

const mockGenerateTOTP = vi.fn().mockReturnValue("123456");
const mockGetTimeRemaining = vi.fn().mockReturnValue(25);
const mockFormatTOTPCode = vi.fn((code: string) => `${code.slice(0, 3)} ${code.slice(3)}`);

vi.mock("@/services/totpService", () => ({
  generateTOTP: (...args: unknown[]) => mockGenerateTOTP(...args),
  getTimeRemaining: (...args: unknown[]) => mockGetTimeRemaining(...args),
  formatTOTPCode: (code: string) => mockFormatTOTPCode(code),
  normalizeTOTPConfig: (config = {}) => ({
    algorithm: (config as { algorithm?: string }).algorithm || "SHA1",
    digits: (config as { digits?: 6 | 8 }).digits || 6,
    period: (config as { period?: number }).period || 30,
  }),
}));

// ============ Tests ============

describe("TOTPDisplay", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockGenerateTOTP.mockReturnValue("123456");
    mockGetTimeRemaining.mockReturnValue(25);
  });

  it("should display a 6-digit TOTP code", () => {
    render(<TOTPDisplay secret="JBSWY3DPEHPK3PXP" />);
    expect(screen.getByText("123 456")).toBeInTheDocument();
  });

  it("should display countdown timer with SVG circle", () => {
    const { container } = render(<TOTPDisplay secret="JBSWY3DPEHPK3PXP" />);
    // SVG countdown circles are rendered
    const circles = container.querySelectorAll("circle");
    expect(circles.length).toBe(2); // background circle + progress circle
    // Timer number is rendered (initial state is 30)
    expect(container.textContent).toContain("30");
  });

  it("should call writeClipboard when copy button is clicked", async () => {
    render(<TOTPDisplay secret="JBSWY3DPEHPK3PXP" />);

    const copyButton = screen.getByRole("button");
    fireEvent.click(copyButton);

    expect(mockWriteClipboard).toHaveBeenCalledWith("123456");
  });

  it("should format code with space in the middle", () => {
    render(<TOTPDisplay secret="JBSWY3DPEHPK3PXP" />);
    expect(mockFormatTOTPCode).toHaveBeenCalledWith("123456");
    expect(screen.getByText("123 456")).toBeInTheDocument();
  });

  it("should pass stored TOTP parameters to code generation and countdown", () => {
    render(
      <TOTPDisplay
        secret="JBSWY3DPEHPK3PXP"
        algorithm="SHA512"
        digits={8}
        period={60}
      />,
    );

    expect(mockGenerateTOTP).toHaveBeenCalledWith("JBSWY3DPEHPK3PXP", {
      algorithm: "SHA512",
      digits: 8,
      period: 60,
    });
  });
});
