// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 — see LICENSE
/**
 * @fileoverview Tests for VaultItemCard Component
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";
import { VaultItemCard } from "../VaultItemCard";

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

const mockWriteClipboard = vi.fn().mockResolvedValue(undefined);
vi.mock("@/services/clipboardService", () => ({
  writeClipboard: (...args: unknown[]) => mockWriteClipboard(...args),
}));

vi.mock("../TOTPDisplay", () => ({
  TOTPDisplay: ({ secret }: { secret: string }) => (
    <div data-testid="totp-display">TOTP: {secret}</div>
  ),
}));

// ============ Helpers ============

const baseItem = {
  id: "item-1",
  title: "My Login",
  website_url: "https://example.com",
  item_type: "password" as const,
  is_favorite: false,
  decryptedData: {
    title: "My Login",
    username: "user@example.com",
    password: "secret123",
    websiteUrl: "https://example.com",
    itemType: "password" as const,
    isFavorite: false,
  },
};

// ============ Tests ============

describe("VaultItemCard", () => {
  const mockOnEdit = vi.fn();

  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe("Grid mode", () => {
    it("should show title and domain", () => {
      render(<VaultItemCard item={baseItem} viewMode="grid" onEdit={mockOnEdit} />);

      expect(screen.getByText("My Login")).toBeInTheDocument();
      expect(screen.getByText("example.com")).toBeInTheDocument();
    });

    it("should show masked password with toggle", () => {
      render(<VaultItemCard item={baseItem} viewMode="grid" onEdit={mockOnEdit} />);

      // Password is masked by default
      expect(screen.getByText("••••••••••")).toBeInTheDocument();
      expect(screen.queryByText("secret123")).not.toBeInTheDocument();
    });

    it("should call onEdit when card is clicked", () => {
      render(<VaultItemCard item={baseItem} viewMode="grid" onEdit={mockOnEdit} />);

      // Click the card itself
      const card = screen.getByText("My Login").closest("[class*='cursor-pointer']");
      if (card) fireEvent.click(card);

      expect(mockOnEdit).toHaveBeenCalled();
    });

    it("should show favorite star when is_favorite is true", () => {
      const favoriteItem = {
        ...baseItem,
        is_favorite: true,
        decryptedData: { ...baseItem.decryptedData, isFavorite: true },
      };

      const { container } = render(
        <VaultItemCard item={favoriteItem} viewMode="grid" onEdit={mockOnEdit} />
      );

      // Star icon is rendered with fill-amber-500 class
      const star = container.querySelector(".fill-amber-500");
      expect(star).not.toBeNull();
    });

    it("should not show favorite star when is_favorite is false", () => {
      const { container } = render(
        <VaultItemCard item={baseItem} viewMode="grid" onEdit={mockOnEdit} />
      );

      const star = container.querySelector(".fill-amber-500");
      expect(star).toBeNull();
    });
  });

  describe("List mode", () => {
    it("should show title and username", () => {
      render(<VaultItemCard item={baseItem} viewMode="list" onEdit={mockOnEdit} />);

      expect(screen.getByText("My Login")).toBeInTheDocument();
      expect(screen.getByText("user@example.com")).toBeInTheDocument();
    });

    it("should show copy password button in list mode", () => {
      const { container } = render(
        <VaultItemCard item={baseItem} viewMode="list" onEdit={mockOnEdit} />
      );

      // There should be action buttons in list mode
      const buttons = container.querySelectorAll("button");
      expect(buttons.length).toBeGreaterThan(0);
    });
  });

  describe("TOTP item", () => {
    const totpItem = {
      ...baseItem,
      item_type: "totp" as const,
      decryptedData: {
        ...baseItem.decryptedData,
        itemType: "totp" as const,
        totpSecret: "JBSWY3DPEHPK3PXP",
        password: undefined,
      },
    };

    it("should NOT render inline TOTPDisplay by default (codes are exclusive to AuthenticatorPage)", () => {
      render(<VaultItemCard item={totpItem} viewMode="grid" onEdit={mockOnEdit} />);
      expect(screen.queryByTestId("totp-display")).not.toBeInTheDocument();
      expect(screen.getByText(baseItem.title)).toBeInTheDocument();
    });

    it("should render inline TOTPDisplay when showTotpCode=true (emergency access context)", () => {
      render(<VaultItemCard item={totpItem} viewMode="grid" onEdit={mockOnEdit} showTotpCode={true} />);
      expect(screen.getByTestId("totp-display")).toBeInTheDocument();
    });
  });
});
