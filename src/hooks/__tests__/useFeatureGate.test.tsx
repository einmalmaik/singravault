// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 — see LICENSE
/**
 * @fileoverview Tests for useFeatureGate Hook
 *
 * Tests feature gating based on subscription tiers.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import { renderHook } from "@testing-library/react";
import { useFeatureGate } from "../useFeatureGate";

// ============ Mock Setup ============

// Mock the SubscriptionContext at module level
const mockUseSubscription = vi.fn();
const mockGetRequiredTier = vi.fn();

vi.mock("@/contexts/SubscriptionContext", () => ({
  useSubscription: () => mockUseSubscription(),
}));

vi.mock("@/extensions/registry", () => ({
  getServiceHooks: () => ({
    getRequiredTier: mockGetRequiredTier,
  }),
}));

// ============ Test Suite ============

describe("useFeatureGate", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockGetRequiredTier.mockImplementation((feature: string) => {
      const featureRequirements: Record<string, string> = {
        unlimited_passwords: "free",
        device_sync: "free",
        password_generator: "free",
        secure_notes: "free",
        external_2fa: "free",
        post_quantum_encryption: "free",
        file_attachments: "premium",
        builtin_authenticator: "premium",
        emergency_access: "premium",
        vault_health_reports: "premium",
        priority_support: "premium",
        duress_password: "premium",
        family_members: "families",
        shared_collections: "families",
      };

      return featureRequirements[feature] ?? "premium";
    });
  });

  describe("Free tier", () => {
    beforeEach(() => {
      mockUseSubscription.mockReturnValue({
        tier: "free",
        hasFeature: (feature: string) => {
          // Free tier features
          const freeFeatures = [
            "unlimited_passwords",
            "device_sync",
            "password_generator",
            "secure_notes",
            "external_2fa",
          ];
          return freeFeatures.includes(feature);
        },
      });
    });

    it("should allow free tier features", () => {
      const { result } = renderHook(() => useFeatureGate("unlimited_passwords"));

      expect(result.current.allowed).toBe(true);
      expect(result.current.currentTier).toBe("free");
      expect(result.current.requiredTier).toBe("free");
      
    });

    it("should block premium features on free tier", () => {
      const { result } = renderHook(() => useFeatureGate("file_attachments"));

      expect(result.current.allowed).toBe(false);
      expect(result.current.currentTier).toBe("free");
      expect(result.current.requiredTier).toBe("premium");
      
    });

    it("should block families-only features on free tier", () => {
      const { result } = renderHook(() => useFeatureGate("family_members"));

      expect(result.current.allowed).toBe(false);
      expect(result.current.currentTier).toBe("free");
      expect(result.current.requiredTier).toBe("families");
      
    });
  });

  describe("Premium tier", () => {
    beforeEach(() => {
      mockUseSubscription.mockReturnValue({
        tier: "premium",
        hasFeature: (feature: string) => {
          // Premium features (all free + premium)
          const blockedFeatures = ["family_members", "shared_collections"];
          return !blockedFeatures.includes(feature);
        },
      });
    });

    it("should allow free tier features on premium", () => {
      const { result } = renderHook(() => useFeatureGate("unlimited_passwords"));

      expect(result.current.allowed).toBe(true);
      expect(result.current.currentTier).toBe("premium");
    });

    it("should allow premium features", () => {
      const { result } = renderHook(() => useFeatureGate("file_attachments"));

      expect(result.current.allowed).toBe(true);
      expect(result.current.currentTier).toBe("premium");
      expect(result.current.requiredTier).toBe("premium");
    });

    it("should block families-only features on premium tier", () => {
      const { result } = renderHook(() => useFeatureGate("family_members"));

      expect(result.current.allowed).toBe(false);
      expect(result.current.currentTier).toBe("premium");
      expect(result.current.requiredTier).toBe("families");
    });
  });

  describe("Families tier", () => {
    beforeEach(() => {
      mockUseSubscription.mockReturnValue({
        tier: "families",
        hasFeature: () => true, // All features available
      });
    });

    it("should allow all features on families tier", () => {
      const freeResult = renderHook(() => useFeatureGate("unlimited_passwords"));
      const premiumResult = renderHook(() => useFeatureGate("file_attachments"));
      const familiesResult = renderHook(() => useFeatureGate("family_members"));

      expect(freeResult.result.current.allowed).toBe(true);
      expect(premiumResult.result.current.allowed).toBe(true);
      expect(familiesResult.result.current.allowed).toBe(true);
      expect(familiesResult.result.current.currentTier).toBe("families");
    });
  });

  describe("Edge cases", () => {
    it("should handle all free-tier features correctly", () => {
      mockUseSubscription.mockReturnValue({
        tier: "free",
        hasFeature: (feature: string) => {
          const freeFeatures = [
            "unlimited_passwords",
            "device_sync",
            "password_generator",
            "secure_notes",
            "external_2fa",
          ];
          return freeFeatures.includes(feature);
        },
      });

      const features = [
        "unlimited_passwords",
        "device_sync",
        "password_generator",
        "secure_notes",
        "external_2fa",
      ] as const;

      features.forEach((feature) => {
        const { result } = renderHook(() => useFeatureGate(feature));
        expect(result.current.allowed).toBe(true);
        expect(result.current.requiredTier).toBe("free");
      });
    });

    it("should handle all premium-only features correctly", () => {
      mockUseSubscription.mockReturnValue({
        tier: "premium",
        hasFeature: (feature: string) => {
          const blockedFeatures = ["family_members", "shared_collections"];
          return !blockedFeatures.includes(feature);
        },
      });

      const premiumFeatures = [
        "file_attachments",
        "builtin_authenticator",
        "emergency_access",
        "vault_health_reports",
        "priority_support",
        "duress_password",
      ] as const;

      premiumFeatures.forEach((feature) => {
        const { result } = renderHook(() => useFeatureGate(feature));
        expect(result.current.allowed).toBe(true);
        expect(result.current.requiredTier).toBe("premium");
      });
    });

    it("should expose post-quantum encryption as a free feature", () => {
      mockUseSubscription.mockReturnValue({
        tier: "free",
        hasFeature: (feature: string) => {
          const freeFeatures = [
            "unlimited_passwords",
            "device_sync",
            "password_generator",
            "secure_notes",
            "external_2fa",
            "post_quantum_encryption",
          ];
          return freeFeatures.includes(feature);
        },
      });

      const { result } = renderHook(() => useFeatureGate("post_quantum_encryption"));
      expect(result.current.allowed).toBe(true);
      expect(result.current.requiredTier).toBe("free");
    });

    it("should handle families-only features correctly", () => {
      mockUseSubscription.mockReturnValue({
        tier: "families",
        hasFeature: () => true,
      });

      const familiesFeatures = ["family_members", "shared_collections"] as const;

      familiesFeatures.forEach((feature) => {
        const { result } = renderHook(() => useFeatureGate(feature));
        expect(result.current.allowed).toBe(true);
        expect(result.current.requiredTier).toBe("families");
      });
    });
  });
});
