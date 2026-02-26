// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 — see LICENSE
/**
 * @fileoverview Tests for useFeatureGate hook
 * 
 * Phase 6: Context Provider and Hook Tests
 * Tests feature gating based on subscription tier.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import { renderHook } from "@testing-library/react";
import { useFeatureGate } from "./useFeatureGate";
import type { SubscriptionTier } from "@/config/planConfig";

// ============ Mocks ============

const mockUseSubscription = vi.hoisted(() => vi.fn());

vi.mock("@/contexts/SubscriptionContext", () => ({
    useSubscription: mockUseSubscription,
}));

// ============ Test Helpers ============

function setupMockSubscription(tier: SubscriptionTier) {
    const featureMatrix: Record<string, Record<string, boolean>> = {
        unlimited_passwords: { free: true, premium: true, families: true },
        device_sync: { free: true, premium: true, families: true },
        password_generator: { free: true, premium: true, families: true },
        secure_notes: { free: true, premium: true, families: true },
        external_2fa: { free: true, premium: true, families: true },
        file_attachments: { free: false, premium: true, families: true },
        builtin_authenticator: { free: false, premium: true, families: true },
        emergency_access: { free: false, premium: true, families: true },
        vault_health_reports: { free: false, premium: true, families: true },
        priority_support: { free: false, premium: true, families: true },
        family_members: { free: false, premium: false, families: true },
        shared_collections: { free: false, premium: false, families: true },
        post_quantum_encryption: { free: true, premium: true, families: true },
        duress_password: { free: false, premium: true, families: true },
    };
    
    const mockHasFeature = (feature: string) => {
        return featureMatrix[feature]?.[tier] ?? false;
    };

    mockUseSubscription.mockReturnValue({
        tier,
        hasFeature: mockHasFeature,
        loading: false,
        status: tier !== "free" ? "active" : null,
    });
}

beforeEach(() => {
    vi.clearAllMocks();
});

// ============ Tests ============

describe("useFeatureGate", () => {
    describe("Free tier", () => {
        beforeEach(() => {
            setupMockSubscription("free");
        });

        it("allows unlimited_passwords", () => {
            const { result } = renderHook(() => useFeatureGate("unlimited_passwords"));
            
            expect(result.current.allowed).toBe(true);
            expect(result.current.requiredTier).toBe("free");
            expect(result.current.currentTier).toBe("free");
        });

        it("allows device_sync", () => {
            const { result } = renderHook(() => useFeatureGate("device_sync"));
            
            expect(result.current.allowed).toBe(true);
            expect(result.current.requiredTier).toBe("free");
        });

        it("allows password_generator", () => {
            const { result } = renderHook(() => useFeatureGate("password_generator"));
            
            expect(result.current.allowed).toBe(true);
            expect(result.current.requiredTier).toBe("free");
        });

        it("allows secure_notes", () => {
            const { result } = renderHook(() => useFeatureGate("secure_notes"));
            
            expect(result.current.allowed).toBe(true);
            expect(result.current.requiredTier).toBe("free");
        });

        it("allows external_2fa", () => {
            const { result } = renderHook(() => useFeatureGate("external_2fa"));
            
            expect(result.current.allowed).toBe(true);
            expect(result.current.requiredTier).toBe("free");
        });

        it("denies file_attachments (requires premium)", () => {
            const { result } = renderHook(() => useFeatureGate("file_attachments"));
            
            expect(result.current.allowed).toBe(false);
            expect(result.current.requiredTier).toBe("premium");
            expect(result.current.currentTier).toBe("free");
        });

        it("denies builtin_authenticator (requires premium)", () => {
            const { result } = renderHook(() => useFeatureGate("builtin_authenticator"));
            
            expect(result.current.allowed).toBe(false);
            expect(result.current.requiredTier).toBe("premium");
        });

        it("denies emergency_access (requires premium)", () => {
            const { result } = renderHook(() => useFeatureGate("emergency_access"));
            
            expect(result.current.allowed).toBe(false);
            expect(result.current.requiredTier).toBe("premium");
        });

        it("denies vault_health_reports (requires premium)", () => {
            const { result } = renderHook(() => useFeatureGate("vault_health_reports"));
            
            expect(result.current.allowed).toBe(false);
            expect(result.current.requiredTier).toBe("premium");
        });

        it("denies priority_support (requires premium)", () => {
            const { result } = renderHook(() => useFeatureGate("priority_support"));
            
            expect(result.current.allowed).toBe(false);
            expect(result.current.requiredTier).toBe("premium");
        });

        it("denies family_members (requires families)", () => {
            const { result } = renderHook(() => useFeatureGate("family_members"));
            
            expect(result.current.allowed).toBe(false);
            expect(result.current.requiredTier).toBe("families");
        });

        it("denies shared_collections (requires families)", () => {
            const { result } = renderHook(() => useFeatureGate("shared_collections"));
            
            expect(result.current.allowed).toBe(false);
            expect(result.current.requiredTier).toBe("families");
        });

        it("allows post_quantum_encryption (available on free)", () => {
            const { result } = renderHook(() => useFeatureGate("post_quantum_encryption"));
            
            expect(result.current.allowed).toBe(true);
            expect(result.current.requiredTier).toBe("free");
        });

        it("denies duress_password (requires premium)", () => {
            const { result } = renderHook(() => useFeatureGate("duress_password"));
            
            expect(result.current.allowed).toBe(false);
            expect(result.current.requiredTier).toBe("premium");
        });
    });

    describe("Premium tier", () => {
        beforeEach(() => {
            setupMockSubscription("premium");
        });

        it("allows all free features", () => {
            const freeFeatures = [
                "unlimited_passwords",
                "device_sync",
                "password_generator",
                "secure_notes",
                "external_2fa",
            ] as const;
            
            freeFeatures.forEach((feature) => {
                const { result } = renderHook(() => useFeatureGate(feature));
                
                expect(result.current.allowed).toBe(true);
                expect(result.current.currentTier).toBe("premium");
            });
        });

        it("allows file_attachments", () => {
            const { result } = renderHook(() => useFeatureGate("file_attachments"));
            
            expect(result.current.allowed).toBe(true);
            expect(result.current.requiredTier).toBe("premium");
        });

        it("allows builtin_authenticator", () => {
            const { result } = renderHook(() => useFeatureGate("builtin_authenticator"));
            
            expect(result.current.allowed).toBe(true);
        });

        it("allows emergency_access", () => {
            const { result } = renderHook(() => useFeatureGate("emergency_access"));
            
            expect(result.current.allowed).toBe(true);
        });

        it("allows vault_health_reports", () => {
            const { result } = renderHook(() => useFeatureGate("vault_health_reports"));
            
            expect(result.current.allowed).toBe(true);
        });

        it("allows priority_support", () => {
            const { result } = renderHook(() => useFeatureGate("priority_support"));
            
            expect(result.current.allowed).toBe(true);
        });

        it("allows post_quantum_encryption", () => {
            const { result } = renderHook(() => useFeatureGate("post_quantum_encryption"));
            
            expect(result.current.allowed).toBe(true);
        });

        it("allows duress_password", () => {
            const { result } = renderHook(() => useFeatureGate("duress_password"));
            
            expect(result.current.allowed).toBe(true);
        });

        it("denies family_members (requires families)", () => {
            const { result } = renderHook(() => useFeatureGate("family_members"));
            
            expect(result.current.allowed).toBe(false);
            expect(result.current.requiredTier).toBe("families");
        });

        it("denies shared_collections (requires families)", () => {
            const { result } = renderHook(() => useFeatureGate("shared_collections"));
            
            expect(result.current.allowed).toBe(false);
            expect(result.current.requiredTier).toBe("families");
        });
    });

    describe("Families tier", () => {
        beforeEach(() => {
            setupMockSubscription("families");
        });

        it("allows all features", () => {
            const allFeatures = [
                "unlimited_passwords",
                "device_sync",
                "password_generator",
                "secure_notes",
                "external_2fa",
                "file_attachments",
                "builtin_authenticator",
                "emergency_access",
                "vault_health_reports",
                "priority_support",
                "family_members",
                "shared_collections",
                "post_quantum_encryption",
                "duress_password",
            ] as const;
            
            allFeatures.forEach((feature) => {
                const { result } = renderHook(() => useFeatureGate(feature));
                
                expect(result.current.allowed).toBe(true);
                expect(result.current.currentTier).toBe("families");
            });
        });

        it("allows family_members", () => {
            const { result } = renderHook(() => useFeatureGate("family_members"));
            
            expect(result.current.allowed).toBe(true);
            expect(result.current.requiredTier).toBe("families");
        });

        it("allows shared_collections", () => {
            const { result } = renderHook(() => useFeatureGate("shared_collections"));
            
            expect(result.current.allowed).toBe(true);
            expect(result.current.requiredTier).toBe("families");
        });
    });

    describe("Return value structure", () => {
        beforeEach(() => {
            setupMockSubscription("premium");
        });

        it("returns all expected fields", () => {
            const { result } = renderHook(() => useFeatureGate("file_attachments"));
            
            expect(result.current).toHaveProperty("allowed");
            expect(result.current).toHaveProperty("requiredTier");
            expect(result.current).toHaveProperty("currentTier");
        });

        it("returns correct types", () => {
            const { result } = renderHook(() => useFeatureGate("file_attachments"));
            
            expect(typeof result.current.allowed).toBe("boolean");
            expect(typeof result.current.requiredTier).toBe("string");
            expect(typeof result.current.currentTier).toBe("string");
        });
    });
});
