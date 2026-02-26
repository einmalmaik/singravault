// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 — see LICENSE
/**
 * @fileoverview Server-Side Plan Configuration
 *
 * Authoritative mapping of plan keys to Stripe Price IDs.
 * The client NEVER determines prices — it only sends symbolic plan keys.
 * This config is duplicated in Edge Functions for server-side enforcement.
 */

export type PlanKey = "premium_monthly" | "premium_yearly" | "families_monthly" | "families_yearly";
export type SubscriptionTier = "free" | "premium" | "families";

export interface PlanInfo {
  priceId: string;
  tier: SubscriptionTier;
  label: string;
  interval: "month" | "year";
  amount: number; // in cents (EUR)
}

/**
 * Server-authoritative plan mapping.
 * Client sends a PlanKey, server resolves to Stripe Price ID.
 */
export const PLAN_CONFIG: Record<PlanKey, PlanInfo> = {
  premium_monthly: {
    priceId: "price_1T3zaxAIZiA8j1RxU3F498yI",
    tier: "premium",
    label: "Premium Monthly",
    interval: "month",
    amount: 165, // €1.65
  },
  premium_yearly: {
    priceId: "price_1T3zaxAIZiA8j1RxwKQTXQKL",
    tier: "premium",
    label: "Premium Yearly",
    interval: "year",
    amount: 1980, // €19.80
  },
  families_monthly: {
    priceId: "price_1T3zayAIZiA8j1RxP9Xv1sbS",
    tier: "families",
    label: "Families Monthly",
    interval: "month",
    amount: 399, // €3.99
  },
  families_yearly: {
    priceId: "price_1T3zayAIZiA8j1RxLZiwiA3X",
    tier: "families",
    label: "Families Yearly",
    interval: "year",
    amount: 4788, // €47.88
  },
} as const;

/** Stripe Coupon ID for 50% off first month */
export const INTRO_COUPON_ID = "K3tViKjk";

/** All valid plan keys */
export const VALID_PLAN_KEYS = Object.keys(PLAN_CONFIG) as PlanKey[];

/**
 * Feature definitions per tier.
 * true = available, false = locked
 */
export type FeatureName =
  | "unlimited_passwords"
  | "device_sync"
  | "password_generator"
  | "secure_notes"
  | "external_2fa"
  | "file_attachments"
  | "builtin_authenticator"
  | "emergency_access"
  | "vault_health_reports"
  | "priority_support"
  | "family_members"
  | "shared_collections"
  | "post_quantum_encryption"
  | "duress_password";

export const FEATURE_MATRIX: Record<FeatureName, Record<SubscriptionTier, boolean>> = {
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

/** Minimum tier required for a feature */
export function getRequiredTier(feature: FeatureName): SubscriptionTier {
  if (FEATURE_MATRIX[feature].free) return "free";
  if (FEATURE_MATRIX[feature].premium) return "premium";
  return "families";
}
