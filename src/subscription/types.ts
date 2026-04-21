/**
 * Generic subscription and feature access types shared between the open core
 * and the optional premium package. The core only knows about a generic
 * subscription snapshot and string-based feature keys.
 */

export type SubscriptionTier = string;
export type FeatureName = string;

export interface SubscriptionSnapshot {
  tier?: string | null;
  status?: string | null;
  cancel_at_period_end?: boolean | null;
  current_period_end?: string | null;
  has_used_intro_discount?: boolean | null;
  stripe_subscription_id?: string | null;
  [key: string]: unknown;
}

export interface FeatureAccessContext {
  tier: SubscriptionTier;
  subscription: SubscriptionSnapshot | null;
  isActive: boolean;
  hasFullAccess: boolean;
}
