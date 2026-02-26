// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 — see LICENSE
/**
 * @fileoverview Feature Gate Hook
 *
 * Returns whether the current user has access to a specific feature
 * based on their subscription tier. Supports self-host mode.
 */

import { useSubscription } from '@/contexts/SubscriptionContext';
import { type FeatureName, getRequiredTier, type SubscriptionTier } from '@/config/planConfig';

interface FeatureGateResult {
    /** Whether the feature is available to the user */
    allowed: boolean;
    /** The minimum tier required for this feature */
    requiredTier: SubscriptionTier;
    /** The user's current tier */
    currentTier: SubscriptionTier;
}

/**
 * Check if the current user has access to a specific feature.
 *
 * @example
 * const { allowed, requiredTier } = useFeatureGate('file_attachments');
 * if (!allowed) {
 *   // Show upgrade prompt
 * }
 */
export function useFeatureGate(feature: FeatureName): FeatureGateResult {
    const { tier, hasFeature } = useSubscription();

    return {
        allowed: hasFeature(feature),
        requiredTier: getRequiredTier(feature),
        currentTier: tier,
    };
}
