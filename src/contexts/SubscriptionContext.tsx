// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 — see LICENSE
/**
 * @fileoverview Subscription Context for Singra Vault
 *
 * Provides subscription state throughout the application.
 * Loads user's subscription tier and status from Supabase.
 * Loads subscription via Premium service hooks when available.
 */

import { createContext, useContext, useEffect, useState, useCallback, ReactNode } from 'react';
import { useAuth } from './AuthContext';
import { FEATURE_MATRIX, type FeatureName, type SubscriptionTier } from '@/config/planConfig';
import { getServiceHooks } from '@/extensions/registry';

/** Subscription data shape (matches subscriptionService.SubscriptionData) */
export interface SubscriptionData {
    id: string;
    user_id: string;
    stripe_customer_id: string | null;
    stripe_subscription_id: string | null;
    stripe_price_id: string | null;
    status: string | null;
    tier: 'free' | 'premium' | 'families' | null;
    current_period_end: string | null;
    cancel_at_period_end: boolean;
    has_used_intro_discount: boolean;
    created_at: string;
    updated_at: string;
}

interface SubscriptionContextType {
    /** Current subscription tier */
    tier: SubscriptionTier;
    /** Stripe subscription status */
    status: string | null;
    /** Whether the subscription is active (active or trialing) */
    isActive: boolean;
    /** Whether cancellation is pending at period end */
    cancelAtPeriodEnd: boolean;
    /** When the current billing period ends */
    currentPeriodEnd: string | null;
    /** Whether intro discount was already used */
    hasUsedIntroDiscount: boolean;
    /** Full subscription data */
    subscription: SubscriptionData | null;
    /** Loading state */
    loading: boolean;
    /** Check if a specific feature is available */
    hasFeature: (feature: FeatureName) => boolean;
    /** Refresh subscription data */
    refresh: () => Promise<void>;
}

const SubscriptionContext = createContext<SubscriptionContextType | undefined>(undefined);

interface SubscriptionProviderProps {
    children: ReactNode;
}

export function SubscriptionProvider({ children }: SubscriptionProviderProps) {
    const { user } = useAuth();
    const [subscription, setSubscription] = useState<SubscriptionData | null>(null);
    const [loading, setLoading] = useState(true);

    const loadSubscription = useCallback(async () => {
        if (!user) {
            setSubscription(null);
            setLoading(false);
            return;
        }

        const hooks = getServiceHooks();
        if (!hooks.getSubscription) {
            // Premium not installed — stay on free tier
            setSubscription(null);
            setLoading(false);
            return;
        }

        try {
            const data = await hooks.getSubscription();
            setSubscription(data);
        } catch (err) {
            console.error('Error loading subscription:', err);
        } finally {
            setLoading(false);
        }
    }, [user]);

    useEffect(() => {
        loadSubscription();
    }, [loadSubscription]);

    const tier: SubscriptionTier = (subscription?.tier as SubscriptionTier) || 'free';

    const status = subscription?.status || null;

    const isActive = status === 'active' || status === 'trialing' || tier === 'free';

    const cancelAtPeriodEnd = subscription?.cancel_at_period_end ?? false;
    const currentPeriodEnd = subscription?.current_period_end ?? null;
    const hasUsedIntroDiscount = subscription?.has_used_intro_discount ?? false;

    const hasFeature = useCallback((feature: FeatureName): boolean => {
        if (!isActive && (tier as string) !== 'free') return false; // Expired paid plan
        return FEATURE_MATRIX[feature]?.[tier] ?? false;
    }, [tier, isActive]);

    const refresh = useCallback(async () => {
        setLoading(true);
        await loadSubscription();
    }, [loadSubscription]);

    return (
        <SubscriptionContext.Provider
            value={{
                tier,
                status,
                isActive,
                cancelAtPeriodEnd,
                currentPeriodEnd,
                hasUsedIntroDiscount,
                subscription,
                loading,
                hasFeature,
                refresh,
            }}
        >
            {children}
        </SubscriptionContext.Provider>
    );
}

/**
 * Hook to access subscription context
 */
// eslint-disable-next-line react-refresh/only-export-components
export function useSubscription() {
    const context = useContext(SubscriptionContext);
    if (context === undefined) {
        throw new Error('useSubscription must be used within a SubscriptionProvider');
    }
    return context;
}
