// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE
/**
 * @fileoverview Subscription Context for Singra Vault
 *
 * Provides subscription state throughout the application.
 * Loads user's subscription tier and status from Supabase.
 * Loads subscription via Premium service hooks when available.
 */

import { createContext, useContext, useEffect, useState, useCallback, ReactNode } from 'react';
import { useAuth } from './AuthContext';
import { getServiceHooks } from '@/extensions/registry';
import type { FeatureName, SubscriptionSnapshot, SubscriptionTier } from '@/subscription/types';

export type SubscriptionData = SubscriptionSnapshot;

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
    const { user, authReady } = useAuth();
    const [subscription, setSubscription] = useState<SubscriptionData | null>(null);
    const [hasFeatureOverride, setHasFeatureOverride] = useState(false);
    const [loading, setLoading] = useState(true);

    const loadSubscription = useCallback(async () => {
        if (!authReady) {
            setLoading(true);
            return;
        }

        if (!user) {
            setSubscription(null);
            setHasFeatureOverride(false);
            setLoading(false);
            return;
        }

        const hooks = getServiceHooks();

        const subscriptionPromise = hooks.getSubscription
            ? hooks.getSubscription().catch((error) => {
                console.error('Error loading subscription:', error);
                return null;
            })
            : Promise.resolve(null);

        const featureOverridePromise = hooks.getFeatureAccessOverride
            ? hooks.getFeatureAccessOverride().catch((error) => {
                console.error('Error loading feature access override:', error);
                return { hasFullAccess: false };
            })
            : Promise.resolve({ hasFullAccess: false });

        const [subscriptionData, accessResult] = await Promise.all([
            subscriptionPromise,
            featureOverridePromise,
        ]);

        setSubscription((subscriptionData as SubscriptionData | null) ?? null);
        setHasFeatureOverride(accessResult.hasFullAccess === true);
        setLoading(false);
    }, [authReady, user]);

    useEffect(() => {
        void loadSubscription();
    }, [loadSubscription]);

    const tier: SubscriptionTier = (subscription?.tier as SubscriptionTier) || 'free';

    const status = subscription?.status || null;

    const isActive = status === 'active' || status === 'trialing' || tier === 'free';

    const cancelAtPeriodEnd = subscription?.cancel_at_period_end ?? false;
    const currentPeriodEnd = subscription?.current_period_end ?? null;
    const hasUsedIntroDiscount = subscription?.has_used_intro_discount ?? false;

    const hasFeature = useCallback((feature: FeatureName): boolean => {
        const hooks = getServiceHooks();

        if (hasFeatureOverride) {
            return true;
        }

        if (!hooks.hasFeatureAccess) {
            return false;
        }

        return hooks.hasFeatureAccess(feature, {
            tier,
            subscription,
            isActive,
            hasFullAccess: hasFeatureOverride,
        });
    }, [hasFeatureOverride, isActive, subscription, tier]);

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
