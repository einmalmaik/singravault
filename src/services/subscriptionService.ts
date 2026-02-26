// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 — see LICENSE
/**
 * @fileoverview Subscription Service
 *
 * Abstraction layer for all subscription-related operations.
 * Calls Supabase Edge Functions — never interacts with Stripe directly.
 */

import { supabase } from '@/integrations/supabase/client';
import { invokeAuthedFunction } from '@/services/edgeFunctionService';
import type { PlanKey } from '@/config/planConfig';

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

interface WiderrufConsent {
    execution: boolean; // "Ich verlange ausdrücklich..."
    loss: boolean;      // "Mir ist bekannt..."
}

/**
 * Fetch the current user's subscription from Supabase
 */
export async function getSubscription(): Promise<SubscriptionData | null> {
    const { data: { user } } = await supabase.auth.getUser();
    if (!user) return null;

    const { data, error } = await supabase
        .from('subscriptions')
        .select('*')
        .eq('user_id', user.id)
        .single();

    if (error || !data) return null;
    return data as SubscriptionData;
}

/**
 * Create a Stripe Checkout session via Edge Function.
 * The server validates plan_key and Widerruf consent.
 * Returns the checkout URL to redirect to.
 */
export async function createCheckoutSession(
    planKey: PlanKey,
    widerrufConsent: WiderrufConsent
): Promise<{ url: string | null; error: string | null }> {
    if (!widerrufConsent.execution || !widerrufConsent.loss) {
        return { url: null, error: 'WIDERRUF_CONSENT_REQUIRED' };
    }

    try {
        const data = await invokeAuthedFunction<{ url: string }>('create-checkout-session', {
            plan_key: planKey,
            widerruf_consent_execution: widerrufConsent.execution,
            widerruf_consent_loss: widerrufConsent.loss,
        });

        return { url: data?.url || null, error: null };
    } catch (error: any) {
        console.error('Checkout session error:', error);
        return { url: null, error: error.message || 'Failed to create checkout session' };
    }
}

/**
 * Create a Stripe Customer Portal session via Edge Function.
 * Returns the portal URL for managing billing.
 */
export async function createPortalSession(): Promise<{ url: string | null; error: string | null }> {
    try {
        const data = await invokeAuthedFunction<{ url: string }>('create-portal-session', {});
        return { url: data?.url || null, error: null };
    } catch (error: any) {
        console.error('Portal session error:', error);
        return { url: null, error: error.message || 'Failed to create portal session' };
    }
}

/**
 * Cancel the current subscription via Edge Function.
 * Cancels at period end (§312k BGB compliant).
 */
export async function cancelSubscription(): Promise<{
    success: boolean;
    cancel_at_period_end?: boolean;
    current_period_end?: string;
    error?: string;
}> {
    try {
        const data = await invokeAuthedFunction<{
            success: boolean;
            cancel_at_period_end?: boolean;
            current_period_end?: string;
        }>('cancel-subscription', {});

        return {
            success: data?.success || false,
            cancel_at_period_end: data?.cancel_at_period_end,
            current_period_end: data?.current_period_end,
        };
    } catch (error: any) {
        console.error('Cancel subscription error:', error);
        return { success: false, error: error.message || 'Failed to cancel subscription' };
    }
}
