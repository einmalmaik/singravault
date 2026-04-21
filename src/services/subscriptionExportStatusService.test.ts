// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE
import { describe, expect, it } from 'vitest';

import type { Database } from '@/integrations/supabase/types';
import {
    getExportSubscriptionHumanLabel,
    getExportSubscriptionStatus,
    toExportSubscriptionSnapshot,
} from '@/services/subscriptionExportStatusService';

describe('subscriptionExportStatusService', () => {
    it('maps active and trialing subscriptions to active', () => {
        expect(getExportSubscriptionStatus('active', false)).toBe('active');
        expect(getExportSubscriptionStatus('trialing', false)).toBe('active');
        expect(getExportSubscriptionStatus(null, false)).toBe('active');
    });

    it('maps cancel-at-period-end subscriptions to canceling', () => {
        expect(getExportSubscriptionStatus('active', true)).toBe('canceling');
        expect(getExportSubscriptionStatus('past_due', true)).toBe('canceling');
    });

    it('maps canceled subscriptions to canceled', () => {
        expect(getExportSubscriptionStatus('canceled', false)).toBe('canceled');
    });

    it('maps past_due subscriptions to past_due', () => {
        expect(getExportSubscriptionStatus('past_due', false)).toBe('past_due');
    });

    it('maps terminal/unknown statuses to ended', () => {
        expect(getExportSubscriptionStatus('unpaid', false)).toBe('ended');
        expect(getExportSubscriptionStatus('incomplete_expired', false)).toBe('ended');
        expect(getExportSubscriptionStatus('paused', false)).toBe('ended');
        expect(getExportSubscriptionStatus('unknown_status', false)).toBe('ended');
    });

    it('adds raw/effective/human labels to export snapshot', () => {
        const row = createSubscriptionRow({
            status: 'active',
            cancel_at_period_end: true,
        });

        const snapshot = toExportSubscriptionSnapshot(row);

        expect(snapshot.status).toBe('canceling');
        expect(snapshot.status_raw).toBe('active');
        expect(snapshot.status_effective).toBe('canceling');
        expect(snapshot.status_human_de).toBe('Wird gekündigt');
    });

    it('returns expected human labels', () => {
        expect(getExportSubscriptionHumanLabel('active')).toBe('Aktiv');
        expect(getExportSubscriptionHumanLabel('canceling')).toBe('Wird gekündigt');
        expect(getExportSubscriptionHumanLabel('canceled')).toBe('Gekündigt');
        expect(getExportSubscriptionHumanLabel('past_due')).toBe('Zahlung überfällig');
        expect(getExportSubscriptionHumanLabel('ended')).toBe('Beendet');
    });
});

function createSubscriptionRow(
    overrides: Partial<Database['public']['Tables']['subscriptions']['Row']> = {},
): Database['public']['Tables']['subscriptions']['Row'] {
    return {
        id: 'sub_123',
        user_id: 'user_123',
        stripe_customer_id: 'cus_123',
        stripe_subscription_id: 'stripe_sub_123',
        stripe_price_id: 'price_123',
        status: 'active',
        tier: 'premium',
        current_period_end: '2026-04-05T00:00:00.000Z',
        cancel_at_period_end: false,
        has_used_intro_discount: false,
        created_at: '2026-01-01T00:00:00.000Z',
        updated_at: '2026-01-01T00:00:00.000Z',
        ...overrides,
    };
}
