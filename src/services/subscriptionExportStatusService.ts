// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE
/**
 * @fileoverview Subscription export status normalization.
 *
 * Converts raw subscription DB rows into a clearer status snapshot for account exports.
 */

import type { Database } from '@/integrations/supabase/types';

const ACTIVE_STATUSES = new Set(['active', 'trialing']);
const ENDED_STATUSES = new Set(['incomplete', 'incomplete_expired', 'paused', 'unpaid']);

/**
 * Convert a subscription row into an export-friendly snapshot with derived status fields.
 *
 * @param row Subscription row from the `subscriptions` table.
 * @returns Snapshot including raw/effective/human-readable status values.
 */
export function toExportSubscriptionSnapshot(row: SubscriptionRow): ExportSubscriptionSnapshot {
    const effectiveStatus = getExportSubscriptionStatus(row.status, row.cancel_at_period_end);

    return {
        ...row,
        status: effectiveStatus,
        status_raw: row.status,
        status_effective: effectiveStatus,
        status_human_de: getExportSubscriptionHumanLabel(effectiveStatus),
    };
}

/**
 * Derive an effective status from Stripe status + cancel-at-period-end.
 *
 * @param status Raw status from Stripe/subscriptions table.
 * @param cancelAtPeriodEnd Cancel marker from subscriptions table.
 * @returns Normalized export status.
 */
export function getExportSubscriptionStatus(
    status: string | null | undefined,
    cancelAtPeriodEnd: boolean | null | undefined,
): ExportSubscriptionStatus {
    if (cancelAtPeriodEnd === true) {
        return 'canceling';
    }

    const normalizedStatus = normalizeStatus(status);
    if (!normalizedStatus) {
        return 'active';
    }

    if (ACTIVE_STATUSES.has(normalizedStatus)) {
        return 'active';
    }

    if (normalizedStatus === 'canceled') {
        return 'canceled';
    }

    if (normalizedStatus === 'past_due') {
        return 'past_due';
    }

    if (ENDED_STATUSES.has(normalizedStatus)) {
        return 'ended';
    }

    return 'ended';
}

/**
 * Translate normalized status to a concise German human label for exports.
 *
 * @param status Normalized status.
 * @returns Human-readable German status label.
 */
export function getExportSubscriptionHumanLabel(status: ExportSubscriptionStatus): string {
    switch (status) {
        case 'active':
            return 'Aktiv';
        case 'canceling':
            return 'Wird gekuendigt';
        case 'canceled':
            return 'Gekuendigt';
        case 'past_due':
            return 'Zahlung ueberfaellig';
        case 'ended':
            return 'Beendet';
    }
}

function normalizeStatus(status: string | null | undefined): string {
    if (typeof status !== 'string') {
        return '';
    }

    return status.trim().toLowerCase();
}

// ============ Type Definitions ============

type SubscriptionRow = Database['public']['Tables']['subscriptions']['Row'];

export type ExportSubscriptionStatus = 'active' | 'canceling' | 'canceled' | 'past_due' | 'ended';

export interface ExportSubscriptionSnapshot extends SubscriptionRow {
    status: ExportSubscriptionStatus;
    status_raw: string | null;
    status_effective: ExportSubscriptionStatus;
    status_human_de: string;
}
