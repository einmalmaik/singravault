// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 — see LICENSE
/**
 * @fileoverview Support Service
 *
 * Client abstraction for support ticket operations via Supabase Edge Functions.
 * All support writes go through edge functions to enforce server-side SLA logic.
 */

import { supabase } from '@/integrations/supabase/client';

// ============ Support API ============

/**
 * Creates a new support ticket and initial message.
 *
 * @param input - Ticket creation payload
 * @returns Created ticket or error
 */
export async function submitSupportTicket(
    input: CreateSupportTicketInput,
): Promise<{ ticket: SupportTicketSummary | null; error: Error | null }> {
    const { data, error } = await supabase.functions.invoke('support-submit', {
        body: {
            subject: input.subject,
            message: input.message,
            category: input.category,
        },
    });

    if (error) {
        return { ticket: null, error: new Error(error.message || 'Failed to submit support ticket') };
    }

    if (!data?.success || !data?.ticket) {
        return { ticket: null, error: new Error('Support ticket creation returned invalid payload') };
    }

    return { ticket: data.ticket as SupportTicketSummary, error: null };
}

/**
 * Loads current support entitlement and latest tickets for the current user.
 *
 * @returns Entitlement + ticket list or error
 */
export async function listSupportTickets(): Promise<{
    entitlement: SupportEntitlement | null;
    tickets: SupportTicketSummary[];
    error: Error | null;
}> {
    const { data, error } = await supabase.functions.invoke('support-list', {
        body: { action: 'list' },
    });

    if (error) {
        return {
            entitlement: null,
            tickets: [],
            error: new Error(error.message || 'Failed to load support tickets'),
        };
    }

    if (!data?.success) {
        return {
            entitlement: null,
            tickets: [],
            error: new Error('Support list returned invalid payload'),
        };
    }

    return {
        entitlement: (data.entitlement || null) as SupportEntitlement | null,
        tickets: (data.tickets || []) as SupportTicketSummary[],
        error: null,
    };
}

/**
 * Loads aggregate support response metrics (admin/moderator only).
 *
 * @param days - Rolling window in days
 * @returns Metrics list; empty when user has no permission
 */
export async function getSupportResponseMetrics(days: number = 30): Promise<{
    metrics: SupportResponseMetric[];
    error: Error | null;
}> {
    const { data, error } = await supabase.functions.invoke('support-metrics', {
        body: { days },
    });

    if (error) {
        // Expected for non-admin users (403 from edge function)
        return {
            metrics: [],
            error: new Error(error.message || 'Failed to load support metrics'),
        };
    }

    if (!data?.success) {
        return {
            metrics: [],
            error: new Error('Support metrics returned invalid payload'),
        };
    }

    return {
        metrics: (data.metrics || []) as SupportResponseMetric[],
        error: null,
    };
}

/**
 * Loads full ticket detail with all public messages for the current user.
 *
 * @param ticketId - The ticket UUID
 * @returns Ticket + messages or error
 */
export async function getSupportTicketDetail(ticketId: string): Promise<{
    ticket: SupportTicketSummary | null;
    messages: SupportMessage[];
    error: Error | null;
}> {
    const { data, error } = await supabase.functions.invoke('support-list', {
        body: { action: 'get_ticket', ticket_id: ticketId },
    });

    if (error) {
        return { ticket: null, messages: [], error: new Error(error.message || 'Failed to load ticket') };
    }

    if (!data?.success) {
        return { ticket: null, messages: [], error: new Error('Ticket detail returned invalid payload') };
    }

    return {
        ticket: (data.ticket || null) as SupportTicketSummary | null,
        messages: (data.messages || []) as SupportMessage[],
        error: null,
    };
}

/**
 * Sends a reply to a support ticket on behalf of the current user.
 *
 * @param ticketId - The ticket UUID
 * @param message - The reply message body
 * @returns Inserted message or error
 */
export async function replySupportTicket(
    ticketId: string,
    message: string,
): Promise<{ message: SupportMessage | null; error: Error | null }> {
    const { data, error } = await supabase.functions.invoke('support-list', {
        body: { action: 'reply_ticket', ticket_id: ticketId, message },
    });

    if (error) {
        return { message: null, error: new Error(error.message || 'Failed to send reply') };
    }

    if (!data?.success) {
        return { message: null, error: new Error('Reply returned invalid payload') };
    }

    return { message: (data.message || null) as SupportMessage | null, error: null };
}

/**
 * Closes a support ticket on behalf of the current user.
 *
 * @param ticketId - The ticket UUID
 * @returns Updated ticket or error
 */
export async function closeSupportTicket(
    ticketId: string,
): Promise<{ error: Error | null }> {
    const { data, error } = await supabase.functions.invoke('support-list', {
        body: { action: 'close_ticket', ticket_id: ticketId },
    });

    if (error) {
        return { error: new Error(error.message || 'Failed to close ticket') };
    }

    if (!data?.success) {
        return { error: new Error('Close ticket returned invalid payload') };
    }

    return { error: null };
}

// ============ Type Definitions ============

export interface CreateSupportTicketInput {
    subject: string;
    message: string;
    category: 'general' | 'technical' | 'billing' | 'security' | 'family' | 'other';
}

export interface SupportEntitlement {
    priority_reason: 'free' | 'premium' | 'families_owner' | 'families_member' | 'self_hosted';
    tier_snapshot: 'free' | 'premium' | 'families' | 'self_hosted';
    sla_hours: number;
    is_priority: boolean;
}

export interface SupportTicketSummary {
    id: string;
    subject: string;
    category: 'general' | 'technical' | 'billing' | 'security' | 'family' | 'other';
    status: 'open' | 'in_progress' | 'waiting_user' | 'resolved' | 'closed';
    priority_reason: 'free' | 'premium' | 'families_owner' | 'families_member' | 'self_hosted';
    tier_snapshot: 'free' | 'premium' | 'families' | 'self_hosted';
    is_priority: boolean;
    sla_hours: number;
    sla_due_at: string;
    first_response_at: string | null;
    first_response_minutes: number | null;
    created_at: string;
    updated_at: string;
    last_message_at: string;
    latest_message?: {
        body: string;
        created_at: string;
        author_role: 'user' | 'support' | 'system';
    } | null;
    sla_label?: string;
    unread_count?: number;
}

export interface SupportMessage {
    id: string;
    ticket_id: string;
    author_user_id: string;
    author_role: 'user' | 'support' | 'system';
    body: string;
    created_at: string;
}

export interface SupportResponseMetric {
    window_days: number;
    segment: string;
    ticket_count: number;
    responded_count: number;
    avg_first_response_minutes: number;
    avg_first_response_hours: number;
    sla_hit_rate_percent: number;
}
