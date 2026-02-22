// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 — see LICENSE
/**
 * @fileoverview Admin Service
 *
 * Client abstraction for internal admin/team operations.
 * All privileged reads/writes go through Supabase Edge Functions.
 */

import { supabase } from '@/integrations/supabase/client';

const ADMIN_SUPPORT_FUNCTION = 'admin-support';
const ADMIN_TEAM_FUNCTION = 'admin-team';

// ============ Internal Helpers ============

/**
 * Invokes an admin edge function with an explicit user session JWT.
 *
 * This prevents fallback to anon credentials, which would otherwise
 * cause 401 responses on admin-only functions with JWT verification enabled.
 *
 * @param functionName - Supabase edge function slug
 * @param body - Request payload
 * @returns Function data payload or error
 */
async function invokeAdminFunction(
    functionName: string,
    body: Record<string, unknown>,
): Promise<{ data: Record<string, unknown> | null; error: Error | null }> {
    // Gatekeeper: await getUser() to guarantee any background token refresh 
    // completes before we invoke the function, preventing race condition 401s.
    // getUser validates server-side instead of just checking localStorage.
    console.debug(`[AdminService] invokeAdminFunction('${functionName}') started. Awaiting getUser()...`);
    const { data: { user }, error: userError } = await supabase.auth.getUser();
    console.debug(`[AdminService] getUser() returned for '${functionName}'. Has user:`, !!user);

    if (userError || !user) {
        return { data: null, error: new Error('Authentication required to access admin functions') };
    }

    console.debug(`[AdminService] Invoking '${functionName}' now...`);
    const startTime = Date.now();
    const { data, error } = await supabase.functions.invoke(functionName, {
        body,
    });
    console.debug(`[AdminService] Invoked '${functionName}' in ${Date.now() - startTime}ms. Error:`, error);

    if (error) {
        return { data: null, error: new Error(error.message || 'Edge function request failed') };
    }

    return { data: (data || null) as Record<string, unknown>, error: null };
}

// ============ Team Access API ============

/**
 * Loads current internal team access (roles + permission keys).
 *
 * @returns Team access payload or error
 */
export async function getTeamAccess(): Promise<{ access: TeamAccess | null; error: Error | null }> {
    const { data, error } = await invokeAdminFunction(ADMIN_TEAM_FUNCTION, {
        action: 'get_access',
    });

    if (error) {
        return { access: null, error: new Error(error.message || 'Failed to load team access') };
    }

    if (!data?.success || !data?.access) {
        return { access: null, error: new Error('Invalid team access payload') };
    }

    return { access: data.access as TeamAccess, error: null };
}

/**
 * Lists team members and their assigned internal roles.
 *
 * @returns Team member list or error
 */
export async function listTeamMembers(): Promise<{ members: TeamMember[]; error: Error | null }> {
    const { data, error } = await invokeAdminFunction(ADMIN_TEAM_FUNCTION, {
        action: 'list_members',
    });

    if (error) {
        return { members: [], error: new Error(error.message || 'Failed to load team members') };
    }

    if (!data?.success) {
        return { members: [], error: new Error('Invalid team members payload') };
    }

    return { members: (data.members || []) as TeamMember[], error: null };
}

/**
 * Sets the primary internal role for a user.
 *
 * @param userId - Target user id
 * @param role - New role
 * @returns Success flag or error
 */
export async function setTeamMemberRole(
    userId: string,
    role: TeamRole,
): Promise<{ success: boolean; error: Error | null }> {
    const { data, error } = await invokeAdminFunction(ADMIN_TEAM_FUNCTION, {
        action: 'set_member_role',
        user_id: userId,
        role,
    });

    if (error) {
        return { success: false, error: new Error(error.message || 'Failed to update member role') };
    }

    if (!data?.success) {
        return { success: false, error: new Error('Invalid role update payload') };
    }

    return { success: true, error: null };
}

/**
 * Loads role-permission matrix for internal team access.
 *
 * @returns Permission matrix rows or error
 */
export async function listRolePermissions(): Promise<{
    permissions: RolePermissionMatrixRow[];
    error: Error | null;
}> {
    const { data, error } = await invokeAdminFunction(ADMIN_TEAM_FUNCTION, {
        action: 'list_role_permissions',
    });

    if (error) {
        return { permissions: [], error: new Error(error.message || 'Failed to load role permissions') };
    }

    if (!data?.success) {
        return { permissions: [], error: new Error('Invalid role permissions payload') };
    }

    return { permissions: (data.permissions || []) as RolePermissionMatrixRow[], error: null };
}

/**
 * Updates a permission mapping for a given role.
 *
 * @param role - Role to update
 * @param permissionKey - Permission key
 * @param enabled - Whether permission should be present for the role
 * @returns Success flag or error
 */
export async function setRolePermission(
    role: TeamPermissionRole,
    permissionKey: string,
    enabled: boolean,
): Promise<{ success: boolean; error: Error | null }> {
    const { data, error } = await invokeAdminFunction(ADMIN_TEAM_FUNCTION, {
        action: 'set_role_permission',
        role,
        permission_key: permissionKey,
        enabled,
    });

    if (error) {
        return { success: false, error: new Error(error.message || 'Failed to update role permission') };
    }

    if (!data?.success) {
        return { success: false, error: new Error('Invalid role permission update payload') };
    }

    return { success: true, error: null };
}

// ============ Admin Support API ============

/**
 * Lists support tickets for internal support team users.
 *
 * @param filters - Optional status/search filter
 * @returns Ticket list or error
 */
export async function listAdminSupportTickets(filters?: {
    status?: AdminSupportTicketStatus;
    search?: string;
    limit?: number;
}): Promise<{ tickets: AdminSupportTicket[]; error: Error | null }> {
    const { data, error } = await invokeAdminFunction(ADMIN_SUPPORT_FUNCTION, {
        action: 'list_tickets',
        status: filters?.status,
        search: filters?.search,
        limit: filters?.limit,
    });

    if (error) {
        return { tickets: [], error: new Error(error.message || 'Failed to load support tickets') };
    }

    if (!data?.success) {
        return { tickets: [], error: new Error('Invalid support tickets payload') };
    }

    return { tickets: (data.tickets || []) as AdminSupportTicket[], error: null };
}

/**
 * Loads one support ticket including its message thread.
 *
 * @param ticketId - Support ticket id
 * @returns Ticket detail or error
 */
export async function getAdminSupportTicket(ticketId: string): Promise<{
    detail: AdminSupportTicketDetail | null;
    error: Error | null;
}> {
    const { data, error } = await invokeAdminFunction(ADMIN_SUPPORT_FUNCTION, {
        action: 'get_ticket',
        ticket_id: ticketId,
    });

    if (error) {
        return { detail: null, error: new Error(error.message || 'Failed to load support ticket') };
    }

    if (!data?.success || !data?.ticket) {
        return { detail: null, error: new Error('Invalid support ticket detail payload') };
    }

    return {
        detail: {
            ticket: data.ticket as AdminSupportTicket,
            messages: (data.messages || []) as AdminSupportMessage[],
            permissions: (data.permissions || {
                can_reply: false,
                can_read_internal: false,
                can_update_status: false,
            }) as AdminSupportPermissions,
        },
        error: null,
    };
}

/**
 * Sends an internal support reply (public or internal note).
 *
 * @param input - Reply payload
 * @returns Created message or error
 */
export async function replyToAdminSupportTicket(input: {
    ticketId: string;
    message: string;
    isInternal?: boolean;
    status?: AdminSupportTicketStatus;
}): Promise<{ message: AdminSupportMessage | null; error: Error | null }> {
    const { data, error } = await invokeAdminFunction(ADMIN_SUPPORT_FUNCTION, {
        action: 'reply_ticket',
        ticket_id: input.ticketId,
        message: input.message,
        is_internal: input.isInternal === true,
        status: input.status,
    });

    if (error) {
        return { message: null, error: new Error(error.message || 'Failed to send support reply') };
    }

    if (!data?.success || !data?.message) {
        return { message: null, error: new Error('Invalid support reply payload') };
    }

    return { message: data.message as AdminSupportMessage, error: null };
}

/**
 * Updates support ticket workflow status.
 *
 * @param ticketId - Ticket id
 * @param status - New status
 * @returns Updated ticket status payload or error
 */
export async function updateAdminSupportTicketStatus(
    ticketId: string,
    status: AdminSupportTicketStatus,
): Promise<{ ticket: AdminTicketStatusUpdate | null; error: Error | null }> {
    const { data, error } = await invokeAdminFunction(ADMIN_SUPPORT_FUNCTION, {
        action: 'update_ticket',
        ticket_id: ticketId,
        status,
    });

    if (error) {
        return { ticket: null, error: new Error(error.message || 'Failed to update ticket status') };
    }

    if (!data?.success || !data?.ticket) {
        return { ticket: null, error: new Error('Invalid support status update payload') };
    }

    return { ticket: data.ticket as AdminTicketStatusUpdate, error: null };
}

/**
 * Loads support SLA metrics for internal users.
 *
 * @param days - Rolling window in days
 * @returns Metrics list or error
 */
export async function listAdminSupportMetrics(days: number = 30): Promise<{
    metrics: AdminSupportMetric[];
    error: Error | null;
}> {
    const { data, error } = await invokeAdminFunction(ADMIN_SUPPORT_FUNCTION, {
        action: 'list_metrics',
        days,
    });

    if (error) {
        return { metrics: [], error: new Error(error.message || 'Failed to load support metrics') };
    }

    if (!data?.success) {
        return { metrics: [], error: new Error('Invalid support metrics payload') };
    }

    return { metrics: (data.metrics || []) as AdminSupportMetric[], error: null };
}

/**
 * Assigns a subscription tier to a user from the admin support panel.
 *
 * @param input - Assignment payload
 * @returns Success flag or error
 */
export async function assignUserSubscription(input: {
    userId: string;
    tier: SubscriptionTier;
    reason: string;
    ticketId?: string;
}): Promise<{ success: boolean; error: Error | null }> {
    const { data, error } = await invokeAdminFunction(ADMIN_SUPPORT_FUNCTION, {
        action: 'assign_subscription',
        user_id: input.userId,
        tier: input.tier,
        reason: input.reason,
        ticket_id: input.ticketId,
    });

    if (error) {
        return { success: false, error: new Error(error.message || 'Failed to assign subscription') };
    }

    if (!data?.success) {
        return { success: false, error: new Error('Invalid assign subscription payload') };
    }

    return { success: true, error: null };
}

// ============ Type Definitions ============

export type TeamRole = 'admin' | 'moderator' | 'user';
export type TeamPermissionRole = 'admin' | 'moderator';
export type SubscriptionTier = 'free' | 'premium' | 'families' | 'self_hosted';

export interface TeamAccess {
    roles: TeamRole[];
    permissions: string[];
    is_admin: boolean;
    can_access_admin: boolean;
}

export interface TeamMember {
    user_id: string;
    email: string | null;
    display_name: string | null;
    roles: TeamRole[];
    primary_role: TeamRole;
    created_at: string | null;
}

export interface RolePermissionMatrixRow {
    permission_key: string;
    label: string;
    description: string;
    category: string;
    roles: Record<TeamPermissionRole, boolean>;
}

export type AdminSupportTicketStatus = 'open' | 'in_progress' | 'waiting_user' | 'resolved' | 'closed';

export interface AdminSupportTicket {
    id: string;
    user_id: string;
    requester_email: string | null;
    subject: string;
    category: 'general' | 'technical' | 'billing' | 'security' | 'family' | 'other';
    status: AdminSupportTicketStatus;
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
    resolved_at?: string | null;
    closed_at?: string | null;
    latest_message?: {
        body: string;
        created_at: string;
        author_role: 'user' | 'support' | 'system';
        is_internal: boolean;
    } | null;
}

export interface AdminSupportMessage {
    id: string;
    ticket_id: string;
    author_user_id: string | null;
    author_role: 'user' | 'support' | 'system';
    is_internal: boolean;
    body: string;
    created_at: string;
}

export interface AdminSupportPermissions {
    can_reply: boolean;
    can_read_internal: boolean;
    can_update_status: boolean;
}

export interface AdminSupportTicketDetail {
    ticket: AdminSupportTicket;
    messages: AdminSupportMessage[];
    permissions: AdminSupportPermissions;
}

export interface AdminTicketStatusUpdate {
    id: string;
    status: AdminSupportTicketStatus;
    resolved_at: string | null;
    closed_at: string | null;
    updated_at: string;
}

export interface AdminSupportMetric {
    window_days: number;
    segment: string;
    ticket_count: number;
    responded_count: number;
    avg_first_response_minutes: number;
    avg_first_response_hours: number;
    sla_hit_rate_percent: number;
}
