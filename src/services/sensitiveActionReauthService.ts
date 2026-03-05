// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 — see LICENSE
/**
 * @fileoverview Step-up reauthentication helpers for sensitive actions.
 *
 * Uses account-password confirmation and checks JWT `iat` freshness to gate
 * dangerous account operations.
 */

import { supabase } from '@/integrations/supabase/client';

const DEFAULT_SENSITIVE_ACTION_MAX_AGE_SECONDS = 300;
const PASSWORD_AUTH_PROVIDER = 'email';

// ============ Public API ============

/**
 * Checks whether the current session is fresh enough for sensitive actions.
 * Freshness is measured from JWT `iat` (issued-at) timestamp.
 *
 * @param maxAgeSeconds - Maximum allowed token age in seconds
 * @returns True when the current JWT age is within the configured window
 */
export async function isSensitiveActionSessionFresh(
    maxAgeSeconds: number = DEFAULT_SENSITIVE_ACTION_MAX_AGE_SECONDS,
): Promise<boolean> {
    if (!Number.isFinite(maxAgeSeconds) || maxAgeSeconds <= 0) {
        return false;
    }

    const { data: { session }, error } = await supabase.auth.getSession();
    if (error || !session?.access_token) {
        return false;
    }

    const issuedAt = parseJwtIssuedAt(session.access_token);
    if (!issuedAt) {
        return false;
    }

    const now = Math.floor(Date.now() / 1000);
    if (issuedAt > now + 30) {
        return false;
    }

    return (now - issuedAt) <= maxAgeSeconds;
}

/**
 * Reauthenticates the current user by confirming the account password.
 * A successful response refreshes the in-memory Supabase session.
 *
 * @param password - Account password (not vault master password)
 * @returns Structured result with status and error code
 */
export async function reauthenticateWithAccountPassword(
    password: string,
): Promise<SensitiveActionReauthResult> {
    if (!password || !password.trim()) {
        return { success: false, error: 'INVALID_CREDENTIALS' };
    }

    const { data: { user }, error: userError } = await supabase.auth.getUser();
    if (userError || !user?.email) {
        return { success: false, error: 'AUTH_REQUIRED' };
    }

    const requestBody: ReauthRequestBody = {
        email: user.email,
        password,
    };

    const inIframe = isInIframe();
    if (inIframe) {
        requestBody.skipCookie = true;
    }

    try {
        const response = await fetch(`${import.meta.env.VITE_SUPABASE_URL}/functions/v1/auth-session`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${import.meta.env.VITE_SUPABASE_PUBLISHABLE_KEY}`,
            },
            credentials: inIframe ? 'omit' : 'include',
            body: JSON.stringify(requestBody),
        });

        if (response.status === 401) {
            return { success: false, error: 'INVALID_CREDENTIALS' };
        }

        if (response.status === 403) {
            return { success: false, error: 'AUTH_REQUIRED' };
        }

        if (!response.ok) {
            return { success: false, error: 'REAUTH_FAILED' };
        }

        const payload = await response.json().catch(() => null) as ReauthResponseBody | null;
        if (payload?.requires2FA) {
            return { success: false, error: 'TWO_FACTOR_REQUIRED' };
        }

        if (!payload?.session?.access_token) {
            return { success: false, error: 'REAUTH_FAILED' };
        }

        const { error: setSessionError } = await supabase.auth.setSession({
            access_token: payload.session.access_token,
            refresh_token: payload.session.refresh_token || '',
        });

        if (setSessionError) {
            return { success: false, error: 'REAUTH_FAILED' };
        }

        return { success: true };
    } catch {
        return { success: false, error: 'REAUTH_FAILED' };
    }
}

/**
 * Resolves which reauthentication method should be shown to the current user.
 * Password-based users get password confirmation, social-only users get the
 * confirmation + session-refresh fallback.
 *
 * @returns Reauth method descriptor for the current account
 */
export async function getSensitiveActionReauthMethod(): Promise<SensitiveActionReauthMethod> {
    const { data: { user }, error } = await supabase.auth.getUser();
    if (error || !user) {
        return 'password';
    }

    const providers = getAuthProviders(user.app_metadata);
    if (providers.includes(PASSWORD_AUTH_PROVIDER)) {
        return 'password';
    }

    if (providers.length > 0) {
        return 'confirmation';
    }

    return user.email ? 'password' : 'confirmation';
}

/**
 * Reauthenticates by forcing a token refresh for providers without account
 * password credentials (for example OAuth-only users).
 *
 * @returns Structured result with status and error code
 */
export async function reauthenticateWithSessionRefresh(): Promise<SensitiveActionReauthResult> {
    const { data: { session }, error: sessionError } = await supabase.auth.getSession();
    if (sessionError || !session?.refresh_token) {
        return { success: false, error: 'AUTH_REQUIRED' };
    }

    const { data: refreshedData, error: refreshError } = await supabase.auth.refreshSession({
        refresh_token: session.refresh_token,
    });

    if (refreshError || !refreshedData.session?.access_token) {
        return { success: false, error: 'REAUTH_FAILED' };
    }

    const issuedAt = parseJwtIssuedAt(refreshedData.session.access_token);
    if (!issuedAt) {
        return { success: false, error: 'REAUTH_FAILED' };
    }

    const now = Math.floor(Date.now() / 1000);
    if (issuedAt > now + 30) {
        return { success: false, error: 'REAUTH_FAILED' };
    }

    return { success: true };
}

// ============ Internal Helpers ============

function isInIframe(): boolean {
    try {
        return window.self !== window.top;
    } catch {
        return true;
    }
}

function parseJwtIssuedAt(accessToken: string): number | null {
    const segments = accessToken.split('.');
    if (segments.length < 2 || !segments[1]) {
        return null;
    }

    try {
        const base64Payload = segments[1].replace(/-/g, '+').replace(/_/g, '/');
        const padded = `${base64Payload}${'='.repeat((4 - (base64Payload.length % 4)) % 4)}`;
        const payload = JSON.parse(atob(padded)) as Record<string, unknown>;
        const iat = payload.iat;

        if (typeof iat === 'number' && Number.isFinite(iat)) {
            return Math.floor(iat);
        }

        if (typeof iat === 'string' && /^\d+$/.test(iat)) {
            return Number(iat);
        }

        return null;
    } catch {
        return null;
    }
}

function getAuthProviders(
    appMetadata: Record<string, unknown> | null | undefined,
): string[] {
    if (!appMetadata || typeof appMetadata !== 'object') {
        return [];
    }

    const providersField = appMetadata.providers;
    if (Array.isArray(providersField)) {
        return providersField
            .filter((value): value is string => typeof value === 'string')
            .map((value) => value.trim().toLowerCase())
            .filter((value) => value.length > 0);
    }

    const providerField = appMetadata.provider;
    if (typeof providerField === 'string' && providerField.trim()) {
        return [providerField.trim().toLowerCase()];
    }

    return [];
}

// ============ Type Definitions ============

export type SensitiveActionReauthMethod = 'password' | 'confirmation';

export type SensitiveActionReauthErrorCode =
    | 'AUTH_REQUIRED'
    | 'INVALID_CREDENTIALS'
    | 'TWO_FACTOR_REQUIRED'
    | 'REAUTH_FAILED';

export interface SensitiveActionReauthResult {
    success: boolean;
    error?: SensitiveActionReauthErrorCode;
}

interface ReauthRequestBody {
    email: string;
    password: string;
    skipCookie?: boolean;
}

interface ReauthResponseBody {
    requires2FA?: boolean;
    session?: {
        access_token?: string;
        refresh_token?: string;
    };
}
