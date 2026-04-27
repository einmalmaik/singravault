// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 — see LICENSE
/**
 * @fileoverview Step-up reauthentication helpers for sensitive actions.
 *
 * Uses account-password confirmation and checks JWT `iat` freshness to gate
 * dangerous account operations.
 */

import { supabase } from '@/integrations/supabase/client';
import type { Session } from '@supabase/supabase-js';
import { refreshCurrentSession } from '@/services/authSessionManager';
import { runtimeConfig } from '@/config/runtimeConfig';
import * as opaqueClient from '@/services/opaqueService';

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

    const inIframe = isInIframe();

    try {
        opaqueClient.assertOpaqueServerKeyPinConfigured();
        const apiUrl = runtimeConfig.supabaseFunctionsUrl ?? `${runtimeConfig.supabaseUrl}/functions/v1`;
        const userIdentifier = opaqueClient.normalizeOpaqueIdentifier(user.email);
        const { clientLoginState, startLoginRequest } = await opaqueClient.startLogin(password);

        const startResponse = await fetch(`${apiUrl}/auth-opaque`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${runtimeConfig.supabasePublishableKey}`,
            },
            credentials: inIframe ? 'omit' : 'include',
            body: JSON.stringify({
                action: 'login-start',
                userIdentifier,
                startLoginRequest,
            }),
        });

        if (startResponse.status === 401) {
            return { success: false, error: 'INVALID_CREDENTIALS' };
        }

        if (startResponse.status === 403) {
            return { success: false, error: 'AUTH_REQUIRED' };
        }

        if (!startResponse.ok) {
            return { success: false, error: 'REAUTH_FAILED' };
        }

        const { loginResponse, loginId } = await startResponse.json() as {
            loginResponse?: string;
            loginId?: string;
        };
        if (!loginResponse || !loginId) {
            return { success: false, error: 'REAUTH_FAILED' };
        }

        const { finishLoginRequest, sessionKey } = await opaqueClient.finishLogin(
            clientLoginState,
            loginResponse,
            password,
        );

        const finishResponse = await fetch(`${apiUrl}/auth-opaque`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${runtimeConfig.supabasePublishableKey}`,
            },
            credentials: inIframe ? 'omit' : 'include',
            body: JSON.stringify({
                action: 'login-finish',
                userIdentifier,
                finishLoginRequest,
                loginId,
                skipCookie: inIframe,
            }),
        });

        if (finishResponse.status === 401) {
            return { success: false, error: 'INVALID_CREDENTIALS' };
        }

        if (finishResponse.status === 403) {
            return { success: false, error: 'AUTH_REQUIRED' };
        }

        if (!finishResponse.ok) {
            return { success: false, error: 'REAUTH_FAILED' };
        }

        const payload = await finishResponse.json().catch(() => null) as ReauthResponseBody | null;
        if (payload?.requires2FA) {
            return { success: false, error: 'TWO_FACTOR_REQUIRED' };
        }

        if (!payload?.session?.access_token) {
            return { success: false, error: 'REAUTH_FAILED' };
        }

        await opaqueClient.verifyOpaqueSessionBinding(sessionKey, payload.session as Session, payload.opaqueSessionBinding);

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
    const hasKnownRefreshToken = !sessionError && Boolean(session?.refresh_token);
    const refreshedSession = await refreshCurrentSession();
    if (!refreshedSession?.access_token) {
        return { success: false, error: hasKnownRefreshToken ? 'REAUTH_FAILED' : 'AUTH_REQUIRED' };
    }

    const issuedAt = parseJwtIssuedAt(refreshedSession.access_token);
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

interface ReauthResponseBody {
    requires2FA?: boolean;
    opaqueSessionBinding?: unknown;
    session?: {
        access_token?: string;
        refresh_token?: string;
        user?: {
            id?: string;
        };
    };
}
