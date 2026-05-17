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
import { runtimeConfig } from '@/config/runtimeConfig';
import * as opaqueClient from '@/services/opaqueService';

const DEFAULT_SENSITIVE_ACTION_MAX_AGE_SECONDS = 300;

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

        // The server inserts a reauth proof in the DB after a successful OPAQUE
        // verification and returns its id. This proof must be presented when
        // requesting any sensitive-action challenge so that challenge issuance
        // cannot be satisfied by a bare session refresh.
        const reauthProofId = typeof payload.reauthProofId === 'string' && payload.reauthProofId
            ? payload.reauthProofId
            : undefined;

        if (!reauthProofId) {
            return { success: false, error: 'REAUTH_FAILED' };
        }

        return { success: true, reauthProofId };
    } catch {
        return { success: false, error: 'REAUTH_FAILED' };
    }
}

/**
 * Resolves which reauthentication method should be shown to the current user.
 * All users must confirm their account password via the OPAQUE credential
 * verification flow. Silent session refresh is not accepted as proof of
 * identity because it does not verify the user's credentials.
 *
 * @returns Reauth method descriptor for the current account
 */
export async function getSensitiveActionReauthMethod(): Promise<SensitiveActionReauthMethod> {
    return 'password';
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

// ============ Type Definitions ============

export type SensitiveActionReauthMethod = 'password';

export type SensitiveActionReauthErrorCode =
    | 'AUTH_REQUIRED'
    | 'INVALID_CREDENTIALS'
    | 'TWO_FACTOR_REQUIRED'
    | 'REAUTH_FAILED';

export interface SensitiveActionReauthResult {
    success: boolean;
    error?: SensitiveActionReauthErrorCode;
    /**
     * Server-issued OPAQUE reauth proof ID. Present on success; must be passed
     * to any sensitive-action challenge RPC (begin_account_delete_challenge,
     * begin_vault_reset_recovery) so the server can verify a real credential
     * proof rather than JWT iat freshness.
     */
    reauthProofId?: string;
}

interface ReauthResponseBody {
    requires2FA?: boolean;
    reauthProofId?: string;
    opaqueSessionBinding?: unknown;
    session?: {
        access_token?: string;
        refresh_token?: string;
        user?: {
            id?: string;
        };
    };
}
