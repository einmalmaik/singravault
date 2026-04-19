// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 — see LICENSE
/**
 * @fileoverview Authenticated Edge Function invocation helper.
 *
 * Ensures every invocation carries a user JWT and normalizes HTTP
 * errors from Supabase Functions into a stable error shape.
 */

import { supabase } from '@/integrations/supabase/client';
import { FunctionsHttpError } from '@supabase/supabase-js';
import { refreshCurrentSession } from '@/services/authSessionManager';

const loggedRetryWarnings = new Set<string>();

// ============ Public API ============

/**
 * Invokes a Supabase Edge Function with the current user's session.
 * Now dynamically handled securely by supabase-js.
 *
 * @param functionName - Edge Function slug
 * @param body - JSON payload sent to the function
 * @returns Parsed function response payload
 * @throws EdgeFunctionServiceError when auth/session/function call fails
 */
export async function invokeAuthedFunction<
    TResponse,
    TBody extends Record<string, unknown> = Record<string, unknown>,
>(
    functionName: string,
    body?: TBody,
): Promise<TResponse> {
    // Gatekeeper: await getSession() to guarantee storage hydration completes
    // before we invoke the function, preventing race condition 401s.
    console.debug(`[EdgeFunctionService] invokeAuthedFunction('${functionName}') started. Awaiting getSession()...`);
    let { data: { session }, error: sessionError } = await supabase.auth.getSession();
    console.debug(`[EdgeFunctionService] getSession() returned for '${functionName}'. Has session:`, !!session);
    logSessionDiagnostics(functionName, 'initial', session);

    if ((sessionError || !session?.access_token) && typeof window !== 'undefined') {
        console.warn(`[EdgeFunctionService] No usable in-memory session for '${functionName}'. Attempting persisted session hydration...`);
        session = await refreshCurrentSession();
        sessionError = session ? null : sessionError;
    }

    // autoRefreshToken is disabled (BFF pattern). Detect expired access_token and
    // attempt a silent refresh via the BFF cookie before failing with 401.
    if (!sessionError && session?.access_token) {
        try {
            const payload = decodeJwtPayload(session.access_token);
            const expiresAt: number = payload?.exp ?? 0;
            const nowSec = Math.floor(Date.now() / 1000);
            if (expiresAt - nowSec < 30) {
                console.debug(`[EdgeFunctionService] Access token expiring/expired for '${functionName}', attempting BFF refresh…`);
                const refreshed = await refreshCurrentSession();
                if (refreshed) {
                    session = refreshed;
                    logSessionDiagnostics(functionName, 'refresh-session', session);
                }
            }
        } catch {
            // ignore decode errors — let the call proceed and fail naturally
        }
    }

    if (sessionError || !session?.access_token) {
        const authError = new Error('Authentication required') as EdgeFunctionServiceError;
        authError.name = 'EdgeFunctionServiceError';
        authError.code = 'AUTH_REQUIRED';
        authError.status = 401;
        throw authError;
    }

    try {
        return await invokeWithSession<TResponse, TBody>(functionName, session.access_token, body);
    } catch (error) {
        logAuthErrorDetails(functionName, error);

        if (!isRetryableAuthError(error) || typeof window === 'undefined') {
            throw error;
        }

        logRetryWarningOnce(functionName);
        const rehydratedSession = await refreshCurrentSession();
        if (!rehydratedSession?.access_token) {
            throw error;
        }

        logSessionDiagnostics(functionName, 'retry-after-refresh', rehydratedSession);
        return await invokeWithSession<TResponse, TBody>(functionName, rehydratedSession.access_token, body);
    }
}

/**
 * Type guard for normalized edge function errors.
 *
 * @param error - Unknown thrown value
 * @returns True when error was normalized by this service
 */
export function isEdgeFunctionServiceError(error: unknown): error is EdgeFunctionServiceError {
    if (!(error instanceof Error)) {
        return false;
    }

    return error.name === 'EdgeFunctionServiceError';
}

// ============ Internal Helpers ============

async function invokeWithSession<
    TResponse,
    TBody extends Record<string, unknown> = Record<string, unknown>,
>(
    functionName: string,
    accessToken: string,
    body?: TBody,
): Promise<TResponse> {
    console.debug(`[EdgeFunctionService] Invoking '${functionName}' now...`);
    const startTime = Date.now();
    const { data, error } = await supabase.functions.invoke(functionName, {
        body,
        headers: {
            Authorization: `Bearer ${accessToken}`,
        },
    });
    console.debug(`[EdgeFunctionService] Invoked '${functionName}' in ${Date.now() - startTime}ms. Error:`, error);

    if (error) {
        throw await normalizeSupabaseFunctionError(error);
    }

    return (data || null) as TResponse;
}

function decodeJwtPayload(token: string): JwtPayload | null {
    try {
        const base64 = token.split('.')[1];
        if (!base64) {
            return null;
        }

        return JSON.parse(atob(base64)) as JwtPayload;
    } catch {
        return null;
    }
}

function logSessionDiagnostics(functionName: string, stage: string, session: AuthSessionLike | null | undefined): void {
    if (!session?.access_token) {
        console.debug(`[EdgeFunctionService] Session diagnostics for '${functionName}' at '${stage}': no access token.`);
        return;
    }

    const payload = decodeJwtPayload(session.access_token);
    if (!payload) {
        console.debug(`[EdgeFunctionService] Session diagnostics for '${functionName}' at '${stage}': token could not be decoded.`);
        return;
    }

    const nowSec = Math.floor(Date.now() / 1000);
    console.debug(`[EdgeFunctionService] Session diagnostics for '${functionName}' at '${stage}':`, {
        sub: payload.sub ?? null,
        aud: payload.aud ?? null,
        role: payload.role ?? null,
        exp: payload.exp ?? null,
        expiresInSec: typeof payload.exp === 'number' ? payload.exp - nowSec : null,
        iss: payload.iss ?? null,
    });
}

function logRetryWarningOnce(functionName: string): void {
    if (loggedRetryWarnings.has(functionName)) {
        return;
    }

    loggedRetryWarnings.add(functionName);
    console.warn(`[EdgeFunctionService] '${functionName}' returned 401. Rehydrating from BFF and retrying once...`);
}

function logAuthErrorDetails(functionName: string, error: unknown): void {
    if (!isEdgeFunctionServiceError(error) || error.status !== 401 || !error.details) {
        return;
    }

    console.warn(`[EdgeFunctionService] '${functionName}' 401 details:`, error.details);
}

function isRetryableAuthError(error: unknown): boolean {
    return isEdgeFunctionServiceError(error) && error.code === 'AUTH_REQUIRED' && error.status === 401;
}

interface FunctionsHttpErrorContext {
    status?: number;
    json?: () => Promise<Record<string, unknown>>;
}

async function normalizeSupabaseFunctionError(error: unknown): Promise<EdgeFunctionServiceError> {
    let status: number | undefined;
    let code: EdgeFunctionErrorCode = 'UNKNOWN';
    let details: Record<string, unknown> | undefined;
    let message = error instanceof Error ? error.message : 'Edge function request failed';

    if (error instanceof FunctionsHttpError) {
        // Extracted context from FunctionsHttpError if available
        const context = (error as { context?: FunctionsHttpErrorContext }).context;
        if (context) {
            if (context.status) {
                status = context.status;
            }
            if (typeof context.json === 'function') {
                try {
                    const json = await context.json();
                    if (json) {
                        details = { ...json };
                        const detailMessage = json.details || json.error || json.message;
                        if (detailMessage && typeof detailMessage === 'string') {
                            message = detailMessage;
                        }
                    }
                } catch {
                    // fallback auf generische Message
                }
            }
        }
    } else {
        // Fallback: parse basic error message for status code
        const match = message.match(/status code: (\d+)/i);
        if (match) {
            status = parseInt(match[1], 10);
        }
    }

    if (status) {
        if (status === 400) code = 'BAD_REQUEST';
        if (status === 401) code = 'AUTH_REQUIRED';
        if (status === 403) code = 'FORBIDDEN';
        if (status >= 500) code = 'SERVER_ERROR';
    }

    if (code === 'AUTH_REQUIRED') {
        message = 'Authentication required';
    } else if (code === 'FORBIDDEN') {
        message = 'Forbidden';
    } else if (code === 'SERVER_ERROR') {
        // Only override to strict "Internal server error" if it's 500 without specifics
        if (message === 'Edge function request failed' || message.includes('status code: 500')) {
            message = 'Internal server error';
        }
    }

    return createEdgeFunctionError(message, code, status, details);
}

function createEdgeFunctionError(
    message: string,
    code: EdgeFunctionErrorCode,
    status?: number,
    details?: Record<string, unknown>,
): EdgeFunctionServiceError {
    const error = new Error(message) as EdgeFunctionServiceError;
    error.name = 'EdgeFunctionServiceError';
    error.code = code;
    error.status = status;
    error.details = details;
    return error;
}

// ============ Type Definitions ============

export type EdgeFunctionErrorCode =
    | 'AUTH_REQUIRED'
    | 'FORBIDDEN'
    | 'BAD_REQUEST'
    | 'SERVER_ERROR'
    | 'UNKNOWN';

export interface EdgeFunctionServiceError extends Error {
    code: EdgeFunctionErrorCode;
    details?: Record<string, unknown>;
    status?: number;
}

interface JwtPayload {
    sub?: string;
    aud?: string | string[];
    role?: string;
    exp?: number;
    iss?: string;
}

interface AuthSessionLike {
    access_token: string;
    refresh_token?: string;
}
