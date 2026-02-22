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
    // Gatekeeper: await getUser() to guarantee any background token refresh 
    // completes before we invoke the function, preventing race condition 401s.
    // getUser validates server-side instead of just checking localStorage.
    console.debug(`[EdgeFunctionService] invokeAuthedFunction('${functionName}') started. Awaiting getUser()...`);
    const { data: { user }, error: userError } = await supabase.auth.getUser();
    console.debug(`[EdgeFunctionService] getUser() returned for '${functionName}'. Has user:`, !!user);

    if (userError || !user) {
        const authError = new Error('Authentication required') as EdgeFunctionServiceError;
        authError.name = 'EdgeFunctionServiceError';
        authError.code = 'AUTH_REQUIRED';
        authError.status = 401;
        throw authError;
    }

    console.debug(`[EdgeFunctionService] Invoking '${functionName}' now...`);
    const startTime = Date.now();
    const { data, error } = await supabase.functions.invoke(functionName, {
        body,
    });
    console.debug(`[EdgeFunctionService] Invoked '${functionName}' in ${Date.now() - startTime}ms. Error:`, error);

    if (error) {
        throw await normalizeSupabaseFunctionError(error);
    }

    return (data || null) as TResponse;
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

async function normalizeSupabaseFunctionError(error: any): Promise<EdgeFunctionServiceError> {
    let status: number | undefined;
    let code: EdgeFunctionErrorCode = 'UNKNOWN';
    let details: Record<string, unknown> | undefined;
    let message = error?.message || 'Edge function request failed';

    if (error instanceof FunctionsHttpError) {
        // Extracted context from FunctionsHttpError if available
        const context = (error as any).context;
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
