// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE
/**
 * Central OPAQUE account-password reset/change flow.
 *
 * The new account password is only passed into client-side OPAQUE helpers.
 * Requests to Edge Functions carry email codes, reset tokens, and OPAQUE
 * protocol messages, never the plaintext password or a password hash.
 */

import type { User } from '@supabase/supabase-js';

import { runtimeConfig } from '@/config/runtimeConfig';
import { supabase } from '@/integrations/supabase/client';
import * as opaqueClient from '@/services/opaqueService';

export type AccountPasswordResetPurpose = 'forgot' | 'change';

export type AccountPasswordResetNextState =
    | 'EMAIL_CODE_REQUESTED'
    | 'TWO_FACTOR_REQUIRED'
    | 'NEW_PASSWORD_ALLOWED'
    | 'DONE';

export interface VerifyEmailCodeResult {
    resetToken: string;
    expiresAt: string;
    requires2FA: boolean;
    nextState: Extract<AccountPasswordResetNextState, 'TWO_FACTOR_REQUIRED' | 'NEW_PASSWORD_ALLOWED'>;
}

const API_URL = runtimeConfig.supabaseFunctionsUrl ?? `${runtimeConfig.supabaseUrl}/functions/v1`;

export async function requestAccountPasswordEmailCode(input: {
    purpose: AccountPasswordResetPurpose;
    email?: string;
}): Promise<{ nextState: 'EMAIL_CODE_REQUESTED' }> {
    const response = await fetch(`${API_URL}/auth-recovery`, {
        method: 'POST',
        headers: await createRecoveryHeaders(input.purpose),
        credentials: 'omit',
        body: JSON.stringify({
            action: 'request-email-code',
            purpose: input.purpose,
            ...(input.purpose === 'forgot' ? { email: normalizeEmailInput(input.email) } : {}),
        }),
    });

    if (!response.ok) {
        throw await endpointError(response, 'Email code request failed');
    }

    return { nextState: 'EMAIL_CODE_REQUESTED' };
}

export async function verifyAccountPasswordEmailCode(input: {
    purpose: AccountPasswordResetPurpose;
    email?: string;
    code: string;
}): Promise<VerifyEmailCodeResult> {
    const response = await fetch(`${API_URL}/auth-recovery`, {
        method: 'POST',
        headers: await createRecoveryHeaders(input.purpose),
        credentials: 'omit',
        body: JSON.stringify({
            action: 'verify-email-code',
            purpose: input.purpose,
            code: input.code,
            ...(input.purpose === 'forgot' ? { email: normalizeEmailInput(input.email) } : {}),
        }),
    });

    if (!response.ok) {
        throw await endpointError(response, 'Email code verification failed');
    }

    const payload = await response.json() as Partial<VerifyEmailCodeResult>;
    if (typeof payload.resetToken !== 'string' || !payload.resetToken) {
        throw new Error('Reset authorization missing');
    }

    return {
        resetToken: payload.resetToken,
        expiresAt: typeof payload.expiresAt === 'string' ? payload.expiresAt : '',
        requires2FA: Boolean(payload.requires2FA),
        nextState: payload.requires2FA ? 'TWO_FACTOR_REQUIRED' : 'NEW_PASSWORD_ALLOWED',
    };
}

export async function verifyAccountPasswordResetSecondFactor(input: {
    resetToken: string;
    code: string;
    isBackupCode: boolean;
}): Promise<{ nextState: 'NEW_PASSWORD_ALLOWED' }> {
    const response = await fetch(`${API_URL}/auth-recovery`, {
        method: 'POST',
        headers: createPublicHeaders(),
        credentials: 'omit',
        body: JSON.stringify({
            action: 'verify-two-factor',
            resetToken: input.resetToken,
            code: input.code,
            isBackupCode: input.isBackupCode,
        }),
    });

    if (!response.ok) {
        throw await endpointError(response, 'Two-factor verification failed');
    }

    return { nextState: 'NEW_PASSWORD_ALLOWED' };
}

export async function completeOpaqueAccountPasswordReset(input: {
    resetToken: string;
    newPassword: string;
}): Promise<{ nextState: 'DONE' }> {
    opaqueClient.assertOpaqueServerKeyPinConfigured();
    const { clientRegistrationState, registrationRequest } = await opaqueClient.startRegistration(input.newPassword);

    const startResponse = await fetch(`${API_URL}/auth-reset-password`, {
        method: 'POST',
        headers: createPublicHeaders(),
        credentials: 'omit',
        body: JSON.stringify({
            action: 'opaque-reset-start',
            resetToken: input.resetToken,
            registrationRequest,
        }),
    });

    if (!startResponse.ok) {
        throw await endpointError(startResponse, 'OPAQUE reset start failed');
    }

    const startPayload = await startResponse.json() as {
        resetRegistrationId?: unknown;
        registrationResponse?: unknown;
    };
    if (typeof startPayload.resetRegistrationId !== 'string' || typeof startPayload.registrationResponse !== 'string') {
        throw new Error('OPAQUE reset start failed');
    }

    const { registrationRecord } = await opaqueClient.finishRegistration(
        clientRegistrationState,
        startPayload.registrationResponse,
        input.newPassword,
    );

    const finishResponse = await fetch(`${API_URL}/auth-reset-password`, {
        method: 'POST',
        headers: createPublicHeaders(),
        credentials: 'omit',
        body: JSON.stringify({
            action: 'opaque-reset-finish',
            resetToken: input.resetToken,
            resetRegistrationId: startPayload.resetRegistrationId,
            registrationRecord,
        }),
    });

    if (!finishResponse.ok) {
        throw await endpointError(finishResponse, 'OPAQUE reset finish failed');
    }

    return { nextState: 'DONE' };
}

export function canCurrentUserUseAppPasswordFlow(user: User | null | undefined): boolean {
    if (!user?.email) {
        return false;
    }

    const providers = getAuthProviders(user.app_metadata);
    return providers.includes('email') || providers.length === 0;
}

function createPublicHeaders(): HeadersInit {
    return {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${runtimeConfig.supabasePublishableKey}`,
    };
}

async function createRecoveryHeaders(purpose: AccountPasswordResetPurpose): Promise<HeadersInit> {
    if (purpose === 'forgot') {
        return createPublicHeaders();
    }

    const { data: { session }, error } = await supabase.auth.getSession();
    if (error || !session?.access_token) {
        throw new Error('Authentication required');
    }

    return {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${session.access_token}`,
    };
}

function normalizeEmailInput(email: string | undefined): string {
    return opaqueClient.normalizeOpaqueIdentifier(email ?? '');
}

function getAuthProviders(appMetadata: Record<string, unknown> | null | undefined): string[] {
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

async function endpointError(response: Response, fallback: string): Promise<Error> {
    const payload = await response.json().catch(() => null) as { error?: unknown; code?: unknown } | null;
    const message = typeof payload?.error === 'string' && payload.error ? payload.error : fallback;
    const error = new Error(message);
    if (typeof payload?.code === 'string') {
        error.name = payload.code;
    }
    return error;
}
