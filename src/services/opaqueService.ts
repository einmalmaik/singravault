// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 — see LICENSE
/**
 * @fileoverview OPAQUE Protocol Client Service
 *
 * Implements the client-side of the OPAQUE PAKE protocol using @serenity-kit/opaque.
 * The password NEVER leaves the client — not even as a hash.
 *
 * Flow:
 *   Registration: startRegistration → server.createRegistrationResponse → finishRegistration
 *   Login:        startLogin → server.createLoginResponse → finishLogin
 *
 * @see https://opaque-auth.com/docs/
 */

import * as opaque from '@serenity-kit/opaque';
import type { Session } from '@supabase/supabase-js';

import { runtimeConfig } from '@/config/runtimeConfig';

export const OPAQUE_SESSION_BINDING_VERSION = 'opaque-session-binding-v1';

// Keep the previous library default explicit. Raising this would invalidate existing OPAQUE records.
const OPAQUE_KEY_STRETCHING: opaque.client.FinishRegistrationParams['keyStretching'] = 'memory-constrained';

// ============ State Management ============

/** Ensures the WASM module is loaded before any operation. */
async function ensureReady(): Promise<void> {
    await opaque.ready;
}

export function normalizeOpaqueIdentifier(identifier: string): string {
    return identifier.trim().toLowerCase();
}

export function assertOpaqueServerKeyPinConfigured(): void {
    if (!runtimeConfig.opaqueServerStaticPublicKey) {
        throw new Error('OPAQUE server static public key pin is not configured');
    }
}

function assertServerStaticPublicKey(serverStaticPublicKey: string): void {
    const expected = runtimeConfig.opaqueServerStaticPublicKey;
    if (!expected) {
        throw new Error('OPAQUE server static public key pin is not configured');
    }

    if (!constantTimeStringEqual(serverStaticPublicKey.trim(), expected.trim())) {
        throw new Error('OPAQUE server static public key mismatch');
    }
}

// ============ Registration (Client Side) ============

/**
 * Starts OPAQUE registration on the client side.
 * Produces a registrationRequest to send to the server.
 *
 * @param password - The user's plaintext password (never sent to server)
 * @returns clientRegistrationState (kept locally) and registrationRequest (sent to server)
 */
export async function startRegistration(password: string): Promise<{
    clientRegistrationState: string;
    registrationRequest: string;
}> {
    await ensureReady();
    const { clientRegistrationState, registrationRequest } = opaque.client.startRegistration({
        password,
    });
    return { clientRegistrationState, registrationRequest };
}

/**
 * Finishes OPAQUE registration on the client side.
 * Takes the server's registrationResponse and produces a registrationRecord.
 *
 * @param clientRegistrationState - State from startRegistration
 * @param registrationResponse - Response from server
 * @param password - The user's plaintext password
 * @returns registrationRecord to send to the server for storage
 */
export async function finishRegistration(
    clientRegistrationState: string,
    registrationResponse: string,
    password: string,
): Promise<{
    registrationRecord: string;
    exportKey: string;
}> {
    await ensureReady();
    const result = opaque.client.finishRegistration({
        clientRegistrationState,
        registrationResponse,
        password,
        keyStretching: OPAQUE_KEY_STRETCHING,
    });
    assertServerStaticPublicKey(result.serverStaticPublicKey);
    return {
        registrationRecord: result.registrationRecord,
        exportKey: result.exportKey,
    };
}

// ============ Login (Client Side) ============

/**
 * Starts OPAQUE login on the client side.
 * Produces a startLoginRequest to send to the server.
 *
 * @param password - The user's plaintext password (never sent to server)
 * @returns clientLoginState (kept locally) and startLoginRequest (sent to server)
 */
export async function startLogin(password: string): Promise<{
    clientLoginState: string;
    startLoginRequest: string;
}> {
    await ensureReady();
    const { clientLoginState, startLoginRequest } = opaque.client.startLogin({
        password,
    });
    return { clientLoginState, startLoginRequest };
}

/**
 * Finishes OPAQUE login on the client side.
 * Takes the server's loginResponse and produces a finishLoginRequest + sessionKey.
 *
 * @param clientLoginState - State from startLogin
 * @param loginResponse - Response from server
 * @param password - The user's plaintext password
 * @returns finishLoginRequest (sent to server) and sessionKey (shared secret)
 */
export async function finishLogin(
    clientLoginState: string,
    loginResponse: string,
    password: string,
): Promise<{
    finishLoginRequest: string;
    sessionKey: string;
}> {
    await ensureReady();
    const result = opaque.client.finishLogin({
        clientLoginState,
        loginResponse,
        password,
        keyStretching: OPAQUE_KEY_STRETCHING,
    });
    if (!result) {
        throw new Error('OPAQUE login failed');
    }
    assertServerStaticPublicKey(result.serverStaticPublicKey);
    return {
        finishLoginRequest: result.finishLoginRequest,
        sessionKey: result.sessionKey,
    };
}

export async function verifyOpaqueSessionBinding(
    sessionKey: string,
    session: Session,
    binding: unknown,
): Promise<void> {
    const parsedBinding = parseOpaqueSessionBinding(binding);
    const userId = session.user?.id || parseJwtSubject(session.access_token);
    if (!userId || userId !== parsedBinding.userId) {
        throw new Error('OPAQUE session binding user mismatch');
    }

    const expectedProof = await createOpaqueSessionBindingProof({
        sessionKey,
        userId,
        accessToken: session.access_token,
    });
    if (!constantTimeStringEqual(expectedProof, parsedBinding.proof)) {
        throw new Error('OPAQUE session binding proof mismatch');
    }
}

async function createOpaqueSessionBindingProof(params: {
    sessionKey: string;
    userId: string;
    accessToken: string;
}): Promise<string> {
    const encoder = new TextEncoder();
    const key = await crypto.subtle.importKey(
        'raw',
        encoder.encode(params.sessionKey),
        { name: 'HMAC', hash: 'SHA-256' },
        false,
        ['sign'],
    );
    const signature = await crypto.subtle.sign(
        'HMAC',
        key,
        encoder.encode(`${OPAQUE_SESSION_BINDING_VERSION}\n${params.userId}\n${params.accessToken}`),
    );
    return Array.from(new Uint8Array(signature))
        .map((byte) => byte.toString(16).padStart(2, '0'))
        .join('');
}

function parseOpaqueSessionBinding(binding: unknown): { version: string; userId: string; proof: string } {
    if (!binding || typeof binding !== 'object') {
        throw new Error('OPAQUE session binding missing');
    }

    const record = binding as Record<string, unknown>;
    if (
        record.version !== OPAQUE_SESSION_BINDING_VERSION
        || typeof record.userId !== 'string'
        || typeof record.proof !== 'string'
        || !/^[0-9a-f]+$/i.test(record.proof)
    ) {
        throw new Error('OPAQUE session binding invalid');
    }

    return {
        version: record.version,
        userId: record.userId,
        proof: record.proof.toLowerCase(),
    };
}

function parseJwtSubject(accessToken: string): string | null {
    const [, payload] = accessToken.split('.');
    if (!payload) {
        return null;
    }

    try {
        const normalized = payload.replace(/-/g, '+').replace(/_/g, '/');
        const padded = `${normalized}${'='.repeat((4 - (normalized.length % 4)) % 4)}`;
        const parsed = JSON.parse(atob(padded)) as Record<string, unknown>;
        return typeof parsed.sub === 'string' ? parsed.sub : null;
    } catch {
        return null;
    }
}

function constantTimeStringEqual(left: string, right: string): boolean {
    if (left.length !== right.length) {
        return false;
    }

    let diff = 0;
    for (let index = 0; index < left.length; index += 1) {
        diff |= left.charCodeAt(index) ^ right.charCodeAt(index);
    }
    return diff === 0;
}
