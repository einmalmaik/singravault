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

// ============ State Management ============

/** Ensures the WASM module is loaded before any operation. */
async function ensureReady(): Promise<void> {
    await opaque.ready;
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
    });
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
    });
    return {
        finishLoginRequest: result.finishLoginRequest,
        sessionKey: result.sessionKey,
    };
}
