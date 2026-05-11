// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 — see LICENSE

/**
 * @fileoverview OPAQUE Password Reset Edge Function
 *
 * Diese Edge Function implementiert das Zurücksetzen des OPAQUE-Passworts.
 * Im Gegensatz zu klassischem Passwort-Reset wird hier das OPAQUE-Registration-Record
 * ersetzt, nicht ein Passwort-Hash.
 *
 * ## Wichtiger Unterschied zu Master-Passwort
 *
 * Diese Funktion setzt das KONTO-Passwort zurück (OPAQUE), nicht das Vault-Master-Passwort.
 * Das Master-Passwort ist clientseitig und kann vom Server nicht zurückgesetzt werden.
 *
 * ## Zwei-Phasen-Reset
 *
 * ### Phase 1: `opaque-reset-start`
 * - Validiert Reset-Token aus auth-recovery
 * - Prüft 2FA-Autorisierung (falls aktiviert)
 * - Generiert neue OPAQUE Registration Response
 * - Erstellt Reset-State mit 15 Min. TTL
 *
 * ### Phase 2: `opaque-reset-finish`
 * - Konsumiert Reset-Token (markiert als verwendet)
 * - Speichert neues OPAQUE Registration Record
 * - Sendet Benachrichtigungs-E-Mail
 *
 * ## Aufruf aus dem Frontend
 *
 * Aufgerufen via `invokeAuthedFunction('auth-reset-password', {...})` aus:
 * - `src/services/accountPasswordResetService.ts`
 * - Passwort-Reset-Flow in `src/pages/Auth.tsx`
 *
 * ## Sicherheitsmaßnahmen
 *
 * - Reset-Token: Kryptografisch sicher, nur Hash in DB
 * - 2FA-Prüfung: Falls aktiviert, muss vor Reset verifiziert werden
 * - Rate-Limiting: opaque_reset Action
 * - Minimum-Response-Zeit: 300ms zur Timing-Attack-Prävention
 *
 * ## Datenbankstruktur
 *
 * Tabellen:
 * - `password_reset_challenges`: Challenge mit Token-Hash, 2FA-Status
 * - `opaque_password_reset_states`: Temporärer State für zwei-Phasen-Reset
 * - `user_opaque_records`: Finales Registration Record
 *
 * @see src/services/accountPasswordResetService.ts - Frontend-Service
 * @see auth-recovery/index.ts - E-Mail-Verifizierung vor Reset
 */

import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import * as opaque from "npm:@serenity-kit/opaque";
import { createClient } from "npm:@supabase/supabase-js@2";
import { getCorsHeaders } from "../_shared/cors.ts";
import {
    authRateLimitResponse,
    checkAuthRateLimit,
    recordAuthRateLimitFailure,
    resetAuthRateLimit,
    type AuthRateLimitFailureResult,
    type AuthRateLimitState,
} from "../_shared/authRateLimit.ts";
import {
    normalizeOpaqueIdentifier,
    sha256Hex,
} from "../_shared/opaqueAuth.ts";
import { AUTH_ERROR_CODES, jsonError } from "../_shared/authErrors.ts";

// ============================================================================
// Konfiguration
// ============================================================================

/**
 * Supabase-URL aus Umgebungsvariablen.
 */
const supabaseUrl = Deno.env.get("SUPABASE_URL")!;

/**
 * Service Role Key für Admin-Operationen.
 */
const supabaseServiceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;

/**
 * Resend API Key für E-Mail-Benachrichtigungen.
 * Optional - falls nicht gesetzt, werden keine Benachrichtigungen gesendet.
 */
const resendApiKey = Deno.env.get("RESEND_API_KEY") ?? "";

/**
 * OPAQUE Server Setup - muss mit Registrierung übereinstimmen.
 */
const OPAQUE_SERVER_SETUP = Deno.env.get("OPAQUE_SERVER_SETUP")!;

/**
 * Admin-Client für Datenbankoperationen.
 */
const supabaseAdmin = createClient(supabaseUrl, supabaseServiceKey);

/**
 * OPAQUE-Bibliothek initialisieren.
 */
await opaque.ready;

// ============================================================================
// Request Handler
// ============================================================================

/**
 * Haupteinstiegspunkt der Edge Function.
 *
 * Routet basierend auf `action`-Feld:
 * - `opaque-reset-start`: Startet OPAQUE-Reset
 * - `opaque-reset-finish`: Schließt OPAQUE-Reset ab
 */
Deno.serve(async (req) => {
    const corsHeaders = getCorsHeaders(req);
    const headers = new Headers({
        ...corsHeaders,
        "Content-Type": "application/json",
    });

    if (req.method === "OPTIONS") {
        return new Response("ok", { headers });
    }

    if (req.method !== "POST") {
        return new Response(JSON.stringify({ error: "Method not allowed" }), { status: 405, headers });
    }

    try {
        const body = await req.json();
        const action = typeof body.action === "string" ? body.action : "";

        if (action === "opaque-reset-start") {
            return await handleOpaqueResetStart(req, body, headers);
        }

        if (action === "opaque-reset-finish") {
            return await handleOpaqueResetFinish(req, body, headers);
        }

        return new Response(JSON.stringify({ error: "OPAQUE password reset required" }), { status: 400, headers });
    } catch (err) {
        console.error("Auth Reset Error:", err);
        return new Response(JSON.stringify({ error: "Internal Server Error" }), { status: 500, headers });
    }
});

// ============================================================================
// Handler-Funktionen
// ============================================================================

/**
 * Startet den OPAQUE-Password-Reset (Phase 1).
 *
 * Workflow:
 * 1. Validiert Reset-Token und Registration-Request
 * 2. Findet aktive Reset-Challenge in DB
 * 3. Prüft Rate-Limits
 * 4. Verifiziert 2FA-Autorisierung (falls erforderlich)
 * 5. Generiert neue OPAQUE Registration Response
 * 6. Erstellt Reset-State (15 Min. gültig)
 *
 * @param req - Original-Request (für Rate-Limiting)
 * @param body - Request-Body mit `resetToken`, `registrationRequest`
 * @param headers - Response-Headers
 * @returns JSON mit `resetRegistrationId`, `registrationResponse`, `expiresAt`
 */
async function handleOpaqueResetStart(
    req: Request,
    body: { resetToken?: unknown; registrationRequest?: unknown },
    headers: Headers,
): Promise<Response> {
    const resetToken = typeof body.resetToken === "string" ? body.resetToken.trim() : "";
    const registrationRequest = typeof body.registrationRequest === "string" ? body.registrationRequest : "";
    if (!resetToken || !registrationRequest) {
        return new Response(JSON.stringify({ error: "Invalid data" }), { status: 400, headers });
    }

    const challenge = await findActiveResetChallenge(resetToken);
    if (!challenge) {
        await delay(300);
        return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401, headers });
    }

    const resetRateLimit = await checkOpaqueResetRateLimit(req, challenge.user_id);
    if (!resetRateLimit.allowed) {
        return authRateLimitResponse(resetRateLimit, headers);
    }

    if (!isResetChallengeAuthorized(challenge)) {
        return await invalidOpaqueResetAttemptResponse(
            resetRateLimit,
            Date.now(),
            headers,
            "Two-factor verification required",
            403,
            "TWO_FACTOR_REQUIRED",
        );
    }

    const email = normalizeOpaqueIdentifier(challenge.email);
    const registrationResponse = opaque.server.createRegistrationResponse({
        serverSetup: OPAQUE_SERVER_SETUP,
        userIdentifier: email,
        registrationRequest,
    }).registrationResponse;

    const resetRegistrationId = crypto.randomUUID();
    const expiresAt = new Date(Date.now() + 15 * 60 * 1000).toISOString();
    const { error: stateError } = await supabaseAdmin
        .from("opaque_password_reset_states")
        .insert({
            id: resetRegistrationId,
            user_id: challenge.user_id,
            email,
            expires_at: expiresAt,
        });

    if (stateError) {
        throw new Error(`Failed to create OPAQUE reset state: ${stateError.message}`);
    }

    return new Response(JSON.stringify({
        success: true,
        resetRegistrationId,
        registrationResponse,
        expiresAt,
    }), { status: 200, headers });
}

/**
 * Schließt den OPAQUE-Password-Reset ab (Phase 2).
 *
 * Workflow:
 * 1. Validiert alle Eingaben
 * 2. Findet aktive Reset-Challenge
 * 3. Prüft Rate-Limits und 2FA-Autorisierung
 * 4. Ruft `finish_opaque_password_reset` RPC auf (atomar)
 * 5. Setzt Rate-Limit zurück
 * 6. Sendet Benachrichtigungs-E-Mail
 *
 * Der RPC führt atomar aus:
 * - Challenge als verwendet markieren
 * - Reset-State konsumieren
 * - Neues Registration Record speichern
 *
 * @param req - Original-Request (für Rate-Limiting)
 * @param body - Request-Body mit `resetToken`, `resetRegistrationId`, `registrationRecord`
 * @param headers - Response-Headers
 * @returns JSON mit `success: true` bei Erfolg
 */
async function handleOpaqueResetFinish(
    req: Request,
    body: { resetToken?: unknown; resetRegistrationId?: unknown; registrationRecord?: unknown },
    headers: Headers,
): Promise<Response> {
    const resetToken = typeof body.resetToken === "string" ? body.resetToken.trim() : "";
    const resetRegistrationId = typeof body.resetRegistrationId === "string" ? body.resetRegistrationId : "";
    const registrationRecord = typeof body.registrationRecord === "string" ? body.registrationRecord : "";
    if (!resetToken || !resetRegistrationId || !registrationRecord) {
        return new Response(JSON.stringify({ error: "Invalid data" }), { status: 400, headers });
    }

    const challenge = await findActiveResetChallenge(resetToken);
    if (!challenge) {
        await delay(300);
        return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401, headers });
    }

    const resetRateLimit = await checkOpaqueResetRateLimit(req, challenge.user_id);
    if (!resetRateLimit.allowed) {
        return authRateLimitResponse(resetRateLimit, headers);
    }

    if (!isResetChallengeAuthorized(challenge)) {
        return await invalidOpaqueResetAttemptResponse(
            resetRateLimit,
            Date.now(),
            headers,
            "Two-factor verification required",
            403,
            "TWO_FACTOR_REQUIRED",
        );
    }

    const { data: finishResult, error: finishError } = await supabaseAdmin.rpc("finish_opaque_password_reset", {
        p_challenge_id: challenge.id,
        p_reset_state_id: resetRegistrationId,
        p_registration_record: registrationRecord,
    });
    const finishedReset = Array.isArray(finishResult) ? finishResult[0] : finishResult;
    if (finishError || !finishedReset) {
        console.error("Failed to finish OPAQUE password reset atomically:", sanitizeAuthError(finishError));
        if (finishError?.message?.includes("OPAQUE_RECORD_CONFLICT")) {
            return jsonError(
                AUTH_ERROR_CODES.OPAQUE_RECORD_CONFLICT,
                "Registration failed",
                409,
                headers,
            );
        }
        return await invalidOpaqueResetAttemptResponse(
            resetRateLimit,
            Date.now(),
            headers,
            "Invalid or expired code",
            401,
            AUTH_ERROR_CODES.AUTH_INVALID_OR_EXPIRED_CODE,
        );
    }

    const email = normalizeOpaqueIdentifier(finishedReset.email);
    await resetAuthRateLimit(resetRateLimit);

    await sendPasswordResetNotification(email);

    return new Response(JSON.stringify({ success: true }), { status: 200, headers });
}

function sanitizeAuthError(error: unknown): Record<string, unknown> {
    const candidate = error as { code?: unknown; message?: unknown; name?: unknown } | null;
    return {
        code: typeof candidate?.code === "string" ? candidate.code : undefined,
        name: typeof candidate?.name === "string" ? candidate.name : undefined,
        message: redactSensitiveLogText(typeof candidate?.message === "string" ? candidate.message : String(error)),
    };
}

function redactSensitiveLogText(value: string): string {
    return value.replace(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi, "[redacted-email]");
}

async function findActiveResetChallenge(resetToken: string): Promise<{
    id: string;
    user_id: string;
    email: string;
    two_factor_required: boolean;
    two_factor_verified_at: string | null;
    authorized_at: string | null;
} | null> {
    const resetTokenHash = await sha256Hex(resetToken);
    const { data: challenges, error } = await supabaseAdmin
        .from("password_reset_challenges")
        .select("id, user_id, email, two_factor_required, two_factor_verified_at, authorized_at")
        .eq("token_hash", resetTokenHash)
        .is("used_at", null)
        .gt("expires_at", new Date().toISOString())
        .limit(1);

    if (error || !challenges || challenges.length === 0) {
        return null;
    }

    return challenges[0] as {
        id: string;
        user_id: string;
        email: string;
        two_factor_required: boolean;
        two_factor_verified_at: string | null;
        authorized_at: string | null;
    };
}

function isResetChallengeAuthorized(challenge: {
    two_factor_required: boolean;
    two_factor_verified_at: string | null;
    authorized_at: string | null;
}): boolean {
    if (!challenge.authorized_at) {
        return false;
    }

    return !challenge.two_factor_required || Boolean(challenge.two_factor_verified_at);
}

async function checkOpaqueResetRateLimit(req: Request, userId: string): Promise<AuthRateLimitState> {
    return await checkAuthRateLimit({
        supabaseAdmin,
        req,
        action: "opaque_reset",
        account: { kind: "user", value: userId },
    });
}

async function invalidOpaqueResetAttemptResponse(
    rateLimitState: AuthRateLimitState,
    startTime: number,
    headers: Headers,
    message: string,
    status = 401,
    code?: string,
): Promise<Response> {
    const failure = await recordAuthRateLimitFailure(rateLimitState);
    await delayUntilMinimum(startTime, 300);
    if (failure.lockedUntil) {
        return authRateLimitResponse(toLockedState(failure), headers);
    }

    return new Response(JSON.stringify({ error: message, ...(code ? { code } : {}) }), {
        status,
        headers,
    });
}

function toLockedState(failure: AuthRateLimitFailureResult) {
    return {
        status: 429 as const,
        error: "Too many attempts",
        attemptsRemaining: failure.attemptsRemaining,
        lockedUntil: failure.lockedUntil,
        retryAfterSeconds: failure.retryAfterSeconds,
    };
}

async function sendPasswordResetNotification(email: string | null): Promise<void> {
    if (!resendApiKey || !email) {
        return;
    }

    try {
        const response = await fetch("https://api.resend.com/emails", {
            method: "POST",
            headers: {
                "Authorization": `Bearer ${resendApiKey}`,
                "Content-Type": "application/json",
            },
            body: JSON.stringify({
                from: "Singra Vault <noreply@mauntingstudios.de>",
                to: [email],
                subject: "Dein Singra Vault Passwort wurde geändert",
                html: `
<p>Dein Singra Vault Kontopasswort wurde soeben geändert.</p>
<p>Wenn du diese Änderung nicht vorgenommen hast, kontaktiere bitte sofort den Support.</p>`,
            }),
        });

        if (!response.ok) {
            console.error("Failed to send password reset notification:", await response.text());
        }
    } catch (error) {
        console.error("Password reset notification failed:", error);
    }
}

async function delay(ms: number): Promise<void> {
    await new Promise((resolve) => setTimeout(resolve, ms));
}

async function delayUntilMinimum(startTime: number, minimumMs: number): Promise<void> {
    const remaining = minimumMs - (Date.now() - startTime);
    if (remaining > 0) {
        await delay(remaining);
    }
}
