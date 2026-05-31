// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 — see LICENSE

/**
 * @fileoverview Auth Session Edge Function (BFF Pattern)
 *
 * Diese Edge Function implementiert das Backend-for-Frontend (BFF) Pattern
 * für sichere Session-Verwaltung. Der Refresh-Token wird in einem HttpOnly
 * Cookie gespeichert, nicht im Client-JavaScript-Speicher.
 *
 * ## Warum BFF statt Client-Storage?
 *
 * - **XSS-Schutz**: HttpOnly Cookies sind für JavaScript nicht lesbar
 * - **CSRF-Schutz**: SameSite=None + Partitioned Cookie-Attribute
 * - **Token-Rotation**: Server kontrolliert Refresh-Zyklus
 *
 * ## Unterstützte HTTP-Methoden
 *
 * ### GET - Session Hydration
 * Liest Refresh-Token aus Cookie und gibt neue Session zurück.
 * Wird beim App-Start aufgerufen, um existierende Sessions wiederherzustellen.
 *
 * ### POST mit `action: "oauth-sync"`
 * Synchronisiert OAuth-Session (Google, GitHub) mit BFF-Cookie.
 * Wird nach erfolgreichem OAuth-Callback aufgerufen.
 *
 * ### POST ohne action (Legacy)
 * Blockiert Legacy-Passwort-Login. Alle App-owned Logins müssen OPAQUE nutzen.
 *
 * ### DELETE
 * Löscht Session-Cookie (Logout).
 *
 * ## Aufruf aus dem Frontend
 *
 * Aufgerufen via `invokeAuthedFunction('auth-session', {...})` aus:
 * - `src/services/authSessionManager.ts` - `refreshCurrentSession()`
 * - `src/contexts/AuthContext.tsx` - Session-Hydration beim Start
 *
 * ## Cookie-Konfiguration
 *
 * ```
 * Name:     sb-bff-session
 * Path:     /
 * HttpOnly: true
 * Secure:   true
 * SameSite: None
 * MaxAge:   14 Tage (konfigurierbar)
 * Partitioned: true (Chrome CHIPS)
 * ```
 *
 * ## Sicherheitsmaßnahmen
 *
 * - Legacy-Passwort-Login komplett blockiert
 * - Rate-Limiting für Legacy-Versuche
 * - Session-Mismatch-Erkennung bei OAuth-Sync
 * - Minimum-Response-Zeit zur Timing-Attack-Prävention
 *
 * @see src/services/authSessionManager.ts - Frontend Session-Manager
 * @see src/integrations/supabase/authStorage.ts - Client-seitige Storage-Abstraction
 */

import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import { getCookies, setCookie } from "https://deno.land/std@0.168.0/http/cookie.ts";
import { createClient } from "npm:@supabase/supabase-js@2";
import { getCorsHeaders } from "../_shared/cors.ts";
import {
    authRateLimitResponse,
    checkAuthRateLimit,
    recordAuthRateLimitFailure,
    type AuthRateLimitFailureResult,
} from "../_shared/authRateLimit.ts";
import { normalizeOpaqueIdentifier } from "../_shared/opaqueAuth.ts";

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
 * Anonymer Schlüssel für Auth-Client.
 */
const supabaseAnonKey = Deno.env.get("SUPABASE_ANON_KEY")!;

/**
 * Admin-Client für Rate-Limiting-Prüfungen.
 */
const supabaseAdmin = createClient(supabaseUrl, supabaseServiceKey);

/**
 * Cookie-Name für BFF-Session.
 * Präfix "sb-" für Supabase-Kompatibilität.
 */
const SESSION_COOKIE_NAME = "sb-bff-session";

/**
 * Cookie-Lebensdauer in Sekunden.
 * Default: 14 Tage (1.209.600 Sekunden).
 */
const SESSION_COOKIE_MAX_AGE = Number(Deno.env.get("SESSION_COOKIE_MAX_AGE_SECONDS") ?? 60 * 60 * 24 * 14);

/**
 * Erstellt einen Supabase-Auth-Client für Session-Operationen.
 * persistSession und autoRefreshToken deaktiviert, da BFF diese kontrolliert.
 */
function createSupabaseAuthClient() {
    return createClient(supabaseUrl, supabaseAnonKey, {
        auth: {
            persistSession: false,
            autoRefreshToken: false,
        },
    });
}

// ============================================================================
// Request Handler
// ============================================================================

/**
 * Haupteinstiegspunkt der Edge Function.
 *
 * Routing:
 * - OPTIONS: CORS-Preflight
 * - DELETE: Session löschen (Logout)
 * - GET: Session aus Cookie hydratisieren
 * - POST mit oauth-sync: OAuth-Session synchronisieren
 * - POST sonst: Legacy-Passwort-Login (blockiert)
 */
Deno.serve(async (req) => {
    const corsHeaders = getCorsHeaders(req);
    const headers = new Headers({
        ...corsHeaders,
        "Access-Control-Allow-Credentials": "true",
    });
    const jsonHeaders = (): Headers => {
        const responseHeaders = new Headers(headers);
        responseHeaders.set("Content-Type", "application/json");
        return responseHeaders;
    };

    if (req.method === "OPTIONS") {
        return new Response("ok", { headers });
    }

    try {
        if (req.method === "DELETE") {
            clearSessionCookie(headers);
            return new Response(JSON.stringify({ success: true }), {
                status: 200,
                headers: jsonHeaders(),
            });
        }

        if (req.method === "GET") {
            return await handleSessionHydration(req, headers, jsonHeaders());
        }

        if (req.method !== "POST") {
            return new Response("Method not allowed", { status: 405, headers });
        }

        const payload = await req.json();
        if (payload?.action === "oauth-sync") {
            return await handleOAuthSync(req, payload, headers, jsonHeaders());
        }

        if (payload?.action === "oauth-reauth") {
            return await handleOAuthReauth(req, headers, jsonHeaders());
        }

        return await legacyPasswordLoginBlockedResponse(req, payload, jsonHeaders());
    } catch (err: unknown) {
        console.error("Auth Session Error:", err);
        return new Response(JSON.stringify({ error: "Internal Server Error" }), {
            status: 500,
            headers: jsonHeaders(),
        });
    }
});

async function handleSessionHydration(
    req: Request,
    headers: Headers,
    responseHeaders: Headers,
): Promise<Response> {
    const cookies = getCookies(req.headers);
    const refreshToken = cookies[SESSION_COOKIE_NAME];

    if (!refreshToken) {
        return new Response(JSON.stringify({ error: "No session cookie" }), {
            status: 401,
            headers: responseHeaders,
        });
    }

    const authClient = createSupabaseAuthClient();
    const { data, error } = await authClient.auth.refreshSession({ refresh_token: refreshToken });

    if (error || !data.session) {
        return new Response(JSON.stringify({ error: "Session expired" }), {
            status: 401,
            headers: responseHeaders,
        });
    }

    setSessionCookie(headers, data.session.refresh_token);

    return new Response(JSON.stringify({ session: data.session }), {
        status: 200,
        headers: responseHeaders,
    });
}

async function handleOAuthSync(
    req: Request,
    payload: Record<string, unknown>,
    headers: Headers,
    responseHeaders: Headers,
): Promise<Response> {
    const accessToken = parseBearerToken(req.headers.get("Authorization"));
    const refreshToken = typeof payload.refreshToken === "string" ? payload.refreshToken : null;
    const skipCookie = Boolean(payload.skipCookie);

    if (!accessToken || !refreshToken) {
        return new Response(JSON.stringify({ error: "Invalid oauth sync payload" }), {
            status: 400,
            headers: responseHeaders,
        });
    }

    const authClient = createClient(supabaseUrl, supabaseAnonKey, {
        auth: {
            persistSession: false,
            autoRefreshToken: false,
        },
        global: { headers: { Authorization: `Bearer ${accessToken}` } },
    });

    const { data: authedUserData, error: authedUserError } = await authClient.auth.getUser();
    if (authedUserError || !authedUserData.user) {
        return new Response(JSON.stringify({ error: "Unauthorized" }), {
            status: 401,
            headers: responseHeaders,
        });
    }

    const refreshClient = createSupabaseAuthClient();
    const { data: refreshedData, error: refreshError } = await refreshClient.auth.refreshSession({
        refresh_token: refreshToken,
    });

    if (refreshError || !refreshedData.session) {
        return new Response(JSON.stringify({ error: "Session expired" }), {
            status: 401,
            headers: responseHeaders,
        });
    }

    if (refreshedData.session.user.id !== authedUserData.user.id) {
        return new Response(JSON.stringify({ error: "Session mismatch" }), {
            status: 403,
            headers: responseHeaders,
        });
    }

    if (!skipCookie) {
        setSessionCookie(headers, refreshedData.session.refresh_token);
    }

    const userId = refreshedData.session.user.id;
    const provider = String(refreshedData.session.user.app_metadata?.provider ?? "oauth");

    // Record the interactive login so handleOAuthReauth can verify freshness
    // without relying on JWT amr claims (which get wiped by silent token refresh).
    await recordSocialLoginEvent(userId, provider);

    const reauthProofId = await issueReauthProof(userId);

    return new Response(JSON.stringify({ success: true, session: refreshedData.session, reauthProofId }), {
        status: 200,
        headers: responseHeaders,
    });
}

async function legacyPasswordLoginBlockedResponse(
    req: Request,
    payload: Record<string, unknown>,
    headers: Headers,
): Promise<Response> {
    const normalizedEmail = normalizeOpaqueIdentifier(payload?.email);
    const passwordRateLimit = await checkAuthRateLimit({
        supabaseAdmin,
        req,
        action: "password_login",
        account: { kind: "email", value: normalizedEmail || "unknown" },
    });
    if (!passwordRateLimit.allowed) {
        return authRateLimitResponse(passwordRateLimit, headers);
    }

    const startTime = Date.now();
    const failure = await recordAuthRateLimitFailure(passwordRateLimit);
    await delayUntilMinimum(startTime, 300);
    if (failure.lockedUntil) {
        return authRateLimitResponse(toLockedState(failure), headers);
    }

    return new Response(JSON.stringify({
        error: "Legacy password login is disabled. App-owned password login must use OPAQUE.",
        code: "LEGACY_PASSWORD_LOGIN_DISABLED",
    }), {
        status: 410,
        headers,
    });
}

function setSessionCookie(headers: Headers, refreshToken: string): void {
    setCookie(headers, {
        name: SESSION_COOKIE_NAME,
        value: refreshToken,
        path: "/",
        httpOnly: true,
        secure: true,
        sameSite: "None",
        maxAge: SESSION_COOKIE_MAX_AGE,
    });
    appendPartitionedCookieAttribute(headers);
}

function clearSessionCookie(headers: Headers): void {
    setCookie(headers, {
        name: SESSION_COOKIE_NAME,
        value: "",
        path: "/",
        httpOnly: true,
        secure: true,
        sameSite: "None",
        maxAge: 0,
    });
    appendPartitionedCookieAttribute(headers);
}

function appendPartitionedCookieAttribute(headers: Headers): void {
    const currentCookie = headers.get("set-cookie");
    if (!currentCookie || /;\s*Partitioned/i.test(currentCookie)) {
        return;
    }

    headers.set("set-cookie", `${currentCookie}; Partitioned`);
}

function parseBearerToken(authHeader: string | null): string | null {
    if (!authHeader) {
        return null;
    }

    if (authHeader.startsWith("Bearer ")) {
        const token = authHeader.slice("Bearer ".length).trim();
        return token || null;
    }

    const token = authHeader.trim();
    return token || null;
}

async function delayUntilMinimum(startTime: number, minimumMs: number): Promise<void> {
    const remaining = minimumMs - (Date.now() - startTime);
    if (remaining > 0) {
        await new Promise((resolve) => setTimeout(resolve, remaining));
    }
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

async function handleOAuthReauth(
    req: Request,
    headers: Headers,
    responseHeaders: Headers,
): Promise<Response> {
    const accessToken = parseBearerToken(req.headers.get("Authorization"));
    if (!accessToken) {
        return new Response(JSON.stringify({ error: "AUTH_REQUIRED" }), {
            status: 401,
            headers: responseHeaders,
        });
    }

    const { data: userData, error: userError } = await supabaseAdmin.auth.getUser(accessToken);
    const userId = userData.user?.id;
    if (userError || !userId) {
        return new Response(JSON.stringify({ error: "AUTH_REQUIRED" }), {
            status: 401,
            headers: responseHeaders,
        });
    }

    // Verify they are an OAuth user (no OPAQUE password record).
    const { data: opaqueRecord, error: dbError } = await supabaseAdmin
        .from("user_opaque_records")
        .select("user_id")
        .eq("user_id", userId)
        .maybeSingle();

    if (dbError) {
        console.error("Database query failed during OAuth reauth check:", dbError);
        return new Response(JSON.stringify({ error: "Internal error" }), {
            status: 500,
            headers: responseHeaders,
        });
    }

    if (opaqueRecord) {
        // Password/OPAQUE users are not allowed to use this path.
        return new Response(JSON.stringify({ error: "FORBIDDEN" }), {
            status: 403,
            headers: responseHeaders,
        });
    }

    // Verify that the user has a recent interactive social login recorded in
    // social_login_events. This is safer than checking JWT amr claims because:
    //   1. The edgeFunctionService auto-refreshes tokens before every call,
    //      overwriting amr with [{method:"refresh"}] even for fresh logins.
    //   2. social_login_events is written server-side (service-role only) during
    //      the oauth-sync flow — the client cannot forge this.
    //   3. The 15-minute window (900s) allows for normal UI interaction time
    //      while still requiring a recent interactive authentication.
    const { data: isFreshData, error: freshCheckError } = await supabaseAdmin.rpc(
        "check_recent_social_login",
        { p_user_id: userId, p_max_age_secs: 900 },
    );
    if (freshCheckError) {
        console.error("social login freshness check failed:", freshCheckError.message);
        return new Response(JSON.stringify({ error: "Internal error" }), {
            status: 500,
            headers: responseHeaders,
        });
    }
    if (!isFreshData) {
        return new Response(JSON.stringify({ error: "REAUTH_REQUIRED" }), {
            status: 401,
            headers: responseHeaders,
        });
    }

    const reauthProofId = await issueReauthProof(userId);
    if (!reauthProofId) {
        return new Response(JSON.stringify({ error: "Internal error" }), {
            status: 500,
            headers: responseHeaders,
        });
    }

    return new Response(JSON.stringify({ success: true, reauthProofId }), {
        status: 200,
        headers: responseHeaders,
    });
}

async function recordSocialLoginEvent(userId: string, provider: string): Promise<void> {
    const { error } = await supabaseAdmin
        .from("social_login_events")
        .insert({ user_id: userId, provider });
    if (error) {
        // Non-fatal: log and continue. The reauth check will fail later if the
        // record is missing, which is the safe (fail-closed) outcome.
        console.error("Failed to record social login event:", error.code ?? error.message);
    }
}

async function issueReauthProof(userId: string): Promise<string | null> {
    const expiresAt = new Date(Date.now() + 5 * 60 * 1000).toISOString();
    const { data, error } = await supabaseAdmin
        .from("reauth_proofs")
        .insert({ user_id: userId, expires_at: expiresAt })
        .select("id")
        .single();

    if (error || !data?.id) {
        console.error("Failed to issue reauth proof:", error?.code ?? "no data");
        return null;
    }

    return data.id as string;
}
