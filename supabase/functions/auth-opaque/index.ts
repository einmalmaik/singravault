/**
 * @fileoverview OPAQUE Protocol Edge Function
 *
 * Implements the server-side of the OPAQUE PAKE protocol.
 * The user's password NEVER reaches this server — not even as a hash.
 *
 * Endpoints (via `action` field in POST body):
 *   - register-start:  Server processes registration request (requires valid session)
 *   - register-finish: Server stores the registration record (requires valid session)
 *   - login-start:     Server processes login request
 *   - login-finish:    Server verifies auth proof and issues session
 *
 * SECURITY:
 *   - serverLoginState is stored server-side in the DB (not sent to client)
 *   - Registration requires an authenticated session (migration only)
 *   - 2FA integration delegates to auth-session with opaqueVerified flag
 *
 * Required Secrets:
 *   - OPAQUE_SERVER_SETUP: Long-term server setup string
 */

import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import * as opaque from "npm:@serenity-kit/opaque";
import { createClient } from "npm:@supabase/supabase-js@2";
import { argon2Verify } from "npm:hash-wasm";
import { setCookie } from "https://deno.land/std@0.168.0/http/cookie.ts";
import { getCorsHeaders } from "../_shared/cors.ts";
import {
    authRateLimitResponse,
    checkAuthRateLimit,
    recordAuthRateLimitFailure,
    resetAuthRateLimit,
    type AuthRateLimitFailureResult,
    type AuthRateLimitState,
} from "../_shared/authRateLimit.ts";

const supabaseUrl = Deno.env.get("SUPABASE_URL")!;
const supabaseServiceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
const supabaseAnonKey = Deno.env.get("SUPABASE_ANON_KEY")!;
const supabaseAdmin = createClient(supabaseUrl, supabaseServiceKey);

const OPAQUE_SERVER_SETUP = Deno.env.get("OPAQUE_SERVER_SETUP")!;
const SESSION_COOKIE_NAME = "sb-bff-session";
const SESSION_COOKIE_MAX_AGE = Number(Deno.env.get("SESSION_COOKIE_MAX_AGE_SECONDS") ?? 60 * 60 * 24 * 400);

await opaque.ready;

function createSupabaseAuthClient() {
    return createClient(supabaseUrl, supabaseAnonKey, {
        auth: {
            persistSession: false,
            autoRefreshToken: false,
        },
    });
}

Deno.serve(async (req) => {
    const corsHeaders = getCorsHeaders(req);
    const headers = new Headers({
        ...corsHeaders,
        "Content-Type": "application/json",
        "Access-Control-Allow-Credentials": "true",
    });

    if (req.method === "OPTIONS") {
        return new Response("ok", { headers });
    }

    if (req.method !== "POST") {
        return new Response(JSON.stringify({ error: "Method not allowed" }), { status: 405, headers });
    }

    try {
        const body = await req.json();
        const { action } = body;

        switch (action) {
            case "register-start":
                return await handleRegisterStart(body, headers, req);
            case "register-finish":
                return await handleRegisterFinish(body, headers, req);
            case "login-start":
                return await handleLoginStart(body, headers, req);
            case "login-finish":
                return await handleLoginFinish(body, headers, req);
            default:
                return new Response(JSON.stringify({ error: "Unknown action" }), { status: 400, headers });
        }
    } catch (err) {
        console.error("auth-opaque error:", err);
        return new Response(JSON.stringify({ error: "Internal Server Error" }), { status: 500, headers });
    }
});

// ============ Auth Helper ============

/**
 * Extracts and validates the JWT from the Authorization header.
 * Returns the authenticated user ID or null.
 */
async function getAuthenticatedUserId(req: Request): Promise<string | null> {
    const authHeader = req.headers.get("Authorization");
    if (!authHeader?.startsWith("Bearer ")) return null;

    const token = authHeader.replace("Bearer ", "");
    const { data, error } = await supabaseAdmin.auth.getUser(token);
    if (error || !data.user) return null;

    return data.user.id;
}

// ============ Registration ============

async function handleRegisterStart(
    body: { userIdentifier: string; registrationRequest: string },
    headers: Headers,
    req: Request,
): Promise<Response> {
    // Registration requires an active session (migration from legacy)
    const authenticatedUserId = await getAuthenticatedUserId(req);
    if (!authenticatedUserId) {
        return new Response(JSON.stringify({ error: "Authentication required" }), { status: 401, headers });
    }

    const { userIdentifier, registrationRequest } = body;
    if (!userIdentifier || !registrationRequest) {
        return new Response(JSON.stringify({ error: "Missing fields" }), { status: 400, headers });
    }

    // Verify the authenticated user matches the requested email
    const { data: users } = await supabaseAdmin.rpc("get_user_id_by_email", { p_email: userIdentifier });
    if (!users || users.length === 0 || users[0].id !== authenticatedUserId) {
        return new Response(JSON.stringify({ error: "Forbidden" }), { status: 403, headers });
    }

    const { registrationResponse } = opaque.server.createRegistrationResponse({
        serverSetup: OPAQUE_SERVER_SETUP,
        userIdentifier,
        registrationRequest,
    });

    return new Response(JSON.stringify({ registrationResponse }), { status: 200, headers });
}

async function handleRegisterFinish(
    body: { userIdentifier: string; registrationRecord: string },
    headers: Headers,
    req: Request,
): Promise<Response> {
    // Registration requires an active session
    const authenticatedUserId = await getAuthenticatedUserId(req);
    if (!authenticatedUserId) {
        return new Response(JSON.stringify({ error: "Authentication required" }), { status: 401, headers });
    }

    const { userIdentifier, registrationRecord } = body;
    if (!userIdentifier || !registrationRecord) {
        return new Response(JSON.stringify({ error: "Missing fields" }), { status: 400, headers });
    }

    // Verify the authenticated user matches the requested email
    const { data: users, error: userError } = await supabaseAdmin.rpc("get_user_id_by_email", { p_email: userIdentifier });
    if (userError || !users || users.length === 0 || users[0].id !== authenticatedUserId) {
        return new Response(JSON.stringify({ error: "Forbidden" }), { status: 403, headers });
    }

    const userId = users[0].id;

    // Store registration record (upsert — handles re-registration)
    const { error: upsertError } = await supabaseAdmin
        .from("user_opaque_records")
        .upsert({
            user_id: userId,
            registration_record: registrationRecord,
            updated_at: new Date().toISOString(),
        }, { onConflict: "user_id" });

    if (upsertError) {
        console.error("Failed to store OPAQUE record:", upsertError);
        return new Response(JSON.stringify({ error: "Failed to store record" }), { status: 500, headers });
    }

    // Update auth_protocol in profiles
    await supabaseAdmin
        .from("profiles")
        .update({ auth_protocol: "opaque" })
        .eq("user_id", userId);

    return new Response(JSON.stringify({ success: true }), { status: 200, headers });
}

// ============ Login ============

async function handleLoginStart(
    body: { userIdentifier: string; startLoginRequest: string },
    headers: Headers,
    req: Request,
): Promise<Response> {
    const { userIdentifier, startLoginRequest } = body;

    if (!userIdentifier || !startLoginRequest) {
        return new Response(JSON.stringify({ error: "Missing fields" }), { status: 400, headers });
    }

    const normalizedIdentifier = String(userIdentifier).toLowerCase().trim();
    const opaqueRateLimit = await checkAuthRateLimit({
        supabaseAdmin,
        req,
        action: "opaque_login",
        account: { kind: "email", value: normalizedIdentifier },
    });
    if (!opaqueRateLimit.allowed) {
        return authRateLimitResponse(opaqueRateLimit, headers);
    }
    const startTime = Date.now();

    // Look up user
    const { data: users, error: userError } = await supabaseAdmin.rpc("get_user_id_by_email", { p_email: normalizedIdentifier });
    if (userError || !users || users.length === 0) {
        return await opaqueUnavailableResponse(opaqueRateLimit, startTime, headers);
    }

    const userId = users[0].id;

    // Fetch OPAQUE registration record
    const { data: opaqueData, error: opaqueError } = await supabaseAdmin
        .from("user_opaque_records")
        .select("registration_record")
        .eq("user_id", userId)
        .single();

    if (opaqueError || !opaqueData) {
        // User doesn't have OPAQUE record — they should use legacy auth
        return await opaqueUnavailableResponse(opaqueRateLimit, startTime, headers);
    }

    const { serverLoginState, loginResponse } = opaque.server.startLogin({
        serverSetup: OPAQUE_SERVER_SETUP,
        userIdentifier: normalizedIdentifier,
        registrationRecord: opaqueData.registration_record,
        startLoginRequest,
    });

    // Store serverLoginState server-side (NEVER send to client)
    // Use a short-lived entry keyed by a random loginId
    const loginId = crypto.randomUUID();
    const expiresAt = new Date(Date.now() + 5 * 60 * 1000).toISOString(); // 5 min TTL

    const { error: storeError } = await supabaseAdmin
        .from("opaque_login_states")
        .insert({
            id: loginId,
            user_id: userId,
            server_login_state: serverLoginState,
            expires_at: expiresAt,
        });

    if (storeError) {
        console.error("Failed to store login state:", storeError);
        return new Response(JSON.stringify({ error: "Internal error" }), { status: 500, headers });
    }

    // Return loginResponse + loginId (opaque reference, NOT the state itself)
    return new Response(JSON.stringify({
        loginResponse,
        loginId,
    }), { status: 200, headers });
}

async function handleLoginFinish(
    body: {
        userIdentifier: string;
        finishLoginRequest: string;
        loginId: string;
        totpCode?: string;
        isBackupCode?: boolean;
        skipCookie?: boolean;
    },
    headers: Headers,
    req: Request,
): Promise<Response> {
    const { userIdentifier, finishLoginRequest, loginId, totpCode, isBackupCode, skipCookie } = body;

    if (!userIdentifier || !finishLoginRequest || !loginId) {
        return new Response(JSON.stringify({ error: "Missing fields" }), { status: 400, headers });
    }

    const normalizedIdentifier = String(userIdentifier).toLowerCase().trim();
    const opaqueRateLimit = await checkAuthRateLimit({
        supabaseAdmin,
        req,
        action: "opaque_login",
        account: { kind: "email", value: normalizedIdentifier },
    });
    if (!opaqueRateLimit.allowed) {
        return authRateLimitResponse(opaqueRateLimit, headers);
    }
    const startTime = Date.now();

    // Retrieve server login state from DB
    const { data: loginState, error: stateError } = await supabaseAdmin
        .from("opaque_login_states")
        .select("server_login_state, user_id, expires_at")
        .eq("id", loginId)
        .single();

    // Always delete the state after retrieval (one-time use)
    await supabaseAdmin.from("opaque_login_states").delete().eq("id", loginId);

    if (stateError || !loginState) {
        return await invalidOpaqueAttemptResponse(opaqueRateLimit, startTime, headers, "Invalid or expired login session");
    }

    // Check expiry
    if (new Date(loginState.expires_at) < new Date()) {
        return await invalidOpaqueAttemptResponse(opaqueRateLimit, startTime, headers, "Login session expired");
    }

    // Verify the login
    const { sessionKey } = opaque.server.finishLogin({
        finishLoginRequest,
        serverLoginState: loginState.server_login_state,
    });

    if (!sessionKey) {
        return await invalidOpaqueAttemptResponse(opaqueRateLimit, startTime, headers, "Invalid credentials");
    }

    // OPAQUE verification succeeded! Password was proven without ever being sent.
    const userId = loginState.user_id;

    // Verify userIdentifier matches
    const { data: users } = await supabaseAdmin.rpc("get_user_id_by_email", { p_email: normalizedIdentifier });
    if (!users || users.length === 0 || users[0].id !== userId) {
        return await invalidOpaqueAttemptResponse(opaqueRateLimit, startTime, headers, "Invalid credentials");
    }

    await resetAuthRateLimit(opaqueRateLimit);

    // Check email confirmation
    const { data: adminUser, error: adminUserError } = await supabaseAdmin.auth.admin.getUserById(userId);
    if (adminUserError || !adminUser.user.email_confirmed_at) {
        return new Response(JSON.stringify({ error: "Email verification required" }), { status: 403, headers });
    }

    // Check 2FA
    const { data: user2fa } = await supabaseAdmin
        .from("user_2fa")
        .select("is_enabled")
        .eq("user_id", userId)
        .single();

    if (user2fa?.is_enabled) {
        // Return a challenge until the client submits a TOTP or backup code.
        if (!totpCode && !isBackupCode) {
            return new Response(JSON.stringify({
                requires2FA: true,
                opaqueVerified: true,
            }), { status: 200, headers });
        }

        if (!totpCode) {
            return new Response(JSON.stringify({ error: "Invalid request payload" }), { status: 400, headers });
        }

        const secondFactorRateLimit = await checkAuthRateLimit({
            supabaseAdmin,
            req,
            action: isBackupCode ? "backup_code_verify" : "totp_verify",
            account: { kind: "user", value: userId },
        });
        if (!secondFactorRateLimit.allowed) {
            return authRateLimitResponse(secondFactorRateLimit, headers);
        }

        const secondFactorStartTime = Date.now();
        const secondFactorValid = isBackupCode
            ? await verifyAndConsumeBackupCode(userId, totpCode)
            : await verifyTotpCode(userId, totpCode);

        if (!secondFactorValid) {
            return await invalidOpaqueAttemptResponse(
                secondFactorRateLimit,
                secondFactorStartTime,
                headers,
                isBackupCode ? "Invalid backup code" : "Invalid 2FA code",
            );
        }

        await resetAuthRateLimit(secondFactorRateLimit);
        await supabaseAdmin.from("user_2fa").update({ last_verified_at: new Date().toISOString() }).eq("user_id", userId);
    }

    // Generate session
    const session = await issueSession(normalizedIdentifier, headers, skipCookie);
    if (!session) {
        return new Response(JSON.stringify({ error: "Session generation failed" }), { status: 500, headers });
    }

    return new Response(JSON.stringify({ success: true, session }), { status: 200, headers });
}

// ============ Helpers ============

async function verifyTotpCode(userId: string, code: string): Promise<boolean> {
    const { data: totpSecret, error: totpSecretError } = await supabaseAdmin.rpc("get_user_2fa_secret", {
        p_user_id: userId,
        p_require_enabled: true,
    });

    if (totpSecretError || !totpSecret) {
        console.error("Failed to load TOTP secret for OPAQUE login:", totpSecretError);
        return false;
    }

    const OTPAuth = await import("npm:otpauth");
    const totp = new OTPAuth.TOTP({
        issuer: "Singra Vault",
        algorithm: "SHA1",
        digits: 6,
        period: 30,
        secret: OTPAuth.Secret.fromBase32(String(totpSecret).replace(/\s/g, "")),
    });

    return totp.validate({ token: code.replace(/\s/g, ""), window: 1 }) !== null;
}

async function verifyAndConsumeBackupCode(userId: string, code: string): Promise<boolean> {
    const { data: backupCodes } = await supabaseAdmin
        .from("backup_codes")
        .select("id, code_hash")
        .eq("user_id", userId)
        .eq("is_used", false);

    let validCodeId: string | null = null;
    if (backupCodes && backupCodes.length > 0) {
        for (const backupCode of backupCodes) {
            const isMatch = await argon2Verify({
                password: code.replace(/\s/g, ""),
                hash: backupCode.code_hash,
            });
            if (isMatch) {
                validCodeId = backupCode.id;
                break;
            }
        }
    }

    if (!validCodeId) {
        return false;
    }

    const { data: consumedBackupCode, error: consumeError } = await supabaseAdmin
        .from("backup_codes")
        .update({
            is_used: true,
            used_at: new Date().toISOString(),
        })
        .eq("id", validCodeId)
        .eq("user_id", userId)
        .eq("is_used", false)
        .select("id")
        .maybeSingle();

    return !consumeError && Boolean(consumedBackupCode);
}

async function issueSession(
    email: string,
    headers: Headers,
    skipCookie?: boolean,
): Promise<Record<string, unknown> | null> {
    const { data: linkData, error: linkError } = await supabaseAdmin.auth.admin.generateLink({
        type: "magiclink",
        email,
    });

    if (linkError || !linkData.properties?.action_link) {
        console.error("Failed to generate session link:", linkError);
        return null;
    }

    const tokenHash = linkData.properties.hashed_token;
    if (!tokenHash) return null;

    const authClient = createSupabaseAuthClient();
    const { data: sessionData, error: verifyError } = await authClient.auth.verifyOtp({
        token_hash: tokenHash,
        type: "magiclink",
    });

    if (verifyError || !sessionData.session) {
        console.error("Failed to verify OTP:", verifyError);
        return null;
    }

    if (!skipCookie) {
        setSessionCookie(headers, sessionData.session.refresh_token);
    }

    return sessionData.session;
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

function appendPartitionedCookieAttribute(headers: Headers): void {
    const currentCookie = headers.get("set-cookie");
    if (!currentCookie || /;\s*Partitioned/i.test(currentCookie)) {
        return;
    }

    headers.set("set-cookie", `${currentCookie}; Partitioned`);
}

async function delayUntilMinimum(startTime: number, minimumMs: number): Promise<void> {
    const remaining = minimumMs - (Date.now() - startTime);
    if (remaining > 0) {
        await new Promise((resolve) => setTimeout(resolve, remaining));
    }
}

async function invalidOpaqueAttemptResponse(
    rateLimitState: AuthRateLimitState,
    startTime: number,
    headers: Headers,
    message: string,
): Promise<Response> {
    const failure = await recordAuthRateLimitFailure(rateLimitState);
    await delayUntilMinimum(startTime, 300);
    if (failure.lockedUntil) {
        return authRateLimitResponse(toLockedState(failure), headers);
    }

    return new Response(JSON.stringify({ error: message }), { status: 401, headers });
}

async function opaqueUnavailableResponse(
    rateLimitState: AuthRateLimitState,
    startTime: number,
    headers: Headers,
): Promise<Response> {
    const failure = await recordAuthRateLimitFailure(rateLimitState);
    await delayUntilMinimum(startTime, 300);
    if (failure.lockedUntil) {
        return authRateLimitResponse(toLockedState(failure), headers);
    }

    return new Response(JSON.stringify({
        error: "OPAQUE not configured",
        useLegacy: true,
    }), { status: 400, headers });
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
