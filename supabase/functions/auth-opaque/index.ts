/**
 * @fileoverview OPAQUE Protocol Edge Function
 *
 * App-owned password authentication is only allowed through OPAQUE.
 * The user's password never reaches this server, not even as a hash.
 *
 * Endpoints (via `action` field in POST body):
 *   - register-start:  Server processes registration request for an authenticated account
 *   - register-finish: Server stores the registration record for an authenticated account
 *   - login-start:     Server processes OPAQUE login request
 *   - login-finish:    Server verifies OPAQUE proof and issues session
 */

import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import * as opaque from "npm:@serenity-kit/opaque";
import { createClient } from "npm:@supabase/supabase-js@2";
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
import {
    createOpaqueSessionBindingProof,
    isValidOpaqueIdentifier,
    normalizeOpaqueIdentifier,
    OPAQUE_SESSION_BINDING_VERSION,
} from "../_shared/opaqueAuth.ts";
import {
    twoFactorFailureResponse,
    verifyTwoFactorServer,
} from "../_shared/twoFactor.ts";

const supabaseUrl = Deno.env.get("SUPABASE_URL")!;
const supabaseServiceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
const supabaseAnonKey = Deno.env.get("SUPABASE_ANON_KEY")!;
const OPAQUE_SERVER_SETUP = Deno.env.get("OPAQUE_SERVER_SETUP")!;
const SESSION_COOKIE_NAME = "sb-bff-session";
const SESSION_COOKIE_MAX_AGE = Number(Deno.env.get("SESSION_COOKIE_MAX_AGE_SECONDS") ?? 60 * 60 * 24 * 400);
const supabaseAdmin = createClient(supabaseUrl, supabaseServiceKey);

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
        switch (body.action) {
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

async function getAuthenticatedUserId(req: Request): Promise<string | null> {
    const authHeader = req.headers.get("Authorization");
    if (!authHeader?.startsWith("Bearer ")) {
        return null;
    }

    const token = authHeader.replace("Bearer ", "");
    const { data, error } = await supabaseAdmin.auth.getUser(token);
    if (error || !data.user) {
        return null;
    }

    return data.user.id;
}

async function handleRegisterStart(
    body: { userIdentifier?: unknown; registrationRequest?: unknown },
    headers: Headers,
    req: Request,
): Promise<Response> {
    const authenticatedUserId = await getAuthenticatedUserId(req);
    if (!authenticatedUserId) {
        return new Response(JSON.stringify({ error: "Authentication required" }), { status: 401, headers });
    }

    const userIdentifier = normalizeOpaqueIdentifier(body.userIdentifier);
    const registrationRequest = typeof body.registrationRequest === "string" ? body.registrationRequest : "";
    if (!isValidOpaqueIdentifier(userIdentifier) || !registrationRequest) {
        return new Response(JSON.stringify({ error: "Missing fields" }), { status: 400, headers });
    }

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
    body: { userIdentifier?: unknown; registrationRecord?: unknown },
    headers: Headers,
    req: Request,
): Promise<Response> {
    const authenticatedUserId = await getAuthenticatedUserId(req);
    if (!authenticatedUserId) {
        return new Response(JSON.stringify({ error: "Authentication required" }), { status: 401, headers });
    }

    const userIdentifier = normalizeOpaqueIdentifier(body.userIdentifier);
    const registrationRecord = typeof body.registrationRecord === "string" ? body.registrationRecord : "";
    if (!isValidOpaqueIdentifier(userIdentifier) || !registrationRecord) {
        return new Response(JSON.stringify({ error: "Missing fields" }), { status: 400, headers });
    }

    const { data: users, error: userError } = await supabaseAdmin.rpc("get_user_id_by_email", { p_email: userIdentifier });
    if (userError || !users || users.length === 0 || users[0].id !== authenticatedUserId) {
        return new Response(JSON.stringify({ error: "Forbidden" }), { status: 403, headers });
    }

    const userId = users[0].id;
    const { error: upsertError } = await supabaseAdmin
        .from("user_opaque_records")
        .upsert({
            user_id: userId,
            opaque_identifier: userIdentifier,
            registration_record: registrationRecord,
            updated_at: new Date().toISOString(),
        }, { onConflict: "user_id" });

    if (upsertError) {
        console.error("Failed to store OPAQUE record:", upsertError);
        return new Response(JSON.stringify({ error: "Failed to store record" }), { status: 500, headers });
    }

    await Promise.all([
        supabaseAdmin.from("profiles").update({ auth_protocol: "opaque" }).eq("user_id", userId),
        supabaseAdmin.from("user_security").delete().eq("id", userId),
    ]);
    await disableGotruePasswordLogin(userId);

    return new Response(JSON.stringify({ success: true }), { status: 200, headers });
}

async function handleLoginStart(
    body: { userIdentifier?: unknown; startLoginRequest?: unknown },
    headers: Headers,
    req: Request,
): Promise<Response> {
    const userIdentifier = normalizeOpaqueIdentifier(body.userIdentifier);
    const startLoginRequest = typeof body.startLoginRequest === "string" ? body.startLoginRequest : "";
    if (!isValidOpaqueIdentifier(userIdentifier) || !startLoginRequest) {
        return new Response(JSON.stringify({ error: "Missing fields" }), { status: 400, headers });
    }

    const opaqueRateLimit = await checkAuthRateLimit({
        supabaseAdmin,
        req,
        action: "opaque_login",
        account: { kind: "email", value: userIdentifier },
    });
    if (!opaqueRateLimit.allowed) {
        return authRateLimitResponse(opaqueRateLimit, headers);
    }
    const startTime = Date.now();

    const { data: users, error: userError } = await supabaseAdmin.rpc("get_user_id_by_email", { p_email: userIdentifier });
    if (userError || !users || users.length === 0) {
        return await opaqueUnavailableResponse(opaqueRateLimit, startTime, headers);
    }

    const userId = users[0].id;
    const { data: opaqueData, error: opaqueError } = await supabaseAdmin
        .from("user_opaque_records")
        .select("registration_record, opaque_identifier")
        .eq("user_id", userId)
        .maybeSingle();

    if (opaqueError || !opaqueData?.registration_record) {
        return await opaqueUnavailableResponse(opaqueRateLimit, startTime, headers);
    }

    const recordIdentifier = normalizeOpaqueIdentifier(opaqueData.opaque_identifier || userIdentifier);
    let loginResponse: string;
    let serverLoginState: string;
    try {
        const result = opaque.server.startLogin({
            serverSetup: OPAQUE_SERVER_SETUP,
            userIdentifier: recordIdentifier,
            registrationRecord: opaqueData.registration_record,
            startLoginRequest,
        });
        loginResponse = result.loginResponse;
        serverLoginState = result.serverLoginState;
    } catch {
        return await invalidOpaqueAttemptResponse(opaqueRateLimit, startTime, headers, "Invalid credentials");
    }

    const loginId = crypto.randomUUID();
    const expiresAt = new Date(Date.now() + 5 * 60 * 1000).toISOString();
    const { error: storeError } = await supabaseAdmin
        .from("opaque_login_states")
        .insert({
            id: loginId,
            user_id: userId,
            opaque_identifier: recordIdentifier,
            server_login_state: serverLoginState,
            expires_at: expiresAt,
        });

    if (storeError) {
        console.error("Failed to store OPAQUE login state:", storeError);
        return new Response(JSON.stringify({ error: "Internal error" }), { status: 500, headers });
    }

    return new Response(JSON.stringify({ loginResponse, loginId }), { status: 200, headers });
}

async function handleLoginFinish(
    body: {
        userIdentifier?: unknown;
        finishLoginRequest?: unknown;
        loginId?: unknown;
        totpCode?: string;
        isBackupCode?: boolean;
        skipCookie?: boolean;
    },
    headers: Headers,
    req: Request,
): Promise<Response> {
    const userIdentifier = normalizeOpaqueIdentifier(body.userIdentifier);
    const finishLoginRequest = typeof body.finishLoginRequest === "string" ? body.finishLoginRequest : "";
    const loginId = typeof body.loginId === "string" ? body.loginId : "";
    if (!isValidOpaqueIdentifier(userIdentifier) || !finishLoginRequest || !loginId) {
        return new Response(JSON.stringify({ error: "Missing fields" }), { status: 400, headers });
    }

    const opaqueRateLimit = await checkAuthRateLimit({
        supabaseAdmin,
        req,
        action: "opaque_login",
        account: { kind: "email", value: userIdentifier },
    });
    if (!opaqueRateLimit.allowed) {
        return authRateLimitResponse(opaqueRateLimit, headers);
    }
    const startTime = Date.now();

    const { data: loginState, error: stateError } = await supabaseAdmin
        .from("opaque_login_states")
        .select("server_login_state, user_id, opaque_identifier, expires_at")
        .eq("id", loginId)
        .maybeSingle();

    await supabaseAdmin.from("opaque_login_states").delete().eq("id", loginId);

    if (stateError || !loginState) {
        return await invalidOpaqueAttemptResponse(opaqueRateLimit, startTime, headers, "Invalid or expired login session");
    }

    if (new Date(loginState.expires_at) < new Date()) {
        return await invalidOpaqueAttemptResponse(opaqueRateLimit, startTime, headers, "Login session expired");
    }

    const stateIdentifier = normalizeOpaqueIdentifier(loginState.opaque_identifier || userIdentifier);
    if (stateIdentifier !== userIdentifier) {
        return await invalidOpaqueAttemptResponse(opaqueRateLimit, startTime, headers, "Invalid credentials");
    }

    let sessionKey: string;
    try {
        const result = opaque.server.finishLogin({
            finishLoginRequest,
            serverLoginState: loginState.server_login_state,
        });
        sessionKey = result.sessionKey;
    } catch {
        return await invalidOpaqueAttemptResponse(opaqueRateLimit, startTime, headers, "Invalid credentials");
    }

    if (!sessionKey) {
        return await invalidOpaqueAttemptResponse(opaqueRateLimit, startTime, headers, "Invalid credentials");
    }

    const userId = loginState.user_id as string;
    const { data: users } = await supabaseAdmin.rpc("get_user_id_by_email", { p_email: userIdentifier });
    if (!users || users.length === 0 || users[0].id !== userId) {
        return await invalidOpaqueAttemptResponse(opaqueRateLimit, startTime, headers, "Invalid credentials");
    }

    await resetAuthRateLimit(opaqueRateLimit);

    const { data: adminUser, error: adminUserError } = await supabaseAdmin.auth.admin.getUserById(userId);
    if (adminUserError || !adminUser.user.email_confirmed_at) {
        return new Response(JSON.stringify({ error: "Email verification required" }), { status: 403, headers });
    }

    const twoFactorResponse = await enforceSecondFactorIfNeeded({
        userId,
        req,
        headers,
        totpCode: body.totpCode,
        isBackupCode: Boolean(body.isBackupCode),
    });
    if (twoFactorResponse) {
        return twoFactorResponse;
    }

    const session = await issueSession(userIdentifier, headers, Boolean(body.skipCookie));
    if (!session) {
        return new Response(JSON.stringify({ error: "Session generation failed" }), { status: 500, headers });
    }

    const opaqueSessionBinding = await createSessionBinding(sessionKey, session);
    return new Response(JSON.stringify({
        success: true,
        session,
        opaqueSessionBinding,
    }), { status: 200, headers });
}

async function enforceSecondFactorIfNeeded(params: {
    userId: string;
    req: Request;
    headers: Headers;
    totpCode?: string;
    isBackupCode: boolean;
}): Promise<Response | null> {
    const { data: user2fa } = await supabaseAdmin
        .from("user_2fa")
        .select("is_enabled")
        .eq("user_id", params.userId)
        .maybeSingle();

    if (!user2fa?.is_enabled) {
        return null;
    }

    if (!params.totpCode && !params.isBackupCode) {
        return new Response(JSON.stringify({
            requires2FA: true,
            opaqueVerified: true,
        }), { status: 200, headers: params.headers });
    }

    if (!params.totpCode) {
        return new Response(JSON.stringify({ error: "Invalid request payload" }), { status: 400, headers: params.headers });
    }

    const secondFactor = await verifyTwoFactorServer({
        supabaseAdmin,
        req: params.req,
        userId: params.userId,
        purpose: "account_login",
        method: params.isBackupCode ? "backup_code" : "totp",
        code: params.totpCode,
    });
    if (!secondFactor.ok) {
        return twoFactorFailureResponse(secondFactor, params.headers);
    }
    return null;
}

async function issueSession(
    email: string,
    headers: Headers,
    skipCookie: boolean,
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
    if (!tokenHash) {
        return null;
    }

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

    return sessionData.session as unknown as Record<string, unknown>;
}

async function createSessionBinding(
    sessionKey: string,
    session: Record<string, unknown>,
): Promise<{ version: string; userId: string; proof: string }> {
    const accessToken = typeof session.access_token === "string" ? session.access_token : "";
    const user = session.user as { id?: unknown } | undefined;
    const userId = typeof user?.id === "string" ? user.id : "";
    if (!accessToken || !userId) {
        throw new Error("Cannot bind OPAQUE session without access token and user id");
    }

    return {
        version: OPAQUE_SESSION_BINDING_VERSION,
        userId,
        proof: await createOpaqueSessionBindingProof({ sessionKey, userId, accessToken }),
    };
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
        error: "Invalid credentials",
        code: "INVALID_CREDENTIALS",
    }), { status: 401, headers });
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

async function disableGotruePasswordLogin(userId: string): Promise<void> {
    const { error } = await supabaseAdmin.rpc("disable_gotrue_password_login", {
        p_user_id: userId,
    });
    if (error) {
        throw new Error(`Failed to disable GoTrue password login: ${error.message}`);
    }
}
