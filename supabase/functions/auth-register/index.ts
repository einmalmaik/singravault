import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import * as opaque from "npm:@serenity-kit/opaque";
import { createClient } from "npm:@supabase/supabase-js@2";
import { getCorsHeaders } from "../_shared/cors.ts";
import {
    authRateLimitResponse,
    checkAuthRateLimit,
    recordAuthRateLimitFailure,
} from "../_shared/authRateLimit.ts";
import {
    createUnusableGotruePassword,
    isValidOpaqueIdentifier,
    normalizeOpaqueIdentifier,
} from "../_shared/opaqueAuth.ts";
import { AUTH_ERROR_CODES, isUniqueViolation, jsonError } from "../_shared/authErrors.ts";

const supabaseUrl = Deno.env.get("SUPABASE_URL")!;
const supabaseServiceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
const supabaseAnonKey = Deno.env.get("SUPABASE_ANON_KEY")!;
const OPAQUE_SERVER_SETUP = Deno.env.get("OPAQUE_SERVER_SETUP")!;
const supabaseAdmin = createClient(supabaseUrl, supabaseServiceKey);

await opaque.ready;

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
        const action = typeof body.action === "string" ? body.action : "start";

        if (action === "finish") {
            return await handleRegistrationFinish(body, headers);
        }

        return await handleRegistrationStart(req, body, headers);
    } catch (err) {
        console.error("Auth Register Error:", err);
        return new Response(JSON.stringify({ error: "Internal Server Error" }), { status: 500, headers });
    }
});

async function handleRegistrationStart(
    req: Request,
    body: { email?: unknown; registrationRequest?: unknown },
    headers: Headers,
): Promise<Response> {
    const email = normalizeOpaqueIdentifier(body.email);
    const registrationRequest = typeof body.registrationRequest === "string" ? body.registrationRequest : "";

    if (!isValidOpaqueIdentifier(email) || !registrationRequest) {
        return new Response(JSON.stringify({ error: "Invalid input" }), { status: 400, headers });
    }

    const registerRateLimit = await checkAuthRateLimit({
        supabaseAdmin,
        req,
        action: "opaque_register",
        account: { kind: "email", value: email },
    });
    if (!registerRateLimit.allowed) {
        return authRateLimitResponse(registerRateLimit, headers);
    }

    const registerFailure = await recordAuthRateLimitFailure(registerRateLimit);
    if (registerFailure.lockedUntil) {
        return authRateLimitResponse({
            status: 429,
            error: "Too many attempts",
            attemptsRemaining: registerFailure.attemptsRemaining,
            lockedUntil: registerFailure.lockedUntil,
            retryAfterSeconds: registerFailure.retryAfterSeconds,
        }, headers);
    }

    const { data: existingUsers } = await supabaseAdmin.rpc("get_user_id_by_email", { p_email: email });
    const existingUserId = Array.isArray(existingUsers) && existingUsers.length > 0
        ? existingUsers[0].id as string
        : null;

    if (existingUserId) {
        return jsonError(
            AUTH_ERROR_CODES.ACCOUNT_ALREADY_EXISTS,
            "Account already exists",
            409,
            headers,
        );
    }

    const { data: existingOpaqueRecord, error: opaqueLookupError } = await supabaseAdmin
        .from("user_opaque_records")
        .select("user_id")
        .eq("opaque_identifier", email)
        .maybeSingle();
    if (opaqueLookupError) {
        console.error("Failed to check OPAQUE registration identifier:", sanitizeAuthError(opaqueLookupError));
        return jsonError(
            AUTH_ERROR_CODES.OPAQUE_REGISTRATION_FAILED,
            "Registration failed",
            500,
            headers,
        );
    }
    if (existingOpaqueRecord) {
        return jsonError(
            AUTH_ERROR_CODES.OPAQUE_RECORD_CONFLICT,
            "Account already exists",
            409,
            headers,
        );
    }

    let userId: string;
    try {
        userId = await createOpaqueOnlyUser(email);
    } catch (error) {
        console.error("Failed to create OPAQUE-only auth user:", sanitizeAuthError(error));
        return jsonError(
            isUniqueViolation(error)
                ? AUTH_ERROR_CODES.AUTH_EMAIL_ALREADY_IN_USE
                : AUTH_ERROR_CODES.OPAQUE_REGISTRATION_FAILED,
            isUniqueViolation(error) ? "Account already exists" : "Registration failed",
            isUniqueViolation(error) ? 409 : 500,
            headers,
        );
    }

    const registrationResponse = opaque.server.createRegistrationResponse({
        serverSetup: OPAQUE_SERVER_SETUP,
        userIdentifier: email,
        registrationRequest,
    }).registrationResponse;

    const registrationId = crypto.randomUUID();
    const expiresAt = new Date(Date.now() + 15 * 60 * 1000).toISOString();
    const { error: challengeError } = await supabaseAdmin
        .from("opaque_registration_challenges")
        .insert({
            id: registrationId,
            user_id: userId,
            email,
            purpose: "signup",
            expires_at: expiresAt,
        });

    if (challengeError) {
        await supabaseAdmin.auth.admin.deleteUser(userId).catch(() => undefined);
        throw challengeError;
    }

    try {
        await sendSignupOtp(email);
    } catch (error) {
        console.error("Failed to send signup verification code:", sanitizeAuthError(error));
        await rollbackRegistrationStart(userId, registrationId);
        return jsonError(
            AUTH_ERROR_CODES.OPAQUE_REGISTRATION_FAILED,
            "Registration failed",
            502,
            headers,
        );
    }

    return new Response(JSON.stringify({
        success: true,
        registrationId,
        registrationResponse,
        expiresAt,
    }), { status: 200, headers });
}

async function handleRegistrationFinish(
    body: { email?: unknown; registrationId?: unknown; registrationRecord?: unknown },
    headers: Headers,
): Promise<Response> {
    const email = normalizeOpaqueIdentifier(body.email);
    const registrationId = typeof body.registrationId === "string" ? body.registrationId : "";
    const registrationRecord = typeof body.registrationRecord === "string" ? body.registrationRecord : "";

    if (!isValidOpaqueIdentifier(email) || !registrationId || !registrationRecord) {
        return new Response(JSON.stringify({ error: "Invalid input" }), { status: 400, headers });
    }

    const { data: consumedChallenge, error: consumeError } = await supabaseAdmin
        .from("opaque_registration_challenges")
        .update({ consumed_at: new Date().toISOString() })
        .eq("id", registrationId)
        .eq("email", email)
        .is("consumed_at", null)
        .gt("expires_at", new Date().toISOString())
        .select("user_id, purpose")
        .maybeSingle();

    if (consumeError || !consumedChallenge) {
        return jsonError(
            AUTH_ERROR_CODES.AUTH_INVALID_OR_EXPIRED_CODE,
            "Invalid or expired code",
            401,
            headers,
        );
    }

    const userId = consumedChallenge.user_id as string;
    const { error: upsertError } = await supabaseAdmin
        .from("user_opaque_records")
        .upsert({
            user_id: userId,
            opaque_identifier: email,
            registration_record: registrationRecord,
            updated_at: new Date().toISOString(),
        }, { onConflict: "user_id" });

    if (upsertError) {
        console.error("Failed to store OPAQUE registration record:", sanitizeAuthError(upsertError));
        await supabaseAdmin.auth.admin.deleteUser(userId).catch(() => undefined);
        return jsonError(
            isUniqueViolation(upsertError)
                ? AUTH_ERROR_CODES.OPAQUE_RECORD_CONFLICT
                : AUTH_ERROR_CODES.OPAQUE_REGISTRATION_FAILED,
            isUniqueViolation(upsertError) ? "Account already exists" : "Registration failed",
            isUniqueViolation(upsertError) ? 409 : 500,
            headers,
        );
    }

    await Promise.all([
        supabaseAdmin.from("profiles").update({ auth_protocol: "opaque" }).eq("user_id", userId),
        supabaseAdmin.from("user_security").delete().eq("id", userId),
    ]);
    await disableGotruePasswordLogin(userId);

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

async function createOpaqueOnlyUser(email: string): Promise<string> {
    const { data: newUser, error: createError } = await supabaseAdmin.auth.admin.createUser({
        email,
        password: createUnusableGotruePassword(),
        email_confirm: false,
    });

    if (createError || !newUser.user?.id) {
        throw createError ?? new Error("User creation failed");
    }

    return newUser.user.id;
}

async function sendSignupOtp(email: string): Promise<void> {
    const anonClient = createClient(supabaseUrl, supabaseAnonKey, {
        auth: {
            persistSession: false,
            autoRefreshToken: false,
        },
    });
    const { error } = await anonClient.auth.resend({
        type: "signup",
        email,
        options: {
            emailRedirectTo: Deno.env.get("SITE_URL") || "https://singravault.mauntingstudios.de/auth",
        },
    });

    if (error) {
        throw new Error(error.message || "Failed to trigger signup OTP email");
    }
}

async function rollbackRegistrationStart(userId: string, registrationId: string): Promise<void> {
    const [challengeCleanup, userCleanup] = await Promise.allSettled([
        supabaseAdmin
            .from("opaque_registration_challenges")
            .delete()
            .eq("id", registrationId),
        supabaseAdmin.auth.admin.deleteUser(userId),
    ]);

    if (challengeCleanup.status === "rejected") {
        console.error("Failed to delete signup registration challenge after OTP send failure:", challengeCleanup.reason);
    }
    if (userCleanup.status === "rejected") {
        console.error("Failed to delete signup auth user after OTP send failure:", userCleanup.reason);
    }
}

async function disableGotruePasswordLogin(userId: string): Promise<void> {
    const { error } = await supabaseAdmin.rpc("disable_gotrue_password_login", {
        p_user_id: userId,
    });
    if (error) {
        throw new Error(`Failed to disable GoTrue password login: ${error.message}`);
    }
}
