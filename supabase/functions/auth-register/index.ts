import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import * as opaque from "npm:@serenity-kit/opaque";
import { createClient } from "npm:@supabase/supabase-js@2";
import { getCorsHeaders } from "../_shared/cors.ts";
import {
    createUnusableGotruePassword,
    isValidOpaqueIdentifier,
    normalizeOpaqueIdentifier,
} from "../_shared/opaqueAuth.ts";

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

        return await handleRegistrationStart(body, headers);
    } catch (err) {
        console.error("Auth Register Error:", err);
        return new Response(JSON.stringify({ error: "Internal Server Error" }), { status: 500, headers });
    }
});

async function handleRegistrationStart(
    body: { email?: unknown; registrationRequest?: unknown },
    headers: Headers,
): Promise<Response> {
    const email = normalizeOpaqueIdentifier(body.email);
    const registrationRequest = typeof body.registrationRequest === "string" ? body.registrationRequest : "";

    if (!isValidOpaqueIdentifier(email) || !registrationRequest) {
        return new Response(JSON.stringify({ error: "Invalid input" }), { status: 400, headers });
    }

    const { data: existingUsers } = await supabaseAdmin.rpc("get_user_id_by_email", { p_email: email });
    const existingUserId = Array.isArray(existingUsers) && existingUsers.length > 0
        ? existingUsers[0].id as string
        : null;

    const userId = existingUserId ?? await createOpaqueOnlyUser(email);
    const isDecoy = Boolean(existingUserId);
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
            user_id: isDecoy ? null : userId,
            email,
            purpose: isDecoy ? "signup-decoy" : "signup",
            expires_at: expiresAt,
        });

    if (challengeError) {
        if (!isDecoy) {
            await supabaseAdmin.auth.admin.deleteUser(userId).catch(() => undefined);
        }
        throw challengeError;
    }

    if (!isDecoy) {
        await sendSignupOtp(email);
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
        return new Response(JSON.stringify({ error: "Invalid or expired registration" }), { status: 401, headers });
    }

    if (!consumedChallenge.user_id) {
        return new Response(JSON.stringify({ success: true }), { status: 200, headers });
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
        console.error("Failed to store OPAQUE registration record:", upsertError);
        await supabaseAdmin.auth.admin.deleteUser(userId).catch(() => undefined);
        return new Response(JSON.stringify({ error: "Failed to persist OPAQUE registration" }), { status: 500, headers });
    }

    await Promise.all([
        supabaseAdmin.from("profiles").update({ auth_protocol: "opaque" }).eq("user_id", userId),
        supabaseAdmin.from("user_security").delete().eq("id", userId),
    ]);
    await disableGotruePasswordLogin(userId);

    return new Response(JSON.stringify({ success: true }), { status: 200, headers });
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
        console.error("Warning: Failed to trigger signup OTP email after OPAQUE registration:", error);
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
