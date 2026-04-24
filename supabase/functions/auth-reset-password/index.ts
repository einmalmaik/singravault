import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import * as opaque from "npm:@serenity-kit/opaque";
import { createClient } from "npm:@supabase/supabase-js@2";
import { getCorsHeaders } from "../_shared/cors.ts";
import {
    createUnusableGotruePassword,
    normalizeOpaqueIdentifier,
    sha256Hex,
} from "../_shared/opaqueAuth.ts";

const supabaseUrl = Deno.env.get("SUPABASE_URL")!;
const supabaseServiceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
const resendApiKey = Deno.env.get("RESEND_API_KEY") ?? "";
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
        const action = typeof body.action === "string" ? body.action : "";

        if (action === "opaque-reset-start") {
            return await handleOpaqueResetStart(body, headers);
        }

        if (action === "opaque-reset-finish") {
            return await handleOpaqueResetFinish(body, headers);
        }

        return new Response(JSON.stringify({ error: "OPAQUE password reset required" }), { status: 400, headers });
    } catch (err) {
        console.error("Auth Reset Error:", err);
        return new Response(JSON.stringify({ error: "Internal Server Error" }), { status: 500, headers });
    }
});

async function handleOpaqueResetStart(
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

async function handleOpaqueResetFinish(
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

    const { data: consumedResetState, error: stateConsumeError } = await supabaseAdmin
        .from("opaque_password_reset_states")
        .update({ consumed_at: new Date().toISOString() })
        .eq("id", resetRegistrationId)
        .eq("user_id", challenge.user_id)
        .is("consumed_at", null)
        .gt("expires_at", new Date().toISOString())
        .select("id, email")
        .maybeSingle();

    if (stateConsumeError || !consumedResetState) {
        return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401, headers });
    }

    const { data: consumedChallenge, error: consumeError } = await supabaseAdmin
        .from("password_reset_challenges")
        .update({ used_at: new Date().toISOString() })
        .eq("id", challenge.id)
        .is("used_at", null)
        .select("id, user_id, email")
        .maybeSingle();

    if (consumeError || !consumedChallenge) {
        return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401, headers });
    }

    const email = normalizeOpaqueIdentifier(consumedResetState.email);
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
        throw new Error(`Failed to update OPAQUE registration record: ${upsertError.message}`);
    }

    const { error: gotruePasswordError } = await supabaseAdmin.auth.admin.updateUserById(userId, {
        password: createUnusableGotruePassword(),
    });
    if (gotruePasswordError) {
        throw new Error(`Failed to randomize GoTrue password: ${gotruePasswordError.message}`);
    }
    await disableGotruePasswordLogin(userId);

    const { error: revokeError } = await supabaseAdmin.rpc("revoke_user_auth_sessions", {
        p_user_id: userId,
    });
    if (revokeError) {
        console.error("Failed to revoke existing sessions after password reset:", revokeError);
        throw new Error("Failed to revoke existing sessions after password reset");
    }

    await Promise.all([
        supabaseAdmin.from("profiles").update({ auth_protocol: "opaque" }).eq("user_id", userId),
        supabaseAdmin.from("user_security").delete().eq("id", userId),
        supabaseAdmin.from("password_reset_challenges").delete().eq("user_id", userId),
        supabaseAdmin.from("opaque_password_reset_states").delete().eq("user_id", userId),
    ]);

    await sendPasswordResetNotification(email);

    return new Response(JSON.stringify({ success: true }), { status: 200, headers });
}

async function findActiveResetChallenge(resetToken: string): Promise<{
    id: string;
    user_id: string;
    email: string;
} | null> {
    const resetTokenHash = await sha256Hex(resetToken);
    const { data: challenges, error } = await supabaseAdmin
        .from("password_reset_challenges")
        .select("id, user_id, email")
        .eq("token_hash", resetTokenHash)
        .is("used_at", null)
        .gt("expires_at", new Date().toISOString())
        .limit(1);

    if (error || !challenges || challenges.length === 0) {
        return null;
    }

    return challenges[0] as { id: string; user_id: string; email: string };
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

async function disableGotruePasswordLogin(userId: string): Promise<void> {
    const { error } = await supabaseAdmin.rpc("disable_gotrue_password_login", {
        p_user_id: userId,
    });
    if (error) {
        throw new Error(`Failed to disable GoTrue password login: ${error.message}`);
    }
}
