import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { crypto } from "https://deno.land/std@0.168.0/crypto/mod.ts";
import { encodeHex } from "https://deno.land/std@0.208.0/encoding/hex.ts";
import { argon2id } from "npm:hash-wasm";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2.49.1";
import { getCorsHeaders } from "../_shared/cors.ts";

const supabaseUrl = Deno.env.get("SUPABASE_URL")!;
const supabaseServiceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
const resendApiKey = Deno.env.get("RESEND_API_KEY") ?? "";
const supabaseAdmin = createClient(supabaseUrl, supabaseServiceKey);

serve(async (req) => {
    const corsHeaders = getCorsHeaders(req);
    if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });

    try {
        const { newPassword, resetToken } = await req.json();

        if (!newPassword || newPassword.length < 12 || !resetToken || typeof resetToken !== "string") {
            return new Response(JSON.stringify({ error: "Invalid data" }), { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
        }

        const resetTokenHash = await sha256Hex(resetToken.trim());
        const { data: challenges, error: challengeLookupError } = await supabaseAdmin
            .from("password_reset_challenges")
            .select("id, user_id, email")
            .eq("token_hash", resetTokenHash)
            .is("used_at", null)
            .gt("expires_at", new Date().toISOString())
            .limit(1);

        if (challengeLookupError || !challenges || challenges.length === 0) {
            await new Promise((resolve) => setTimeout(resolve, 300));
            return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401, headers: { ...corsHeaders, "Content-Type": "application/json" } });
        }

        const challenge = challenges[0];
        const usedAt = new Date().toISOString();
        const { data: consumedChallenge, error: consumeError } = await supabaseAdmin
            .from("password_reset_challenges")
            .update({ used_at: usedAt })
            .eq("id", challenge.id)
            .is("used_at", null)
            .select("id, user_id, email")
            .maybeSingle();

        if (consumeError || !consumedChallenge) {
            return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401, headers: { ...corsHeaders, "Content-Type": "application/json" } });
        }

        // HIBP K-Anonymity Check
        const encoder = new TextEncoder();
        const hexHashBuffer = await crypto.subtle.digest("SHA-1", encoder.encode(newPassword));
        const hexHash = encodeHex(hexHashBuffer).toUpperCase();
        const prefix = hexHash.substring(0, 5);
        const suffix = hexHash.substring(5);

        const hibpReq = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`);
        const hibpRes = await hibpReq.text();

        if (hibpRes.includes(suffix)) {
            return new Response(JSON.stringify({ error: "Password found in data breaches." }), {
                status: 400,
                headers: { ...corsHeaders, "Content-Type": "application/json" }
            });
        }

        // Setze neues Passwort (Argon2id)
        const salt = new Uint8Array(16);
        crypto.getRandomValues(salt);
        const hash = await argon2id({
            password: newPassword,
            salt,
            parallelism: 1,
            iterations: 3,
            memorySize: 65536, // 64 MiB RAM (aligned with client-side security level)
            hashLength: 32,
            outputType: "encoded",
        });

        // Update Argon2 hash in custom table
        const { error: upsertError } = await supabaseAdmin.from('user_security').upsert({
            id: consumedChallenge.user_id,
            argon2_hash: hash,
        });
        if (upsertError) {
            throw new Error(`Failed to update custom password hash: ${upsertError.message}`);
        }

        // Update GoTrue password
        const { error: updateError } = await supabaseAdmin.auth.admin.updateUserById(consumedChallenge.user_id, {
            password: newPassword
        });

        if (updateError) {
            throw new Error(`Failed to update GoTrue password: ${updateError.message}`);
        }

        const { error: revokeError } = await supabaseAdmin.rpc("revoke_user_auth_sessions", {
            p_user_id: consumedChallenge.user_id,
        });
        if (revokeError) {
            console.error("Failed to revoke existing sessions after password reset:", revokeError);
            throw new Error("Failed to revoke existing sessions after password reset");
        }

        await supabaseAdmin
            .from("password_reset_challenges")
            .delete()
            .eq("user_id", consumedChallenge.user_id);

        await sendPasswordResetNotification(consumedChallenge.email);

        return new Response(JSON.stringify({ success: true }), {
            status: 200,
            headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
    } catch (err: unknown) {
        console.error("Auth Reset Error:", err);
        return new Response(JSON.stringify({ error: "Internal Server Error" }), { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }
});

async function sha256Hex(value: string): Promise<string> {
    const data = new TextEncoder().encode(value);
    const digest = await crypto.subtle.digest("SHA-256", data);
    return Array.from(new Uint8Array(digest))
        .map((byte) => byte.toString(16).padStart(2, "0"))
        .join("");
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
