import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { crypto } from "https://deno.land/std@0.168.0/crypto/mod.ts";
import { encodeHex } from "https://deno.land/std@0.208.0/encoding/hex.ts";
import { argon2id } from "npm:hash-wasm";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2.49.1";
import { getCorsHeaders } from "../_shared/cors.ts";

const supabaseUrl = Deno.env.get("SUPABASE_URL")!;
const supabaseServiceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
const supabaseAdmin = createClient(supabaseUrl, supabaseServiceKey);

serve(async (req) => {
    const corsHeaders = getCorsHeaders(req);
    if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });

    try {
        const { newPassword } = await req.json();

        if (!newPassword || newPassword.length < 12) {
            return new Response(JSON.stringify({ error: "Invalid data" }), { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
        }

        const authHeader = req.headers.get("Authorization");
        if (!authHeader || !authHeader.startsWith("Bearer ")) {
            return new Response(JSON.stringify({ error: "Missing or invalid authorization header" }), { status: 401, headers: { ...corsHeaders, "Content-Type": "application/json" } });
        }
        const jwt = authHeader.replace("Bearer ", "");
        const { data: { user }, error: authError } = await supabaseAdmin.auth.getUser(jwt);

        if (authError || !user) {
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
        await supabaseAdmin.from('user_security').upsert({
            id: user.id,
            argon2_hash: hash,
        });

        // Update GoTrue password
        const { error: updateError } = await supabaseAdmin.auth.admin.updateUserById(user.id, {
            password: newPassword
        });

        if (updateError) {
            throw new Error(`Failed to update GoTrue password: ${updateError.message}`);
        }

        return new Response(JSON.stringify({ success: true }), {
            status: 200,
            headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
    } catch (err: any) {
        console.error("Auth Reset Error:", err);
        return new Response(JSON.stringify({ error: "Internal Server Error" }), { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }
});
