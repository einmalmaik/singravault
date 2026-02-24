import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { crypto } from "https://deno.land/std@0.168.0/crypto/mod.ts";
import { encodeHex, decodeHex } from "https://deno.land/std@0.208.0/encoding/hex.ts";
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
        const { email, token, newPassword } = await req.json();

        if (!email || !token || !newPassword || newPassword.length < 12) {
            return new Response(JSON.stringify({ error: "Invalid data" }), { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
        }

        // 1. Deno's std crypto: Das Token kommt vom Client als Hex-String
        // auth-recovery hashte das rawToken (Uint8Array).
        // Um das zu rekonstruieren, müssten wir hex_decode machen.
        // EINFACHER und sicherer: Wir waschen einfach beide Seiten auf Hex-Strings.

        // Fix: auth-recovery hat Hash über rawToken gebildet.
        // Wir decodieren den Hex-String zurück zu Uint8Array:
        const rawTokenBuffer = decodeHex(token);
        const tokenHashBuffer = await crypto.subtle.digest("SHA-256", rawTokenBuffer);
        const tokenHash = encodeHex(new Uint8Array(tokenHashBuffer));

        // 2. Suche in der Datenbank
        const { data: dbTokens, error: dbError } = await supabaseAdmin
            .from('recovery_tokens')
            .select('*')
            .eq('email', email)
            .eq('token_hash', tokenHash);

        if (dbError || !dbTokens || dbTokens.length === 0) {
            return new Response(JSON.stringify({ error: "Invalid or expired token" }), { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
        }

        const validToken = dbTokens[0];

        // 3. Prüfe Ablauf
        if (new Date(validToken.expires_at).getTime() < Date.now()) {
            await supabaseAdmin.from('recovery_tokens').delete().eq('id', validToken.id);
            return new Response(JSON.stringify({ error: "Token expired" }), { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
        }

        // 4. Setze neues Passwort (Argon2id)
        const salt = new Uint8Array(16);
        crypto.getRandomValues(salt);
        const hash = await argon2id({
            password: newPassword,
            salt,
            parallelism: 1,
            iterations: 2,
            memorySize: 19456,
            hashLength: 32,
            outputType: "encoded",
        });

        const { data: users } = await supabaseAdmin.rpc('get_user_id_by_email', { p_email: email });
        const user = users && users.length > 0 ? users[0] : null;

        if (user) {
            await supabaseAdmin.from('user_security').upsert({
                id: user.id,
                argon2_hash: hash,
            });
        }

        // 5. Lösche Token nach Gebrauch
        await supabaseAdmin.from('recovery_tokens').delete().eq('id', validToken.id);

        return new Response(JSON.stringify({ success: true }), {
            status: 200,
            headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
    } catch (err: any) {
        console.error("Auth Reset Error:", err);
        return new Response(JSON.stringify({ error: "Internal Server Error" }), { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }
});
