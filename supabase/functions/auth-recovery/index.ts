import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { crypto } from "https://deno.land/std@0.168.0/crypto/mod.ts";
import { encodeHex } from "https://deno.land/std@0.208.0/encoding/hex.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2.49.1";
import { getCorsHeaders } from "../_shared/cors.ts";

const supabaseUrl = Deno.env.get("SUPABASE_URL")!;
const supabaseServiceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
const supabaseAdmin = createClient(supabaseUrl, supabaseServiceKey);
const RESEND_API_KEY = Deno.env.get("RESEND_API_KEY");

serve(async (req) => {
    const corsHeaders = getCorsHeaders(req);
    if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });

    try {
        const { email } = await req.json();
        if (!email) {
            return new Response(JSON.stringify({ error: "Invalid email" }), { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
        }

        const startTime = Date.now();

        // 1. CSPRNG Token
        const rawToken = new Uint8Array(32);
        crypto.getRandomValues(rawToken);
        const resetTokenClient = encodeHex(rawToken);

        // 2. Hash(Token)
        const tokenHashBuffer = await crypto.subtle.digest("SHA-256", rawToken);
        const dbTokenHash = encodeHex(new Uint8Array(tokenHashBuffer));

        // 3. TTL: 15 Minuten
        const expiresAt = new Date(Date.now() + 15 * 60 * 1000).toISOString();

        // 4. Upsert (Nur Hash speichern!)
        // Enumeration Guard: Ob die E-Mail existiert, prüfen wir bewusst nach dem Hash generieren
        // um Timing Unterschiede gering zu halten.
        await supabaseAdmin.from('recovery_tokens').delete().eq('email', email); // Alte löschen
        await supabaseAdmin.from('recovery_tokens').insert({
            email,
            token_hash: dbTokenHash,
            expires_at: expiresAt
        });

        // Dummy für E-Mail Versand mit Resend (aus Performance- und Auth-Architektur)
        if (RESEND_API_KEY) {
            // Mock: Link wäre z.B. https://domain.com/auth/reset?token=xyz...
            console.log("Email Recovery Token generated for:", email, "Token:", resetTokenClient);
        }

        // Konstante Antwortzeit simulieren
        const elapsed = Date.now() - startTime;
        if (elapsed < 500) await new Promise(r => setTimeout(r, 500 - elapsed));

        // IMMER Erfolg, um Enumeration auszuschließen
        return new Response(JSON.stringify({ success: true }), {
            status: 200,
            headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
    } catch (err: any) {
        console.error("Auth Recovery Error:", err);
        return new Response(JSON.stringify({ error: "Internal Server Error" }), { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }
});
