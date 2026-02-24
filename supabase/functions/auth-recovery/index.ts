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

        // E-Mail Versand mit Resend
        if (RESEND_API_KEY) {
            const origin = req.headers.get("origin") || "https://singravault.mauntingstudios.de";
            const resetLink = `${origin}/auth?mode=recover&token=${resetTokenClient}`;

            try {
                const mailRes = await fetch("https://api.resend.com/emails", {
                    method: "POST",
                    headers: {
                        "Authorization": `Bearer ${RESEND_API_KEY}`,
                        "Content-Type": "application/json"
                    },
                    body: JSON.stringify({
                        from: "Singra Vault <noreply@mauntingstudios.de>",
                        to: email,
                        subject: "Singra Vault - Passwort zurücksetzen",
                        html: `
                            <div style="font-family: sans-serif; color: #333;">
                                <h2>Passwort zurücksetzen</h2>
                                <p>Du hast angefordert, dein Passwort zurückzusetzen.</p>
                                <p>Klicke auf den folgenden Link, um ein neues Passwort zu vergeben:</p>
                                <p><a href="${resetLink}" style="background-color: #6366f1; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">Passwort zurücksetzen</a></p>
                                <p>Dieser Link ist für 15 Minuten gültig.</p>
                                <p>Wenn du diese Anfrage nicht gestellt hast, kannst du diese E-Mail ignorieren.</p>
                                <br/>
                                <p><small>Alternativ: Kopiere diesen Token in das Formular: <code>${resetTokenClient}</code></small></p>
                            </div>
                        `
                    })
                });

                if (!mailRes.ok) {
                    console.error("Resend API error:", await mailRes.text());
                } else {
                    console.log("Recovery email sent to:", email);
                }
            } catch (err) {
                console.error("Failed to send recovery email:", err);
            }
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
