import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { argon2id } from "npm:hash-wasm";
import { crypto } from "https://deno.land/std@0.168.0/crypto/mod.ts";
import { encodeHex } from "https://deno.land/std@0.208.0/encoding/hex.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2.49.1";
import { getCorsHeaders } from "../_shared/cors.ts";

// Supabase Admin Client
const supabaseUrl = Deno.env.get("SUPABASE_URL")!;
const supabaseServiceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
const supabaseAdmin = createClient(supabaseUrl, supabaseServiceKey);

serve(async (req) => {
    const corsHeaders = getCorsHeaders(req);

    if (req.method === "OPTIONS") {
        return new Response("ok", { headers: corsHeaders });
    }

    try {
        const { email, password } = await req.json();

        if (!email || !password || password.length < 12) {
            return new Response(JSON.stringify({ error: "Invalid input" }), {
                status: 400,
                headers: { ...corsHeaders, "Content-Type": "application/json" }
            });
        }

        // 1. HIBP K-Anonymity Check
        const encoder = new TextEncoder();
        const passwordHashBuffer = await crypto.subtle.digest("SHA-1", encoder.encode(password));
        const passwordHash = encodeHex(passwordHashBuffer).toUpperCase();
        const prefix = passwordHash.substring(0, 5);
        const suffix = passwordHash.substring(5);

        const hibpReq = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`);
        const hibpRes = await hibpReq.text();

        if (hibpRes.includes(suffix)) {
            return new Response(JSON.stringify({ error: "Password found in data breaches." }), {
                status: 400,
                headers: { ...corsHeaders, "Content-Type": "application/json" }
            });
        }

        // 2. Argon2id Hash generieren
        const salt = new Uint8Array(16);
        crypto.getRandomValues(salt);

        const hash = await argon2id({
            password,
            salt,
            parallelism: 1,
            iterations: 2,
            memorySize: 19456, // 19 MiB RAM
            hashLength: 32,
            outputType: "encoded"
        });

        // 3. User in Supabase erstellen (Admin API) - GoTrue speichert standardmäßig auch Passwörter,
        // wir speichern unseren Argon2id-Hash idealerweise in einer custom_users oder auth.users Erweiterung,
        // ABER da GoTrue verwendet wird, können wir das GoTrue-Passwort auf einen randomisierten Wert setzen 
        // und den echten Argon2id-Hash separat persistieren (falls GoTrue umgangen werden soll).
        // Alternativ nutzen wir Supabase signInWithPassword ganz normal und verwerfen Argon2id? 
        // NEIN, die Anweisung verlangt Argon2id! Daher ignorieren wir das Standard-GoTrue-Passwort 
        // via Dummy-Passwort und nutzen eine Custom Authentifizierung im Backend-BFF.

        // Wir rufen supabase.auth.admin.createUser auf, um den User anzulegen.
        // Das Dummy-Passwort ist der Hash selbst (damit niemand es kennen kann).
        const { data: newUser, error: createError } = await supabaseAdmin.auth.admin.createUser({
            email: email,
            password: crypto.randomUUID(), // Unusable password for standard GoTrue
            email_confirm: false
        });

        if (createError) {
            // User Enumeration Prevention: Even if email exists, return success
            if (createError.status === 422 || createError.message.includes("already registered")) {
                return new Response(JSON.stringify({ success: true }), {
                    status: 200,
                    headers: { ...corsHeaders, "Content-Type": "application/json" }
                });
            }
            throw createError;
        }

        // 4. Echten Hash speichern (ideal in einer separaten Tabelle `user_security`)
        await supabaseAdmin.from('user_security').upsert({
            id: newUser.user.id,
            argon2_hash: hash,
        });

        return new Response(JSON.stringify({ success: true }), {
            status: 200,
            headers: { ...corsHeaders, "Content-Type": "application/json" }
        });

    } catch (err: any) {
        console.error("Auth Register Error:", err);
        return new Response(JSON.stringify({ error: "Internal Server Error" }), {
            status: 500,
            headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
    }
});
