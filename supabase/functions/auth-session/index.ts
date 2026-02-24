import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { setCookie } from "https://deno.land/std@0.168.0/http/cookie.ts";
import { argon2Verify } from "npm:hash-wasm";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2.49.1";
import { getCorsHeaders } from "../_shared/cors.ts";

const supabaseUrl = Deno.env.get("SUPABASE_URL")!;
const supabaseServiceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
const supabaseAdmin = createClient(supabaseUrl, supabaseServiceKey);

serve(async (req) => {
    const corsHeaders = getCorsHeaders(req);

    // Credentials explizit für Cookies erlauben
    const origin = req.headers.get("Origin") || "*";
    const headers = new Headers({
        ...corsHeaders,
        "Access-Control-Allow-Origin": origin,
        "Access-Control-Allow-Credentials": "true",
    });

    if (req.method === "OPTIONS") {
        return new Response("ok", { headers });
    }

    try {
        const { email, password } = await req.json();

        if (!email || !password) {
            return new Response(JSON.stringify({ error: "Invalid credentials" }), {
                status: 400,
                headers: { ...headers, "Content-Type": "application/json" }
            });
        }

        // künstliches Delay gegen Timing Attacks (simuliert Argon2id Zeit)
        const startTime = Date.now();

        // 1. Hole den User anhand der Email (via auth.users)
        const { data: users, error: userError } = await supabaseAdmin.auth.admin.listUsers();
        if (userError) throw userError;

        const user = users.users.find((u) => u.email === email);
        if (!user) {
            // Konstante Zeitverzögerung
            await new Promise(r => setTimeout(r, 500 - (Date.now() - startTime)));
            return new Response(JSON.stringify({ error: "Invalid credentials" }), {
                status: 401,
                headers: { ...headers, "Content-Type": "application/json" }
            });
        }

        // 2. Lade den Argon2id Hash
        const { data: secData, error: secError } = await supabaseAdmin
            .from('user_security')
            .select('argon2_hash')
            .eq('id', user.id)
            .single();

        if (secError || !secData) {
            // Wenn der Hash fehlt, simulieren wir die Zeit, um Enumeration abzuwehren
            await new Promise(r => setTimeout(r, 500 - (Date.now() - startTime)));
            return new Response(JSON.stringify({ error: "Invalid credentials" }), {
                status: 401,
                headers: { ...headers, "Content-Type": "application/json" }
            });
        }

        // 3. Verifiziere das Passwort mit Argon2id
        const isValid = await argon2Verify({ password, hash: secData.argon2_hash });

        if (!isValid) {
            return new Response(JSON.stringify({ error: "Invalid credentials" }), {
                status: 401,
                headers: { ...headers, "Content-Type": "application/json" }
            });
        }

        // 4. Session generieren (BFF Pattern)
        // Wir fordern ein JWT von Supabase GoTrue an, indem wir einen Magic Link Flow
        // oder Service Role Flow nutzen, um dem User einen authentifizierten Session JWT auszustellen.
        // Da wir das Passwort neu gesetzt haben (Random), melden wir ihn nicht so an. Wir erstellen einen
        // Custom JWT ODER weisen GoTrue an, ein JWT auszustellen:
        // supabase.auth.admin.generateLink({ type: 'magiclink', email }) ist möglich, aber
        // eleganter ist es, einen eigenen Tokenizer zu schreiben, ODER die Session API zu nutzen:
        // Aber GoTrue unterstützt kein direkte Ausstellung per API Node ohne Email-Click.
        // -> Workaround für Enterprise Architektur: 
        // Wir nutzen unser eigenes Backend-Cookie-Session Management.
        // Für dieses Audit-Scope: Wir setzendas JWT manuell in ein Cookie.

        // (Hinweis: Normalerweise würde hier ein signiertes JWT mit Deno/jose generiert werden, das
        // in Supabase als Custom JWT validiert wird).
        const sessionToken = crypto.randomUUID(); // Dummy-Token für den Prototyp

        // Secure, HttpOnly, SameSite=Strict Setzen
        setCookie(headers, {
            name: "sb-bff-session",
            value: sessionToken,
            path: "/",
            httpOnly: true,
            secure: true,
            sameSite: "Strict",
            maxAge: 3600, // 1h
        });

        return new Response(JSON.stringify({ success: true }), {
            status: 200,
            headers: { ...headers, "Content-Type": "application/json" }
        });

    } catch (err: any) {
        console.error("Auth Session Error:", err);
        return new Response(JSON.stringify({ error: "Internal Server Error" }), {
            status: 500,
            headers: { ...headers, "Content-Type": "application/json" }
        });
    }
});
