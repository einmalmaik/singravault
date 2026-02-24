import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { getCookies, setCookie } from "https://deno.land/std@0.168.0/http/cookie.ts";
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
        // --- GET: Session Hydration & Refresh ---
        if (req.method === "GET") {
            const cookies = getCookies(req.headers);
            const refreshToken = cookies["sb-bff-session"];

            if (!refreshToken) {
                return new Response(JSON.stringify({ error: "No session cookie" }), {
                    status: 401,
                    headers: { ...headers, "Content-Type": "application/json" }
                });
            }

            // Refresh via Admin oder Anon Client
            const { data, error } = await supabaseAdmin.auth.refreshSession({ refresh_token: refreshToken });

            if (error || !data.session) {
                return new Response(JSON.stringify({ error: "Session expired" }), {
                    status: 401,
                    headers: { ...headers, "Content-Type": "application/json" }
                });
            }

            // Neues Cookie setzen
            setCookie(headers, {
                name: "sb-bff-session",
                value: data.session.refresh_token,
                path: "/",
                httpOnly: true,
                secure: true,
                sameSite: "Strict",
                maxAge: 60 * 60 * 24 * 7, // 7 days
            });

            return new Response(JSON.stringify({ session: data.session }), {
                status: 200,
                headers: { ...headers, "Content-Type": "application/json" }
            });
        }

        // --- POST: Login (Credentials Verification) ---
        if (req.method !== "POST") {
            return new Response("Method not allowed", { status: 405, headers });
        }
        const { email, password } = await req.json();

        if (!email || !password) {
            return new Response(JSON.stringify({ error: "Invalid credentials" }), {
                status: 400,
                headers: { ...headers, "Content-Type": "application/json" }
            });
        }

        // künstliches Delay gegen Timing Attacks (simuliert Argon2id Zeit)
        const startTime = Date.now();

        // 1. Hole den User anhand der Email über sicheren RPC (P2 Fix)
        const { data: users, error: userError } = await supabaseAdmin.rpc('get_user_id_by_email', { p_email: email });

        if (userError || !users || users.length === 0) {
            // Konstante Zeitverzögerung (Timing Attack Guard)
            await new Promise(r => setTimeout(r, 500 - (Date.now() - startTime)));
            return new Response(JSON.stringify({ error: "Invalid credentials" }), {
                status: 401,
                headers: { ...headers, "Content-Type": "application/json" }
            });
        }

        const user = users[0];

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

        // 4. Session generieren (BFF Pattern - OTP Hack)
        // Wir fordern eine Magic Link Generierung vom Admin, konvertieren sie zu OTP, um eine valide GoTrue
        // Session für das Frontend auszustellen!
        const { data: linkData, error: linkError } = await supabaseAdmin.auth.admin.generateLink({
            type: 'magiclink',
            email: email,
        });

        if (linkError || !linkData.properties?.action_link) {
            throw new Error("Failed to generate session link");
        }

        const url = new URL(linkData.properties.action_link);
        const token = url.searchParams.get('token');

        if (!token) throw new Error("No token in magic link");

        // Wir verifizieren den Token mit dem generellen Supabase Client (Anonym)
        const { data: sessionData, error: verifyError } = await supabaseAdmin.auth.verifyOtp({
            email,
            token,
            type: 'magiclink'
        });

        if (verifyError || !sessionData.session) {
            throw new Error("Failed to verify OTP for session");
        }

        // Secure, HttpOnly, SameSite=Strict Setzen (nur refresh_token im Backend!)
        setCookie(headers, {
            name: "sb-bff-session",
            value: sessionData.session.refresh_token,
            path: "/",
            httpOnly: true,
            secure: true,
            sameSite: "Strict",
            maxAge: 60 * 60 * 24 * 7, // 7 Days
        });

        return new Response(JSON.stringify({ success: true, session: sessionData.session }), {
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
