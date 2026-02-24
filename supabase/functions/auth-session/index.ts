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

    // Credentials explizit für Cookies erlauben, aber Origin NICHT reflektieren!
    // getCorsHeaders liefert den strikten CORS-Header bereits sicher zurück.
    const headers = new Headers({
        ...corsHeaders,
        "Access-Control-Allow-Credentials": "true",
        "Content-Type": "application/json"
    });

    if (req.method === "OPTIONS") {
        return new Response("ok", { headers });
    }

    try {
        // --- DELETE: Session Invalidation ---
        if (req.method === "DELETE") {
            setCookie(headers, {
                name: "sb-bff-session",
                value: "",
                path: "/",
                httpOnly: true,
                secure: true,
                sameSite: "None",
                maxAge: 0, // expire immediately
            });
            return new Response(JSON.stringify({ success: true }), {
                status: 200,
                headers
            });
        }

        // --- GET: Session Hydration & Refresh ---
        if (req.method === "GET") {
            const cookies = getCookies(req.headers);
            const refreshToken = cookies["sb-bff-session"];

            if (!refreshToken) {
                return new Response(JSON.stringify({ error: "No session cookie" }), {
                    status: 401,
                    headers
                });
            }

            // Refresh via Admin oder Anon Client
            const { data, error } = await supabaseAdmin.auth.refreshSession({ refresh_token: refreshToken });

            if (error || !data.session) {
                return new Response(JSON.stringify({ error: "Session expired" }), {
                    status: 401,
                    headers
                });
            }

            // Neues Cookie setzen
            setCookie(headers, {
                name: "sb-bff-session",
                value: data.session.refresh_token,
                path: "/",
                httpOnly: true,
                secure: true,
                sameSite: "None",
                maxAge: 60 * 60 * 24 * 7, // 7 days
            });

            return new Response(JSON.stringify({ session: data.session }), {
                status: 200,
                headers
            });
        }

        // --- PUT: Sync OAuth/External Session to Cookie ---
        if (req.method === "PUT") {
            const authHeader = req.headers.get("Authorization");
            if (!authHeader || !authHeader.startsWith("Bearer ")) {
                return new Response(JSON.stringify({ error: "Missing token" }), { status: 401, headers });
            }

            const jwt = authHeader.replace("Bearer ", "");
            // Verify that the JWT is actually valid and belongs to a user
            const { data: { user }, error: authError } = await supabaseAdmin.auth.getUser(jwt);

            if (authError || !user) {
                return new Response(JSON.stringify({ error: "Invalid token" }), { status: 401, headers });
            }

            const { refresh_token } = await req.json();

            if (!refresh_token) {
                return new Response(JSON.stringify({ error: "Missing refresh_token" }), { status: 400, headers });
            }

            setCookie(headers, {
                name: "sb-bff-session",
                value: refresh_token,
                path: "/",
                httpOnly: true,
                secure: true,
                sameSite: "None",
                maxAge: 60 * 60 * 24 * 7, // 7 Days
            });

            return new Response(JSON.stringify({ success: true }), {
                status: 200,
                headers
            });
        }

        // --- POST: Login (Credentials Verification) ---
        if (req.method !== "POST") {
            return new Response("Method not allowed", { status: 405, headers });
        }
        const { email, password, totpCode, isBackupCode } = await req.json();

        if (!email || !password) {
            return new Response(JSON.stringify({ error: "Invalid credentials" }), {
                status: 400,
                headers
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
                headers
            });
        }

        const user = users[0];

        // 2. Lade den Argon2id Hash
        const { data: secData, error: secError } = await supabaseAdmin
            .from('user_security')
            .select('argon2_hash')
            .eq('id', user.id)
            .single();

        let credentialsValid = false;

        if (secError || !secData) {
            // Legacy GoTrue Fallback (Bug 15)
            const { data: fallbackAuth, error: fallbackError } = await supabaseAdmin.auth.signInWithPassword({
                email,
                password
            });

            if (fallbackError || !fallbackAuth.user) {
                await new Promise(r => setTimeout(r, Math.max(0, 500 - (Date.now() - startTime))));
                return new Response(JSON.stringify({ error: "Invalid credentials" }), {
                    status: 401,
                    headers
                });
            }
            credentialsValid = true;
        } else {
            // 3. Verifiziere das Passwort mit Argon2id
            credentialsValid = await argon2Verify({ password, hash: secData.argon2_hash });
        }

        if (!credentialsValid) {
            await new Promise(r => setTimeout(r, Math.max(0, 500 - (Date.now() - startTime))));
            return new Response(JSON.stringify({ error: "Invalid credentials" }), {
                status: 401,
                headers
            });
        }

        // 3.2. Email Confirm Guard (Bug 16)
        const { data: adminUser, error: adminUserError } = await supabaseAdmin.auth.admin.getUserById(user.id);
        if (adminUserError || !adminUser.user.email_confirmed_at) {
            return new Response(JSON.stringify({ error: "Email verification required" }), {
                status: 403,
                headers
            });
        }

        // 3.5. 2FA Check (Enforce 2FA before issuing session)
        const { data: user2fa } = await supabaseAdmin
            .from('user_2fa')
            .select('is_enabled, totp_secret')
            .eq('user_id', user.id)
            .single();

        if (user2fa?.is_enabled) {
            if (!totpCode && !isBackupCode) {
                // Password correct, but 2FA required. Do NOT issue BFF session yet.
                return new Response(JSON.stringify({
                    requires2FA: true,
                    userId: user.id
                }), {
                    status: 200,
                    headers
                });
            }

            if (!isBackupCode) {
                const OTPAuth = await import("npm:otpauth");
                const totp = new OTPAuth.TOTP({
                    issuer: 'Singra Vault',
                    algorithm: 'SHA1',
                    digits: 6,
                    period: 30,
                    secret: OTPAuth.Secret.fromBase32(user2fa.totp_secret.replace(/\s/g, '')),
                });

                const delta = totp.validate({ token: totpCode.replace(/\s/g, ''), window: 1 });
                if (delta === null) {
                    await new Promise(r => setTimeout(r, 500));
                    return new Response(JSON.stringify({ error: "Invalid 2FA code" }), {
                        status: 401,
                        headers
                    });
                }

                await supabaseAdmin.from('user_2fa').update({ last_verified_at: new Date().toISOString() }).eq('user_id', user.id);
            } else if (isBackupCode && totpCode) {
                // Backup Code Verification Path
                const { data: backupCodes } = await supabaseAdmin
                    .from('backup_codes')
                    .select('id, code_hash')
                    .eq('user_id', user.id)
                    .eq('used', false);

                let validCodeId = null;

                if (backupCodes && backupCodes.length > 0) {
                    for (const bc of backupCodes) {
                        const isMatch = await argon2Verify({ password: totpCode.replace(/\s/g, ''), hash: bc.code_hash });
                        if (isMatch) {
                            validCodeId = bc.id;
                            break;
                        }
                    }
                }

                if (!validCodeId) {
                    await new Promise(r => setTimeout(r, 500));
                    return new Response(JSON.stringify({ error: "Invalid backup code" }), {
                        status: 401,
                        headers
                    });
                }

                // Mark the specific Backup Code as used
                await supabaseAdmin
                    .from('backup_codes')
                    .update({
                        used: true,
                        used_at: new Date().toISOString()
                    })
                    .eq('id', validCodeId);

                await supabaseAdmin.from('user_2fa').update({ last_verified_at: new Date().toISOString() }).eq('user_id', user.id);
            } else {
                return new Response(JSON.stringify({ error: "Invalid request payload" }), {
                    status: 400,
                    headers
                });
            }
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
            sameSite: "None",
            maxAge: 60 * 60 * 24 * 7, // 7 Days
        });

        return new Response(JSON.stringify({ success: true, session: sessionData.session }), {
            status: 200,
            headers
        });

    } catch (err: any) {
        console.error("Auth Session Error:", err);
        return new Response(JSON.stringify({ error: "Internal Server Error" }), {
            status: 500,
            headers
        });
    }
});
