import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import { getCookies, setCookie } from "https://deno.land/std@0.168.0/http/cookie.ts";
import { argon2Verify } from "npm:hash-wasm";
import { createClient } from "npm:@supabase/supabase-js@2";
import { getCorsHeaders } from "../_shared/cors.ts";

const supabaseUrl = Deno.env.get("SUPABASE_URL")!;
const supabaseServiceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
const supabaseAdmin = createClient(supabaseUrl, supabaseServiceKey);

Deno.serve(async (req) => {
    const corsHeaders = getCorsHeaders(req);

    // Credentials explizit für Cookies erlauben, aber Origin NICHT reflektieren!
    // getCorsHeaders liefert den strikten CORS-Header bereits sicher zurück.
    const headers = new Headers({
        ...corsHeaders,
        "Access-Control-Allow-Credentials": "true",
    });
    const jsonHeaders = (): Headers => {
        const responseHeaders = new Headers(headers);
        responseHeaders.set("Content-Type", "application/json");
        return responseHeaders;
    };

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
                headers: jsonHeaders()
            });
        }

        // --- GET: Session Hydration & Refresh ---
        if (req.method === "GET") {
            const cookies = getCookies(req.headers);
            const refreshToken = cookies["sb-bff-session"];

            if (!refreshToken) {
                return new Response(JSON.stringify({ error: "No session cookie" }), {
                    status: 401,
                    headers: jsonHeaders()
                });
            }

            // Refresh via Admin oder Anon Client
            const { data, error } = await supabaseAdmin.auth.refreshSession({ refresh_token: refreshToken });

            if (error || !data.session) {
                return new Response(JSON.stringify({ error: "Session expired" }), {
                    status: 401,
                    headers: jsonHeaders()
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
                headers: jsonHeaders()
            });
        }

        // --- POST: Login (Credentials Verification) ---
        if (req.method !== "POST") {
            return new Response("Method not allowed", { status: 405, headers });
        }
        const payload = await req.json();
        const { action } = payload;

        if (action === "oauth-sync") {
            const authHeader = req.headers.get("Authorization");
            const accessToken = parseBearerToken(authHeader);
            const refreshToken = typeof payload.refreshToken === "string" ? payload.refreshToken : null;
            const skipCookie = Boolean(payload.skipCookie);

            if (!accessToken || !refreshToken) {
                return new Response(JSON.stringify({ error: "Invalid oauth sync payload" }), {
                    status: 400,
                    headers: jsonHeaders(),
                });
            }

            const supabaseAnonKey = Deno.env.get("SUPABASE_ANON_KEY")!;
            const authClient = createClient(supabaseUrl, supabaseAnonKey, {
                global: { headers: { Authorization: `Bearer ${accessToken}` } },
            });

            const { data: authedUserData, error: authedUserError } = await authClient.auth.getUser();
            if (authedUserError || !authedUserData.user) {
                return new Response(JSON.stringify({ error: "Unauthorized" }), {
                    status: 401,
                    headers: jsonHeaders(),
                });
            }

            const { data: refreshedData, error: refreshError } = await supabaseAdmin.auth.refreshSession({
                refresh_token: refreshToken,
            });

            if (refreshError || !refreshedData.session) {
                return new Response(JSON.stringify({ error: "Session expired" }), {
                    status: 401,
                    headers: jsonHeaders(),
                });
            }

            if (refreshedData.session.user.id !== authedUserData.user.id) {
                return new Response(JSON.stringify({ error: "Session mismatch" }), {
                    status: 403,
                    headers: jsonHeaders(),
                });
            }

            if (!skipCookie) {
                setCookie(headers, {
                    name: "sb-bff-session",
                    value: refreshedData.session.refresh_token,
                    path: "/",
                    httpOnly: true,
                    secure: true,
                    sameSite: "None",
                    maxAge: 60 * 60 * 24 * 7, // 7 days
                });
            }

            return new Response(JSON.stringify({ success: true, session: refreshedData.session }), {
                status: 200,
                headers: jsonHeaders(),
            });
        }

        const { email, password, totpCode, isBackupCode, skipCookie } = payload;

        if (!email || !password) {
            return new Response(JSON.stringify({ error: "Invalid credentials" }), {
                status: 400,
                headers: jsonHeaders()
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
                headers: jsonHeaders()
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
                    headers: jsonHeaders()
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
                headers: jsonHeaders()
            });
        }

        // 3.2. Email Confirm Guard (Bug 16)
        const { data: adminUser, error: adminUserError } = await supabaseAdmin.auth.admin.getUserById(user.id);
        if (adminUserError || !adminUser.user.email_confirmed_at) {
            return new Response(JSON.stringify({ error: "Email verification required" }), {
                status: 403,
                headers: jsonHeaders()
            });
        }

        // 3.5. 2FA Check (Enforce 2FA before issuing session)
        const { data: user2fa } = await supabaseAdmin
            .from('user_2fa')
            .select('is_enabled')
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
                    headers: jsonHeaders()
                });
            }

            if (!isBackupCode) {
                // Fetch TOTP secret via secure RPC (decrypts server-side, never reads plaintext column)
                const { data: totpSecret, error: totpSecretError } = await supabaseAdmin.rpc('get_user_2fa_secret', {
                    p_user_id: user.id,
                    p_require_enabled: true,
                });

                if (totpSecretError || !totpSecret) {
                    return new Response(JSON.stringify({ error: "2FA configuration error" }), {
                        status: 500,
                        headers: jsonHeaders()
                    });
                }

                const OTPAuth = await import("npm:otpauth");
                const totp = new OTPAuth.TOTP({
                    issuer: 'Singra Vault',
                    algorithm: 'SHA1',
                    digits: 6,
                    period: 30,
                    secret: OTPAuth.Secret.fromBase32(totpSecret.replace(/\s/g, '')),
                });

                const delta = totp.validate({ token: totpCode.replace(/\s/g, ''), window: 1 });
                if (delta === null) {
                    await new Promise(r => setTimeout(r, 500));
                    return new Response(JSON.stringify({ error: "Invalid 2FA code" }), {
                        status: 401,
                        headers: jsonHeaders()
                    });
                }

                await supabaseAdmin.from('user_2fa').update({ last_verified_at: new Date().toISOString() }).eq('user_id', user.id);
            } else if (isBackupCode && totpCode) {
                // Backup Code Verification Path
                const { data: backupCodes } = await supabaseAdmin
                    .from('backup_codes')
                    .select('id, code_hash')
                    .eq('user_id', user.id)
                    .eq('is_used', false);

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
                        headers: jsonHeaders()
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
                    headers: jsonHeaders()
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

        // Nutze den hashed_token aus generateLink (PKCE-kompatibel)
        const tokenHash = linkData.properties.hashed_token;

        if (!tokenHash) throw new Error("No hashed_token in generateLink response");

        // Verifiziere den Token über token_hash (korrekte API seit Supabase PKCE)
        const { data: sessionData, error: verifyError } = await supabaseAdmin.auth.verifyOtp({
            token_hash: tokenHash,
            type: 'magiclink'
        });

        if (verifyError || !sessionData.session) {
            throw new Error("Failed to verify OTP for session");
        }

        // Secure, HttpOnly Cookie nur setzen wenn nicht im Iframe-Modus
        if (!skipCookie) {
            setCookie(headers, {
                name: "sb-bff-session",
                value: sessionData.session.refresh_token,
                path: "/",
                httpOnly: true,
                secure: true,
                sameSite: "None",
                maxAge: 60 * 60 * 24 * 7, // 7 Days
            });
        }

        return new Response(JSON.stringify({ success: true, session: sessionData.session }), {
            status: 200,
            headers: jsonHeaders()
        });

    } catch (err: any) {
        console.error("Auth Session Error:", err);
        return new Response(JSON.stringify({ error: "Internal Server Error" }), {
            status: 500,
            headers: jsonHeaders()
        });
    }
});

function parseBearerToken(authHeader: string | null): string | null {
    if (!authHeader) {
        return null;
    }

    if (authHeader.startsWith("Bearer ")) {
        const token = authHeader.slice("Bearer ".length).trim();
        return token || null;
    }

    const token = authHeader.trim();
    return token || null;
}

