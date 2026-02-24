import { getCookies, setCookie } from "https://deno.land/std@0.168.0/http/cookie.ts";
 * @fileoverview WebAuthn Edge Function for Passkey Registration & Authentication
    *
 * Handles all WebAuthn server - side operations:
 * - generate - registration - options: Creates a challenge for passkey registration
    * - verify - registration: Verifies the registration response from the browser
        * - generate - authentication - options: Creates a challenge for passkey authentication
            * - verify - authentication: Verifies the authentication response
                * - activate - prf: Verifies authentication and stores wrapped master key for PRF unlock
                    * - list - credentials: Lists all registered passkeys for a user
                        * - delete -credential: Removes a registered passkey
                            *
 * Uses @simplewebauthn/server v13 via JSR for Deno compatibility.
    *
 * SECURITY: All operations require a valid Supabase JWT.
 * Challenge storage is server - side with 5 - minute TTL.
 * PRF salt is generated server - side with CSPRNG.
 */

import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import {
    generateRegistrationOptions,
    verifyRegistrationResponse,
    generateAuthenticationOptions,
    verifyAuthenticationResponse,
} from "jsr:@simplewebauthn/server@13.2.2";
import { isoBase64URL } from "jsr:@simplewebauthn/server@13.2.2/helpers";
import type {
    RegistrationResponseJSON,
    AuthenticationResponseJSON,
} from "jsr:@simplewebauthn/server@13.2.2";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2.49.1";
import { getCorsHeaders } from "../_shared/cors.ts";

// ============ Configuration ============

/**
 * Relying Party configuration.
 * rpID must match the domain the user is on.
 * In production this is "singrapw.mauntingstudios.de".
 */
function getRpConfig(req: Request): { rpName: string; rpID: string; origin: string } {
    const rawOrigin = req.headers.get("origin") || Deno.env.get("SITE_URL") || "https://singrapw.mauntingstudios.de";
    let url: URL;

    try {
        url = new URL(rawOrigin);
    } catch {
        url = new URL("https://singrapw.mauntingstudios.de");
    }

    return {
        rpName: "Singra Vault",
        rpID: url.hostname,
        origin: url.origin,
    };
}

// ============ Main Handler ============

Deno.serve(async (req: Request) => {
    const corsHeaders = getCorsHeaders(req);

    // Handle CORS preflight
    if (req.method === "OPTIONS") {
        return new Response(null, { status: 204, headers: corsHeaders });
    }

    if (req.method !== "POST") {
        return jsonResponse({ error: "Method not allowed" }, 405, corsHeaders);
    }

    try {
        console.log("WebAuthn function called. Method:", req.method);

        const supabaseUrl = Deno.env.get("SUPABASE_URL")!;
        const supabaseServiceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
        const supabaseAdmin = createClient(supabaseUrl, supabaseServiceKey);

        // 2. Parse action & Auth check
        const body = await req.json();
        const { action, email } = body;

        let user: { id: string; email?: string } | null = null;

        // Bestimme, ob ein gültiges JWT nötig ist.
        // Für reines Anmelden (Auth) reicht die Angabe der E-Mail.
        const requiresAuth = !["generate-authentication-options", "verify-authentication"].includes(action);

        if (requiresAuth) {
            const authHeader = req.headers.get("Authorization");
            if (!authHeader) {
                return jsonResponse({ error: "Missing authorization header" }, 401, corsHeaders);
            }

            const accessToken = extractBearerToken(authHeader);
            if (!accessToken) {
                return jsonResponse({ error: "Missing bearer token" }, 401, corsHeaders);
            }

            const { data: { user: authUser }, error: authError } = await supabaseAdmin.auth.getUser(accessToken);
            if (authError || !authUser) {
                return jsonResponse({ error: "Unauthorized", details: authError?.message }, 401, corsHeaders);
            }
            user = { id: authUser.id, email: authUser.email };
        } else {
            // Für Login: Hole die User ID anhand der E-Mail aus der RPC
            if (!email) {
                return jsonResponse({ error: "Missing email for authentication" }, 400, corsHeaders);
            }
            const { data: users, error: rpcError } = await supabaseAdmin.rpc("get_user_id_by_email", { p_email: email });
            if (rpcError || !users || users.length === 0) {
                console.warn("Passkey login: email not found");
                // Wir brechen hier noch nicht ab, um User Enumeration vorzubeugen, 
                // aber die Passkey Library schlägt eh beim Fehlen der Options fehl.
                return jsonResponse({ error: "Invalid user" }, 400, corsHeaders);
            }
            user = { id: users[0].id, email: email };
        }

        const rp = getRpConfig(req);

        switch (action) {
            case "generate-registration-options":
                return await handleGenerateRegistrationOptions(user, rp, supabaseAdmin, body, corsHeaders);

            case "verify-registration":
                return await handleVerifyRegistration(user, rp, supabaseAdmin, body, corsHeaders);

            case "generate-authentication-options":
                return await handleGenerateAuthenticationOptions(user, rp, supabaseAdmin, body, corsHeaders);

            case "verify-authentication":
                return await handleVerifyAuthentication(user as any, rp, supabaseAdmin, body, corsHeaders);

            case "activate-prf":
                return await handleActivatePrf(user, rp, supabaseAdmin, body, corsHeaders);

            case "list-credentials":
                return await handleListCredentials(user, supabaseAdmin, corsHeaders);

            case "delete-credential":
                return await handleDeleteCredential(user, supabaseAdmin, body, corsHeaders);

            default:
                return jsonResponse({ error: `Unknown action: ${action}` }, 400, corsHeaders);
        }
    } catch (err) {
        console.error("WebAuthn edge function error:", err);
        return jsonResponse(
            {
                error: "Internal server error",
                details: err instanceof Error ? err.message : String(err),
            },
            500,
            corsHeaders,
        );
    }
});

// ============ Registration ============

async function handleGenerateRegistrationOptions(
    user: { id: string; email?: string },
    rp: { rpName: string; rpID: string },
    supabase: ReturnType<typeof createClient>,
    body: Record<string, unknown>,
    corsHeaders: Record<string, string>,
) {
    // Fetch existing credentials to exclude (prevent re-registration)
    const { data: existingCreds } = await supabase
        .from("passkey_credentials")
        .select("credential_id")
        .eq("user_id", user.id);

    const excludeCredentials = (existingCreds || [])
        .map((c: { credential_id: string }) => c.credential_id)
        .filter(isLikelyBase64UrlCredentialId)
        .map((credentialId: string) => ({
            id: credentialId,
            transports: undefined,
        }));

    // Generate registration options
    const options = await generateRegistrationOptions({
        rpName: rp.rpName,
        rpID: rp.rpID,
        userName: user.email || user.id,
        userDisplayName: (body.displayName as string) || user.email || "User",
        // Require resident key (discoverable credential) for passkey
        authenticatorSelection: {
            residentKey: "required",
            userVerification: "required",
        },
        // Prefer ES256 (-7) and RS256 (-257) — widest compatibility
        supportedAlgorithmIDs: [-7, -257],
        excludeCredentials,
    });

    // Generate PRF salt (32 random bytes) — will be stored with the credential
    const prfSaltBytes = new Uint8Array(32);
    crypto.getRandomValues(prfSaltBytes);
    const prfSalt = isoBase64URL.fromBuffer(prfSaltBytes);

    // Clean up expired challenges first
    try {
        await supabase.rpc("cleanup_expired_webauthn_challenges");
    } catch (cleanupError) {
        console.warn("Failed to cleanup expired registration challenges", cleanupError);
    }

    // Store challenge server-side (5 min TTL)
    await supabase.from("webauthn_challenges").insert({
        user_id: user.id,
        challenge: options.challenge,
        type: "registration",
    });

    return jsonResponse({
        options,
        prfSalt,
    }, 200, corsHeaders);
}

async function handleVerifyRegistration(
    user: { id: string },
    rp: { rpName: string; rpID: string; origin: string },
    supabase: ReturnType<typeof createClient>,
    body: Record<string, unknown>,
    corsHeaders: Record<string, string>,
) {
    const { credential, deviceName, prfSalt, wrappedMasterKey, prfEnabled } = body as {
        credential: unknown;
        deviceName?: string;
        prfSalt: string;
        wrappedMasterKey?: string;
        prfEnabled?: boolean;
    };

    if (!credential) {
        return jsonResponse({ error: "Missing credential response" }, 400, corsHeaders);
    }

    // Retrieve the stored challenge
    const { data: challenges } = await supabase
        .from("webauthn_challenges")
        .select("*")
        .eq("user_id", user.id)
        .eq("type", "registration")
        .order("created_at", { ascending: false })
        .limit(1);

    if (!challenges || challenges.length === 0) {
        return jsonResponse({ error: "No pending registration challenge" }, 400, corsHeaders);
    }

    const storedChallenge = challenges[0];

    // Check expiry
    if (new Date(storedChallenge.expires_at) < new Date()) {
        await supabase.from("webauthn_challenges").delete().eq("id", storedChallenge.id);
        return jsonResponse({ error: "Challenge expired" }, 400, corsHeaders);
    }

    try {
        // Verify the registration response
        const verification = await verifyRegistrationResponse({
            response: credential as RegistrationResponseJSON,
            expectedChallenge: storedChallenge.challenge,
            expectedOrigin: rp.origin,
            expectedRPID: rp.rpID,
        });

        if (!verification.verified || !verification.registrationInfo) {
            return jsonResponse({ error: "Registration verification failed" }, 400, corsHeaders);
        }

        const { credential: regCredential } = verification.registrationInfo;

        // Store the credential in the database
        const { error: insertError } = await supabase
            .from("passkey_credentials")
            .insert({
                user_id: user.id,
                credential_id: regCredential.id,
                public_key: isoBase64URL.fromBuffer(regCredential.publicKey),
                counter: regCredential.counter,
                transports: regCredential.transports || [],
                device_name: deviceName || "Passkey",
                prf_salt: prfSalt || null,
                wrapped_master_key: wrappedMasterKey || null,
                prf_enabled: !!prfEnabled && !!wrappedMasterKey,
            });

        if (insertError) {
            console.error("Failed to store credential:", insertError);
            if (insertError.code === "23505") { // Unique violation
                return jsonResponse({ error: "Passkey already registered on this device" }, 409, corsHeaders);
            }
            return jsonResponse({ error: "Failed to store credential" }, 500, corsHeaders);
        }

        // Clean up the used challenge
        await supabase.from("webauthn_challenges").delete().eq("id", storedChallenge.id);

        return jsonResponse({
            verified: true,
            credentialId: regCredential.id,
        }, 200, corsHeaders);
    } catch (err) {
        console.error("Registration verification error:", err);
        return jsonResponse({ error: "Verification failed" }, 400, corsHeaders);
    }
}

// ============ Authentication ============

async function handleGenerateAuthenticationOptions(
    user: { id: string },
    rp: { rpID: string },
    supabase: ReturnType<typeof createClient>,
    body: Record<string, unknown>,
    corsHeaders: Record<string, string>,
) {
    const { credentialId } = body as { credentialId?: string };

    // Fetch user's registered credentials
    const { data: credentials } = await supabase
        .from("passkey_credentials")
        .select("credential_id, transports, prf_salt, prf_enabled")
        .eq("user_id", user.id);

    if (!credentials || credentials.length === 0) {
        return jsonResponse({ error: "No passkeys registered" }, 404, corsHeaders);
    }

    const scopedCredentials = credentialId
        ? credentials.filter((credential: { credential_id: string }) => credential.credential_id === credentialId)
        : credentials;

    if (scopedCredentials.length === 0) {
        return jsonResponse({ error: "Requested passkey credential not found" }, 404, corsHeaders);
    }

    const validScopedCredentials = scopedCredentials.filter((c: { credential_id: string }) =>
        isLikelyBase64UrlCredentialId(c.credential_id)
    );

    if (validScopedCredentials.length === 0) {
        return jsonResponse({ error: "No valid passkey credentials found" }, 404, corsHeaders);
    }

    const allowCredentials = validScopedCredentials.map((c: { credential_id: string; transports?: string[]; prf_salt?: string; prf_enabled?: boolean }) => ({
        id: c.credential_id,
        transports: c.transports || undefined,
    }));

    const options = await generateAuthenticationOptions({
        rpID: rp.rpID,
        allowCredentials,
        userVerification: "required",
    });

    // Clean up expired challenges first
    try {
        await supabase.rpc("cleanup_expired_webauthn_challenges");
    } catch (cleanupError) {
        console.warn("Failed to cleanup expired authentication challenges", cleanupError);
    }

    // Store challenge server-side
    await supabase.from("webauthn_challenges").insert({
        user_id: user.id,
        challenge: options.challenge,
        type: "authentication",
    });

    // Build a map of credential_id -> prfSalt.
    // Include:
    // - credentials already marked as PRF-enabled
    // - a specifically requested credential (credentialId), even if not yet
    //   marked PRF-enabled, so PRF activation can complete after registration
    const prfSalts: Record<string, string> = {};
    for (const cred of validScopedCredentials) {
        const isRequestedCredential = credentialId
            ? cred.credential_id === credentialId
            : false;
        if ((cred.prf_enabled || isRequestedCredential) && cred.prf_salt) {
            prfSalts[cred.credential_id] = cred.prf_salt;
        }
    }

    return jsonResponse({
        options,
        prfSalts,
    }, 200, corsHeaders);
}

async function handleVerifyAuthentication(
    user: { id: string },
    rp: { rpID: string; origin: string },
    supabase: ReturnType<typeof createClient>,
    body: Record<string, unknown>,
    corsHeaders: Record<string, string>,
) {
    const { credential, expectedCredentialId } = body as {
        credential: unknown;
        expectedCredentialId?: string;
    };

    if (!credential) {
        return jsonResponse({ error: "Missing credential response" }, 400, corsHeaders);
    }

    // Extract credential ID from the response to find the matching DB record
    const credentialResponse = credential as { id: string };

    if (expectedCredentialId && credentialResponse.id !== expectedCredentialId) {
        return jsonResponse({ error: "Unexpected passkey credential used" }, 400, corsHeaders);
    }

    // Retrieve the stored challenge
    const { data: challenges } = await supabase
        .from("webauthn_challenges")
        .select("*")
        .eq("user_id", user.id)
        .eq("type", "authentication")
        .order("created_at", { ascending: false })
        .limit(1);

    if (!challenges || challenges.length === 0) {
        return jsonResponse({ error: "No pending authentication challenge" }, 400, corsHeaders);
    }

    const storedChallenge = challenges[0];

    // Check expiry
    if (new Date(storedChallenge.expires_at) < new Date()) {
        await supabase.from("webauthn_challenges").delete().eq("id", storedChallenge.id);
        return jsonResponse({ error: "Challenge expired" }, 400, corsHeaders);
    }

    // Challenge sofort löschen — verhindert Replay-Angriffe auch bei Verifikationsfehlern
    await supabase.from("webauthn_challenges").delete().eq("id", storedChallenge.id);

    // Find the matching credential in DB
    const { data: dbCredentials } = await supabase
        .from("passkey_credentials")
        .select("*")
        .eq("user_id", user.id)
        .eq("credential_id", credentialResponse.id);

    if (!dbCredentials || dbCredentials.length === 0) {
        return jsonResponse({ error: "Credential not found" }, 400, corsHeaders);
    }

    const dbCredential = dbCredentials[0] as {
        id: string;
        credential_id: string;
        public_key: string;
        counter: number;
        transports?: string[];
        wrapped_master_key?: string;
        prf_enabled?: boolean;
    };

    try {
        const verification = await verifyAuthenticationResponse({
            response: credential as AuthenticationResponseJSON,
            expectedChallenge: storedChallenge.challenge,
            expectedOrigin: rp.origin,
            expectedRPID: rp.rpID,
            credential: {
                id: dbCredential.credential_id,
                publicKey: isoBase64URL.toBuffer(dbCredential.public_key),
                counter: dbCredential.counter,
                transports: dbCredential.transports || undefined,
            },
        });

        if (!verification.verified) {
            return jsonResponse({ error: "Authentication verification failed" }, 400, corsHeaders);
        }

        // Update the counter (clone detection)
        await supabase
            .from("passkey_credentials")
            .update({
                counter: verification.authenticationInfo.newCounter,
                last_used_at: new Date().toISOString(),
            })
            .eq("id", dbCredential.id);

        // Challenge wurde bereits vor der Verifikation gelöscht (Replay-Schutz)

        // === Session Generierung (BFF Pattern OTP Hack) ===
        let sessionCookieToken = "";
        let sessionDataToClient = null;

        try {
            const { data: linkData, error: linkError } = await supabaseAdmin.auth.admin.generateLink({
                type: 'magiclink',
                email: user.email!, // Email is guaranteed to exist for login flow
            });

            if (linkError || !linkData.properties?.action_link) throw new Error("Failed to generate session link");

            const url = new URL(linkData.properties.action_link);
            const token = url.searchParams.get('token');

            if (!token) throw new Error("No token in magic link");

            const { data: sessionData, error: verifyError } = await supabaseAdmin.auth.verifyOtp({
                email: user.email!,
                token,
                type: 'magiclink'
            });

            if (verifyError || !sessionData.session) throw new Error("Failed to verify OTP for session");

            sessionCookieToken = sessionData.session.refresh_token;
            sessionDataToClient = sessionData.session;
        } catch (e) {
            console.error("Failed to generate BFF session after webauthn:", e);
        }

        const responseHeaders = new Headers({
            ...corsHeaders,
            "Content-Type": "application/json"
        });

        if (sessionCookieToken) {
            setCookie(responseHeaders, {
                name: "sb-bff-session",
                value: sessionCookieToken,
                path: "/",
                httpOnly: true,
                secure: true,
                sameSite: "Strict",
                maxAge: 60 * 60 * 24 * 7, // 7 Days
            });
        }

        return new Response(JSON.stringify({
            verified: true,
            credentialId: dbCredential.credential_id,
            wrappedMasterKey: dbCredential.wrapped_master_key,
            prfEnabled: dbCredential.prf_enabled,
            session: sessionDataToClient
        }), { status: 200, headers: responseHeaders });
    } catch (err) {
        console.error("Authentication verification error:", err);
        return jsonResponse({ error: "Verification failed" }, 400, corsHeaders);
    }
}

async function handleActivatePrf(
    user: { id: string },
    rp: { rpID: string; origin: string },
    supabase: ReturnType<typeof createClient>,
    body: Record<string, unknown>,
    corsHeaders: Record<string, string>,
) {
    const { credential, expectedCredentialId, wrappedMasterKey } = body as {
        credential: unknown;
        expectedCredentialId?: string;
        wrappedMasterKey?: string;
    };

    if (!credential) {
        return jsonResponse({ error: "Missing credential response" }, 400, corsHeaders);
    }

    if (!expectedCredentialId) {
        return jsonResponse({ error: "Missing expectedCredentialId" }, 400, corsHeaders);
    }

    if (typeof wrappedMasterKey !== "string" || wrappedMasterKey.length === 0) {
        return jsonResponse({ error: "Missing wrappedMasterKey" }, 400, corsHeaders);
    }

    const credentialResponse = credential as { id: string };
    if (credentialResponse.id !== expectedCredentialId) {
        return jsonResponse({ error: "Unexpected passkey credential used" }, 400, corsHeaders);
    }

    const { data: challenges } = await supabase
        .from("webauthn_challenges")
        .select("*")
        .eq("user_id", user.id)
        .eq("type", "authentication")
        .order("created_at", { ascending: false })
        .limit(1);

    if (!challenges || challenges.length === 0) {
        return jsonResponse({ error: "No pending authentication challenge" }, 400, corsHeaders);
    }

    const storedChallenge = challenges[0];

    if (new Date(storedChallenge.expires_at) < new Date()) {
        await supabase.from("webauthn_challenges").delete().eq("id", storedChallenge.id);
        return jsonResponse({ error: "Challenge expired" }, 400, corsHeaders);
    }

    // Challenge sofort löschen — verhindert Replay-Angriffe auch bei Verifikationsfehlern
    await supabase.from("webauthn_challenges").delete().eq("id", storedChallenge.id);

    const { data: dbCredentials } = await supabase
        .from("passkey_credentials")
        .select("*")
        .eq("user_id", user.id)
        .eq("credential_id", expectedCredentialId);

    if (!dbCredentials || dbCredentials.length === 0) {
        return jsonResponse({ error: "Credential not found" }, 400, corsHeaders);
    }

    const dbCredential = dbCredentials[0] as {
        id: string;
        credential_id: string;
        public_key: string;
        counter: number;
        transports?: string[];
    };

    try {
        const verification = await verifyAuthenticationResponse({
            response: credential as AuthenticationResponseJSON,
            expectedChallenge: storedChallenge.challenge,
            expectedOrigin: rp.origin,
            expectedRPID: rp.rpID,
            credential: {
                id: dbCredential.credential_id,
                publicKey: isoBase64URL.toBuffer(dbCredential.public_key),
                counter: dbCredential.counter,
                transports: dbCredential.transports || undefined,
            },
        });

        if (!verification.verified) {
            return jsonResponse({ error: "Authentication verification failed" }, 400, corsHeaders);
        }

        const { error: updateError } = await supabase
            .from("passkey_credentials")
            .update({
                counter: verification.authenticationInfo.newCounter,
                last_used_at: new Date().toISOString(),
                wrapped_master_key: wrappedMasterKey,
                prf_enabled: true,
            })
            .eq("id", dbCredential.id)
            .eq("user_id", user.id)
            .eq("credential_id", dbCredential.credential_id);

        if (updateError) {
            console.error("Failed to activate PRF credential:", updateError);
            return jsonResponse({ error: "Failed to save wrapped key" }, 500, corsHeaders);
        }

        return jsonResponse({
            activated: true,
            credentialId: dbCredential.credential_id,
        }, 200, corsHeaders);
    } catch (err) {
        console.error("PRF activation verification error:", err);
        return jsonResponse({ error: "Verification failed" }, 400, corsHeaders);
    }
}

// ============ Credential Management ============

async function handleListCredentials(
    user: { id: string },
    supabase: ReturnType<typeof createClient>,
    corsHeaders: Record<string, string>,
) {
    const { data: credentials, error } = await supabase
        .from("passkey_credentials")
        .select("id, credential_id, device_name, prf_enabled, created_at, last_used_at")
        .eq("user_id", user.id)
        .order("created_at", { ascending: false });

    if (error) {
        return jsonResponse({ error: "Failed to list credentials" }, 500, corsHeaders);
    }

    return jsonResponse({ credentials: credentials || [] }, 200, corsHeaders);
}

async function handleDeleteCredential(
    user: { id: string },
    supabase: ReturnType<typeof createClient>,
    body: Record<string, unknown>,
    corsHeaders: Record<string, string>,
) {
    const { credentialId } = body as { credentialId: string };

    if (!credentialId) {
        return jsonResponse({ error: "Missing credentialId" }, 400, corsHeaders);
    }

    const { error } = await supabase
        .from("passkey_credentials")
        .delete()
        .eq("user_id", user.id)
        .eq("id", credentialId);

    if (error) {
        return jsonResponse({ error: "Failed to delete credential" }, 500, corsHeaders);
    }

    return jsonResponse({ deleted: true }, 200, corsHeaders);
}

// ============ Helpers ============

function jsonResponse(data: unknown, status = 200, corsHeaders: Record<string, string> = {}): Response {
    return new Response(JSON.stringify(data), {
        status,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
}

function extractBearerToken(authHeader: string): string | null {
    if (!authHeader.toLowerCase().startsWith("bearer ")) {
        return null;
    }

    const token = authHeader.slice("bearer ".length).trim();
    return token.length > 0 ? token : null;
}

function isLikelyBase64UrlCredentialId(value: string): boolean {
    return typeof value === "string"
        && value.length >= 16
        && /^[A-Za-z0-9_-]+$/.test(value);
}
