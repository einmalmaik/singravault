/**
 * @fileoverview WebAuthn Edge Function for Passkey Registration & Authentication 
 *
 * Handles all WebAuthn server-side operations:
 * - generate-registration-options: Creates a challenge for passkey registration
 * - verify-registration: Verifies the registration response from the browser
 * - generate-authentication-options: Creates a challenge for passkey authentication
 * - verify-authentication: Verifies the authentication response
 * - activate-prf: Verifies authentication and stores wrapped master key for PRF unlock
 * - upgrade-wrapped-key: Verifies authentication and rotates legacy wrapped key material
 * - list-credentials: Lists all registered passkeys for a user
 * - delete-credential: Removes a registered passkey
 *
 * Uses @simplewebauthn/server v13 via JSR for Deno compatibility.
 *
 * SECURITY: All operations require a valid Supabase JWT.
 * Challenge storage is server-side with 5-minute TTL.
 * PRF salt is generated server-side with CSPRNG.
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
import {
    FIRST_PARTY_DESKTOP_ORIGINS,
    FIRST_PARTY_LOCAL_DEV_ORIGINS,
} from "../_shared/desktopOrigins.ts";
import {
    authorizeWebauthnAction,
    isWebauthnAction,
    type WebauthnAction,
} from "./authPolicy.ts";
import {
    authRateLimitResponse,
    checkAuthRateLimit,
    recordAuthRateLimitFailure,
    resetAuthRateLimit,
    type AuthRateLimitAction,
    type AuthRateLimitState,
} from "../_shared/authRateLimit.ts";

const DEFAULT_SITE_URL = "https://singravault.mauntingstudios.de";
const CONFIGURED_SITE_ORIGIN = normalizeHttpOrigin(Deno.env.get("SITE_URL")) ?? DEFAULT_SITE_URL;
const CONFIGURED_SITE_RP_ID = new URL(CONFIGURED_SITE_ORIGIN).hostname;

type RpConfig = ReturnType<typeof getRpConfig>;

interface StoredWebauthnChallenge {
    id: string;
    challenge: string;
    type: "registration" | "authentication";
    expires_at: string;
    rp_id?: string | null;
    origin?: string | null;
    credential_id?: string | null;
}

// ============ Configuration ============

/**
 * Relying Party configuration.
 * The active request origin decides the registration RP ID. Verification accepts
 * known first-party Web and Tauri origins so Web and Desktop can coexist
 * without forking the WebAuthn implementation.
 */
function getRpConfig(req: Request): {
    rpName: string;
    rpID: string;
    origin: string;
    expectedOrigins: string[];
    expectedRPIDs: string[];
} {
    const requestedOrigin = normalizeHttpOrigin(req.headers.get("origin"));
    const primaryOrigin = requestedOrigin ?? CONFIGURED_SITE_ORIGIN;
    const expectedOrigins = dedupeOrigins([
        primaryOrigin,
        CONFIGURED_SITE_ORIGIN,
        ...FIRST_PARTY_LOCAL_DEV_ORIGINS,
        ...FIRST_PARTY_DESKTOP_ORIGINS,
    ]);

    return {
        rpName: "Singra Vault",
        rpID: new URL(primaryOrigin).hostname,
        origin: primaryOrigin,
        expectedOrigins,
        expectedRPIDs: dedupeRpIds(expectedOrigins),
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
        const { action } = body;

        if (!isWebauthnAction(action)) {
            return jsonResponse({ error: `Unknown action: ${String(action)}` }, 400, corsHeaders);
        }

        let user: { id: string; email?: string } | null = null;

        const authHeader = req.headers.get("Authorization");
        const accessToken = authHeader ? extractBearerToken(authHeader) : null;
        let authErrorDetails = null;

        if (accessToken) {
            const { data: { user: authUser }, error: authError } = await supabaseAdmin.auth.getUser(accessToken);
            if (!authError && authUser) {
                user = { id: authUser.id, email: authUser.email };
            } else {
                authErrorDetails = authError?.message;
            }
        }

        // WebAuthn here extends vault unlock for an already authenticated app
        // identity. It must not become a parallel login channel.
        const authz = authorizeWebauthnAction(action, user, authErrorDetails);
        if (!authz.ok) {
            return jsonResponse(authz.body, authz.status, corsHeaders);
        }
        user = authz.user;

        const rateLimitState = await checkAuthRateLimit({
            supabaseAdmin,
            req,
            action: getWebauthnRateLimitAction(action),
            account: { kind: "user", value: user.id },
        });
        if (!rateLimitState.allowed) {
            return authRateLimitResponse(rateLimitState, new Headers(corsHeaders));
        }

        const rp = getRpConfig(req);
        let response: Response;

        switch (action) {
            case "generate-registration-options":
                response = await handleGenerateRegistrationOptions(user, rp, supabaseAdmin, body, corsHeaders);
                break;

            case "verify-registration":
                response = await handleVerifyRegistration(user, rp, supabaseAdmin, body, corsHeaders);
                break;

            case "generate-authentication-options":
                response = await handleGenerateAuthenticationOptions(user, rp, supabaseAdmin, body, corsHeaders);
                break;

            case "verify-authentication":
                response = await handleVerifyAuthentication(user, rp, supabaseAdmin, body, corsHeaders);
                break;

            case "activate-prf":
                response = await handleActivatePrf(user, rp, supabaseAdmin, body, corsHeaders);
                break;

            case "upgrade-wrapped-key":
                response = await handleUpgradeWrappedKey(user, rp, supabaseAdmin, body, corsHeaders);
                break;

            case "list-credentials":
                response = await handleListCredentials(user, rp, supabaseAdmin, corsHeaders);
                break;

            case "delete-credential":
                response = await handleDeleteCredential(user, rp, supabaseAdmin, body, corsHeaders);
                break;

            default:
                response = jsonResponse({ error: `Unknown action: ${action}` }, 400, corsHeaders);
        }

        await recordWebauthnRateLimitOutcome(action, rateLimitState, response);
        return response;
    } catch (err) {
        console.error("WebAuthn edge function error:", err);
        return jsonResponse({ error: "Internal server error" }, 500, corsHeaders);
    }
});

// ============ Registration ============

async function handleGenerateRegistrationOptions(
    user: { id: string; email?: string },
    rp: RpConfig,
    supabase: ReturnType<typeof createClient>,
    body: Record<string, unknown>,
    corsHeaders: Record<string, string>,
) {
    // Fetch existing credentials to exclude (prevent re-registration)
    const { data: existingCreds } = await supabase
        .from("passkey_credentials")
        .select("credential_id, rp_id")
        .eq("user_id", user.id);

    const excludeCredentials = (existingCreds || [])
        .filter((c: { credential_id: string; rp_id?: string | null }) =>
            isCredentialAvailableForRp(c.rp_id, rp.rpID)
        )
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
    const { data: challengeRow, error: challengeError } = await supabase.from("webauthn_challenges").insert({
        user_id: user.id,
        challenge: options.challenge,
        type: "registration",
        rp_id: rp.rpID,
        origin: rp.origin,
    }).select("id").single();

    if (challengeError || !challengeRow?.id) {
        console.error("Failed to store registration challenge:", challengeError);
        return jsonResponse({ error: "Failed to store registration challenge" }, 500, corsHeaders);
    }

    return jsonResponse({
        options,
        prfSalt,
        challengeId: challengeRow.id,
    }, 200, corsHeaders);
}

async function handleVerifyRegistration(
    user: { id: string },
    rp: RpConfig,
    supabase: ReturnType<typeof createClient>,
    body: Record<string, unknown>,
    corsHeaders: Record<string, string>,
) {
    const { credential, deviceName, prfSalt, wrappedMasterKey, prfEnabled, challengeId } = body as {
        credential: unknown;
        deviceName?: string;
        prfSalt: string;
        wrappedMasterKey?: string;
        prfEnabled?: boolean;
        challengeId?: string;
    };

    if (!credential) {
        return jsonResponse({ error: "Missing credential response" }, 400, corsHeaders);
    }

    const storedChallenge = await loadPendingWebauthnChallenge(
        supabase,
        user.id,
        "registration",
        challengeId,
        corsHeaders,
    );
    if (storedChallenge instanceof Response) return storedChallenge;

    // Check expiry
    if (new Date(storedChallenge.expires_at) < new Date()) {
        await supabase.from("webauthn_challenges").delete().eq("id", storedChallenge.id);
        return jsonResponse({ error: "Challenge expired" }, 400, corsHeaders);
    }

    const challengeScope = getChallengeVerificationScope(storedChallenge, rp);
    if (!challengeScope) {
        await supabase.from("webauthn_challenges").delete().eq("id", storedChallenge.id);
        return jsonResponse({ error: "Challenge scope mismatch" }, 400, corsHeaders);
    }

    try {
        // Verify the registration response
        const verification = await verifyRegistrationResponse({
            response: credential as RegistrationResponseJSON,
            expectedChallenge: storedChallenge.challenge,
            expectedOrigin: challengeScope.expectedOrigin,
            expectedRPID: challengeScope.expectedRPID,
        });

        if (!verification.verified || !verification.registrationInfo) {
            return jsonResponse({ error: "Registration verification failed" }, 400, corsHeaders);
        }

        const { credential: regCredential } = verification.registrationInfo;

        if (wrappedMasterKey && await isDeviceKeyRequiredForUser(supabase, user.id)) {
            await supabase.from("webauthn_challenges").delete().eq("id", storedChallenge.id);
            return jsonResponse({ error: "Device Key required for passkey vault unlock" }, 403, corsHeaders);
        }

        // Store the credential in the database
        const { error: insertError } = await supabase
            .from("passkey_credentials")
            .insert({
                user_id: user.id,
                credential_id: regCredential.id,
                rp_id: challengeScope.expectedRPID,
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
    rp: RpConfig,
    supabase: ReturnType<typeof createClient>,
    body: Record<string, unknown>,
    corsHeaders: Record<string, string>,
) {
    const { credentialId } = body as { credentialId?: string };

    // Fetch user's registered credentials
    const { data: credentials } = await supabase
        .from("passkey_credentials")
        .select("credential_id, transports, prf_salt, prf_enabled, rp_id")
        .eq("user_id", user.id);

    if (!credentials || credentials.length === 0) {
        return jsonResponse({ error: "No passkeys registered" }, 404, corsHeaders);
    }

    const scopedCredentials = credentialId
        ? credentials.filter((credential: { credential_id: string }) => credential.credential_id === credentialId)
        : credentials;

    const rpScopedCredentials = scopedCredentials.filter((credential: {
        credential_id: string;
        rp_id?: string | null;
    }) => isCredentialAvailableForRp(credential.rp_id, rp.rpID));

    if (rpScopedCredentials.length === 0) {
        return jsonResponse({ error: "Requested passkey credential not found" }, 404, corsHeaders);
    }

    const validScopedCredentials = rpScopedCredentials.filter((c: { credential_id: string }) =>
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
    const { data: challengeRow, error: challengeError } = await supabase.from("webauthn_challenges").insert({
        user_id: user.id,
        challenge: options.challenge,
        type: "authentication",
        rp_id: rp.rpID,
        origin: rp.origin,
        credential_id: credentialId ?? null,
    }).select("id").single();

    if (challengeError || !challengeRow?.id) {
        console.error("Failed to store authentication challenge:", challengeError);
        return jsonResponse({ error: "Failed to store authentication challenge" }, 500, corsHeaders);
    }

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
        challengeId: challengeRow.id,
    }, 200, corsHeaders);
}

async function handleVerifyAuthentication(
    user: { id: string },
    rp: RpConfig,
    supabase: ReturnType<typeof createClient>,
    body: Record<string, unknown>,
    corsHeaders: Record<string, string>,
) {
    const { credential, expectedCredentialId, challengeId } = body as {
        credential: unknown;
        expectedCredentialId?: string;
        challengeId?: string;
    };

    if (!credential) {
        return jsonResponse({ error: "Missing credential response" }, 400, corsHeaders);
    }

    // Extract credential ID from the response to find the matching DB record
    const credentialResponse = credential as { id: string };

    if (expectedCredentialId && credentialResponse.id !== expectedCredentialId) {
        return jsonResponse({ error: "Unexpected passkey credential used" }, 400, corsHeaders);
    }

    const storedChallenge = await loadPendingWebauthnChallenge(
        supabase,
        user.id,
        "authentication",
        challengeId,
        corsHeaders,
    );
    if (storedChallenge instanceof Response) return storedChallenge;

    // Check expiry
    if (new Date(storedChallenge.expires_at) < new Date()) {
        await supabase.from("webauthn_challenges").delete().eq("id", storedChallenge.id);
        return jsonResponse({ error: "Challenge expired" }, 400, corsHeaders);
    }

    const challengeScope = getChallengeVerificationScope(storedChallenge, rp);
    if (!challengeScope || (storedChallenge.credential_id && storedChallenge.credential_id !== credentialResponse.id)) {
        await supabase.from("webauthn_challenges").delete().eq("id", storedChallenge.id);
        return jsonResponse({ error: "Challenge scope mismatch" }, 400, corsHeaders);
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
        rp_id?: string | null;
        public_key: string;
        counter: number;
        transports?: string[];
        wrapped_master_key?: string;
        prf_enabled?: boolean;
    };

    if (!isCredentialAvailableForRp(dbCredential.rp_id, rp.rpID)) {
        return jsonResponse({ error: "Credential not available for this app surface" }, 400, corsHeaders);
    }

    try {
        const verification = await verifyAuthenticationResponse({
            response: credential as AuthenticationResponseJSON,
            expectedChallenge: storedChallenge.challenge,
            expectedOrigin: challengeScope.expectedOrigin,
            expectedRPID: challengeScope.expectedRPID,
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

        // Dieser Endpoint bestätigt nur den Passkey und liefert den
        // verschlüsselten Vault-Schlüssel zurück.
        if (dbCredential.wrapped_master_key && await isDeviceKeyRequiredForUser(supabase, user.id)) {
            return jsonResponse({ error: "Device Key required for passkey vault unlock" }, 403, corsHeaders);
        }

        return jsonResponse({
            verified: true,
            credentialId: dbCredential.credential_id,
            wrappedMasterKey: dbCredential.wrapped_master_key,
            prfEnabled: dbCredential.prf_enabled,
        }, 200, corsHeaders);
    } catch (err) {
        console.error("Authentication verification error:", err);
        return jsonResponse({ error: "Verification failed" }, 400, corsHeaders);
    }
}

async function handleActivatePrf(
    user: { id: string },
    rp: RpConfig,
    supabase: ReturnType<typeof createClient>,
    body: Record<string, unknown>,
    corsHeaders: Record<string, string>,
) {
    const { credential, expectedCredentialId, wrappedMasterKey, challengeId } = body as {
        credential: unknown;
        expectedCredentialId?: string;
        wrappedMasterKey?: string;
        challengeId?: string;
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

    if (await isDeviceKeyRequiredForUser(supabase, user.id)) {
        return jsonResponse({ error: "Device Key required for passkey vault unlock" }, 403, corsHeaders);
    }

    const credentialResponse = credential as { id: string };
    if (credentialResponse.id !== expectedCredentialId) {
        return jsonResponse({ error: "Unexpected passkey credential used" }, 400, corsHeaders);
    }

    const storedChallenge = await loadPendingWebauthnChallenge(
        supabase,
        user.id,
        "authentication",
        challengeId,
        corsHeaders,
    );
    if (storedChallenge instanceof Response) return storedChallenge;

    if (new Date(storedChallenge.expires_at) < new Date()) {
        await supabase.from("webauthn_challenges").delete().eq("id", storedChallenge.id);
        return jsonResponse({ error: "Challenge expired" }, 400, corsHeaders);
    }

    const challengeScope = getChallengeVerificationScope(storedChallenge, rp);
    if (!challengeScope || (storedChallenge.credential_id && storedChallenge.credential_id !== expectedCredentialId)) {
        await supabase.from("webauthn_challenges").delete().eq("id", storedChallenge.id);
        return jsonResponse({ error: "Challenge scope mismatch" }, 400, corsHeaders);
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
        rp_id?: string | null;
        public_key: string;
        counter: number;
        transports?: string[];
    };

    if (!isCredentialAvailableForRp(dbCredential.rp_id, rp.rpID)) {
        return jsonResponse({ error: "Credential not available for this app surface" }, 400, corsHeaders);
    }

    try {
        const verification = await verifyAuthenticationResponse({
            response: credential as AuthenticationResponseJSON,
            expectedChallenge: storedChallenge.challenge,
            expectedOrigin: challengeScope.expectedOrigin,
            expectedRPID: challengeScope.expectedRPID,
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

async function handleUpgradeWrappedKey(
    user: { id: string },
    rp: RpConfig,
    supabase: ReturnType<typeof createClient>,
    body: Record<string, unknown>,
    corsHeaders: Record<string, string>,
) {
    const { credential, expectedCredentialId, credentialId, wrappedMasterKey, challengeId } = body as {
        credential: unknown;
        expectedCredentialId?: string;
        credentialId?: string;
        wrappedMasterKey?: string;
        challengeId?: string;
    };
    const targetCredentialId = expectedCredentialId || credentialId;

    if (!credential) {
        return jsonResponse({ error: "Missing credential response" }, 400, corsHeaders);
    }

    if (!targetCredentialId) {
        return jsonResponse({ error: "Missing expectedCredentialId" }, 400, corsHeaders);
    }

    if (typeof wrappedMasterKey !== "string" || wrappedMasterKey.trim().length === 0) {
        return jsonResponse({ error: "Missing wrappedMasterKey" }, 400, corsHeaders);
    }

    if (await isDeviceKeyRequiredForUser(supabase, user.id)) {
        return jsonResponse({ error: "Device Key required for passkey vault unlock" }, 403, corsHeaders);
    }

    const credentialResponse = credential as { id?: string };
    if (credentialResponse.id !== targetCredentialId) {
        return jsonResponse({ error: "Unexpected passkey credential used" }, 400, corsHeaders);
    }

    const storedChallenge = await loadPendingWebauthnChallenge(
        supabase,
        user.id,
        "authentication",
        challengeId,
        corsHeaders,
    );
    if (storedChallenge instanceof Response) return storedChallenge;

    if (new Date(storedChallenge.expires_at) < new Date()) {
        await supabase.from("webauthn_challenges").delete().eq("id", storedChallenge.id);
        return jsonResponse({ error: "Challenge expired" }, 400, corsHeaders);
    }

    const challengeScope = getChallengeVerificationScope(storedChallenge, rp);
    if (!challengeScope || (storedChallenge.credential_id && storedChallenge.credential_id !== targetCredentialId)) {
        await supabase.from("webauthn_challenges").delete().eq("id", storedChallenge.id);
        return jsonResponse({ error: "Challenge scope mismatch" }, 400, corsHeaders);
    }

    await supabase.from("webauthn_challenges").delete().eq("id", storedChallenge.id);

    const { data: dbCredentials } = await supabase
        .from("passkey_credentials")
        .select("*")
        .eq("user_id", user.id)
        .eq("credential_id", targetCredentialId);

    if (!dbCredentials || dbCredentials.length === 0) {
        return jsonResponse({ error: "Credential not found" }, 400, corsHeaders);
    }

    const dbCredential = dbCredentials[0] as {
        id: string;
        credential_id: string;
        rp_id?: string | null;
        public_key: string;
        counter: number;
        transports?: string[];
    };

    if (!isCredentialAvailableForRp(dbCredential.rp_id, rp.rpID)) {
        return jsonResponse({ error: "Credential not available for this app surface" }, 400, corsHeaders);
    }

    try {
        const verification = await verifyAuthenticationResponse({
            response: credential as AuthenticationResponseJSON,
            expectedChallenge: storedChallenge.challenge,
            expectedOrigin: challengeScope.expectedOrigin,
            expectedRPID: challengeScope.expectedRPID,
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

        const { error } = await supabase
            .from("passkey_credentials")
            .update({
                counter: verification.authenticationInfo.newCounter,
                wrapped_master_key: wrappedMasterKey,
                prf_enabled: true,
                last_used_at: new Date().toISOString(),
            })
            .eq("id", dbCredential.id)
            .eq("user_id", user.id)
            .eq("credential_id", dbCredential.credential_id);

        if (error) {
            console.error("Failed to upgrade wrapped passkey key:", error);
            return jsonResponse({ error: "Failed to update wrapped key" }, 500, corsHeaders);
        }

        return jsonResponse({ updated: true, credentialId: dbCredential.credential_id }, 200, corsHeaders);
    } catch (err) {
        console.error("Wrapped-key upgrade verification error:", err);
        return jsonResponse({ error: "Verification failed" }, 400, corsHeaders);
    }
}

// ============ Credential Management ============

async function handleListCredentials(
    user: { id: string },
    rp: { rpID: string },
    supabase: ReturnType<typeof createClient>,
    corsHeaders: Record<string, string>,
) {
    const { data: credentials, error } = await supabase
        .from("passkey_credentials")
        .select("id, credential_id, device_name, prf_enabled, created_at, last_used_at, rp_id")
        .eq("user_id", user.id)
        .order("created_at", { ascending: false });

    if (error) {
        return jsonResponse({ error: "Failed to list credentials" }, 500, corsHeaders);
    }

    const scopedCredentials = (credentials || []).filter((credential: { rp_id?: string | null }) =>
        isCredentialAvailableForRp(credential.rp_id, rp.rpID)
    );

    return jsonResponse({ credentials: scopedCredentials }, 200, corsHeaders);
}

async function handleDeleteCredential(
    user: { id: string },
    rp: { rpID: string },
    supabase: ReturnType<typeof createClient>,
    body: Record<string, unknown>,
    corsHeaders: Record<string, string>,
) {
    const { credentialId } = body as { credentialId: string };

    if (!credentialId) {
        return jsonResponse({ error: "Missing credentialId" }, 400, corsHeaders);
    }

    const { data: credential, error: lookupError } = await supabase
        .from("passkey_credentials")
        .select("id, rp_id")
        .eq("user_id", user.id)
        .eq("id", credentialId)
        .maybeSingle();

    if (lookupError) {
        return jsonResponse({ error: "Failed to load credential" }, 500, corsHeaders);
    }

    if (!credential || !isCredentialAvailableForRp((credential as { rp_id?: string | null }).rp_id, rp.rpID)) {
        return jsonResponse({ error: "Credential not available for this app surface" }, 404, corsHeaders);
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

function getWebauthnRateLimitAction(action: WebauthnAction): AuthRateLimitAction {
    if (
        action === "generate-registration-options" ||
        action === "generate-authentication-options"
    ) {
        return "webauthn_challenge";
    }

    if (
        action === "verify-registration" ||
        action === "verify-authentication" ||
        action === "activate-prf" ||
        action === "upgrade-wrapped-key"
    ) {
        return "webauthn_verify";
    }

    return "webauthn_manage";
}

async function recordWebauthnRateLimitOutcome(
    action: WebauthnAction,
    state: AuthRateLimitState,
    response: Response,
): Promise<void> {
    const requestQuotaAction = action === "generate-registration-options" ||
        action === "generate-authentication-options";

    if (requestQuotaAction || response.status >= 400) {
        await recordAuthRateLimitFailure(state);
        return;
    }

    if (state.action === "webauthn_verify") {
        await resetAuthRateLimit(state);
    }
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

function isCredentialAvailableForRp(
    credentialRpId: string | null | undefined,
    currentRpId: string,
): boolean {
    if (credentialRpId === currentRpId) {
        return true;
    }

    // Legacy rows were created before RP scoping existed and belong to the
    // hosted web surface. Keep them visible there so existing users do not lose
    // their web passkeys, while desktop/local surfaces stay isolated.
    return !credentialRpId && currentRpId === CONFIGURED_SITE_RP_ID;
}

async function isDeviceKeyRequiredForUser(
    supabase: ReturnType<typeof createClient>,
    userId: string,
): Promise<boolean> {
    const { data, error } = await supabase
        .from("profiles")
        .select("vault_protection_mode")
        .eq("id", userId)
        .maybeSingle();

    if (error) {
        console.error("Failed to load vault protection mode for WebAuthn:", error);
        return true;
    }

    return (data as { vault_protection_mode?: string } | null)?.vault_protection_mode === "device_key_required";
}

async function loadPendingWebauthnChallenge(
    supabase: ReturnType<typeof createClient>,
    userId: string,
    type: StoredWebauthnChallenge["type"],
    challengeId: unknown,
    corsHeaders: Record<string, string>,
): Promise<StoredWebauthnChallenge | Response> {
    if (typeof challengeId !== "string" || challengeId.trim().length === 0) {
        return jsonResponse({ error: "Missing challengeId" }, 400, corsHeaders);
    }

    const { data, error } = await supabase
        .from("webauthn_challenges")
        .select("*")
        .eq("id", challengeId)
        .eq("user_id", userId)
        .eq("type", type)
        .maybeSingle();

    if (error) {
        console.error("Failed to load WebAuthn challenge:", error);
        return jsonResponse({ error: "Failed to load challenge" }, 500, corsHeaders);
    }

    if (!data) {
        return jsonResponse({ error: `No pending ${type} challenge` }, 400, corsHeaders);
    }

    return data as StoredWebauthnChallenge;
}

function getChallengeVerificationScope(
    challenge: StoredWebauthnChallenge,
    rp: RpConfig,
): { expectedOrigin: string; expectedRPID: string } | null {
    const challengeRpId = typeof challenge.rp_id === "string" && challenge.rp_id.trim().length > 0
        ? challenge.rp_id.trim()
        : rp.rpID;
    const challengeOrigin = normalizeHttpOrigin(challenge.origin) ?? rp.origin;

    if (challengeRpId !== rp.rpID || challengeOrigin !== rp.origin) {
        return null;
    }

    return {
        expectedOrigin: challengeOrigin,
        expectedRPID: challengeRpId,
    };
}

function normalizeHttpOrigin(value: string | null | undefined): string | null {
    if (!value) {
        return null;
    }

    try {
        const parsed = new URL(value);
        if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
            return null;
        }

        return parsed.origin;
    } catch {
        return null;
    }
}

function dedupeOrigins(origins: Array<string | null | undefined>): string[] {
    const uniqueOrigins = new Set<string>();

    for (const origin of origins) {
        const normalizedOrigin = normalizeHttpOrigin(origin);
        if (normalizedOrigin) {
            uniqueOrigins.add(normalizedOrigin);
        }
    }

    return Array.from(uniqueOrigins);
}

function dedupeRpIds(origins: string[]): string[] {
    const uniqueRpIds = new Set<string>();

    for (const origin of origins) {
        try {
            uniqueRpIds.add(new URL(origin).hostname);
        } catch {
            // Ignore malformed origins in the allow-list.
        }
    }

    return Array.from(uniqueRpIds);
}

