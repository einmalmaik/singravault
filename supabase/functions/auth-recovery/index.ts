import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2.49.1";
import { argon2Verify } from "npm:hash-wasm";
import { getCorsHeaders } from "../_shared/cors.ts";
import {
    authRateLimitResponse,
    checkAuthRateLimit,
    getTrustedClientIp,
    recordAuthRateLimitFailure,
    resetAuthRateLimit,
    type AuthRateLimitFailureResult,
    type AuthRateLimitState,
} from "../_shared/authRateLimit.ts";
import {
    isValidOpaqueIdentifier,
    normalizeOpaqueIdentifier,
    sha256Hex,
} from "../_shared/opaqueAuth.ts";

type ResetPurpose = "forgot" | "change";

interface AuthUser {
    id: string;
    email: string | null;
    app_metadata?: Record<string, unknown>;
}

interface ResetChallenge {
    id: string;
    user_id: string;
    email: string;
    two_factor_required: boolean;
    two_factor_verified_at: string | null;
    authorized_at: string | null;
}

const supabaseUrl = Deno.env.get("SUPABASE_URL")!;
const supabaseServiceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
const resendApiKey = Deno.env.get("RESEND_API_KEY") ?? "";
const recoveryCodePepper = Deno.env.get("AUTH_RECOVERY_CODE_PEPPER") ?? "";
const supabaseAdmin = createClient(supabaseUrl, supabaseServiceKey);

const EMAIL_CODE_TTL_MS = 10 * 60 * 1000;
const RESET_TOKEN_TTL_MS = 15 * 60 * 1000;
const REQUEST_MIN_RESPONSE_MS = 500;
const VERIFY_MIN_RESPONSE_MS = 300;

function generateCode(): string {
    const bytes = new Uint8Array(4);
    crypto.getRandomValues(bytes);
    const num = ((bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3]) >>> 0;
    return String(num % 100_000_000).padStart(8, "0");
}

function generateResetToken(): string {
    const bytes = new Uint8Array(32);
    crypto.getRandomValues(bytes);
    let binary = "";
    bytes.forEach((byte) => {
        binary += String.fromCharCode(byte);
    });
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function buildEmailHtml(params: { code: string; purpose: ResetPurpose }): string {
    const intro = params.purpose === "change"
        ? "Du hast eine Änderung deines Singra Vault Kontopassworts angefordert."
        : "Du hast eine Anfrage zum Zurücksetzen deines Singra Vault Kontopassworts gestellt.";

    return `<!DOCTYPE html>
<html lang="de">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Singra Vault Sicherheitscode</title>
<style>
body,table,td{margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,'Helvetica Neue',Arial,sans-serif;line-height:1.6;color:#1a1a2e;background-color:#f4f4f8}
.wrapper{max-width:600px;margin:0 auto;padding:40px 20px}
.card{background:#ffffff;border-radius:16px;box-shadow:0 4px 24px rgba(0,0,0,0.08);overflow:hidden}
.header{background:#18202f;padding:32px;text-align:center;color:#ffffff;font-size:24px;font-weight:700}
.content{padding:40px 32px}
h1{margin:0 0 16px;font-size:24px;font-weight:700;color:#1a1a2e}
p{margin:0 0 16px;color:#4a4a68}
.code{display:inline-block;background:#f4f4f8;padding:16px 32px;border-radius:12px;border:2px dashed #6366f1;letter-spacing:4px;font-size:32px;font-weight:700;color:#1a1a2e;font-family:monospace}
.warning-box{background:#fef3c7;border:1px solid #f59e0b;border-radius:8px;padding:16px;margin:16px 0}
.warning-box p{color:#92400e;margin:0}
.note{font-size:14px;color:#6b6b80}
.footer{padding:24px 32px;background:#f8f8fc;text-align:center;font-size:12px;color:#6b6b80}
@media(prefers-color-scheme:dark){body{background-color:#0f0f1a;color:#e4e4e7}.card{background:#1a1a2e}h1{color:#ffffff}p{color:#a1a1aa}.footer{background:#0f0f1a}.code{color:#1a1a2e}}
</style>
</head>
<body>
<div class="wrapper">
<div class="card">
<div class="header">Singra Vault</div>
<div class="content">
<h1>Sicherheitscode</h1>
<p>${intro} Verwende den folgenden 8-stelligen Code in der App:</p>
<div style="text-align:center;margin:32px 0;"><div class="code">${params.code}</div></div>
<div class="warning-box">
<p><strong>Wichtig:</strong> Das Zurücksetzen des Kontopassworts entschlüsselt keine Vault-Daten und ersetzt nicht dein Master-Passwort.</p>
</div>
<p class="note">Wenn du diese Anfrage nicht gestellt hast, ignoriere diese E-Mail. Der Code ist 10 Minuten gültig.</p>
</div>
<div class="footer">
<p>&copy; 2026 Singra Vault. Diese E-Mail wurde automatisch gesendet.</p>
</div>
</div>
</div>
</body>
</html>`;
}

serve(async (req) => {
    const corsHeaders = getCorsHeaders(req);
    const headers = new Headers({ ...corsHeaders, "Content-Type": "application/json" });
    if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });

    if (req.method !== "POST") {
        return new Response(JSON.stringify({ error: "Method not allowed" }), { status: 405, headers });
    }

    try {
        const body = await req.json();
        const action = typeof body.action === "string" ? body.action : "request-email-code";

        if (action === "verify" || action === "verify-email-code") {
            return await handleVerifyEmailCode(req, body, corsHeaders);
        }

        if (action === "verify-two-factor") {
            return await handleVerifyTwoFactor(req, body, headers);
        }

        return await handleRequestEmailCode(req, body, corsHeaders);
    } catch (err: unknown) {
        console.error("Auth Recovery Error:", err);
        return new Response(JSON.stringify({ error: "Internal Server Error" }), {
            status: 500,
            headers,
        });
    }
});

async function handleRequestEmailCode(
    req: Request,
    body: Record<string, unknown>,
    corsHeaders: Record<string, string>,
): Promise<Response> {
    const startTime = Date.now();
    const purpose = parsePurpose(body.purpose);
    const context = await resolveRequestContext(req, body, purpose);

    if (context.response) {
        return context.response;
    }

    const email = context.email;
    const requestRateLimit = await checkAuthRateLimit({
        supabaseAdmin,
        req,
        action: "recovery_request",
        account: { kind: "email", value: email },
    });
    if (!requestRateLimit.allowed) {
        return authRateLimitResponse(
            requestRateLimit,
            new Headers({ ...corsHeaders, "Content-Type": "application/json" }),
        );
    }

    await recordAuthRateLimitFailure(requestRateLimit);

    if (context.userId) {
        await maybeIssueEmailCode(email, purpose);
    }

    await delayUntilMinimum(startTime, REQUEST_MIN_RESPONSE_MS);
    return new Response(JSON.stringify({ success: true }), {
        status: 200,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
}

async function handleVerifyEmailCode(
    req: Request,
    body: Record<string, unknown>,
    corsHeaders: Record<string, string>,
): Promise<Response> {
    const startTime = Date.now();
    const purpose = parsePurpose(body.purpose);
    const code = typeof body.code === "string" ? body.code.trim() : "";
    const context = await resolveRequestContext(req, body, purpose);

    if (context.response) {
        return context.response;
    }

    if (!/^\d{8}$/.test(code)) {
        return new Response(JSON.stringify({ error: "Invalid or expired code" }), {
            status: 400,
            headers: { ...corsHeaders, "Content-Type": "application/json" },
        });
    }

    const recoveryRateLimit = await checkAuthRateLimit({
        supabaseAdmin,
        req,
        action: "recovery_verify",
        account: { kind: "email", value: context.email },
    });
    if (!recoveryRateLimit.allowed) {
        return authRateLimitResponse(
            recoveryRateLimit,
            new Headers({ ...corsHeaders, "Content-Type": "application/json" }),
        );
    }

    const consumedToken = await consumeEmailCode(context.email, purpose, code);
    if (!consumedToken) {
        return await invalidRecoveryAttemptResponse(
            recoveryRateLimit,
            startTime,
            corsHeaders,
            "Invalid or expired code",
        );
    }

    if (!context.userId) {
        return await invalidRecoveryAttemptResponse(
            recoveryRateLimit,
            startTime,
            corsHeaders,
            "Invalid or expired code",
        );
    }

    const twoFactorRequired = await isTwoFactorEnabled(context.userId);
    const resetToken = generateResetToken();
    const resetTokenHash = await sha256Hex(resetToken);
    const nowIso = new Date().toISOString();
    const expiresAt = new Date(Date.now() + RESET_TOKEN_TTL_MS).toISOString();

    await supabaseAdmin
        .from("password_reset_challenges")
        .delete()
        .eq("user_id", context.userId);

    const { error: challengeError } = await supabaseAdmin
        .from("password_reset_challenges")
        .insert({
            user_id: context.userId,
            email: context.email,
            token_hash: resetTokenHash,
            purpose,
            email_verified_at: nowIso,
            two_factor_required: twoFactorRequired,
            two_factor_verified_at: null,
            authorized_at: twoFactorRequired ? null : nowIso,
            expires_at: expiresAt,
            ip_address: getTrustedClientIp(req),
            user_agent: req.headers.get("user-agent") || "unknown",
        });

    if (challengeError) {
        console.error("Failed to create password reset challenge:", challengeError);
        return new Response(JSON.stringify({ error: "Reset challenge creation failed" }), {
            status: 500,
            headers: { ...corsHeaders, "Content-Type": "application/json" },
        });
    }

    await resetAuthRateLimit(recoveryRateLimit);

    return new Response(JSON.stringify({
        success: true,
        resetToken,
        expiresAt,
        requires2FA: twoFactorRequired,
        nextState: twoFactorRequired ? "TWO_FACTOR_REQUIRED" : "NEW_PASSWORD_ALLOWED",
    }), {
        status: 200,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
}

async function handleVerifyTwoFactor(
    req: Request,
    body: Record<string, unknown>,
    headers: Headers,
): Promise<Response> {
    const resetToken = typeof body.resetToken === "string" ? body.resetToken.trim() : "";
    const code = typeof body.code === "string" ? body.code.trim() : "";
    const isBackupCode = Boolean(body.isBackupCode);
    if (!resetToken || !code) {
        return new Response(JSON.stringify({ error: "Invalid request payload" }), { status: 400, headers });
    }

    const challenge = await findActiveResetChallenge(resetToken);
    if (!challenge) {
        await delay(VERIFY_MIN_RESPONSE_MS);
        return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401, headers });
    }

    if (!challenge.two_factor_required) {
        return new Response(JSON.stringify({
            success: true,
            nextState: "NEW_PASSWORD_ALLOWED",
        }), { status: 200, headers });
    }

    const secondFactorRateLimit = await checkAuthRateLimit({
        supabaseAdmin,
        req,
        action: isBackupCode ? "backup_code_verify" : "totp_verify",
        account: { kind: "user", value: challenge.user_id },
    });
    if (!secondFactorRateLimit.allowed) {
        return authRateLimitResponse(secondFactorRateLimit, headers);
    }

    const startTime = Date.now();
    const valid = isBackupCode
        ? await verifyAndConsumeBackupCode(challenge.user_id, code)
        : await verifyTotpCode(challenge.user_id, code);

    if (!valid) {
        return await invalidSecondFactorAttemptResponse(
            secondFactorRateLimit,
            startTime,
            headers,
            isBackupCode ? "Invalid backup code" : "Invalid 2FA code",
        );
    }

    const nowIso = new Date().toISOString();
    const { data: updatedChallenge, error: updateError } = await supabaseAdmin
        .from("password_reset_challenges")
        .update({
            two_factor_verified_at: nowIso,
            authorized_at: nowIso,
        })
        .eq("id", challenge.id)
        .is("used_at", null)
        .gt("expires_at", nowIso)
        .select("id")
        .maybeSingle();

    if (updateError || !updatedChallenge) {
        return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401, headers });
    }

    await resetAuthRateLimit(secondFactorRateLimit);
    await supabaseAdmin.from("user_2fa").update({ last_verified_at: nowIso }).eq("user_id", challenge.user_id);

    return new Response(JSON.stringify({
        success: true,
        nextState: "NEW_PASSWORD_ALLOWED",
    }), { status: 200, headers });
}

async function resolveRequestContext(
    req: Request,
    body: Record<string, unknown>,
    purpose: ResetPurpose,
): Promise<{ email: string; userId: string | null; response?: Response }> {
    if (purpose === "change") {
        const authUser = await getAuthenticatedUser(req);
        if (!authUser?.email) {
            return {
                email: "unknown",
                userId: null,
                response: new Response(JSON.stringify({ error: "Authentication required" }), {
                    status: 401,
                    headers: { ...getCorsHeaders(req), "Content-Type": "application/json" },
                }),
            };
        }

        const email = normalizeOpaqueIdentifier(authUser.email);
        if (!await canUseAppPasswordReset(authUser.id, authUser)) {
            return {
                email,
                userId: null,
                response: new Response(JSON.stringify({ error: "App-password credentials are not configured for this account" }), {
                    status: 403,
                    headers: { ...getCorsHeaders(req), "Content-Type": "application/json" },
                }),
            };
        }

        return { email, userId: authUser.id };
    }

    const email = normalizeOpaqueIdentifier(body.email);
    if (!isValidOpaqueIdentifier(email)) {
        return {
            email: "unknown",
            userId: null,
            response: new Response(JSON.stringify({ error: "Invalid email" }), {
                status: 400,
                headers: { ...getCorsHeaders(req), "Content-Type": "application/json" },
            }),
        };
    }

    const user = await findAppPasswordUserByEmail(email);
    return { email, userId: user?.id ?? null };
}

async function maybeIssueEmailCode(email: string, purpose: ResetPurpose): Promise<void> {
    const { data: recentTokens } = await supabaseAdmin
        .from("recovery_tokens")
        .select("created_at")
        .eq("email", email)
        .eq("purpose", purpose)
        .is("used_at", null)
        .gt("created_at", new Date(Date.now() - 60_000).toISOString())
        .limit(1);

    if (recentTokens && recentTokens.length > 0) {
        return;
    }

    await supabaseAdmin
        .from("recovery_tokens")
        .delete()
        .eq("email", email)
        .eq("purpose", purpose);

    const code = generateCode();
    const codeHash = await hashRecoveryEmailCode(email, purpose, code);
    const expiresAt = new Date(Date.now() + EMAIL_CODE_TTL_MS).toISOString();

    const { error: insertError } = await supabaseAdmin
        .from("recovery_tokens")
        .insert({
            email,
            token_hash: codeHash,
            purpose,
            expires_at: expiresAt,
        });

    if (insertError) {
        console.error("Failed to insert recovery token:", insertError);
        return;
    }

    await sendRecoveryEmail(email, code, purpose);
}

async function sendRecoveryEmail(email: string, code: string, purpose: ResetPurpose): Promise<void> {
    if (!resendApiKey) {
        console.error("RESEND_API_KEY missing; cannot send recovery email.");
        return;
    }

    const response = await fetch("https://api.resend.com/emails", {
        method: "POST",
        headers: {
            "Authorization": `Bearer ${resendApiKey}`,
            "Content-Type": "application/json",
        },
        body: JSON.stringify({
            from: "Singra Vault <noreply@mauntingstudios.de>",
            to: [email],
            subject: purpose === "change"
                ? "Sicherheitscode zum Ändern deines Singra Vault Passworts"
                : "Sicherheitscode zum Zurücksetzen deines Singra Vault Passworts",
            html: buildEmailHtml({ code, purpose }),
        }),
    });

    if (!response.ok) {
        console.error("Resend API error:", await response.text());
    }
}

async function consumeEmailCode(email: string, purpose: ResetPurpose, code: string): Promise<boolean> {
    const codeHash = recoveryCodePepper
        ? await hashRecoveryEmailCode(email, purpose, code)
        : "";
    if (codeHash && await consumeEmailCodeByHash(email, purpose, codeHash)) {
        return true;
    }

    const legacyCodeHash = await sha256Hex(code);
    return await consumeEmailCodeByHash(email, purpose, legacyCodeHash);
}

async function consumeEmailCodeByHash(email: string, purpose: ResetPurpose, tokenHash: string): Promise<boolean> {
    const { data, error } = await supabaseAdmin
        .from("recovery_tokens")
        .update({ used_at: new Date().toISOString() })
        .eq("email", email)
        .eq("purpose", purpose)
        .eq("token_hash", tokenHash)
        .is("used_at", null)
        .gt("expires_at", new Date().toISOString())
        .select("id")
        .maybeSingle();

    return !error && Boolean(data);
}

async function hashRecoveryEmailCode(email: string, purpose: ResetPurpose, code: string): Promise<string> {
    if (!recoveryCodePepper) {
        throw new Error("AUTH_RECOVERY_CODE_PEPPER is required for recovery code hashing");
    }

    const key = await crypto.subtle.importKey(
        "raw",
        new TextEncoder().encode(recoveryCodePepper),
        { name: "HMAC", hash: "SHA-256" },
        false,
        ["sign"],
    );
    const message = `${purpose}\0${normalizeOpaqueIdentifier(email)}\0${code}`;
    const signature = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(message));
    const hex = Array.from(new Uint8Array(signature))
        .map((byte) => byte.toString(16).padStart(2, "0"))
        .join("");
    return `hmac-sha256:v1:${hex}`;
}

async function findAppPasswordUserByEmail(email: string): Promise<AuthUser | null> {
    const { data: users, error } = await supabaseAdmin.rpc("get_user_id_by_email", {
        p_email: email,
    });
    if (error || !users || users.length === 0) {
        return null;
    }

    const userId = users[0].id as string;
    const { data: adminUserData, error: adminUserError } = await supabaseAdmin.auth.admin.getUserById(userId);
    if (adminUserError || !adminUserData.user) {
        return null;
    }

    const authUser = adminUserData.user as AuthUser;
    return await canUseAppPasswordReset(userId, authUser) ? authUser : null;
}

async function canUseAppPasswordReset(userId: string, authUser: AuthUser): Promise<boolean> {
    const { data: opaqueRecord } = await supabaseAdmin
        .from("user_opaque_records")
        .select("user_id")
        .eq("user_id", userId)
        .maybeSingle();
    if (opaqueRecord) {
        return true;
    }

    const providers = getAuthProviders(authUser.app_metadata);
    if (providers.includes("email")) {
        return true;
    }

    // Older email/password accounts may not carry complete provider metadata.
    return providers.length === 0 && Boolean(authUser.email);
}

async function getAuthenticatedUser(req: Request): Promise<AuthUser | null> {
    const token = parseBearerToken(req.headers.get("Authorization"));
    if (!token) {
        return null;
    }

    const { data, error } = await supabaseAdmin.auth.getUser(token);
    if (error || !data.user) {
        return null;
    }

    return data.user as AuthUser;
}

async function findActiveResetChallenge(resetToken: string): Promise<ResetChallenge | null> {
    const resetTokenHash = await sha256Hex(resetToken);
    const { data: challenge, error } = await supabaseAdmin
        .from("password_reset_challenges")
        .select("id, user_id, email, two_factor_required, two_factor_verified_at, authorized_at")
        .eq("token_hash", resetTokenHash)
        .is("used_at", null)
        .gt("expires_at", new Date().toISOString())
        .maybeSingle();

    if (error || !challenge) {
        return null;
    }

    return challenge as ResetChallenge;
}

async function isTwoFactorEnabled(userId: string): Promise<boolean> {
    const { data: user2fa } = await supabaseAdmin
        .from("user_2fa")
        .select("is_enabled")
        .eq("user_id", userId)
        .maybeSingle();

    return Boolean(user2fa?.is_enabled);
}

async function verifyTotpCode(userId: string, code: string): Promise<boolean> {
    const { data: totpSecret, error: totpSecretError } = await supabaseAdmin.rpc("get_user_2fa_secret", {
        p_user_id: userId,
        p_require_enabled: true,
    });

    if (totpSecretError || !totpSecret) {
        console.error("Failed to load TOTP secret for password reset:", totpSecretError);
        return false;
    }

    const OTPAuth = await import("npm:otpauth");
    const totp = new OTPAuth.TOTP({
        issuer: "Singra Vault",
        algorithm: "SHA1",
        digits: 6,
        period: 30,
        secret: OTPAuth.Secret.fromBase32(String(totpSecret).replace(/\s/g, "")),
    });

    return totp.validate({ token: code.replace(/\s/g, ""), window: 1 }) !== null;
}

async function verifyAndConsumeBackupCode(userId: string, code: string): Promise<boolean> {
    const { data: backupCodes } = await supabaseAdmin
        .from("backup_codes")
        .select("id, code_hash")
        .eq("user_id", userId)
        .eq("is_used", false);

    let validCodeId: string | null = null;
    if (backupCodes && backupCodes.length > 0) {
        for (const backupCode of backupCodes) {
            const isMatch = await argon2Verify({
                password: code.replace(/\s/g, ""),
                hash: backupCode.code_hash,
            });
            if (isMatch) {
                validCodeId = backupCode.id;
                break;
            }
        }
    }

    if (!validCodeId) {
        return false;
    }

    const { data: consumedBackupCode, error: consumeError } = await supabaseAdmin
        .from("backup_codes")
        .update({
            is_used: true,
            used_at: new Date().toISOString(),
        })
        .eq("id", validCodeId)
        .eq("user_id", userId)
        .eq("is_used", false)
        .select("id")
        .maybeSingle();

    return !consumeError && Boolean(consumedBackupCode);
}

function parsePurpose(value: unknown): ResetPurpose {
    return value === "change" ? "change" : "forgot";
}

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

function getAuthProviders(appMetadata: Record<string, unknown> | null | undefined): string[] {
    if (!appMetadata || typeof appMetadata !== "object") {
        return [];
    }

    const providersField = appMetadata.providers;
    if (Array.isArray(providersField)) {
        return providersField
            .filter((value): value is string => typeof value === "string")
            .map((value) => value.trim().toLowerCase())
            .filter((value) => value.length > 0);
    }

    const providerField = appMetadata.provider;
    if (typeof providerField === "string" && providerField.trim()) {
        return [providerField.trim().toLowerCase()];
    }

    return [];
}

async function invalidRecoveryAttemptResponse(
    rateLimitState: AuthRateLimitState,
    startTime: number,
    corsHeaders: Record<string, string>,
    message: string,
): Promise<Response> {
    const failure = await recordAuthRateLimitFailure(rateLimitState);
    await delayUntilMinimum(startTime, VERIFY_MIN_RESPONSE_MS);
    if (failure.lockedUntil) {
        return authRateLimitResponse(
            toLockedState(failure),
            new Headers({ ...corsHeaders, "Content-Type": "application/json" }),
        );
    }

    return new Response(JSON.stringify({ error: message }), {
        status: 400,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
}

async function invalidSecondFactorAttemptResponse(
    rateLimitState: AuthRateLimitState,
    startTime: number,
    headers: Headers,
    message: string,
): Promise<Response> {
    const failure = await recordAuthRateLimitFailure(rateLimitState);
    await delayUntilMinimum(startTime, VERIFY_MIN_RESPONSE_MS);
    if (failure.lockedUntil) {
        return authRateLimitResponse(toLockedState(failure), headers);
    }

    return new Response(JSON.stringify({ error: message }), { status: 401, headers });
}

function toLockedState(failure: AuthRateLimitFailureResult) {
    return {
        status: 429 as const,
        error: "Too many attempts",
        attemptsRemaining: failure.attemptsRemaining,
        lockedUntil: failure.lockedUntil,
        retryAfterSeconds: failure.retryAfterSeconds,
    };
}

async function delayUntilMinimum(startTime: number, minimumMs: number): Promise<void> {
    const remaining = minimumMs - (Date.now() - startTime);
    if (remaining > 0) {
        await delay(remaining);
    }
}

async function delay(ms: number): Promise<void> {
    await new Promise((resolve) => setTimeout(resolve, ms));
}
