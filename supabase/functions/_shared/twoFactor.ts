import { argon2id } from "npm:hash-wasm";
import {
  authRateLimitResponse,
  checkAuthRateLimit,
  recordAuthRateLimitFailure,
  resetAuthRateLimit,
  type AuthRateLimitAction,
  type AuthRateLimitFailureResult,
  type AuthRateLimitState,
} from "./authRateLimit.ts";

export type TwoFactorPurpose =
  | "account_login"
  | "password_reset"
  | "password_change"
  | "account_security_change"
  | "disable_2fa"
  | "vault_unlock"
  | "critical_action";

export type TwoFactorMethod = "totp" | "backup_code";

interface SupabaseAdminClient {
  from: (table: string) => unknown;
  rpc: (fn: string, args: Record<string, unknown>) => Promise<{
    data: unknown;
    error: { message?: string } | null;
  }>;
}

interface TwoFactorStatusRow {
  is_enabled: boolean | null;
  vault_2fa_enabled?: boolean | null;
}

export interface TwoFactorRequirement {
  required: boolean;
  status: "loaded" | "unavailable";
  reason?: "account_2fa_enabled" | "vault_2fa_enabled" | "status_unavailable";
}

export interface VerifyTwoFactorInput {
  supabaseAdmin: SupabaseAdminClient;
  req: Request;
  userId: string;
  purpose: TwoFactorPurpose;
  method: TwoFactorMethod;
  code: string;
  challengeId?: string | null;
}

export type VerifyTwoFactorResult =
  | { ok: true; required: boolean }
  | {
      ok: false;
      status: 400 | 401 | 429 | 503;
      error: string;
      attemptsRemaining?: number;
      lockedUntil?: string | null;
      retryAfterSeconds?: number | null;
    };

const GENERIC_2FA_ERROR = "Invalid or expired verification code";

export async function getTwoFactorRequirementServer(
  supabaseAdmin: SupabaseAdminClient,
  userId: string,
  purpose: TwoFactorPurpose,
): Promise<TwoFactorRequirement> {
  const { data, error } = await (supabaseAdmin.from("user_2fa") as {
    select: (columns: string) => {
      eq: (column: string, value: string) => {
        maybeSingle: () => Promise<{ data: TwoFactorStatusRow | null; error: { message?: string } | null }>;
      };
    };
  })
    .select("is_enabled, vault_2fa_enabled")
    .eq("user_id", userId)
    .maybeSingle();

  if (error) {
    console.error("Failed to load 2FA status:", error);
    return { required: true, status: "unavailable", reason: "status_unavailable" };
  }

  if (!data?.is_enabled) {
    return { required: false, status: "loaded" };
  }

  if (purpose === "vault_unlock") {
    return {
      required: Boolean(data.vault_2fa_enabled),
      status: "loaded",
      reason: data.vault_2fa_enabled ? "vault_2fa_enabled" : undefined,
    };
  }

  return { required: true, status: "loaded", reason: "account_2fa_enabled" };
}

export async function verifyTwoFactorServer(input: VerifyTwoFactorInput): Promise<VerifyTwoFactorResult> {
  const code = normalizeCode(input.code, input.method);
  if (!code) {
    return { ok: false, status: 400, error: GENERIC_2FA_ERROR };
  }

  if (input.purpose === "disable_2fa" && input.method === "backup_code") {
    return { ok: false, status: 400, error: GENERIC_2FA_ERROR };
  }

  const requirement = await getTwoFactorRequirementServer(input.supabaseAdmin, input.userId, input.purpose);
  if (requirement.status === "unavailable") {
    return { ok: false, status: 503, error: "Verification temporarily unavailable" };
  }

  if (!requirement.required) {
    return { ok: true, required: false };
  }

  const rateLimit = await checkAuthRateLimit({
    supabaseAdmin: input.supabaseAdmin,
    req: input.req,
    action: getRateLimitAction(input.purpose, input.method),
    account: { kind: "user", value: input.userId },
  });
  if (!rateLimit.allowed) {
    return rateLimitToResult(rateLimit);
  }

  const valid = input.method === "backup_code"
    ? await verifyAndConsumeBackupCodeServer(input.supabaseAdmin, input.userId, code)
    : await verifyTotpCodeServer(input.supabaseAdmin, input.userId, code);

  if (!valid) {
    const failure = await recordAuthRateLimitFailure(rateLimit);
    if (failure.lockedUntil) {
      return failureToRateLimitedResult(failure);
    }
    return {
      ok: false,
      status: 401,
      error: GENERIC_2FA_ERROR,
      attemptsRemaining: failure.attemptsRemaining,
    };
  }

  await resetAuthRateLimit(rateLimit);
  await (input.supabaseAdmin.from("user_2fa") as {
    update: (values: Record<string, unknown>) => {
      eq: (column: string, value: string) => Promise<{ error: { message?: string } | null }>;
    };
  })
    .update({ last_verified_at: new Date().toISOString() })
    .eq("user_id", input.userId);

  return { ok: true, required: true };
}

export function twoFactorFailureResponse(result: Exclude<VerifyTwoFactorResult, { ok: true }>, headers: Headers): Response {
  const responseHeaders = new Headers(headers);
  responseHeaders.set("Content-Type", "application/json");
  if (result.retryAfterSeconds && result.retryAfterSeconds > 0) {
    responseHeaders.set("Retry-After", String(result.retryAfterSeconds));
  }

  return new Response(JSON.stringify({
    error: result.error,
    attemptsRemaining: result.attemptsRemaining,
    lockedUntil: result.lockedUntil,
  }), {
    status: result.status,
    headers: responseHeaders,
  });
}

export function twoFactorRateLimitResponse(state: AuthRateLimitState, headers: Headers): Response {
  return authRateLimitResponse(state, headers);
}

async function verifyTotpCodeServer(
  supabaseAdmin: SupabaseAdminClient,
  userId: string,
  code: string,
): Promise<boolean> {
  const { data: totpSecret, error } = await supabaseAdmin.rpc("get_user_2fa_secret", {
    p_user_id: userId,
    p_require_enabled: true,
  });

  if (error || !totpSecret) {
    console.error("Failed to load TOTP secret for 2FA verification:", error);
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

  return totp.validate({ token: code, window: 1 }) !== null;
}

async function verifyAndConsumeBackupCodeServer(
  supabaseAdmin: SupabaseAdminClient,
  userId: string,
  code: string,
): Promise<boolean> {
  const backupCodeQuery = ((supabaseAdmin.from("backup_codes") as {
    select: (columns: string) => {
      eq: (column: string, value: string) => {
        eq: (column: string, value: boolean) => Promise<{
          data: Array<{ id: string; code_hash: string }> | null;
          error: { message?: string } | null;
        }>;
      };
    };
  })
    .select("id, code_hash")
    .eq("user_id", userId));

  const unusedResult = await backupCodeQuery.eq("is_used", false);
  if (unusedResult.error || !unusedResult.data?.length) {
    return false;
  }

  const userSalt = await getUserEncryptionSalt(supabaseAdmin, userId);
  let validCodeId: string | null = null;
  for (const storedCode of unusedResult.data) {
    if (await verifyBackupCodeHashServer(code, storedCode.code_hash, userSalt)) {
      validCodeId = storedCode.id;
      break;
    }
  }

  if (!validCodeId) {
    return false;
  }

  const consumeQuery = ((supabaseAdmin.from("backup_codes") as {
    update: (values: Record<string, unknown>) => {
      eq: (column: string, value: string) => {
        eq: (column: string, value: string) => {
          eq: (column: string, value: boolean) => {
            select: (columns: string) => {
              maybeSingle: () => Promise<{ data: { id: string } | null; error: { message?: string } | null }>;
            };
          };
        };
      };
    };
  })
    .update({
      is_used: true,
      used_at: new Date().toISOString(),
    })
    .eq("id", validCodeId));

  const consumeResult = await consumeQuery
    .eq("user_id", userId)
    .eq("is_used", false)
    .select("id")
    .maybeSingle();

  return !consumeResult.error && Boolean(consumeResult.data);
}

async function verifyBackupCodeHashServer(code: string, storedHash: string, userSalt: string | null): Promise<boolean> {
  if (storedHash.startsWith("v3:")) {
    const [, saltBase64, hash] = storedHash.split(":");
    if (!saltBase64 || !hash) {
      return false;
    }
    const salt = Uint8Array.from(atob(saltBase64), (char) => char.charCodeAt(0));
    const computedHash = await argon2id({
      password: code,
      salt,
      parallelism: 1,
      iterations: 2,
      memorySize: 16384,
      hashLength: 32,
      outputType: "hex",
    });
    return computedHash === hash;
  }

  if (userSalt && storedHash === await legacyHmacBackupCodeHash(code, userSalt)) {
    return true;
  }
  return storedHash === await legacySha256Hex(code);
}

async function getUserEncryptionSalt(supabaseAdmin: SupabaseAdminClient, userId: string): Promise<string | null> {
  const { data } = await (supabaseAdmin.from("profiles") as {
    select: (columns: string) => {
      eq: (column: string, value: string) => {
        maybeSingle: () => Promise<{ data: { encryption_salt: string | null } | null; error: { message?: string } | null }>;
      };
    };
  })
    .select("encryption_salt")
    .eq("user_id", userId)
    .maybeSingle();
  return data?.encryption_salt ?? null;
}

async function legacyHmacBackupCodeHash(code: string, salt: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(salt),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const signature = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(code));
  return bytesToHex(new Uint8Array(signature));
}

async function legacySha256Hex(code: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(code));
  return bytesToHex(new Uint8Array(digest));
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

function normalizeCode(code: string, method: TwoFactorMethod): string {
  if (method === "backup_code") {
    return code.replace(/[\s-]/g, "").toUpperCase();
  }
  return code.replace(/\s/g, "");
}

function getRateLimitAction(purpose: TwoFactorPurpose, method: TwoFactorMethod): AuthRateLimitAction {
  if (purpose === "vault_unlock") {
    return method === "backup_code" ? "vault_backup_code_verify" : "vault_totp_verify";
  }
  if (purpose === "disable_2fa") {
    return "disable_2fa_verify";
  }
  if (purpose === "password_reset" || purpose === "password_change") {
    return method === "backup_code" ? "password_reset_backup_code_verify" : "password_reset_totp_verify";
  }
  if (purpose === "critical_action" || purpose === "account_security_change") {
    return "critical_2fa_verify";
  }
  return method === "backup_code" ? "login_backup_code_verify" : "login_totp_verify";
}

function rateLimitToResult(state: AuthRateLimitState): VerifyTwoFactorResult {
  return {
    ok: false,
    status: state.status,
    error: state.error ?? "Too many attempts",
    attemptsRemaining: state.attemptsRemaining,
    lockedUntil: state.lockedUntil,
    retryAfterSeconds: state.retryAfterSeconds,
  };
}

function failureToRateLimitedResult(failure: AuthRateLimitFailureResult): VerifyTwoFactorResult {
  return {
    ok: false,
    status: 429,
    error: "Too many attempts",
    attemptsRemaining: failure.attemptsRemaining,
    lockedUntil: failure.lockedUntil,
    retryAfterSeconds: failure.retryAfterSeconds,
  };
}
