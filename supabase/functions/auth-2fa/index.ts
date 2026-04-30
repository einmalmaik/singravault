import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "npm:@supabase/supabase-js@2";
import { getCorsHeaders } from "../_shared/cors.ts";
import {
  getTwoFactorRequirementServer,
  twoFactorFailureResponse,
  type TwoFactorMethod,
  type TwoFactorPurpose,
  verifyTwoFactorServer,
} from "../_shared/twoFactor.ts";

const supabaseUrl = Deno.env.get("SUPABASE_URL")!;
const supabaseServiceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
const supabaseAdmin = createClient(supabaseUrl, supabaseServiceKey);
const CHALLENGE_TTL_MS = 5 * 60 * 1000;
const DEVICE_KEY_DEACTIVATION_CONFIRMATION_WORD = "DISABLE DEVICE KEY";

Deno.serve(async (req) => {
  const corsHeaders = getCorsHeaders(req);
  const headers = new Headers({
    ...corsHeaders,
    "Content-Type": "application/json",
  });

  if (req.method === "OPTIONS") {
    return new Response("ok", { headers });
  }

  if (req.method !== "POST") {
    return new Response(JSON.stringify({ error: "Method not allowed" }), { status: 405, headers });
  }

  try {
    const userId = await getAuthenticatedUserId(req);
    if (!userId) {
      return new Response(JSON.stringify({ error: "Authentication required" }), { status: 401, headers });
    }

    const body = await req.json();
    const action = typeof body.action === "string" ? body.action : "";

    if (action === "requirement") {
      return await handleRequirement(userId, body, headers);
    }

    if (action === "create-challenge") {
      return await handleCreateChallenge(userId, body, headers);
    }

    if (action === "verify-challenge") {
      return await handleVerifyChallenge(req, userId, body, headers);
    }

    if (action === "disable-2fa") {
      return await handleDisableTwoFactor(req, userId, body, headers);
    }

    if (action === "complete-device-key-deactivation") {
      return await handleCompleteDeviceKeyDeactivation(req, userId, body, headers);
    }

    return new Response(JSON.stringify({ error: "Unknown action" }), { status: 400, headers });
  } catch (error) {
    console.error("auth-2fa error:", error);
    return new Response(JSON.stringify({ error: "Internal Server Error" }), { status: 500, headers });
  }
});

async function handleRequirement(userId: string, body: Record<string, unknown>, headers: Headers): Promise<Response> {
  const purpose = parsePurpose(body.context);
  if (!purpose) {
    return new Response(JSON.stringify({ error: "Invalid request payload" }), { status: 400, headers });
  }

  const requirement = await getTwoFactorRequirementServer(supabaseAdmin, userId, purpose);
  if (requirement.status === "unavailable") {
    return new Response(JSON.stringify({
      required: true,
      status: "unavailable",
      reason: "status_unavailable",
    }), { status: 200, headers });
  }

  return new Response(JSON.stringify({
    required: requirement.required,
    status: "loaded",
    reason: requirement.reason,
  }), { status: 200, headers });
}

async function handleCompleteDeviceKeyDeactivation(
  req: Request,
  userId: string,
  body: Record<string, unknown>,
  headers: Headers,
): Promise<Response> {
  const confirmationWord = typeof body.confirmationWord === "string" ? body.confirmationWord : "";
  const twoFactorCode = typeof body.twoFactorCode === "string" ? body.twoFactorCode : "";
  const encryptedUserKey = typeof body.encryptedUserKey === "string" ? body.encryptedUserKey : "";
  const verificationHash = typeof body.verificationHash === "string" ? body.verificationHash : "";
  const kdfVersion = typeof body.kdfVersion === "number" && Number.isInteger(body.kdfVersion)
    ? body.kdfVersion
    : null;
  const targetProtectionMode = typeof body.targetProtectionMode === "string" ? body.targetProtectionMode : "";

  if (
    !encryptedUserKey ||
    !verificationHash ||
    !kdfVersion ||
    targetProtectionMode !== "master_only"
  ) {
    return new Response(JSON.stringify({ error: "Invalid request payload" }), { status: 400, headers });
  }

  if (confirmationWord !== DEVICE_KEY_DEACTIVATION_CONFIRMATION_WORD) {
    return new Response(JSON.stringify({
      error: "Invalid request payload",
      errorCode: "INVALID_CONFIRMATION",
    }), { status: 400, headers });
  }

  const requirement = await getTwoFactorRequirementServer(supabaseAdmin, userId, "vault_unlock");
  if (requirement.status === "unavailable") {
    return new Response(JSON.stringify({ error: "Verification temporarily unavailable" }), { status: 503, headers });
  }

  if (requirement.required) {
    if (!twoFactorCode) {
      return new Response(JSON.stringify({ error: "Invalid or expired verification code" }), { status: 400, headers });
    }

    const result = await verifyTwoFactorServer({
      supabaseAdmin,
      req,
      userId,
      purpose: "critical_action",
      method: "totp",
      code: twoFactorCode,
    });

    if (!result.ok) {
      return twoFactorFailureResponse(result, headers);
    }
  }

  const { error } = await supabaseAdmin
    .from("profiles")
    .update({
      master_password_verifier: verificationHash,
      kdf_version: kdfVersion,
      encrypted_user_key: encryptedUserKey,
      vault_protection_mode: "master_only",
      device_key_version: null,
      device_key_enabled_at: null,
      device_key_backup_acknowledged_at: null,
    })
    .eq("user_id", userId)
    .eq("vault_protection_mode", "device_key_required");

  if (error) {
    console.error("Failed to complete Device Key deactivation:", error);
    return new Response(JSON.stringify({ error: "Device Key protection state could not be updated" }), { status: 503, headers });
  }

  return new Response(JSON.stringify({ success: true }), { status: 200, headers });
}

async function handleCreateChallenge(userId: string, body: Record<string, unknown>, headers: Headers): Promise<Response> {
  const purpose = parsePurpose(body.context);
  if (!purpose) {
    return new Response(JSON.stringify({ error: "Invalid request payload" }), { status: 400, headers });
  }

  const requirement = await getTwoFactorRequirementServer(supabaseAdmin, userId, purpose);
  if (requirement.status === "unavailable") {
    return new Response(JSON.stringify({ error: "Verification temporarily unavailable" }), { status: 503, headers });
  }

  if (!requirement.required) {
    return new Response(JSON.stringify({ required: false }), { status: 200, headers });
  }

  const expiresAt = new Date(Date.now() + CHALLENGE_TTL_MS).toISOString();
  const { data, error } = await supabaseAdmin
    .from("two_factor_challenges")
    .insert({
      user_id: userId,
      purpose,
      expires_at: expiresAt,
    })
    .select("id, expires_at")
    .maybeSingle();

  if (error || !data) {
    console.error("Failed to create 2FA challenge:", error);
    return new Response(JSON.stringify({ error: "Verification temporarily unavailable" }), { status: 503, headers });
  }

  return new Response(JSON.stringify({
    required: true,
    challengeId: data.id,
    expiresAt: data.expires_at,
  }), { status: 200, headers });
}

async function handleVerifyChallenge(
  req: Request,
  userId: string,
  body: Record<string, unknown>,
  headers: Headers,
): Promise<Response> {
  const challengeId = typeof body.challengeId === "string" ? body.challengeId.trim() : "";
  const purpose = parsePurpose(body.context);
  const method = parseMethod(body.method);
  const code = typeof body.code === "string" ? body.code : "";

  if (!challengeId || !purpose || !method || !code) {
    return new Response(JSON.stringify({ error: "Invalid request payload" }), { status: 400, headers });
  }

  const challenge = await loadActiveChallenge(userId, challengeId, purpose);
  if (!challenge) {
    return new Response(JSON.stringify({ error: "Invalid or expired verification code" }), { status: 401, headers });
  }

  const result = await verifyTwoFactorServer({
    supabaseAdmin,
    req,
    userId,
    purpose,
    method,
    code,
    challengeId,
  });

  if (!result.ok) {
    return twoFactorFailureResponse(result, headers);
  }

  const nowIso = new Date().toISOString();
  const { data: consumed, error } = await supabaseAdmin
    .from("two_factor_challenges")
    .update({
      verified_at: nowIso,
      consumed_at: nowIso,
      method,
    })
    .eq("id", challengeId)
    .eq("user_id", userId)
    .eq("purpose", purpose)
    .is("consumed_at", null)
    .gt("expires_at", nowIso)
    .select("id")
    .maybeSingle();

  if (error || !consumed) {
    return new Response(JSON.stringify({ error: "Invalid or expired verification code" }), { status: 401, headers });
  }

  return new Response(JSON.stringify({ success: true, verified: true }), { status: 200, headers });
}

async function handleDisableTwoFactor(
  req: Request,
  userId: string,
  body: Record<string, unknown>,
  headers: Headers,
): Promise<Response> {
  const code = typeof body.code === "string" ? body.code : "";
  const method = parseMethod(body.method ?? "totp");
  if (!code || method !== "totp") {
    return new Response(JSON.stringify({ error: "Invalid or expired verification code" }), { status: 400, headers });
  }

  const result = await verifyTwoFactorServer({
    supabaseAdmin,
    req,
    userId,
    purpose: "disable_2fa",
    method: "totp",
    code,
  });

  if (!result.ok) {
    return twoFactorFailureResponse(result, headers);
  }

  const { error } = await supabaseAdmin
    .from("user_2fa")
    .delete()
    .eq("user_id", userId);
  if (error) {
    console.error("Failed to disable 2FA:", error);
    return new Response(JSON.stringify({ error: "Verification temporarily unavailable" }), { status: 503, headers });
  }

  await supabaseAdmin.from("backup_codes").delete().eq("user_id", userId);
  return new Response(JSON.stringify({ success: true }), { status: 200, headers });
}

async function loadActiveChallenge(userId: string, challengeId: string, purpose: TwoFactorPurpose) {
  const { data, error } = await supabaseAdmin
    .from("two_factor_challenges")
    .select("id")
    .eq("id", challengeId)
    .eq("user_id", userId)
    .eq("purpose", purpose)
    .is("consumed_at", null)
    .gt("expires_at", new Date().toISOString())
    .maybeSingle();

  if (error) {
    console.error("Failed to load 2FA challenge:", error);
    return null;
  }
  return data;
}

async function getAuthenticatedUserId(req: Request): Promise<string | null> {
  const authHeader = req.headers.get("Authorization");
  if (!authHeader?.startsWith("Bearer ")) {
    return null;
  }

  const token = authHeader.slice("Bearer ".length).trim();
  if (!token) {
    return null;
  }

  const { data, error } = await supabaseAdmin.auth.getUser(token);
  if (error || !data.user) {
    return null;
  }

  return data.user.id;
}

function parsePurpose(value: unknown): TwoFactorPurpose | null {
  switch (value) {
    case "account_login":
    case "password_reset":
    case "password_change":
    case "account_security_change":
    case "disable_2fa":
    case "vault_unlock":
    case "critical_action":
      return value;
    default:
      return null;
  }
}

function parseMethod(value: unknown): TwoFactorMethod | null {
  if (value === "totp" || value === "backup_code") {
    return value;
  }
  return null;
}
