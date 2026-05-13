// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 — see LICENSE

/**
 * @fileoverview Two-Factor Authentication (2FA) Edge Function
 *
 * Diese Edge Function verwaltet alle serverseitigen 2FA-Operationen.
 * Unterstützt TOTP (Time-based One-Time Password) und Backup-Codes.
 *
 * ## Verfügbare Aktionen
 *
 * | Aktion                              | Beschreibung                                       |
 * |-------------------------------------|---------------------------------------------------|
 * | `requirement`                       | Prüft ob 2FA für einen bestimmten Zweck nötig ist |
 * | `create-challenge`                  | Erstellt Challenge für 2FA-Verifikation           |
 * | `verify-challenge`                  | Verifiziert TOTP/Backup-Code gegen Challenge      |
 * | `disable-2fa`                       | Deaktiviert 2FA (erfordert gültigen TOTP-Code)    |
 * | `complete-device-key-deactivation`  | Deaktiviert Device-Key-Schutz (kritische Aktion)  |
 *
 * ## 2FA-Zwecke (Purposes)
 *
 * | Purpose                   | Beschreibung                                |
 * |---------------------------|---------------------------------------------|
 * | `account_login`           | Login mit OPAQUE                            |
 * | `password_reset`          | Passwort-Reset via E-Mail                   |
 * | `password_change`         | Passwort-Änderung (authentifiziert)         |
 * | `account_security_change` | Sicherheitseinstellungen ändern             |
 * | `disable_2fa`             | 2FA deaktivieren                            |
 * | `vault_unlock`            | Vault entsperren (optional je nach Policy)  |
 * | `critical_action`         | Kritische Aktionen wie Device-Key-Änderung  |
 *
 * ## Challenge-Flow
 *
 * ```
 * 1. Client: create-challenge → {challengeId, expiresAt}
 * 2. User: Gibt TOTP-Code oder Backup-Code ein
 * 3. Client: verify-challenge → {success: true, verified: true}
 * ```
 *
 * ## Aufruf aus dem Frontend
 *
 * Aufgerufen via `invokeAuthedFunction('auth-2fa', {...})` aus:
 * - `src/services/twoFactorService.ts` - 2FA-Verifikation
 * - `src/components/settings/TwoFactorSettings.tsx` - 2FA-Setup/Disable
 * - `src/components/settings/SecuritySettings.tsx` - Device-Key-Deaktivierung
 *
 * ## Sicherheitsmaßnahmen
 *
 * - Rate-Limiting via `_shared/twoFactor.ts`
 * - Challenge-TTL: 5 Minuten
 * - Backup-Codes: Einmalig verwendbar
 * - Device-Key-Deaktivierung: Erfordert Bestätigungswort + 2FA
 *
 * @see src/services/twoFactorService.ts - Frontend 2FA-Service
 * @see _shared/twoFactor.ts - Shared 2FA-Utilities
 */

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

// ============================================================================
// Konfiguration
// ============================================================================

/**
 * Supabase-URL aus Umgebungsvariablen.
 */
const supabaseUrl = Deno.env.get("SUPABASE_URL")!;

/**
 * Service Role Key für Admin-Operationen.
 */
const supabaseServiceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;

/**
 * Admin-Client für Datenbankoperationen.
 */
const supabaseAdmin = createClient(supabaseUrl, supabaseServiceKey);

/**
 * Challenge-Gültigkeit: 5 Minuten.
 * Kurz genug für Sicherheit, lang genug für Benutzerfreundlichkeit.
 */
const CHALLENGE_TTL_MS = 5 * 60 * 1000;

/**
 * Bestätigungswort für Device-Key-Deaktivierung.
 * Muss exakt eingegeben werden, um versehentliche Deaktivierung zu verhindern.
 */
const DEVICE_KEY_DEACTIVATION_CONFIRMATION_WORD = "DISABLE DEVICE KEY";

// ============================================================================
// Request Handler
// ============================================================================

/**
 * Haupteinstiegspunkt der Edge Function.
 *
 * Alle Aktionen erfordern einen authentifizierten Benutzer (Bearer Token).
 */
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

  const { data: updatedProfile, error } = await supabaseAdmin
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
    .eq("vault_protection_mode", "device_key_required")
    .select("user_id, vault_protection_mode")
    .maybeSingle();

  if (error) {
    console.error("Failed to complete Device Key deactivation:", error);
    return new Response(JSON.stringify({ error: "Device Key protection state could not be updated" }), { status: 503, headers });
  }

  if (!updatedProfile) {
    return new Response(JSON.stringify({
      error: "Device Key protection state could not be updated",
      errorCode: "DEVICE_KEY_STATE_CONFLICT",
    }), { status: 409, headers });
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
