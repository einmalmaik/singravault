/**
 * @fileoverview Vault Recovery Codes Edge Function
 *
 * Diese Edge Function verwaltet Recovery-Codes für das Vault-Device-Trust-System.
 * Recovery-Codes ermöglichen die Wiederherstellung des Vault-Zugriffs, wenn alle
 * vertrauenswürdigen Geräte verloren gehen.
 *
 * ## Sicherheitskonzept
 *
 * Recovery-Codes sind ein kritischer Bestandteil der Zero-Knowledge-Architektur:
 * - Server speichert nur Argon2id-Hashes der Codes (niemals Klartext)
 * - Commitments ermöglichen kryptografische Bindung ohne Code-Offenlegung
 * - Rate-Limiting schützt vor Brute-Force-Angriffen
 * - Device-Trust-Operationen sind signiert und verifizierbar
 *
 * ## Verfügbare Aktionen
 *
 * | Aktion              | Beschreibung                                        |
 * |---------------------|-----------------------------------------------------|
 * | `status`            | Prüft ob aktive Recovery-Codes existieren           |
 * | `prepare-code-set`  | Generiert neues Code-Set (5 Codes, noch inaktiv)    |
 * | `activate-code-set` | Aktiviert Code-Set via signierter Vault-Operation   |
 * | `redeem-code`       | Löst Code ein für Device-Trust-Recovery             |
 *
 * ## Authentifizierung
 *
 * Alle Endpoints erfordern einen gültigen Bearer-Token (JWT) im Authorization-Header.
 * Die Funktion nutzt `verify_jwt = false` in config.toml, da die JWT-Validierung
 * manuell über `supabaseAdmin.auth.getUser()` erfolgt (ermöglicht bessere Fehlerbehandlung).
 *
 * ## Deployment-Hinweise
 *
 * Bei 401-Fehlern beim Deployment prüfen:
 * 1. `supabase login` - CLI-Authentifizierung aktiv?
 * 2. `supabase link --project-ref lcrtadxlojaucwapgzmy` - Projekt verknüpft?
 * 3. Benutzer hat Deploy-Rechte für das Projekt?
 *
 * @see EDGE_FUNCTION_MANIFEST.md für die Zuordnung Core vs. Premium Functions
 */

import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "npm:@supabase/supabase-js@2";
import { argon2id } from "npm:hash-wasm";
import { getCorsHeaders } from "../_shared/cors.ts";
import {
  authRateLimitResponse,
  checkAuthRateLimit,
  recordAuthRateLimitFailure,
  resetAuthRateLimit,
} from "../_shared/authRateLimit.ts";

// ============================================================================
// Konfiguration
// ============================================================================

/**
 * Supabase-URL aus Umgebungsvariablen.
 * Wird automatisch vom Supabase Edge Function Runtime gesetzt.
 */
const supabaseUrl = Deno.env.get("SUPABASE_URL")!;

/**
 * Service Role Key für Admin-Operationen.
 * ACHTUNG: Dieser Key umgeht RLS - nur für vertrauenswürdige Server-Operationen verwenden!
 */
const supabaseServiceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;

/**
 * Admin-Client für Datenbankoperationen mit vollen Rechten.
 * Wird benötigt für:
 * - Lesen/Schreiben von Recovery-Code-Sets
 * - Verifizieren von Device-Trust-Records
 * - Ausführen von RPC-Funktionen
 */
const supabaseAdmin = createClient(supabaseUrl, supabaseServiceKey);

// ============================================================================
// Recovery-Code Konstanten
// ============================================================================

/**
 * Anzahl der Recovery-Codes pro Set.
 * 5 Codes bieten gute Balance zwischen Sicherheit und Benutzerfreundlichkeit.
 */
const CODE_COUNT = 5;

/**
 * Länge des Code-Körpers (ohne Präfix und Trennzeichen).
 * 26 Zeichen = ca. 130 Bit Entropie (log2(32^26)).
 */
const CODE_BODY_LENGTH = 26;

/**
 * Zeichensatz für Recovery-Codes.
 * Ausgeschlossen: 0, O, 1, I, L (zur Vermeidung von Verwechslungen)
 * Enthält: A-H, J-N, P-Z, 2-9 (32 eindeutige Zeichen)
 */
const CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

/**
 * Hash-Version für gespeicherte Code-Hashes.
 * Format: "v3:<base64url-salt>:<hex-hash>"
 */
const HASH_VERSION = "argon2id-v3";

/**
 * ECDSA P-256 Algorithmus für Signaturverifikation.
 * Verwendet für Device-Trust-Operationen.
 */
const SIGNING_ALGORITHM = { name: "ECDSA", namedCurve: "P-256" } as const;

/**
 * Signaturparameter: ECDSA mit SHA-256 für Operation-Signaturen.
 */
const SIGNING_PARAMS = { name: "ECDSA", hash: "SHA-256" } as const;

// ============================================================================
// Request Handler
// ============================================================================

/**
 * Haupteinstiegspunkt der Edge Function.
 *
 * Verarbeitet eingehende HTTP-Requests und routet sie zur passenden Handler-Funktion.
 * Alle Requests (außer OPTIONS) erfordern authentifizierte Benutzer.
 *
 * @example
 * ```bash
 * # Status abfragen
 * curl -X POST https://project.supabase.co/functions/v1/vault-recovery-codes \
 *   -H "Authorization: Bearer $TOKEN" \
 *   -H "Content-Type: application/json" \
 *   -d '{"action": "status", "vaultId": "uuid"}'
 * ```
 */
Deno.serve(async (req) => {
  const headers = new Headers({
    ...getCorsHeaders(req),
    "Content-Type": "application/json",
  });

  if (req.method === "OPTIONS") {
    return new Response("ok", { headers });
  }
  if (req.method !== "POST") {
    return json({ error: "Method not allowed" }, 405, headers);
  }

  try {
    const userId = await getAuthenticatedUserId(req);
    if (!userId) {
      return json({ error: "Authentication required" }, 401, headers);
    }

    const body = await req.json();
    const action = typeof body.action === "string" ? body.action : "";

    if (action === "status") {
      return await handleStatus(userId, body, headers);
    }
    if (action === "prepare-code-set") {
      return await handlePrepareCodeSet(userId, body, headers);
    }
    if (action === "activate-code-set") {
      return await handleActivateCodeSet(userId, body, headers);
    }
    if (action === "redeem-code") {
      return await handleRedeemCode(req, userId, body, headers);
    }

    return json({ error: "Unknown action" }, 400, headers);
  } catch (error) {
    console.error("vault-recovery-codes error:", classifyServerError(error));
    return json({ error: "Internal Server Error" }, 500, headers);
  }
});

// ============================================================================
// Handler-Funktionen
// ============================================================================

/**
 * Prüft den Status der Recovery-Codes für einen Vault.
 *
 * Gibt zurück:
 * - `hasActiveSet`: Ob ein aktives Code-Set existiert
 * - `activeSetId`: UUID des aktiven Sets (oder null)
 * - `remainingCodes`: Anzahl noch nicht verwendeter Codes
 *
 * @param userId - Authentifizierter Benutzer
 * @param body - Request-Body mit `vaultId`
 * @param headers - Response-Headers (inkl. CORS)
 * @returns JSON-Response mit Status-Informationen
 */
async function handleStatus(userId: string, body: Record<string, unknown>, headers: Headers): Promise<Response> {
  const vaultId = readString(body.vaultId);
  if (!vaultId || !await ownsVault(userId, vaultId)) {
    return json({ error: "Invalid request payload" }, 400, headers);
  }

  const { data: activeSet } = await supabaseAdmin
    .from("vault_recovery_code_sets")
    .select("set_id")
    .eq("vault_id", vaultId)
    .eq("user_id", userId)
    .eq("status", "active")
    .order("activated_at", { ascending: false })
    .limit(1)
    .maybeSingle();

  if (!activeSet?.set_id) {
    return json({ hasActiveSet: false, activeSetId: null, remainingCodes: 0 }, 200, headers);
  }

  const { data: unusedCodes } = await supabaseAdmin
    .from("vault_recovery_codes")
    .select("code_id")
    .eq("vault_id", vaultId)
    .eq("user_id", userId)
    .eq("set_id", activeSet.set_id)
    .eq("is_used", false);

  return json({
    hasActiveSet: true,
    activeSetId: activeSet.set_id,
    remainingCodes: Array.isArray(unusedCodes) ? unusedCodes.length : 0,
  }, 200, headers);
}

/**
 * Generiert ein neues Recovery-Code-Set (noch nicht aktiviert).
 *
 * Workflow:
 * 1. Generiert 5 kryptografisch sichere Recovery-Codes
 * 2. Berechnet Argon2id-Hashes für sichere Speicherung
 * 3. Berechnet Commitments für kryptografische Bindung
 * 4. Speichert Set mit Status "pending" (30 Min. gültig)
 * 5. Gibt Klartext-Codes zurück (nur dieses eine Mal!)
 *
 * WICHTIG: Die Codes werden nur bei der Erstellung zurückgegeben.
 * Der Server speichert nur Hashes - keine Wiederherstellung möglich!
 *
 * @param userId - Authentifizierter Benutzer
 * @param body - Request-Body mit `vaultId`
 * @param headers - Response-Headers
 * @returns JSON mit `setId`, `codes` (Klartext), `commitments`, `createdAt`
 */
async function handlePrepareCodeSet(userId: string, body: Record<string, unknown>, headers: Headers): Promise<Response> {
  const vaultId = readString(body.vaultId);
  if (!vaultId || !await ownsVault(userId, vaultId)) {
    return json({ error: "Invalid request payload" }, 400, headers);
  }

  const setId = crypto.randomUUID();
  const createdAt = new Date().toISOString();
  const generated = [];
  for (let index = 0; index < CODE_COUNT; index += 1) {
    const code = generateRecoveryCode();
    const normalized = normalizeRecoveryCode(code);
    generated.push({
      code,
      normalized,
      commitment: await computeRecoveryCodeCommitment({ vaultId, setId, normalizedCode: normalized }),
      hash: await hashRecoveryCode(normalized),
    });
  }

  const { error: setError } = await supabaseAdmin
    .from("vault_recovery_code_sets")
    .insert({
      set_id: setId,
      vault_id: vaultId,
      user_id: userId,
      status: "pending",
      created_at: createdAt,
      expires_at: new Date(Date.now() + 30 * 60 * 1000).toISOString(),
    });
  if (setError) {
    return json({ error: "Recovery code set could not be prepared" }, 503, headers);
  }

  const { error: codesError } = await supabaseAdmin
    .from("vault_recovery_codes")
    .insert(generated.map((entry) => ({
      code_id: crypto.randomUUID(),
      set_id: setId,
      vault_id: vaultId,
      user_id: userId,
      code_hash: entry.hash,
      hash_version: HASH_VERSION,
      commitment: entry.commitment,
    })));
  if (codesError) {
    await supabaseAdmin.from("vault_recovery_code_sets").delete().eq("set_id", setId);
    return json({ error: "Recovery code set could not be prepared" }, 503, headers);
  }

  return json({
    setId,
    codes: generated.map((entry) => entry.code),
    commitments: generated.map((entry) => entry.commitment),
    createdAt,
  }, 200, headers);
}

/**
 * Aktiviert ein zuvor vorbereitetes Recovery-Code-Set.
 *
 * Erfordert eine signierte Vault-Operation vom Typ "recovery_codes_rotate".
 * Die Operation muss von einem vertrauenswürdigen Gerät signiert sein.
 *
 * Sicherheitsprüfungen:
 * - Vault-Ownership-Validierung
 * - Device-Trust-Verifikation (Signatur + Trust-Epoch)
 * - Commitment-Matching (alle 5 Codes)
 * - Idempotenz-Prüfung (Wiederholte Requests sind sicher)
 *
 * @param userId - Authentifizierter Benutzer
 * @param body - Request-Body mit `vaultId`, `setId`, `operation`
 * @param headers - Response-Headers
 * @returns JSON mit `applied: true` und `currentHead` bei Erfolg
 */
async function handleActivateCodeSet(userId: string, body: Record<string, unknown>, headers: Headers): Promise<Response> {
  const vaultId = readString(body.vaultId);
  const setId = readString(body.setId);
  const operation = body.operation;
  if (!vaultId || !setId || !isPlainObject(operation) || !await ownsVault(userId, vaultId)) {
    return json({ error: "Invalid request payload" }, 400, headers);
  }

  const op = mapOperationToRpcPayload(operation);
  if (op.signed_body?.recoveryCodeSetId !== setId) {
    return json({ error: "Invalid recovery rotation operation" }, 403, headers);
  }
  const existing = await findExistingRecoveryOperation(userId, vaultId, op, "recovery_codes_rotate");
  if (existing.kind === "conflict") {
    return json({ error: "Recovery operation conflicts with an existing operation" }, 409, headers);
  }
  if (existing.kind === "match") {
    return json({ applied: true, currentHead: existing.currentHead }, 200, headers);
  }

  if (!await verifyRecoveryRotationOperation(userId, vaultId, setId, op)) {
    return json({ error: "Invalid recovery rotation operation" }, 403, headers);
  }

  const { data: codes } = await supabaseAdmin
    .from("vault_recovery_codes")
    .select("commitment")
    .eq("vault_id", vaultId)
    .eq("user_id", userId)
    .eq("set_id", setId);
  const expectedCommitments = new Set((codes ?? []).map((row: { commitment: string }) => row.commitment));
  const signedCommitments = op.signed_body.recoveryCodeCommitments;
  if (
    !Array.isArray(signedCommitments)
    || signedCommitments.length !== CODE_COUNT
    || signedCommitments.some((commitment: unknown) => typeof commitment !== "string" || !expectedCommitments.has(commitment))
  ) {
    return json({ error: "Invalid recovery rotation operation" }, 403, headers);
  }

  const { data, error } = await supabaseAdmin.rpc("activate_vault_recovery_code_set", {
    p_user_id: userId,
    p_set_id: setId,
    p_op: op,
  });
  if (error) {
    return json({ error: "Recovery code set could not be activated" }, 409, headers);
  }

  return json({ applied: true, currentHead: data?.current_head ?? null }, 200, headers);
}

/**
 * Löst einen Recovery-Code ein, um ein neues Gerät zu autorisieren.
 *
 * Dies ist der kritische Wiederherstellungspfad, wenn alle vertrauenswürdigen
 * Geräte verloren gegangen sind. Ein gültiger Recovery-Code berechtigt zur
 * Erstellung eines neuen Device-Trust-Records.
 *
 * Sicherheitsmechanismen:
 * - Rate-Limiting: Schutz vor Brute-Force (pro User+Vault)
 * - Code-Validierung: Argon2id-Hash-Verifikation
 * - Commitment-Matching: Kryptografische Bindung
 * - Operation-Signatur: Selbst-Signatur des neuen Geräts
 * - Pending-Request-Validierung: Challenge muss noch gültig sein
 *
 * Nach erfolgreicher Einlösung:
 * - Code wird als "verwendet" markiert (einmalig!)
 * - Neues Gerät erhält Trust-Record mit Epoch 0
 * - Rate-Limit wird zurückgesetzt
 *
 * @param req - Original-Request (für Rate-Limiting)
 * @param userId - Authentifizierter Benutzer
 * @param body - Request-Body mit `vaultId`, `requestId`, `recoveryCode`, `operation`
 * @param headers - Response-Headers
 * @returns JSON mit `applied: true` und `currentHead` bei Erfolg
 */
async function handleRedeemCode(
  req: Request,
  userId: string,
  body: Record<string, unknown>,
  headers: Headers,
): Promise<Response> {
  const vaultId = readString(body.vaultId);
  const requestId = readString(body.requestId);
  const recoveryCode = readString(body.recoveryCode);
  const operation = body.operation;
  if (!vaultId || !requestId || !recoveryCode || !isPlainObject(operation) || !await ownsVault(userId, vaultId)) {
    return json({ error: "Invalid request payload" }, 400, headers);
  }

  const rateLimit = await checkAuthRateLimit({
    supabaseAdmin,
    req,
    action: "vault_recovery_code_redeem",
    account: { kind: "user", value: `${userId}:${vaultId}` },
  });
  if (!rateLimit.allowed) {
    return authRateLimitResponse(rateLimit, headers);
  }

  const op = mapOperationToRpcPayload(operation);
  const existing = await findExistingRecoveryOperation(userId, vaultId, op, "recover_device");
  if (existing.kind === "conflict") {
    return json({ error: "Recovery operation conflicts with an existing operation" }, 409, headers);
  }
  if (existing.kind === "match") {
    await resetAuthRateLimit(rateLimit);
    return json({ applied: true, currentHead: existing.currentHead }, 200, headers);
  }

  const normalizedCode = normalizeRecoveryCode(recoveryCode);
  if (!isNormalizedRecoveryCode(normalizedCode)) {
    await recordAuthRateLimitFailure(rateLimit);
    return json({ error: "Invalid recovery code" }, 401, headers);
  }

  const activeSetId = readString(op.signed_body.recoveryCodeSetId);
  const commitment = readString(op.signed_body.recoveryCodeCommitment);
  if (!activeSetId || !commitment) {
    await recordAuthRateLimitFailure(rateLimit);
    return json({ error: "Invalid recovery operation" }, 400, headers);
  }
  const expectedCommitment = await computeRecoveryCodeCommitment({ vaultId, setId: activeSetId, normalizedCode });
  if (commitment !== expectedCommitment) {
    await recordAuthRateLimitFailure(rateLimit);
    return json({ error: "Invalid recovery code" }, 401, headers);
  }

  const { data: codeRows } = await supabaseAdmin
    .from("vault_recovery_codes")
    .select("code_id, code_hash, set_id")
    .eq("vault_id", vaultId)
    .eq("user_id", userId)
    .eq("set_id", activeSetId)
    .eq("commitment", commitment)
    .eq("is_used", false)
    .limit(1);
  const codeRow = Array.isArray(codeRows) ? codeRows[0] : null;
  if (!codeRow || !await verifyRecoveryCodeHash(normalizedCode, codeRow.code_hash)) {
    await recordAuthRateLimitFailure(rateLimit);
    return json({ error: "Invalid recovery code" }, 401, headers);
  }

  if (!await verifyRecoverDeviceOperation(userId, vaultId, requestId, op)) {
    await recordAuthRateLimitFailure(rateLimit);
    return json({ error: "Invalid recovery operation" }, 403, headers);
  }

  const { data, error } = await supabaseAdmin.rpc("redeem_vault_recovery_code_for_device", {
    p_user_id: userId,
    p_request_id: requestId,
    p_code_id: codeRow.code_id,
    p_op: op,
    p_device_trust_payload: buildRecoverDeviceTrustPayload(op),
  });
  if (error) {
    await recordAuthRateLimitFailure(rateLimit);
    return json({ error: "Recovery code could not be redeemed" }, 409, headers);
  }

  await resetAuthRateLimit(rateLimit);
  return json({ applied: true, currentHead: data?.current_head ?? null }, 200, headers);
}

// ============================================================================
// Verifikations-Funktionen
// ============================================================================

/**
 * Verifiziert eine Recovery-Code-Rotations-Operation.
 *
 * Prüft:
 * - Operation-Typ ist "recovery_codes_rotate"
 * - Autor-Gerät ist vertrauenswürdig (Status + Trust-Epoch)
 * - Signatur ist gültig (ECDSA P-256)
 *
 * @param userId - Benutzer-ID
 * @param vaultId - Vault-ID
 * @param setId - Recovery-Code-Set-ID
 * @param op - RPC-Operation-Payload
 * @returns true wenn Operation gültig
 */
async function verifyRecoveryRotationOperation(
  userId: string,
  vaultId: string,
  setId: string,
  op: RpcOperationPayload,
): Promise<boolean> {
  if (
    op.vault_id !== vaultId
    || op.op_type !== "recovery_codes_rotate"
    || op.record_id !== setId
    || op.record_type !== "manifest"
    || op.signature_schema !== "device-signature-v2"
    || op.signed_body?.recoveryCodeSetId !== setId
  ) {
    return false;
  }
  const { data: trust } = await supabaseAdmin
    .from("vault_device_trust_records")
    .select("public_signing_key, trust_epoch")
    .eq("vault_id", vaultId)
    .eq("user_id", userId)
    .eq("device_id", op.author_device_id)
    .eq("status", "trusted")
    .maybeSingle();
  if (!trust || Number(trust.trust_epoch) !== Number(op.trust_epoch)) {
    return false;
  }
  return verifySignedOperation(op, trust.public_signing_key);
}

/**
 * Verifiziert eine Device-Recovery-Operation.
 *
 * Diese Funktion prüft, ob ein neues Gerät berechtigt ist, via Recovery-Code
 * dem Vault beizutreten. Die Operation muss selbst-signiert sein.
 *
 * Prüfungen:
 * - Operation-Typ ist "recover_device"
 * - Pending-Request existiert und ist noch gültig
 * - Public-Key in Operation = Public-Key in Request
 * - Signatur ist gültig
 *
 * @param userId - Benutzer-ID
 * @param vaultId - Vault-ID
 * @param requestId - Pending-Device-Request-ID
 * @param op - RPC-Operation-Payload
 * @returns true wenn Operation gültig
 */
async function verifyRecoverDeviceOperation(
  userId: string,
  vaultId: string,
  requestId: string,
  op: RpcOperationPayload,
): Promise<boolean> {
  if (
    op.vault_id !== vaultId
    || op.op_type !== "recover_device"
    || op.record_type !== "device"
    || op.signature_schema !== "device-signature-v2"
    || op.record_id !== op.author_device_id
  ) {
    return false;
  }
  const publicKey = readString(op.signed_body?.targetPublicSigningKey);
  if (!publicKey) {
    return false;
  }
  const { data: request } = await supabaseAdmin
    .from("vault_pending_device_requests")
    .select("requested_device_id, requested_public_signing_key, status, challenge_expires_at")
    .eq("request_id", requestId)
    .eq("vault_id", vaultId)
    .eq("user_id", userId)
    .maybeSingle();
  if (
    !request
    || request.status !== "pending"
    || new Date(request.challenge_expires_at).getTime() <= Date.now()
    || request.requested_device_id !== op.record_id
    || request.requested_public_signing_key !== publicKey
  ) {
    return false;
  }
  return verifySignedOperation(op, publicKey);
}

/**
 * Verifiziert die digitale Signatur einer Vault-Operation.
 *
 * Workflow:
 * 1. Berechnet Op-Hash aus signedBody neu
 * 2. Vergleicht mit übermitteltem op_hash
 * 3. Importiert Public-Key (SPKI-Format, Base64URL)
 * 4. Verifiziert ECDSA-Signatur über kanonisiertem signedBody
 *
 * @param op - Operation mit Signatur
 * @param publicKeyB64Url - Public-Key in Base64URL-Kodierung
 * @returns true wenn Signatur gültig
 */
async function verifySignedOperation(op: RpcOperationPayload, publicKeyB64Url: string): Promise<boolean> {
  const recomputedOpHash = await computeOpHash(op.signed_body);
  if (recomputedOpHash !== op.op_hash) {
    return false;
  }
  const publicKey = await crypto.subtle.importKey(
    "spki",
    decodeBase64Url(publicKeyB64Url),
    SIGNING_ALGORITHM,
    false,
    ["verify"],
  );
  return crypto.subtle.verify(
    SIGNING_PARAMS,
    publicKey,
    decodeBase64Url(op.signature),
    canonicalizeVaultStructure(op.signed_body),
  );
}

// ============================================================================
// Mapping-Funktionen
// ============================================================================

/**
 * Konvertiert Client-Operation in RPC-Payload-Format.
 *
 * Transformiert camelCase (Client) zu snake_case (Datenbank/RPC).
 * Validiert, dass signedBody existiert.
 *
 * @param operation - Operation im Client-Format
 * @returns Operation im RPC-Format
 * @throws Error wenn signedBody fehlt
 */
function mapOperationToRpcPayload(operation: Record<string, unknown>): RpcOperationPayload {
  const signedBody = operation.signedBody;
  if (!isPlainObject(signedBody)) {
    throw new Error("operation signed body missing");
  }
  return {
    op_id: readString(operation.opId) ?? "",
    op_hash: readString(operation.opHash) ?? "",
    vault_id: readString(operation.vaultId) ?? "",
    author_device_id: readString(operation.authorDeviceId) ?? "",
    op_type: readString(operation.opType) ?? "",
    record_id: readString(operation.recordId) ?? "",
    record_type: readString(operation.recordType) ?? "",
    base_record_version: operation.baseRecordVersion ?? null,
    previous_ciphertext_hash: operation.previousCiphertextHash ?? null,
    new_record_hash: operation.newRecordHash ?? null,
    base_vault_head: operation.baseVaultHead ?? null,
    resulting_vault_head: readString(operation.resultingVaultHead) ?? "",
    intent_id: operation.intentId ?? null,
    rebased_from_op_id: operation.rebasedFromOpId ?? null,
    payload_ciphertext_hash: operation.payloadCiphertextHash ?? null,
    payload_aad_hash: operation.payloadAadHash ?? null,
    signed_body: signedBody,
    signature: readString(operation.signature) ?? "",
    signature_schema: readString(operation.signatureSchema) ?? "",
    trust_epoch: Number(operation.trustEpoch ?? 0),
    created_at_client: readString(operation.createdAtClient) ?? "",
  };
}

/**
 * Erstellt das Trust-Payload für Device-Recovery.
 *
 * Dieses Payload wird vom RPC verwendet, um den neuen Device-Trust-Record
 * zu erstellen. Enthält alle notwendigen Informationen für die Recovery.
 *
 * @param op - Die validierte Recovery-Operation
 * @returns Trust-Payload für RPC
 */
function buildRecoverDeviceTrustPayload(op: RpcOperationPayload): Record<string, unknown> {
  return {
    kind: "recover",
    device: {
      device_id: op.record_id,
      public_signing_key: op.signed_body.targetPublicSigningKey,
      device_name_encrypted: "",
      added_by_device_id: null,
      added_at: op.created_at_client,
      trust_epoch: 0,
    },
    recovery_code_set_id: op.signed_body.recoveryCodeSetId,
    recovery_code_commitment: op.signed_body.recoveryCodeCommitment,
  };
}

// ============================================================================
// Validierungs-Funktionen
// ============================================================================

/**
 * Prüft, ob ein Benutzer einen Vault besitzt.
 *
 * Einfache Ownership-Prüfung über die vaults-Tabelle.
 *
 * @param userId - Benutzer-ID
 * @param vaultId - Vault-ID
 * @returns true wenn Benutzer Vault-Owner ist
 */
async function ownsVault(userId: string, vaultId: string): Promise<boolean> {
  const { data } = await supabaseAdmin
    .from("vaults")
    .select("id")
    .eq("id", vaultId)
    .eq("user_id", userId)
    .maybeSingle();
  return Boolean(data);
}

/**
 * Sucht nach einer existierenden Recovery-Operation mit gleicher ID.
 *
 * Ermöglicht Idempotenz: Wiederholte Requests mit gleicher op_id sind sicher.
 *
 * Rückgabewerte:
 * - `none`: Keine existierende Operation gefunden (neuer Request)
 * - `conflict`: Operation existiert, aber mit anderen Parametern
 * - `match`: Identische Operation bereits verarbeitet
 *
 * @param userId - Benutzer-ID
 * @param vaultId - Vault-ID
 * @param op - Operation zum Vergleich
 * @param expectedOpType - Erwarteter Operations-Typ
 * @returns Ergebnis der Idempotenz-Prüfung
 */
async function findExistingRecoveryOperation(
  userId: string,
  vaultId: string,
  op: RpcOperationPayload,
  expectedOpType: string,
): Promise<
  | { kind: "none" }
  | { kind: "conflict" }
  | { kind: "match"; currentHead: string | null }
> {
  if (!op.op_id) {
    return { kind: "none" };
  }
  const { data } = await supabaseAdmin
    .from("vault_operations")
    .select("op_hash,resulting_vault_head,vault_id,user_id,op_type")
    .eq("op_id", op.op_id)
    .maybeSingle();
  if (!data) {
    return { kind: "none" };
  }
  if (
    data.op_hash !== op.op_hash
    || data.vault_id !== vaultId
    || data.user_id !== userId
    || data.op_type !== expectedOpType
  ) {
    return { kind: "conflict" };
  }
  return { kind: "match", currentHead: data.resulting_vault_head ?? null };
}

// ============================================================================
// Authentifizierung
// ============================================================================

/**
 * Extrahiert die User-ID aus dem Authorization-Header.
 *
 * Erwartet: "Bearer <jwt-token>"
 * Nutzt supabaseAdmin.auth.getUser() für serverseitige JWT-Validierung.
 *
 * HINWEIS: verify_jwt = false in config.toml, da wir hier manuell validieren.
 * Das ermöglicht bessere Fehlerbehandlung und einheitliche Responses.
 *
 * @param req - Eingehender Request
 * @returns User-ID oder null wenn nicht authentifiziert
 */
async function getAuthenticatedUserId(req: Request): Promise<string | null> {
  const authHeader = req.headers.get("Authorization");
  if (!authHeader?.startsWith("Bearer ")) {
    return null;
  }
  const token = authHeader.slice("Bearer ".length).trim();
  const { data, error } = await supabaseAdmin.auth.getUser(token);
  if (error || !data.user) {
    return null;
  }
  return data.user.id;
}

// ============================================================================
// Recovery-Code Generierung & Validierung
// ============================================================================

/**
 * Generiert einen kryptografisch sicheren Recovery-Code.
 *
 * Format: SVR-XXXXX-XXXXX-XXXXX-XXXXX-XXXXXX
 * - Präfix "SVR" für SingraVault Recovery
 * - 26 Zeichen aus 32-Zeichen-Alphabet
 * - ca. 130 Bit Entropie
 *
 * @returns Formatierter Recovery-Code mit Trennzeichen
 */
function generateRecoveryCode(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(CODE_BODY_LENGTH));
  const body = Array.from(bytes, (byte) => CODE_ALPHABET[byte % CODE_ALPHABET.length]).join("");
  return `SVR-${body.slice(0, 5)}-${body.slice(5, 10)}-${body.slice(10, 15)}-${body.slice(15, 20)}-${body.slice(20)}`;
}

/**
 * Normalisiert einen Recovery-Code für Vergleiche.
 *
 * - Konvertiert zu Großbuchstaben
 * - Entfernt Leerzeichen und Bindestriche
 * - Entfernt SVR-Präfix
 * - Unicode-Normalisierung (NFKC)
 *
 * @param value - Code in beliebigem Format
 * @returns 26-Zeichen normalisierter Code
 */
function normalizeRecoveryCode(value: string): string {
  const compact = value.normalize("NFKC").toUpperCase().replace(/[\s-]+/gu, "");
  return compact.startsWith("SVR") && compact.length === CODE_BODY_LENGTH + 3
    ? compact.slice(3)
    : compact;
}

/**
 * Prüft, ob ein Wert ein gültig normalisierter Recovery-Code ist.
 *
 * Gültig: Genau 26 Zeichen aus dem erlaubten Alphabet (A-Z ohne I,L,O + 2-9)
 *
 * @param value - Zu prüfender Wert
 * @returns true wenn gültiges Format
 */
function isNormalizedRecoveryCode(value: string): boolean {
  return /^[A-Z2-9]{26}$/u.test(value);
}

// ============================================================================
// Kryptografische Funktionen
// ============================================================================

/**
 * Berechnet einen sicheren Hash des Recovery-Codes mit Argon2id.
 *
 * Parameter (OWASP-konform für moderate Sicherheit):
 * - parallelism: 1 (Edge-Function-kompatibel)
 * - iterations: 2 (Zeit-Kosten)
 * - memorySize: 16 MB (Speicher-Kosten)
 * - hashLength: 32 Bytes (256 Bit)
 *
 * Ausgabeformat: "v3:<salt-base64url>:<hash-hex>"
 *
 * @param normalizedCode - Normalisierter Recovery-Code
 * @returns Versionierter Hash-String
 */
async function hashRecoveryCode(normalizedCode: string): Promise<string> {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const hash = await argon2id({
    password: normalizedCode,
    salt,
    parallelism: 1,
    iterations: 2,
    memorySize: 16384,
    hashLength: 32,
    outputType: "hex",
  });
  return `v3:${encodeBase64Url(salt)}:${hash}`;
}

/**
 * Verifiziert einen Recovery-Code gegen den gespeicherten Hash.
 *
 * Nutzt konstante-Zeit-Vergleich (safeEqualText) zur Vermeidung
 * von Timing-Angriffen.
 *
 * @param normalizedCode - Eingegebener Code (normalisiert)
 * @param storedHash - Gespeicherter Hash aus Datenbank
 * @returns true wenn Code korrekt
 */
async function verifyRecoveryCodeHash(normalizedCode: string, storedHash: string): Promise<boolean> {
  const [version, saltB64Url, hash] = storedHash.split(":");
  if (version !== "v3" || !saltB64Url || !hash) {
    return false;
  }
  const computed = await argon2id({
    password: normalizedCode,
    salt: decodeBase64Url(saltB64Url),
    parallelism: 1,
    iterations: 2,
    memorySize: 16384,
    hashLength: 32,
    outputType: "hex",
  });
  return safeEqualText(computed, hash);
}

/**
 * Berechnet ein kryptografisches Commitment für einen Recovery-Code.
 *
 * Das Commitment bindet den Code an einen spezifischen Vault und Set,
 * ohne den Code selbst preiszugeben. Es ermöglicht:
 * - Nachweis, dass ein bestimmter Code zu einem Set gehört
 * - Verifikation ohne Hash-Vergleich
 *
 * @param input - Vault-ID, Set-ID und normalisierter Code
 * @returns SHA-256 Hash als Base64URL
 */
async function computeRecoveryCodeCommitment(input: {
  vaultId: string;
  setId: string;
  normalizedCode: string;
}): Promise<string> {
  return sha256Base64Url(canonicalizeVaultStructure({
    app: "singra-vault",
    purpose: "vault-device-recovery-code-commitment-v1",
    vaultId: input.vaultId,
    setId: input.setId,
    code: input.normalizedCode,
  }));
}

/**
 * Berechnet den Hash einer Operation für Signaturverifikation.
 *
 * Der op_hash ist die SHA-256 Prüfsumme des kanonisierten signedBody.
 * Er wird in der Operation mitgeschickt und hier neu berechnet.
 *
 * @param signedBody - Der signierte Teil der Operation
 * @returns SHA-256 Hash als Base64URL
 */
async function computeOpHash(signedBody: Record<string, unknown>): Promise<string> {
  return sha256Base64Url(canonicalizeVaultStructure({
    schema: "op-hash-v1",
    body: signedBody,
  }));
}

/**
 * Berechnet SHA-256 Hash und gibt ihn als Base64URL zurück.
 *
 * @param bytes - Zu hashende Bytes
 * @returns SHA-256 Digest als Base64URL
 */
async function sha256Base64Url(bytes: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return encodeBase64Url(new Uint8Array(digest));
}

// ============================================================================
// Kanonisierung
// ============================================================================

/**
 * Konvertiert einen JavaScript-Wert in kanonische Byte-Repräsentation.
 *
 * Die Kanonisierung gewährleistet deterministisches Hashing:
 * - Objekt-Keys werden byte-lexikografisch sortiert
 * - Strings werden NFC-normalisiert
 * - Keine Whitespace-Variationen
 *
 * @param value - Zu kanonisierender Wert
 * @returns UTF-8 kodierte Bytes
 */
function canonicalizeVaultStructure(value: unknown): Uint8Array {
  const parts: string[] = [];
  emitCanonical(value, parts, new WeakSet<object>());
  return new TextEncoder().encode(parts.join(""));
}

/**
 * Rekursive Hilfsfunktion für Kanonisierung.
 *
 * Unterstützte Typen:
 * - null
 * - string (NFC-normalisiert, JSON-escaped)
 * - number (endlich, Integer bevorzugt)
 * - boolean
 * - Array (rekursiv)
 * - Plain Object (Keys sortiert, rekursiv)
 *
 * @param value - Zu verarbeitender Wert
 * @param parts - Ausgabe-Array für Strings
 * @param seen - WeakSet für Zyklus-Erkennung
 * @throws Error bei zyklischen oder nicht unterstützten Werten
 */
function emitCanonical(value: unknown, parts: string[], seen: WeakSet<object>): void {
  if (value === null) {
    parts.push("null");
    return;
  }
  if (typeof value === "string") {
    parts.push(JSON.stringify(value.normalize("NFC")));
    return;
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new Error("non-finite number");
    parts.push(Number.isInteger(value) && Number.isSafeInteger(value) ? value.toString(10) : value.toString(10));
    return;
  }
  if (typeof value === "boolean") {
    parts.push(value ? "true" : "false");
    return;
  }
  if (Array.isArray(value)) {
    if (seen.has(value)) throw new Error("cyclic value");
    seen.add(value);
    parts.push("[");
    value.forEach((entry, index) => {
      if (index > 0) parts.push(",");
      emitCanonical(entry, parts, seen);
    });
    parts.push("]");
    seen.delete(value);
    return;
  }
  if (isPlainObject(value)) {
    if (seen.has(value)) throw new Error("cyclic value");
    seen.add(value);
    const entries = Object.keys(value)
      .map((key) => ({
        key: key.normalize("NFC"),
        value: value[key],
        bytes: new TextEncoder().encode(key.normalize("NFC")),
      }))
      .sort((left, right) => compareBytes(left.bytes, right.bytes));
    parts.push("{");
    entries.forEach((entry, index) => {
      if (index > 0) parts.push(",");
      parts.push(JSON.stringify(entry.key));
      parts.push(":");
      emitCanonical(entry.value, parts, seen);
    });
    parts.push("}");
    seen.delete(value);
    return;
  }
  throw new Error("unsupported canonical value");
}

/**
 * Byte-lexikografischer Vergleich für Objekt-Key-Sortierung.
 *
 * @param left - Erstes Byte-Array
 * @param right - Zweites Byte-Array
 * @returns Negativ wenn left < right, 0 wenn gleich, positiv wenn left > right
 */
function compareBytes(left: Uint8Array, right: Uint8Array): number {
  const min = Math.min(left.length, right.length);
  for (let index = 0; index < min; index += 1) {
    if (left[index] !== right[index]) return left[index] - right[index];
  }
  return left.length - right.length;
}

// ============================================================================
// Encoding-Hilfsfunktionen
// ============================================================================

/**
 * Kodiert Bytes zu Base64URL (RFC 4648, URL-sicher, ohne Padding).
 *
 * @param bytes - Zu kodierende Bytes
 * @returns Base64URL-String
 */
function encodeBase64Url(bytes: Uint8Array): string {
  let binary = "";
  bytes.forEach((byte) => {
    binary += String.fromCharCode(byte);
  });
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/u, "");
}

/**
 * Dekodiert Base64URL zu Bytes.
 *
 * Wandelt URL-sichere Zeichen zurück und ergänzt fehlendes Padding.
 *
 * @param value - Base64URL-String
 * @returns Dekodierte Bytes
 */
function decodeBase64Url(value: string): Uint8Array {
  const base64 = value.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(value.length / 4) * 4, "=");
  return Uint8Array.from(atob(base64), (char) => char.charCodeAt(0));
}

// ============================================================================
// Sicherheits-Hilfsfunktionen
// ============================================================================

/**
 * Konstante-Zeit String-Vergleich zur Vermeidung von Timing-Angriffen.
 *
 * WICHTIG: Diese Funktion muss für sicherheitskritische Vergleiche verwendet
 * werden (Hash-Verifikation, Token-Vergleiche), da normaler === Vergleich
 * unterschiedliche Ausführungszeiten je nach erstem unterschiedlichen Zeichen hat.
 *
 * @param left - Erster String
 * @param right - Zweiter String
 * @returns true wenn identisch
 */
function safeEqualText(left: string, right: string): boolean {
  if (left.length !== right.length) return false;
  let diff = 0;
  for (let index = 0; index < left.length; index += 1) {
    diff |= left.charCodeAt(index) ^ right.charCodeAt(index);
  }
  return diff === 0;
}

// ============================================================================
// Utility-Funktionen
// ============================================================================

/**
 * Liest einen String aus einem unbekannten Wert.
 *
 * @param value - Unbekannter Wert
 * @returns String wenn vorhanden und nicht leer, sonst null
 */
function readString(value: unknown): string | null {
  return typeof value === "string" && value.length > 0 ? value : null;
}

/**
 * Prüft, ob ein Wert ein Plain Object ist.
 *
 * Ein Plain Object hat Object.prototype oder null als Prototype
 * (also keine Klassen-Instanzen, Arrays, etc.).
 *
 * @param value - Zu prüfender Wert
 * @returns true wenn Plain Object
 */
function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== "object") return false;
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

/**
 * Erstellt eine JSON-Response mit korrekten Headers.
 *
 * @param payload - Response-Body (wird zu JSON serialisiert)
 * @param status - HTTP-Status-Code
 * @param headers - Response-Headers (CORS, etc.)
 * @returns Response-Objekt
 */
function json(payload: Record<string, unknown>, status: number, headers: Headers): Response {
  return new Response(JSON.stringify(payload), { status, headers });
}

/**
 * Klassifiziert Server-Fehler für Logging.
 *
 * Gibt Fehlermeldung zurück (für Logs), aber keine internen Details
 * an den Client (siehe catch-Block im Request-Handler).
 *
 * @param error - Gefangener Fehler
 * @returns Klassifizierte Fehlermeldung
 */
function classifyServerError(error: unknown): string {
  return error instanceof Error ? error.message : "unknown";
}

// ============================================================================
// Typen
// ============================================================================

/**
 * Payload-Format für Vault-Operationen beim RPC-Aufruf.
 *
 * Dieses Interface definiert die Struktur einer signierten Vault-Operation
 * im snake_case Format (wie in der Datenbank gespeichert).
 */
interface RpcOperationPayload {
  op_id: string;
  op_hash: string;
  vault_id: string;
  author_device_id: string;
  op_type: string;
  record_id: string;
  record_type: string;
  base_record_version: unknown;
  previous_ciphertext_hash: unknown;
  new_record_hash: unknown;
  base_vault_head: unknown;
  resulting_vault_head: string;
  intent_id: unknown;
  rebased_from_op_id: unknown;
  payload_ciphertext_hash: unknown;
  payload_aad_hash: unknown;
  signed_body: Record<string, unknown>;
  signature: string;
  signature_schema: string;
  trust_epoch: number;
  created_at_client: string;
}
