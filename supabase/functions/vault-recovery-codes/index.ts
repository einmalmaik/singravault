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

const supabaseUrl = Deno.env.get("SUPABASE_URL")!;
const supabaseServiceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
const supabaseAdmin = createClient(supabaseUrl, supabaseServiceKey);

const CODE_COUNT = 5;
const CODE_BODY_LENGTH = 26;
const CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
const HASH_VERSION = "argon2id-v3";
const SIGNING_ALGORITHM = { name: "ECDSA", namedCurve: "P-256" } as const;
const SIGNING_PARAMS = { name: "ECDSA", hash: "SHA-256" } as const;

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

async function ownsVault(userId: string, vaultId: string): Promise<boolean> {
  const { data } = await supabaseAdmin
    .from("vaults")
    .select("id")
    .eq("id", vaultId)
    .eq("user_id", userId)
    .maybeSingle();
  return Boolean(data);
}

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

function generateRecoveryCode(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(CODE_BODY_LENGTH));
  const body = Array.from(bytes, (byte) => CODE_ALPHABET[byte % CODE_ALPHABET.length]).join("");
  return `SVR-${body.slice(0, 5)}-${body.slice(5, 10)}-${body.slice(10, 15)}-${body.slice(15, 20)}-${body.slice(20)}`;
}

function normalizeRecoveryCode(value: string): string {
  const compact = value.normalize("NFKC").toUpperCase().replace(/[\s-]+/gu, "");
  return compact.startsWith("SVR") && compact.length === CODE_BODY_LENGTH + 3
    ? compact.slice(3)
    : compact;
}

function isNormalizedRecoveryCode(value: string): boolean {
  return /^[A-Z2-9]{26}$/u.test(value);
}

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

async function computeOpHash(signedBody: Record<string, unknown>): Promise<string> {
  return sha256Base64Url(canonicalizeVaultStructure({
    schema: "op-hash-v1",
    body: signedBody,
  }));
}

async function sha256Base64Url(bytes: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return encodeBase64Url(new Uint8Array(digest));
}

function canonicalizeVaultStructure(value: unknown): Uint8Array {
  const parts: string[] = [];
  emitCanonical(value, parts, new WeakSet<object>());
  return new TextEncoder().encode(parts.join(""));
}

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

function compareBytes(left: Uint8Array, right: Uint8Array): number {
  const min = Math.min(left.length, right.length);
  for (let index = 0; index < min; index += 1) {
    if (left[index] !== right[index]) return left[index] - right[index];
  }
  return left.length - right.length;
}

function encodeBase64Url(bytes: Uint8Array): string {
  let binary = "";
  bytes.forEach((byte) => {
    binary += String.fromCharCode(byte);
  });
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/u, "");
}

function decodeBase64Url(value: string): Uint8Array {
  const base64 = value.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(value.length / 4) * 4, "=");
  return Uint8Array.from(atob(base64), (char) => char.charCodeAt(0));
}

function safeEqualText(left: string, right: string): boolean {
  if (left.length !== right.length) return false;
  let diff = 0;
  for (let index = 0; index < left.length; index += 1) {
    diff |= left.charCodeAt(index) ^ right.charCodeAt(index);
  }
  return diff === 0;
}

function readString(value: unknown): string | null {
  return typeof value === "string" && value.length > 0 ? value : null;
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== "object") return false;
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

function json(payload: Record<string, unknown>, status: number, headers: Headers): Response {
  return new Response(JSON.stringify(payload), { status, headers });
}

function classifyServerError(error: unknown): string {
  return error instanceof Error ? error.message : "unknown";
}

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
