// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 — see LICENSE

/**
 * @fileoverview Account Delete Edge Function
 *
 * Diese Edge Function implementiert die vollständige Kontolöschung.
 * Sie ist ein kritischer und unwiderruflicher Vorgang, der alle Benutzerdaten
 * einschließlich Vault-Daten, Anhänge und Auth-Records löscht.
 *
 * ## Lösch-Umfang
 *
 * Folgende Daten werden gelöscht:
 * - Supabase Auth User (via `delete_my_account` RPC)
 * - Alle Tabellen mit user_id Foreign Key (CASCADE)
 * - Storage-Objekte im `vault-attachments` Bucket
 *
 * ## Sicherheitsanforderungen
 *
 * 1. **Authentifizierung**: Gültiger Bearer Token erforderlich
 * 2. **2FA-Challenge**: Falls 2FA aktiviert, muss Challenge-ID übergeben werden
 * 3. **Re-Authentifizierung**: Letzte Auth darf nicht zu lange her sein
 * 4. **Rate-Limiting**: Max. 3 Versuche pro Stunde
 *
 * ## Lösch-Flow
 *
 * ```
 * 1. Token validieren
 * 2. Rate-Limit prüfen
 * 3. 2FA-Challenge validieren (falls erforderlich)
 * 4. delete_my_account RPC aufrufen (atomar)
 * 5. Storage-Objekte löschen (best-effort)
 * 6. Ergebnis zurückgeben
 * ```
 *
 * ## Aufruf aus dem Frontend
 *
 * Aufgerufen via `invokeAuthedFunction('account-delete', {...})` aus:
 * - `src/components/settings/AccountSettings.tsx` - "Account löschen" Button
 *
 * ## Fehlerbehandlung
 *
 * | Fehlercode                    | Bedeutung                                    |
 * |-------------------------------|---------------------------------------------|
 * | `AUTH_REQUIRED`               | Kein oder ungültiger Token                   |
 * | `REAUTH_REQUIRED`             | Session zu alt, erneuter Login nötig         |
 * | `ACCOUNT_DELETE_2FA_REQUIRED` | 2FA-Challenge fehlt                          |
 * | `ACCOUNT_DELETE_INCOMPLETE`   | Teilweise Löschung (DB ok, Storage fehlerhaft)|
 * | `ACCOUNT_DELETE_FAILED`       | Löschung fehlgeschlagen                      |
 *
 * ## Storage-Cleanup
 *
 * Storage-Objekte werden nach dem Account-Löschen entfernt:
 * - Paginierter Abruf aller Objekte unter `{userId}/`
 * - Batch-Löschung (100 Objekte pro Batch)
 * - Best-Effort: Fehler werden geloggt, aber nicht geworfen
 *
 * @see src/components/settings/AccountSettings.tsx - Frontend Account-Löschung
 * @see supabase/migrations - delete_my_account RPC Definition
 */

import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "npm:@supabase/supabase-js@2";
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
 */
const supabaseUrl = Deno.env.get("SUPABASE_URL")!;

/**
 * Service Role Key für Admin-Operationen.
 */
const supabaseServiceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;

/**
 * Anonymer Schlüssel für User-scoped RPC-Aufrufe.
 */
const supabaseAnonKey = Deno.env.get("SUPABASE_ANON_KEY")!;

/**
 * Admin-Client für Storage-Cleanup.
 * persistSession deaktiviert, da Edge Function.
 */
const supabaseAdmin = createClient(supabaseUrl, supabaseServiceKey, {
    auth: {
        persistSession: false,
        autoRefreshToken: false,
    },
});

/**
 * Bucket-Name für Vault-Anhänge.
 */
const ATTACHMENTS_BUCKET = "vault-attachments";

/**
 * Seitengröße beim Auflisten von Storage-Objekten.
 */
const STORAGE_PAGE_SIZE = 100;

/**
 * Batch-Größe beim Löschen von Storage-Objekten.
 */
const REMOVE_BATCH_SIZE = 100;

// ============================================================================
// Request Handler
// ============================================================================

/**
 * Haupteinstiegspunkt der Edge Function.
 *
 * Nur POST-Methode erlaubt. OPTIONS für CORS-Preflight.
 */
Deno.serve(async (req) => {
    const corsHeaders = getCorsHeaders(req, { allowedMethods: "POST, OPTIONS" });
    const headers = new Headers({
        ...corsHeaders,
        "Content-Type": "application/json",
    });

    if (req.method === "OPTIONS") {
        return new Response("ok", { headers });
    }

    if (req.method !== "POST") {
        return jsonResponse({ error: "Method not allowed" }, 405, headers);
    }

    try {
        const accessToken = getBearerToken(req);
        if (!accessToken) {
            return jsonResponse({ error: "AUTH_REQUIRED" }, 401, headers);
        }

        const { data: userData, error: userError } = await supabaseAdmin.auth.getUser(accessToken);
        const userId = userData.user?.id;
        if (userError || !userId) {
            return jsonResponse({ error: "AUTH_REQUIRED" }, 401, headers);
        }

        const rateLimitState = await checkAuthRateLimit({
            supabaseAdmin,
            req,
            action: "account_delete",
            account: { kind: "user", value: userId },
        });
        if (!rateLimitState.allowed) {
            return authRateLimitResponse(rateLimitState, headers);
        }

        const payload = await parsePayload(req);
        const userClient = createClient(supabaseUrl, supabaseAnonKey, {
            auth: {
                persistSession: false,
                autoRefreshToken: false,
            },
            global: {
                headers: {
                    Authorization: `Bearer ${accessToken}`,
                },
            },
        });

        const { data, error } = await userClient.rpc("delete_my_account", {
            p_two_factor_challenge_id: payload.twoFactorChallengeId ?? null,
            p_sensitive_action_challenge_id: payload.sensitiveActionChallengeId,
        });
        if (error) {
            await recordAuthRateLimitFailure(rateLimitState);
            const publicError = mapAccountDeleteError(error.message);
            return jsonResponse({ error: publicError }, mapAccountDeleteStatus(publicError), headers);
        }
        await resetAuthRateLimit(rateLimitState);

        let removedStorageObjects = 0;
        let storageCleanupFailed = false;
        try {
            removedStorageObjects = await removeUserAttachmentObjects(userId);
        } catch (storageError) {
            storageCleanupFailed = true;
            console.error("Account delete storage cleanup failed", storageError);
        }

        return jsonResponse({
            deleted: data?.deleted === true,
            user_id: data?.user_id ?? userId,
            removed_storage_objects: removedStorageObjects,
            storage_cleanup_failed: storageCleanupFailed,
        }, 200, headers);
    } catch (error) {
        console.error("Account delete failed", error);
        return jsonResponse({ error: "SERVER_ERROR" }, 500, headers);
    }
});

function getBearerToken(req: Request): string | null {
    const authorization = req.headers.get("Authorization") ?? "";
    const match = authorization.match(/^Bearer\s+(.+)$/i);
    return match?.[1]?.trim() || null;
}

async function parsePayload(req: Request): Promise<{ twoFactorChallengeId: string | null; sensitiveActionChallengeId: string | null }> {
    const body = await req.json().catch(() => ({}));
    const twoFactorChallengeId = typeof body?.twoFactorChallengeId === "string"
        && body.twoFactorChallengeId.trim().length > 0
        ? body.twoFactorChallengeId.trim()
        : null;
    const sensitiveActionChallengeId = typeof body?.sensitiveActionChallengeId === "string"
        && body.sensitiveActionChallengeId.trim().length > 0
        ? body.sensitiveActionChallengeId.trim()
        : null;
    return { twoFactorChallengeId, sensitiveActionChallengeId };
}

async function removeUserAttachmentObjects(userId: string): Promise<number> {
    const paths = await listStoragePaths(`${userId}`);
    let removed = 0;

    for (let index = 0; index < paths.length; index += REMOVE_BATCH_SIZE) {
        const batch = paths.slice(index, index + REMOVE_BATCH_SIZE);
        if (batch.length === 0) continue;

        const { error } = await supabaseAdmin.storage
            .from(ATTACHMENTS_BUCKET)
            .remove(batch);
        if (error) {
            throw new Error(`STORAGE_CLEANUP_FAILED:${error.message}`);
        }
        removed += batch.length;
    }

    return removed;
}

async function listStoragePaths(prefix: string): Promise<string[]> {
    const paths: string[] = [];
    let offset = 0;

    while (true) {
        const { data, error } = await supabaseAdmin.storage
            .from(ATTACHMENTS_BUCKET)
            .list(prefix, {
                limit: STORAGE_PAGE_SIZE,
                offset,
                sortBy: { column: "name", order: "asc" },
            });
        if (error) {
            throw new Error(`STORAGE_LIST_FAILED:${error.message}`);
        }
        if (!data || data.length === 0) {
            break;
        }

        for (const entry of data) {
            const path = `${prefix}/${entry.name}`;
            if (isStorageFolder(entry)) {
                paths.push(...await listStoragePaths(path));
            } else {
                paths.push(path);
            }
        }

        if (data.length < STORAGE_PAGE_SIZE) {
            break;
        }
        offset += data.length;
    }

    return paths;
}

function isStorageFolder(entry: { id?: string | null; metadata?: unknown }): boolean {
    return !entry.id && !entry.metadata;
}

function mapAccountDeleteError(message: string): string {
    if (message.includes("AUTH_REQUIRED")) return "AUTH_REQUIRED";
    if (message.includes("REAUTH_PROOF_REQUIRED")) return "REAUTH_REQUIRED";
    if (message.includes("REAUTH_REQUIRED")) return "REAUTH_REQUIRED";
    if (message.includes("ACCOUNT_DELETE_CHALLENGE_REQUIRED")) return "REAUTH_REQUIRED";
    if (message.includes("RECOVERY_CHALLENGE_REQUIRED")) return "REAUTH_REQUIRED";
    if (message.includes("ACCOUNT_DELETE_2FA_REQUIRED")) return "ACCOUNT_DELETE_2FA_REQUIRED";
    if (message.includes("ACCOUNT_DELETE_INCOMPLETE")) return "ACCOUNT_DELETE_INCOMPLETE";
    if (message.includes("AUTH_USER_DELETE_FAILED")) return "ACCOUNT_DELETE_FAILED";
    return "ACCOUNT_DELETE_FAILED";
}

function mapAccountDeleteStatus(errorCode: string): number {
    if (errorCode === "AUTH_REQUIRED") return 401;
    if (errorCode === "REAUTH_REQUIRED") return 401;
    if (errorCode === "ACCOUNT_DELETE_2FA_REQUIRED") return 403;
    if (errorCode === "ACCOUNT_DELETE_INCOMPLETE") return 500;
    if (errorCode === "ACCOUNT_DELETE_FAILED") return 500;
    return 400;
}

function jsonResponse(body: Record<string, unknown>, status: number, headers: Headers): Response {
    return new Response(JSON.stringify(body), { status, headers });
}
