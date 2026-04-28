import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "npm:@supabase/supabase-js@2";
import { getCorsHeaders } from "../_shared/cors.ts";

const supabaseUrl = Deno.env.get("SUPABASE_URL")!;
const supabaseServiceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
const supabaseAnonKey = Deno.env.get("SUPABASE_ANON_KEY")!;
const supabaseAdmin = createClient(supabaseUrl, supabaseServiceKey, {
    auth: {
        persistSession: false,
        autoRefreshToken: false,
    },
});

const ATTACHMENTS_BUCKET = "vault-attachments";
const STORAGE_PAGE_SIZE = 100;
const REMOVE_BATCH_SIZE = 100;

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
        });
        if (error) {
            const publicError = mapAccountDeleteError(error.message);
            return jsonResponse({ error: publicError }, mapAccountDeleteStatus(publicError), headers);
        }

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

async function parsePayload(req: Request): Promise<{ twoFactorChallengeId: string | null }> {
    const body = await req.json().catch(() => ({}));
    const twoFactorChallengeId = typeof body?.twoFactorChallengeId === "string"
        && body.twoFactorChallengeId.trim().length > 0
        ? body.twoFactorChallengeId.trim()
        : null;
    return { twoFactorChallengeId };
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
    if (message.includes("REAUTH_REQUIRED")) return "REAUTH_REQUIRED";
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
