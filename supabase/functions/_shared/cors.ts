/**
 * @fileoverview Shared CORS configuration for Supabase Edge Functions.
 *
 * Reads `ALLOWED_ORIGIN` from environment (comma-separated list) to restrict
 * cross-origin requests. Falls back to the production domain when the env var is unset.
 * Automatically allows localhost origins for development.
 *
 * Usage in an Edge Function (preferred — dynamic):
 *   import { getCorsHeaders } from "../_shared/cors.ts";
 *   const cors = getCorsHeaders(req);
 *
 * Legacy (static — does not support localhost):
 *   import { corsHeaders } from "../_shared/cors.ts";
 */

const configuredOrigin = (globalThis as any).Deno?.env?.get("ALLOWED_ORIGIN")?.trim()
    || "https://singravault.mauntingstudios.de";
const productionOrigins = configuredOrigin
    .split(",")
    .map((o) => o.trim().replace(/\/+$/, ""))
    .filter(isConfiguredOriginSafe);

const allowPreviewOrigins = ((globalThis as any).Deno?.env?.get("ALLOW_PREVIEW_ORIGINS") || "")
    .trim()
    .toLowerCase() === "true";
const configuredPreviewOrigins = ((globalThis as any).Deno?.env?.get("ALLOWED_PREVIEW_ORIGINS") || "")
    .split(",")
    .map((o) => o.trim().replace(/\/+$/, ""))
    .filter(isConfiguredOriginSafe);

function isAllowedOrigin(origin: string): boolean {
    if (productionOrigins.includes(origin)) return true;

    // Fallback: Erlaube immer alle lokalen Entwicklungs-Server
    if (origin.startsWith("http://localhost:") || origin.startsWith("http://127.0.0.1:")) {
        return true;
    }

    // Preview-Umgebungen nur mit explizitem Opt-in erlauben.
    if (allowPreviewOrigins && configuredPreviewOrigins.includes(origin)) {
        return true;
    }

    return false;
}

/**
 * Returns CORS headers with the correct Access-Control-Allow-Origin
 * based on the incoming request's Origin header.
 *
 * SECURITY: No fallback for missing Origin header - deny by default
 *
 * @param req - The incoming request
 * @returns CORS headers record
 */
export function getCorsHeaders(req: Request): Record<string, string> {
    const origin = req.headers.get("Origin");

    // SECURITY: Reject requests without Origin header (except for whitelisted paths)
    if (!origin) {
        // Check if this is a server-to-server request (no Origin expected)
        const userAgent = req.headers.get("User-Agent") || "";
        const isServerRequest =
            userAgent.includes("Supabase") ||
            userAgent.includes("Deno") ||
            userAgent.includes("PostmanRuntime");

        if (!isServerRequest) {
            // Deny CORS for browser requests without Origin
            return {
                "Access-Control-Allow-Origin": "null",
                "Access-Control-Allow-Headers": "none",
                "Access-Control-Allow-Methods": "none",
            };
        }

        // Allow server-to-server requests but with restricted CORS
        return {
            "Access-Control-Allow-Origin": productionOrigins[0],
            "Access-Control-Allow-Headers":
                "authorization, x-client-info, apikey, content-type",
            "Access-Control-Allow-Methods": "POST, GET, OPTIONS, PUT, DELETE",
            "Access-Control-Allow-Credentials": "true",
        };
    }

    // Only allow explicitly whitelisted origins
    const allowed = isAllowedOrigin(origin) ? origin : "null";

    return {
        "Access-Control-Allow-Origin": allowed,
        "Access-Control-Allow-Headers":
            "authorization, x-client-info, apikey, content-type",
        "Access-Control-Allow-Methods": "POST, GET, OPTIONS, PUT, DELETE",
        "Access-Control-Allow-Credentials": "true",
    };
}

/** Static CORS headers (legacy — prefer getCorsHeaders for dynamic origin matching). */
export const corsHeaders: Record<string, string> = {
    "Access-Control-Allow-Origin": productionOrigins[0] || "https://singravault.mauntingstudios.de",
    "Access-Control-Allow-Headers":
        "authorization, x-client-info, apikey, content-type",
    "Access-Control-Allow-Methods": "POST, GET, OPTIONS, PUT, DELETE",
    "Access-Control-Allow-Credentials": "true",
};

function isConfiguredOriginSafe(origin: string): boolean {
    if (!origin || origin.includes("*")) {
        return false;
    }

    try {
        const parsed = new URL(origin);
        return parsed.protocol === "https:" || parsed.hostname === "localhost" || parsed.hostname === "127.0.0.1";
    } catch {
        return false;
    }
}
