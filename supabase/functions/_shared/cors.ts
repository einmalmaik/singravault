/**
 * @fileoverview Shared CORS configuration for Supabase Edge Functions.
 *
 * Reads `ALLOWED_ORIGIN` from environment (comma-separated list) to restrict
 * cross-origin requests. Falls back to the production domain when the env var is unset.
 * Local development origins are opt-in only.
 *
 * Preview environments support two allow-list modes:
 * - `ALLOWED_PREVIEW_ORIGINS`: exact origin matches
 * - `ALLOWED_PREVIEW_ORIGIN_SUFFIXES`: hostname suffix matches for owned preview domains
 *
 * Usage in an Edge Function (preferred — dynamic):
 *   import { getCorsHeaders } from "../_shared/cors.ts";
 *   const cors = getCorsHeaders(req);
 *
 * Legacy (static — does not support localhost):
 *   import { corsHeaders } from "../_shared/cors.ts";
 */

import { FIRST_PARTY_DESKTOP_ORIGINS, FIRST_PARTY_LOCAL_DEV_ORIGINS } from "./desktopOrigins.ts";

interface DenoRuntime {
    env?: {
        get?: (key: string) => string | undefined;
    };
}

function readEnv(key: string): string {
    return ((globalThis as typeof globalThis & { Deno?: DenoRuntime }).Deno?.env?.get?.(key) || "");
}

const configuredOrigin = readEnv("ALLOWED_ORIGIN").trim()
    || "https://singravault.mauntingstudios.de";
const productionOrigins = configuredOrigin
    .split(",")
    .map((o) => o.trim().replace(/\/+$/, ""))
    .filter(isConfiguredOriginSafe);
const securityResponseHeaders = {
    "X-Content-Type-Options": "nosniff",
    "Cache-Control": "no-store",
};

const allowPreviewOrigins = readEnv("ALLOW_PREVIEW_ORIGINS")
    .trim()
    .toLowerCase() === "true";
const configuredPreviewOrigins = readEnv("ALLOWED_PREVIEW_ORIGINS")
    .split(",")
    .map((o) => o.trim().replace(/\/+$/, ""))
    .filter(isConfiguredOriginSafe);
const configuredDesktopOrigins = (readEnv("ALLOWED_DESKTOP_ORIGINS")
    || FIRST_PARTY_DESKTOP_ORIGINS.join(","))
    .split(",")
    .map((o) => o.trim().replace(/\/+$/, ""))
    .filter(isConfiguredOriginSafe);
const allowLocalDevOrigins = readEnv("ALLOW_LOCAL_DEV_ORIGINS")
    .trim()
    .toLowerCase() === "true";
const configuredLocalDevOrigins = (readEnv("ALLOWED_DEV_ORIGINS")
    || (allowLocalDevOrigins ? FIRST_PARTY_LOCAL_DEV_ORIGINS.join(",") : ""))
    .split(",")
    .map((o) => o.trim().replace(/\/+$/, ""))
    .filter(isConfiguredOriginSafe);
const configuredPreviewOriginSuffixes = readEnv("ALLOWED_PREVIEW_ORIGIN_SUFFIXES")
    .split(",")
    .map((suffix) => normalizeHostnameSuffix(suffix))
    .filter((suffix): suffix is string => Boolean(suffix));

function isAllowedOrigin(origin: string): boolean {
    if (productionOrigins.includes(origin)) return true;
    if (configuredDesktopOrigins.includes(origin)) return true;
    if (configuredLocalDevOrigins.includes(origin)) return true;

    // Preview-Umgebungen nur mit explizitem Opt-in erlauben.
    if (allowPreviewOrigins && (
        configuredPreviewOrigins.includes(origin)
        || matchesAllowedPreviewOriginSuffix(origin)
    )) {
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
                ...securityResponseHeaders,
                "Access-Control-Allow-Origin": "null",
                "Access-Control-Allow-Headers": "none",
                "Access-Control-Allow-Methods": "none",
            };
        }

        // Allow server-to-server requests but with restricted CORS
        return {
            ...securityResponseHeaders,
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
        ...securityResponseHeaders,
        "Access-Control-Allow-Origin": allowed,
        "Access-Control-Allow-Headers":
            "authorization, x-client-info, apikey, content-type",
        "Access-Control-Allow-Methods": "POST, GET, OPTIONS, PUT, DELETE",
        "Access-Control-Allow-Credentials": "true",
    };
}

/** Static CORS headers (legacy — prefer getCorsHeaders for dynamic origin matching). */
export const corsHeaders: Record<string, string> = {
    ...securityResponseHeaders,
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
        return parsed.protocol === "https:"
            || parsed.protocol === "tauri:"
            || parsed.hostname === "localhost"
            || parsed.hostname === "127.0.0.1"
            || parsed.hostname === "tauri.localhost";
    } catch {
        return false;
    }
}

function matchesAllowedPreviewOriginSuffix(origin: string): boolean {
    if (configuredPreviewOriginSuffixes.length === 0) {
        return false;
    }

    try {
        const parsed = new URL(origin);
        if (parsed.protocol !== "https:") {
            return false;
        }

        return configuredPreviewOriginSuffixes.some((suffix) =>
            parsed.hostname === suffix
            || parsed.hostname.endsWith(`.${suffix}`)
            || parsed.hostname.endsWith(`-${suffix}`)
        );
    } catch {
        return false;
    }
}

function normalizeHostnameSuffix(value: string): string | null {
    const trimmed = value.trim().replace(/^https?:\/\//, "").replace(/\/+$/, "").replace(/^\.+/, "");
    if (!trimmed || trimmed.includes("*")) {
        return null;
    }

    const looksLikeHost = /^[a-z0-9.-]+$/i.test(trimmed);
    if (!looksLikeHost) {
        return null;
    }

    return trimmed.toLowerCase();
}
