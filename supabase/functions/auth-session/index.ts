import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import { getCookies, setCookie } from "https://deno.land/std@0.168.0/http/cookie.ts";
import { createClient } from "npm:@supabase/supabase-js@2";
import { getCorsHeaders } from "../_shared/cors.ts";
import {
    authRateLimitResponse,
    checkAuthRateLimit,
    recordAuthRateLimitFailure,
    type AuthRateLimitFailureResult,
} from "../_shared/authRateLimit.ts";
import { normalizeOpaqueIdentifier } from "../_shared/opaqueAuth.ts";

const supabaseUrl = Deno.env.get("SUPABASE_URL")!;
const supabaseServiceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
const supabaseAnonKey = Deno.env.get("SUPABASE_ANON_KEY")!;
const supabaseAdmin = createClient(supabaseUrl, supabaseServiceKey);
const SESSION_COOKIE_NAME = "sb-bff-session";
const SESSION_COOKIE_MAX_AGE = Number(Deno.env.get("SESSION_COOKIE_MAX_AGE_SECONDS") ?? 60 * 60 * 24 * 14);

function createSupabaseAuthClient() {
    return createClient(supabaseUrl, supabaseAnonKey, {
        auth: {
            persistSession: false,
            autoRefreshToken: false,
        },
    });
}

Deno.serve(async (req) => {
    const corsHeaders = getCorsHeaders(req);
    const headers = new Headers({
        ...corsHeaders,
        "Access-Control-Allow-Credentials": "true",
    });
    const jsonHeaders = (): Headers => {
        const responseHeaders = new Headers(headers);
        responseHeaders.set("Content-Type", "application/json");
        return responseHeaders;
    };

    if (req.method === "OPTIONS") {
        return new Response("ok", { headers });
    }

    try {
        if (req.method === "DELETE") {
            clearSessionCookie(headers);
            return new Response(JSON.stringify({ success: true }), {
                status: 200,
                headers: jsonHeaders(),
            });
        }

        if (req.method === "GET") {
            return await handleSessionHydration(req, headers, jsonHeaders());
        }

        if (req.method !== "POST") {
            return new Response("Method not allowed", { status: 405, headers });
        }

        const payload = await req.json();
        if (payload?.action === "oauth-sync") {
            return await handleOAuthSync(req, payload, headers, jsonHeaders());
        }

        return await legacyPasswordLoginBlockedResponse(req, payload, jsonHeaders());
    } catch (err: unknown) {
        console.error("Auth Session Error:", err);
        return new Response(JSON.stringify({ error: "Internal Server Error" }), {
            status: 500,
            headers: jsonHeaders(),
        });
    }
});

async function handleSessionHydration(
    req: Request,
    headers: Headers,
    responseHeaders: Headers,
): Promise<Response> {
    const cookies = getCookies(req.headers);
    const refreshToken = cookies[SESSION_COOKIE_NAME];

    if (!refreshToken) {
        return new Response(JSON.stringify({ error: "No session cookie" }), {
            status: 401,
            headers: responseHeaders,
        });
    }

    const authClient = createSupabaseAuthClient();
    const { data, error } = await authClient.auth.refreshSession({ refresh_token: refreshToken });

    if (error || !data.session) {
        return new Response(JSON.stringify({ error: "Session expired" }), {
            status: 401,
            headers: responseHeaders,
        });
    }

    setSessionCookie(headers, data.session.refresh_token);

    return new Response(JSON.stringify({ session: data.session }), {
        status: 200,
        headers: responseHeaders,
    });
}

async function handleOAuthSync(
    req: Request,
    payload: Record<string, unknown>,
    headers: Headers,
    responseHeaders: Headers,
): Promise<Response> {
    const accessToken = parseBearerToken(req.headers.get("Authorization"));
    const refreshToken = typeof payload.refreshToken === "string" ? payload.refreshToken : null;
    const skipCookie = Boolean(payload.skipCookie);

    if (!accessToken || !refreshToken) {
        return new Response(JSON.stringify({ error: "Invalid oauth sync payload" }), {
            status: 400,
            headers: responseHeaders,
        });
    }

    const authClient = createClient(supabaseUrl, supabaseAnonKey, {
        auth: {
            persistSession: false,
            autoRefreshToken: false,
        },
        global: { headers: { Authorization: `Bearer ${accessToken}` } },
    });

    const { data: authedUserData, error: authedUserError } = await authClient.auth.getUser();
    if (authedUserError || !authedUserData.user) {
        return new Response(JSON.stringify({ error: "Unauthorized" }), {
            status: 401,
            headers: responseHeaders,
        });
    }

    const refreshClient = createSupabaseAuthClient();
    const { data: refreshedData, error: refreshError } = await refreshClient.auth.refreshSession({
        refresh_token: refreshToken,
    });

    if (refreshError || !refreshedData.session) {
        return new Response(JSON.stringify({ error: "Session expired" }), {
            status: 401,
            headers: responseHeaders,
        });
    }

    if (refreshedData.session.user.id !== authedUserData.user.id) {
        return new Response(JSON.stringify({ error: "Session mismatch" }), {
            status: 403,
            headers: responseHeaders,
        });
    }

    if (!skipCookie) {
        setSessionCookie(headers, refreshedData.session.refresh_token);
    }

    return new Response(JSON.stringify({ success: true, session: refreshedData.session }), {
        status: 200,
        headers: responseHeaders,
    });
}

async function legacyPasswordLoginBlockedResponse(
    req: Request,
    payload: Record<string, unknown>,
    headers: Headers,
): Promise<Response> {
    const normalizedEmail = normalizeOpaqueIdentifier(payload?.email);
    const passwordRateLimit = await checkAuthRateLimit({
        supabaseAdmin,
        req,
        action: "password_login",
        account: { kind: "email", value: normalizedEmail || "unknown" },
    });
    if (!passwordRateLimit.allowed) {
        return authRateLimitResponse(passwordRateLimit, headers);
    }

    const startTime = Date.now();
    const failure = await recordAuthRateLimitFailure(passwordRateLimit);
    await delayUntilMinimum(startTime, 300);
    if (failure.lockedUntil) {
        return authRateLimitResponse(toLockedState(failure), headers);
    }

    return new Response(JSON.stringify({
        error: "Legacy password login is disabled. App-owned password login must use OPAQUE.",
        code: "LEGACY_PASSWORD_LOGIN_DISABLED",
    }), {
        status: 410,
        headers,
    });
}

function setSessionCookie(headers: Headers, refreshToken: string): void {
    setCookie(headers, {
        name: SESSION_COOKIE_NAME,
        value: refreshToken,
        path: "/",
        httpOnly: true,
        secure: true,
        sameSite: "None",
        maxAge: SESSION_COOKIE_MAX_AGE,
    });
    appendPartitionedCookieAttribute(headers);
}

function clearSessionCookie(headers: Headers): void {
    setCookie(headers, {
        name: SESSION_COOKIE_NAME,
        value: "",
        path: "/",
        httpOnly: true,
        secure: true,
        sameSite: "None",
        maxAge: 0,
    });
    appendPartitionedCookieAttribute(headers);
}

function appendPartitionedCookieAttribute(headers: Headers): void {
    const currentCookie = headers.get("set-cookie");
    if (!currentCookie || /;\s*Partitioned/i.test(currentCookie)) {
        return;
    }

    headers.set("set-cookie", `${currentCookie}; Partitioned`);
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

async function delayUntilMinimum(startTime: number, minimumMs: number): Promise<void> {
    const remaining = minimumMs - (Date.now() - startTime);
    if (remaining > 0) {
        await new Promise((resolve) => setTimeout(resolve, remaining));
    }
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
