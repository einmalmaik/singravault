// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 — see LICENSE
/**
 * @fileoverview Post-auth redirect policy service.
 *
 * Defines where users land after a successful authentication flow.
 * The desktop shell must never bounce back to `/auth` after login, so the
 * default destination is always the vault unless an explicit safe in-app
 * redirect was requested by a protected route.
 */

/**
 * Resolves the post-login destination.
 *
 * @param redirectParam - Redirect target from the query string.
 * @param locationState - React Router location state from a guarded route.
 * @returns Safe in-app destination, defaulting to `/vault`.
 */
export function resolvePostAuthRedirectPath(
    redirectParam: string | null,
    locationState: unknown,
): string {
    const requestedRedirect = resolveRequestedRedirect(redirectParam, locationState);
    return requestedRedirect ?? "/vault";
}

interface LocationStateLike {
    from?: {
        pathname?: string;
        search?: string;
        hash?: string;
    };
}

function resolveRequestedRedirect(
    redirectParam: string | null,
    locationState: unknown,
): string | null {
    const locationRedirect = resolveLocationRedirect(locationState);
    const candidates = [redirectParam, locationRedirect];

    for (const candidate of candidates) {
        if (!candidate) {
            continue;
        }

        const normalized = normalizeRedirectPath(candidate);
        if (normalized) {
            return normalized;
        }
    }

    return null;
}

function resolveLocationRedirect(locationState: unknown): string | null {
    const state = locationState as LocationStateLike | null;
    const pathname = state?.from?.pathname;
    if (typeof pathname !== "string" || !pathname) {
        return null;
    }

    const search = typeof state.from?.search === "string" ? state.from.search : "";
    const hash = typeof state.from?.hash === "string" ? state.from.hash : "";
    return `${pathname}${search}${hash}`;
}

function normalizeRedirectPath(candidate: string): string | null {
    if (!candidate.startsWith("/")) {
        return null;
    }

    if (candidate.startsWith("//")) {
        return null;
    }

    if (candidate === "/auth" || candidate.startsWith("/auth?") || candidate.startsWith("/auth#")) {
        return null;
    }

    return candidate;
}

