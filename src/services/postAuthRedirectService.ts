// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 — see LICENSE
/**
 * @fileoverview Post-auth redirect policy service.
 *
 * Defines where users land after a successful authentication flow.
 */

/**
 * Resolves the post-login destination.
 *
 * Policy decision: always navigate to the landing page after auth.
 *
 * @param _redirectParam - Ignored legacy redirect query param.
 * @param _locationState - Ignored legacy location state.
 * @returns Root landing path.
 */
export function resolvePostAuthRedirectPath(
    _redirectParam: string | null,
    _locationState: unknown,
): string {
    return '/';
}

