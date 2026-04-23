/**
 * WebAuthn in Singra Vault is a vault-unlock extension for an already
 * authenticated app user, not an alternative primary login flow.
 *
 * Every action in this function therefore requires the regular app session so
 * passkey verification cannot bypass session, reauth, or 2FA controls.
 */

export const WEBAUTHN_ACTIONS = [
    "generate-registration-options",
    "verify-registration",
    "generate-authentication-options",
    "verify-authentication",
    "activate-prf",
    "upgrade-wrapped-key",
    "list-credentials",
    "delete-credential",
] as const;

export type WebauthnAction = typeof WEBAUTHN_ACTIONS[number];

export interface WebauthnSessionUser {
    id: string;
    email?: string;
}

interface AuthorizedWebauthnRequest {
    ok: true;
    user: WebauthnSessionUser;
}

interface UnauthorizedWebauthnRequest {
    ok: false;
    status: 401;
    body: {
        error: "Unauthorized";
        details?: string;
    };
}

const ACTION_SESSION_POLICIES: Record<WebauthnAction, "session-required"> = {
    "generate-registration-options": "session-required",
    "verify-registration": "session-required",
    "generate-authentication-options": "session-required",
    "verify-authentication": "session-required",
    "activate-prf": "session-required",
    "upgrade-wrapped-key": "session-required",
    "list-credentials": "session-required",
    "delete-credential": "session-required",
};

export function isWebauthnAction(value: unknown): value is WebauthnAction {
    return typeof value === "string"
        && Object.prototype.hasOwnProperty.call(ACTION_SESSION_POLICIES, value);
}

export function authorizeWebauthnAction(
    action: WebauthnAction,
    user: WebauthnSessionUser | null,
    authErrorDetails: string | null = null,
): AuthorizedWebauthnRequest | UnauthorizedWebauthnRequest {
    const sessionPolicy = ACTION_SESSION_POLICIES[action];

    if (sessionPolicy === "session-required" && user) {
        return {
            ok: true,
            user,
        };
    }

    return {
        ok: false,
        status: 401,
        body: authErrorDetails
            ? { error: "Unauthorized", details: authErrorDetails }
            : { error: "Unauthorized" },
    };
}
