// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE

import { describe, expect, it } from "vitest";
import {
    authorizeWebauthnAction,
    WEBAUTHN_ACTIONS,
} from "../../supabase/functions/webauthn/authPolicy";

describe("webauthn auth policy", () => {
    it.each(WEBAUTHN_ACTIONS)(
        "rejects unauthenticated %s requests",
        (action) => {
            expect(authorizeWebauthnAction(action, null, "JWT expired")).toEqual({
                ok: false,
                status: 401,
                body: {
                    error: "Unauthorized",
                    details: "JWT expired",
                },
            });
        },
    );

    it("allows authenticated requests for every action", () => {
        const user = {
            id: "user-123",
            email: "user@example.com",
        };

        for (const action of WEBAUTHN_ACTIONS) {
            expect(authorizeWebauthnAction(action, user)).toEqual({
                ok: true,
                user,
            });
        }
    });
});
