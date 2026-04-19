// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE

import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";

describe("auth-session edge function cookie hardening", () => {
    it("adds the Partitioned attribute to the BFF session cookie", () => {
        const source = readFileSync("supabase/functions/auth-session/index.ts", "utf-8");
        const opaqueSource = readFileSync("supabase/functions/auth-opaque/index.ts", "utf-8");

        expect(source).toContain('SESSION_COOKIE_MAX_AGE_SECONDS") ?? 60 * 60 * 24 * 400');
        expect(source).toContain("function appendPartitionedCookieAttribute");
        expect(source).toContain("headers.set(\"set-cookie\", `${currentCookie}; Partitioned`)");
        expect(source).toContain("setSessionCookie(headers, data.session.refresh_token)");
        expect(source).toContain("setSessionCookie(headers, refreshedData.session.refresh_token)");
        expect(source).toContain("setSessionCookie(headers, sessionData.session.refresh_token)");
        expect(opaqueSource).toContain('SESSION_COOKIE_MAX_AGE_SECONDS") ?? 60 * 60 * 24 * 400');
        expect(opaqueSource).toContain("function appendPartitionedCookieAttribute");
        expect(opaqueSource).toContain("setSessionCookie(headers, sessionData.session.refresh_token)");
    });
});
