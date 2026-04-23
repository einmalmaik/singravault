// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE

import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";

describe("auth edge functions use anon auth clients for user sessions", () => {
    it("keeps auth-session user session operations on an anon auth client", () => {
        const source = readFileSync("supabase/functions/auth-session/index.ts", "utf-8");

        expect(source).toContain('const supabaseAnonKey = Deno.env.get("SUPABASE_ANON_KEY")!');
        expect(source).toContain("function createSupabaseAuthClient()");
        expect(source).toContain("authClient.auth.refreshSession");
        expect(source).toContain("authClient.auth.signInWithPassword");
        expect(source).toContain("authClient.auth.verifyOtp");
    });

    it("keeps other session-issuing auth flows on anon auth clients", () => {
        const opaqueSource = readFileSync("supabase/functions/auth-opaque/index.ts", "utf-8");
        const recoverySource = readFileSync("supabase/functions/auth-recovery/index.ts", "utf-8");

        expect(opaqueSource).toContain('const supabaseAnonKey = Deno.env.get("SUPABASE_ANON_KEY")!');
        expect(opaqueSource).toContain("authClient.auth.verifyOtp");

        expect(recoverySource).toContain('const supabaseAnonKey = Deno.env.get("SUPABASE_ANON_KEY")!');
        expect(recoverySource).toContain("authClient.auth.verifyOtp");
    });

    it("keeps webauthn focused on passkey verification without issuing auth sessions", () => {
        const webauthnSource = readFileSync("supabase/functions/webauthn/index.ts", "utf-8");

        expect(webauthnSource).not.toContain("authClient.auth.verifyOtp");
        expect(webauthnSource).not.toContain("createSupabaseAuthClient");
        expect(webauthnSource).not.toContain("setCookie(");
        expect(webauthnSource).not.toContain("get_user_id_by_email");
        expect(webauthnSource).not.toContain("Missing email for authentication");
    });
});
