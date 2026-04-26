// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE

import { createClient, type Session } from "@supabase/supabase-js";
import { describe, expect, it } from "vitest";

import {
  finishLogin,
  finishRegistration,
  startLogin,
  startRegistration,
  verifyOpaqueSessionBinding,
} from "@/services/opaqueService";

const supabaseUrl = process.env.VITE_SUPABASE_URL || "";
const supabasePublishableKey =
  process.env.VITE_SUPABASE_ANON_KEY ||
  process.env.SUPABASE_ANON_KEY ||
  process.env.VITE_SUPABASE_PUBLISHABLE_KEY ||
  "";
const supabaseServiceKey = process.env.SUPABASE_SERVICE_ROLE_KEY || "";
const hasSupabaseTestEnv = Boolean(
  supabaseUrl &&
  supabasePublishableKey &&
  supabaseServiceKey &&
  process.env.VITE_OPAQUE_SERVER_STATIC_PUBLIC_KEY,
);

const supabaseAdmin = createClient(
  supabaseUrl || "http://localhost:54321",
  supabaseServiceKey || "test-service-role-key",
);
const supabaseAnon = createClient(
  supabaseUrl || "http://localhost:54321",
  supabasePublishableKey || "test-anon-key",
  {
    auth: {
      persistSession: false,
      autoRefreshToken: false,
      detectSessionInUrl: false,
    },
  },
);
const describeIfSupabase = hasSupabaseTestEnv ? describe : describe.skip;

describeIfSupabase("OPAQUE registration flow", () => {
  it("registers a fresh OPAQUE account, confirms the signup code, and allows OPAQUE login", async () => {
    const email = `opaque-signup-${Date.now()}-${Math.random().toString(16).slice(2)}@example.com`;
    const password = `OpaqueSignup!${Date.now()}#aB3`;
    let userId: string | null = null;

    try {
      const { clientRegistrationState, registrationRequest } = await startRegistration(password);

      const startResponse = await invokePublicAuthFunction("auth-register", {
        email,
        registrationRequest,
      });
      expect(startResponse.status).toBe(200);
      expect(startResponse.json.registrationId).toBeTypeOf("string");
      expect(startResponse.json.registrationResponse).toBeTypeOf("string");

      const finishedRegistration = await finishRegistration(
        clientRegistrationState,
        startResponse.json.registrationResponse,
        password,
      );

      const finishResponse = await invokePublicAuthFunction("auth-register", {
        action: "finish",
        email,
        registrationId: startResponse.json.registrationId,
        registrationRecord: finishedRegistration.registrationRecord,
      });
      expect(finishResponse.status).toBe(200);
      expect(finishResponse.json.success).toBe(true);

      const { data: users } = await supabaseAdmin.rpc("get_user_id_by_email", {
        p_email: email,
      });
      userId = Array.isArray(users) && users.length > 0 ? String(users[0].id) : null;
      expect(userId).toBeTruthy();

      const { data: authUserData, error: authUserError } = await supabaseAdmin.auth.admin.getUserById(userId!);
      expect(authUserError).toBeNull();
      expect(authUserData.user?.email_confirmed_at ?? null).toBeNull();
      expect(authUserData.user?.confirmation_sent_at).toBeTruthy();

      const { data: opaqueRecord, error: opaqueRecordError } = await supabaseAdmin
        .from("user_opaque_records")
        .select("opaque_identifier")
        .eq("user_id", userId!)
        .single();
      expect(opaqueRecordError).toBeNull();
      expect(opaqueRecord?.opaque_identifier).toBe(email);

      const { data: profile, error: profileError } = await supabaseAdmin
        .from("profiles")
        .select("auth_protocol")
        .eq("user_id", userId!)
        .single();
      expect(profileError).toBeNull();
      expect(profile?.auth_protocol).toBe("opaque");

      const linkResult = await supabaseAdmin.auth.admin.generateLink({
        type: "signup",
        email,
        password: `unused-${Date.now()}-${Math.random().toString(16).slice(2)}`,
      });
      expect(linkResult.error).toBeNull();
      expect(linkResult.data.properties?.email_otp).toBeTruthy();

      const verifyResult = await supabaseAnon.auth.verifyOtp({
        email,
        token: linkResult.data.properties!.email_otp,
        type: "signup",
      });
      expect(verifyResult.error).toBeNull();
      expect(verifyResult.data.user?.email_confirmed_at).toBeTruthy();

      const { clientLoginState, startLoginRequest } = await startLogin(password);
      const loginStartResponse = await invokePublicAuthFunction("auth-opaque", {
        action: "login-start",
        userIdentifier: email,
        startLoginRequest,
      });
      expect(loginStartResponse.status).toBe(200);
      expect(loginStartResponse.json.loginId).toBeTypeOf("string");
      expect(loginStartResponse.json.loginResponse).toBeTypeOf("string");

      const finishedLogin = await finishLogin(
        clientLoginState,
        loginStartResponse.json.loginResponse,
        password,
      );
      const loginFinishResponse = await invokePublicAuthFunction("auth-opaque", {
        action: "login-finish",
        userIdentifier: email,
        finishLoginRequest: finishedLogin.finishLoginRequest,
        loginId: loginStartResponse.json.loginId,
        skipCookie: true,
      });
      expect(loginFinishResponse.status).toBe(200);
      expect(loginFinishResponse.json.session?.access_token).toBeTypeOf("string");
      expect(loginFinishResponse.json.session?.refresh_token).toBeTypeOf("string");
      expect(loginFinishResponse.json.opaqueSessionBinding).toBeTruthy();

      await verifyOpaqueSessionBinding(
        finishedLogin.sessionKey,
        loginFinishResponse.json.session as Session,
        loginFinishResponse.json.opaqueSessionBinding,
      );
    } finally {
      if (userId) {
        await supabaseAdmin.auth.admin.deleteUser(userId);
      }
    }
  }, 30000);
});

async function invokePublicAuthFunction(
  functionName: "auth-register" | "auth-opaque",
  body: Record<string, unknown>,
): Promise<{ status: number; json: Record<string, any> }> {
  const response = await fetch(`${supabaseUrl}/functions/v1/${functionName}`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${supabasePublishableKey}`,
    },
    body: JSON.stringify(body),
  });

  return {
    status: response.status,
    json: (await response.json().catch(() => ({}))) as Record<string, any>,
  };
}
