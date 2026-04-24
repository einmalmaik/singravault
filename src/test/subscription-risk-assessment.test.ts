// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 — see LICENSE
import { readFile } from "node:fs/promises";
import { createClient } from "@supabase/supabase-js";
import { describe, expect, it } from "vitest";

const supabaseUrl = process.env.VITE_SUPABASE_URL || "";
const supabaseAnonKey =
  process.env.VITE_SUPABASE_ANON_KEY ||
  process.env.SUPABASE_ANON_KEY ||
  process.env.VITE_SUPABASE_PUBLISHABLE_KEY ||
  "";
const supabaseServiceKey = process.env.SUPABASE_SERVICE_ROLE_KEY || "";

const supabaseAdmin = createClient(supabaseUrl, supabaseServiceKey);

async function createAndSignInTestUser() {
  const email = `risk-subscription-${Date.now()}-${Math.random()
    .toString(16)
    .slice(2)}@example.com`;

  const createUserResult = await supabaseAdmin.auth.admin.createUser({
    email,
    email_confirm: true,
  });

  if (createUserResult.error || !createUserResult.data.user) {
    throw new Error(
      `admin.createUser failed: ${
        createUserResult.error?.message || "missing user"
      }`
    );
  }

  const userClient = createClient(supabaseUrl, supabaseAnonKey);
  const linkResult = await supabaseAdmin.auth.admin.generateLink({
    type: "magiclink",
    email,
  });
  const tokenHash = linkResult.data.properties?.hashed_token;

  if (linkResult.error || !tokenHash) {
    throw new Error(`magic link generation failed: ${linkResult.error?.message || "missing token"}`);
  }

  const signInResult = await userClient.auth.verifyOtp({
    token_hash: tokenHash,
    type: "magiclink",
  });

  if (signInResult.error) {
    throw new Error(`test session creation failed: ${signInResult.error.message}`);
  }

  return { userClient, userId: createUserResult.data.user.id };
}

describe("Subscription risk assessment", () => {
  it("allows parallel checkout session creation for the same user and plan (duplicate-flow risk)", async () => {
    const { userClient, userId } = await createAndSignInTestUser();

    const payload = {
      plan_key: "premium_monthly",
      widerruf_consent_execution: true,
      widerruf_consent_loss: true,
    };

    try {
      const [first, second] = await Promise.all([
        userClient.functions.invoke("create-checkout-session", { body: payload }),
        userClient.functions.invoke("create-checkout-session", { body: payload }),
      ]);

      expect(first.error).toBeNull();
      expect(second.error).toBeNull();
      expect(first.data?.url).toBeTypeOf("string");
      expect(second.data?.url).toBeTypeOf("string");
      expect(first.data.url).not.toEqual(second.data.url);
    } finally {
      await supabaseAdmin.auth.admin.deleteUser(userId);
    }
  }, 30000);

  it("has no dedicated webhook event dedupe persistence in code/migrations (idempotency gap)", async () => {
    const [webhookSource, migrationSource] = await Promise.all([
      readFile("supabase/functions/stripe-webhook/index.ts", "utf8"),
      readFile("supabase/migrations/20260210180000_subscription_system.sql", "utf8"),
    ]);

    expect(webhookSource).not.toMatch(/processed_webhook_events/i);
    expect(webhookSource).not.toMatch(/webhook_events/i);
    expect(webhookSource).not.toMatch(/ON CONFLICT .*event/i);

    expect(migrationSource).not.toMatch(/processed_webhook_events/i);
    expect(migrationSource).not.toMatch(/webhook_events/i);
    expect(migrationSource).not.toMatch(/unique .*event_id/i);
  });
});
