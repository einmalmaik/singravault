#!/usr/bin/env node
// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE

import { createClient } from "@supabase/supabase-js";
import { createHash } from "node:crypto";
import { config as loadDotenv } from "dotenv";

loadDotenv({ path: ".env" });
loadDotenv({ path: ".env.local", override: true });

const enabled = readBoolean(process.env.SINGRA_DEV_TEST_ACCOUNT_ENABLED);
const createUser = readBoolean(process.env.SINGRA_DEV_TEST_CREATE_USER);
const autoConfirm = readBoolean(process.env.SINGRA_DEV_TEST_AUTO_CONFIRM);
const resetVault = readBoolean(process.env.SINGRA_DEV_TEST_RESET_VAULT);
const email = readString(process.env.SINGRA_DEV_TEST_EMAIL);
const configuredPassword = readString(process.env.SINGRA_DEV_TEST_PASSWORD);
const configuredMasterPassword = readString(process.env.SINGRA_DEV_TEST_MASTER_PASSWORD);
const supabaseUrl = readString(process.env.VITE_SUPABASE_URL ?? process.env.SUPABASE_URL);
const serviceRoleKey = readString(process.env.SUPABASE_SERVICE_ROLE_KEY ?? process.env.SINGRA_SUPABASE_SERVICE_ROLE_KEY);
const SUPABASE_DEV_PASSWORD_PATTERN = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+\-=[\]{};':"|<>?,./`~]).+$/;

if (!enabled) {
  safeLog("Dev test account disabled.");
  process.exit(0);
}

assertDevOnly();

if (!email || !configuredMasterPassword) {
  safeLog("Dev test account env is incomplete; skipping account provisioning.");
  process.exit(0);
}

const password = isValidSupabaseDevPassword(configuredPassword)
  ? configuredPassword
  : deriveLocalDevPassword(email);
const masterPassword = isValidSupabaseDevPassword(configuredMasterPassword)
  ? configuredMasterPassword
  : deriveLocalDevPassword(`${email}:master`);

if (!isValidSupabaseDevPassword(password) || !isValidSupabaseDevPassword(masterPassword)) {
  safeLog(
    "Dev test account password policy could not be satisfied; skipping account provisioning.",
  );
  process.exit(0);
}

if (!isValidSupabaseDevPassword(configuredPassword)) {
  safeLog("Configured dev test account password did not satisfy policy; using a generated local-only value.");
}

if (!isValidSupabaseDevPassword(configuredMasterPassword)) {
  safeLog("Configured dev test master password did not satisfy policy; using a generated local-only value.");
}

if (!createUser) {
  safeLog("Dev test account env is present; account creation disabled.");
  process.exit(0);
}

if (!supabaseUrl || !serviceRoleKey) {
  safeLog("Dev test account creation skipped; Supabase URL or service-role key is missing.");
  process.exit(0);
}

const supabase = createClient(supabaseUrl, serviceRoleKey, {
  auth: {
    autoRefreshToken: false,
    persistSession: false,
  },
});

const user = await findUserByEmail(email);
if (user) {
  await updateUser(user.id);
  safeLog(`Dev test account ready: ${email}`);
} else {
  const created = await createDevUser();
  safeLog(`Dev test account created: ${created.email ?? email}`);
}

if (resetVault) {
  safeLog("SINGRA_DEV_TEST_RESET_VAULT is set, but destructive vault reset is intentionally not automated here.");
}

async function findUserByEmail(targetEmail) {
  let page = 1;
  const perPage = 100;

  while (page < 100) {
    const { data, error } = await supabase.auth.admin.listUsers({ page, perPage });
    if (error) {
      throw new Error(`Could not list Supabase users: ${error.message}`);
    }

    const match = data.users.find((candidate) => candidate.email?.toLowerCase() === targetEmail.toLowerCase());
    if (match) {
      return match;
    }

    if (data.users.length < perPage) {
      return null;
    }

    page += 1;
  }

  throw new Error("Could not locate dev test account within the first 9900 Supabase users.");
}

async function createDevUser() {
  const { data, error } = await supabase.auth.admin.createUser({
    email,
    password,
    email_confirm: autoConfirm,
    user_metadata: {
      purpose: "local-dev-test-account",
    },
  });

  if (error || !data.user) {
    throw new Error(`Could not create dev test account: ${error?.message ?? "missing user"}`);
  }

  return data.user;
}

async function updateUser(userId) {
  const { error } = await supabase.auth.admin.updateUserById(userId, {
    password,
    email_confirm: autoConfirm,
    user_metadata: {
      purpose: "local-dev-test-account",
    },
  });

  if (error) {
    throw new Error(`Could not update dev test account: ${error.message}`);
  }
}

function assertDevOnly() {
  const nodeEnv = String(process.env.NODE_ENV ?? "").toLowerCase();
  const ci = readBoolean(process.env.CI);
  const release = readBoolean(process.env.SINGRA_RELEASE_BUILD);

  if (nodeEnv === "production" || ci || release) {
    throw new Error("SINGRA_DEV_TEST_ACCOUNT_ENABLED must not be enabled for production, CI, or release builds.");
  }
}

function readBoolean(value) {
  return String(value ?? "").trim().toLowerCase() === "true";
}

function readString(value) {
  const normalized = String(value ?? "").trim();
  return normalized.length > 0 ? normalized : null;
}

function isValidSupabaseDevPassword(value) {
  return typeof value === "string" && value.length >= 12 && SUPABASE_DEV_PASSWORD_PATTERN.test(value);
}

function deriveLocalDevPassword(seed) {
  const digest = createHash("sha256").update(String(seed)).digest("hex");
  return `LocalDev!${digest.slice(0, 24)}aA1`;
}

function safeLog(message) {
  console.log(`[dev-test-account] ${message}`);
}
