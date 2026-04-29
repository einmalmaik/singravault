// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE

import { assertNoUnsafeE2ETestMode } from "./testMode";

const MISSING_SUPABASE_URL = "https://missing-supabase-url.invalid";
const MISSING_SUPABASE_PUBLISHABLE_KEY = "missing-supabase-publishable-key";

assertNoUnsafeE2ETestMode();

function readEnv(name: "VITE_SUPABASE_URL" | "VITE_SUPABASE_PUBLISHABLE_KEY" | "VITE_OPAQUE_SERVER_STATIC_PUBLIC_KEY"): string {
  return String(import.meta.env[name] ?? "").trim();
}

function normalizeUrl(url: string): string {
  return url.replace(/\/+$/, "");
}

export function isSupabaseConfigured(): boolean {
  return Boolean(readEnv("VITE_SUPABASE_URL") && readEnv("VITE_SUPABASE_PUBLISHABLE_KEY"));
}

export function getSupabaseUrl(): string {
  const supabaseUrl = readEnv("VITE_SUPABASE_URL");
  return supabaseUrl ? normalizeUrl(supabaseUrl) : MISSING_SUPABASE_URL;
}

export function getSupabasePublishableKey(): string {
  return readEnv("VITE_SUPABASE_PUBLISHABLE_KEY") || MISSING_SUPABASE_PUBLISHABLE_KEY;
}

export function getSupabaseFunctionsUrl(): string | null {
  const supabaseUrl = readEnv("VITE_SUPABASE_URL");
  return supabaseUrl ? `${normalizeUrl(supabaseUrl)}/functions/v1` : null;
}

export function getWebUrl(): string {
  return String(import.meta.env.VITE_SITE_URL ?? import.meta.env.VITE_WEB_URL ?? window.location.origin).replace(/\/+$/, "");
}

export function getOpaqueServerStaticPublicKey(): string {
  return readEnv("VITE_OPAQUE_SERVER_STATIC_PUBLIC_KEY");
}

export const runtimeConfig = {
  get supabaseUrl(): string {
    return getSupabaseUrl();
  },
  get supabasePublishableKey(): string {
    return getSupabasePublishableKey();
  },
  get supabaseFunctionsUrl(): string | null {
    return getSupabaseFunctionsUrl();
  },
  get webUrl(): string {
    return getWebUrl();
  },
  get opaqueServerStaticPublicKey(): string {
    return getOpaqueServerStaticPublicKey();
  },
  get isSupabaseConfigured(): boolean {
    return isSupabaseConfigured();
  },
};
