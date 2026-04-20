// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE

import type { Session } from "@supabase/supabase-js";
import { runtimeConfig } from "@/config/runtimeConfig";
import { clearPkceVerifier, loadPkceVerifier, savePkceVerifier } from "./pkceVerifierStore";

export type DesktopOAuthProvider = "google" | "discord" | "github";
export type DesktopOAuthTokens = Pick<Session, "access_token" | "refresh_token">;

const DESKTOP_OAUTH_KEY_PREFIX = "singra-desktop-oauth";
const ACTIVE_DESKTOP_OAUTH_KEY = `${DESKTOP_OAUTH_KEY_PREFIX}:active`;
const DESKTOP_OAUTH_BRIDGE_PATH = "/auth";
const desktopExchangeInFlight = new Map<string, Promise<DesktopOAuthTokens>>();

interface TokenResponse {
  access_token?: string;
  refresh_token?: string;
  error?: string;
  error_description?: string;
  msg?: string;
  message?: string;
}

export async function createDesktopOAuthUrl(provider: DesktopOAuthProvider): Promise<string> {
  const verifier = createVerifier();
  const challenge = await createChallenge(verifier);

  await savePkceVerifier(ACTIVE_DESKTOP_OAUTH_KEY, verifier);

  const authUrl = new URL(`${runtimeConfig.supabaseUrl}/auth/v1/authorize`);
  authUrl.searchParams.set("provider", provider);
  authUrl.searchParams.set("redirect_to", getDesktopOAuthBridgeUrl());
  authUrl.searchParams.set("code_challenge", challenge);
  authUrl.searchParams.set("code_challenge_method", "s256");

  return authUrl.toString();
}

export async function exchangeDesktopOAuthCode(
  code: string | null,
): Promise<DesktopOAuthTokens> {
  if (!code) {
    throw new Error("Desktop OAuth callback did not include an auth code");
  }

  const normalizedCode = code.trim();
  const existingExchange = desktopExchangeInFlight.get(normalizedCode);
  if (existingExchange) {
    return existingExchange;
  }

  const exchangePromise = exchangeDesktopOAuthCodeUncached(normalizedCode).finally(() => {
    desktopExchangeInFlight.delete(normalizedCode);
  });
  desktopExchangeInFlight.set(normalizedCode, exchangePromise);

  return exchangePromise;
}

async function exchangeDesktopOAuthCodeUncached(code: string): Promise<DesktopOAuthTokens> {
  const verifier = await loadPkceVerifier(ACTIVE_DESKTOP_OAUTH_KEY);
  if (!verifier) {
    throw new Error("Desktop OAuth verifier is missing or expired");
  }

  let shouldClearVerifier = false;
  try {
    const response = await fetch(`${runtimeConfig.supabaseUrl}/auth/v1/token?grant_type=pkce`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json;charset=UTF-8",
        "apikey": runtimeConfig.supabasePublishableKey,
        "Authorization": `Bearer ${runtimeConfig.supabasePublishableKey}`,
      },
      body: JSON.stringify({
        auth_code: code,
        code_verifier: verifier,
      }),
    });

    const payload = await response.json().catch(() => null) as TokenResponse | null;
    if (!response.ok) {
      shouldClearVerifier = !isRetryableDesktopOAuthError(response.status);
      throw new Error(payload?.error_description ?? payload?.message ?? payload?.msg ?? payload?.error ?? "Desktop OAuth token exchange failed");
    }

    if (!payload?.access_token || !payload.refresh_token) {
      shouldClearVerifier = true;
      throw new Error("Desktop OAuth token exchange did not return a session");
    }

    shouldClearVerifier = true;
    return {
      access_token: payload.access_token,
      refresh_token: payload.refresh_token,
    };
  } finally {
    if (shouldClearVerifier) {
      await clearPkceVerifier(ACTIVE_DESKTOP_OAUTH_KEY);
    }
  }
}

export function getDesktopOAuthBridgeUrl(): string {
  const bridgeUrl = new URL(DESKTOP_OAUTH_BRIDGE_PATH, `${runtimeConfig.webUrl}/`);
  bridgeUrl.searchParams.set("source", "tauri");
  return bridgeUrl.toString();
}

function createVerifier(): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return base64UrlEncode(bytes);
}

async function createChallenge(verifier: string): Promise<string> {
  const data = new TextEncoder().encode(verifier);
  const digest = await crypto.subtle.digest("SHA-256", data);
  return base64UrlEncode(new Uint8Array(digest));
}

function base64UrlEncode(bytes: Uint8Array): string {
  let binary = "";
  bytes.forEach((byte) => {
    binary += String.fromCharCode(byte);
  });

  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function isRetryableDesktopOAuthError(status: number): boolean {
  return status === 429 || status >= 500;
}
