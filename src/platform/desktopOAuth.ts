// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE

import type { Session } from "@supabase/supabase-js";
import { runtimeConfig } from "@/config/runtimeConfig";
import { clearPkceVerifier, loadPkceVerifier, savePkceVerifier } from "./pkceVerifierStore";

export type DesktopOAuthProvider = "google" | "discord" | "github";
export type DesktopOAuthTokens = Pick<Session, "access_token" | "refresh_token">;
export interface DesktopOAuthExchangeInput {
  code: string | null;
  flowId?: string | null;
  state?: string | null;
}

const DESKTOP_OAUTH_KEY_PREFIX = "singra-desktop-oauth";
const ACTIVE_DESKTOP_OAUTH_FLOW_KEY = `${DESKTOP_OAUTH_KEY_PREFIX}:active-flow`;
const LEGACY_ACTIVE_DESKTOP_OAUTH_KEY = `${DESKTOP_OAUTH_KEY_PREFIX}:active`;
const DESKTOP_OAUTH_BRIDGE_PATH = "/auth";
const DESKTOP_OAUTH_FLOW_QUERY_KEY = "desktop_oauth_flow";
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
  const flowId = createFlowId();
  const challenge = await createChallenge(verifier);

  await Promise.all([
    savePkceVerifier(getDesktopOAuthVerifierKey(flowId), verifier),
    savePkceVerifier(ACTIVE_DESKTOP_OAUTH_FLOW_KEY, flowId),
  ]);

  const authUrl = new URL(`${runtimeConfig.supabaseUrl}/auth/v1/authorize`);
  authUrl.searchParams.set("provider", provider);
  authUrl.searchParams.set("redirect_to", getDesktopOAuthBridgeUrl(flowId));
  authUrl.searchParams.set("code_challenge", challenge);
  authUrl.searchParams.set("code_challenge_method", "s256");

  return authUrl.toString();
}

export async function exchangeDesktopOAuthCode(
  input: DesktopOAuthExchangeInput,
): Promise<DesktopOAuthTokens> {
  const code = input.code;
  if (!code) {
    throw new Error("Desktop OAuth callback did not include an auth code");
  }

  const normalizedCode = code.trim();
  const existingExchange = desktopExchangeInFlight.get(normalizedCode);
  if (existingExchange) {
    return existingExchange;
  }

  const exchangePromise = exchangeDesktopOAuthCodeUncached(normalizedCode, input.flowId ?? input.state).finally(() => {
    desktopExchangeInFlight.delete(normalizedCode);
  });
  desktopExchangeInFlight.set(normalizedCode, exchangePromise);

  return exchangePromise;
}

async function exchangeDesktopOAuthCodeUncached(
  code: string,
  flowId?: string | null,
): Promise<DesktopOAuthTokens> {
  const flow = await loadDesktopOAuthFlow(flowId);
  if (!flow) {
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
        code_verifier: flow.verifier,
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
      await clearDesktopOAuthFlow(flow);
    }
  }
}

export function getDesktopOAuthBridgeUrl(flowId?: string | null): string {
  const bridgeUrl = new URL(DESKTOP_OAUTH_BRIDGE_PATH, `${runtimeConfig.webUrl}/`);
  bridgeUrl.searchParams.set("source", "tauri");
  if (flowId?.trim()) {
    bridgeUrl.searchParams.set(DESKTOP_OAUTH_FLOW_QUERY_KEY, flowId.trim());
  }
  return bridgeUrl.toString();
}

function createFlowId(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return base64UrlEncode(bytes);
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

interface DesktopOAuthFlow {
  flowId: string | null;
  verifier: string;
  verifierKey: string;
}

async function loadDesktopOAuthFlow(flowIdOrLegacyState?: string | null): Promise<DesktopOAuthFlow | null> {
  const normalizedFlowId = flowIdOrLegacyState?.trim() || null;
  if (normalizedFlowId) {
    const flowVerifier = await loadPkceVerifier(getDesktopOAuthVerifierKey(normalizedFlowId));
    if (flowVerifier) {
      return {
        flowId: normalizedFlowId,
        verifier: flowVerifier,
        verifierKey: getDesktopOAuthVerifierKey(normalizedFlowId),
      };
    }
  }

  const activeFlowId = (await loadPkceVerifier(ACTIVE_DESKTOP_OAUTH_FLOW_KEY))?.trim() || null;
  if (activeFlowId) {
    const activeVerifier = await loadPkceVerifier(getDesktopOAuthVerifierKey(activeFlowId));
    if (activeVerifier) {
      return {
        flowId: activeFlowId,
        verifier: activeVerifier,
        verifierKey: getDesktopOAuthVerifierKey(activeFlowId),
      };
    }
  }

  const legacyVerifier = await loadPkceVerifier(LEGACY_ACTIVE_DESKTOP_OAUTH_KEY);
  if (!legacyVerifier) {
    return null;
  }

  return {
    flowId: null,
    verifier: legacyVerifier,
    verifierKey: LEGACY_ACTIVE_DESKTOP_OAUTH_KEY,
  };
}

async function clearDesktopOAuthFlow(flow: DesktopOAuthFlow): Promise<void> {
  await clearPkceVerifier(flow.verifierKey);
  await clearLegacyDesktopOAuthVerifier();

  if (!flow.flowId) {
    return;
  }

  const activeFlowId = (await loadPkceVerifier(ACTIVE_DESKTOP_OAUTH_FLOW_KEY))?.trim() || null;
  if (activeFlowId === flow.flowId) {
    await clearPkceVerifier(ACTIVE_DESKTOP_OAUTH_FLOW_KEY);
  }
}

async function clearLegacyDesktopOAuthVerifier(): Promise<void> {
  const legacyVerifier = await loadPkceVerifier(LEGACY_ACTIVE_DESKTOP_OAUTH_KEY);
  if (!legacyVerifier) {
    return;
  }

  await clearPkceVerifier(LEGACY_ACTIVE_DESKTOP_OAUTH_KEY);
}

function getDesktopOAuthVerifierKey(state: string): string {
  return `${DESKTOP_OAUTH_KEY_PREFIX}:verifier:${state}`;
}
