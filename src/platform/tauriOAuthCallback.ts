// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE

export const TAURI_OAUTH_CALLBACK_URL = "singravault://auth/callback";

const TAURI_CALLBACK_PROTOCOL = "singravault:";
const TAURI_CALLBACK_HOST = "auth";
const TAURI_CALLBACK_PATH = "/callback";
const WEB_CALLBACK_PATH = "/auth";
const BRIDGE_ONLY_CALLBACK_KEYS = new Set(["source"]);
const BLOCKED_SUPABASE_CALLBACK_TYPES = new Set(["recovery", "signup", "magiclink", "email_change"]);
const AUTH_PAYLOAD_KEYS = [
  "access_token",
  "refresh_token",
  "code",
  "error",
  "error_code",
  "error_description",
] as const;

export interface OAuthSessionTokens {
  access_token: string;
  refresh_token: string;
}

export interface OAuthCallbackError {
  error: string;
  errorCode: string | null;
  description: string | null;
}

export interface OAuthCallbackPayload {
  params: URLSearchParams;
  hasAuthPayload: boolean;
  tokens: OAuthSessionTokens | null;
  code: string | null;
  error: OAuthCallbackError | null;
}

export function parseOAuthCallbackPayload(callbackUrl: string, baseUrl?: string): OAuthCallbackPayload | null {
  const parsed = parseCallbackUrl(callbackUrl, baseUrl);
  if (!parsed) {
    return null;
  }

  if (!isExpectedCallbackLocation(parsed, baseUrl)) {
    return null;
  }

  const params = collectCallbackParams(parsed);
  const error = params.get("error") || params.get("error_code");
  const accessToken = params.get("access_token");
  const refreshToken = params.get("refresh_token");
  const code = params.get("code");

  return {
    params,
    hasAuthPayload: hasOAuthPayload(params),
    tokens: accessToken && refreshToken
      ? { access_token: accessToken, refresh_token: refreshToken }
      : null,
    code: code || null,
    error: error
      ? {
        error,
        errorCode: params.get("error_code"),
        description: params.get("error_description"),
      }
      : null,
  };
}

export function hasOAuthCallbackPayload(callbackUrl: string, baseUrl?: string): boolean {
  const payload = parseOAuthCallbackPayload(callbackUrl, baseUrl);
  return Boolean(payload?.hasAuthPayload);
}

export function getSupabaseCallbackType(payload: OAuthCallbackPayload): string | null {
  const callbackType = payload.params.get("type");
  return callbackType ? callbackType.trim().toLowerCase() : null;
}

export function isBlockedSupabaseAuthCallback(payload: OAuthCallbackPayload): boolean {
  const callbackType = getSupabaseCallbackType(payload);
  if (!callbackType) {
    return false;
  }

  return BLOCKED_SUPABASE_CALLBACK_TYPES.has(callbackType) || Boolean(payload.tokens);
}

export function isDesktopOAuthBridgeUrl(callbackUrl: string, baseUrl?: string): boolean {
  const parsed = parseCallbackUrl(callbackUrl, baseUrl);
  if (!parsed) {
    return false;
  }

  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    return false;
  }

  if (!baseUrl) {
    return false;
  }

  const base = parseCallbackUrl(baseUrl);
  if (parsed.origin !== base?.origin || parsed.pathname !== WEB_CALLBACK_PATH) {
    return false;
  }

  return collectCallbackParams(parsed).get("source") === "tauri";
}

export function isTauriOAuthCallbackUrl(callbackUrl: string): boolean {
  const parsed = parseCallbackUrl(callbackUrl);
  return Boolean(parsed && isTauriCallbackLocation(parsed));
}

export function normalizeOAuthCallbackInput(input: string, webCallbackOrigin = getConfiguredWebCallbackOrigin()): string | null {
  const trimmed = input.trim();
  if (!trimmed) {
    return null;
  }

  const withoutHash = trimmed.startsWith("#") ? trimmed.slice(1) : trimmed;
  const shouldTreatAsRawParams = trimmed.startsWith("#") || /^[A-Za-z_][A-Za-z0-9_]*=/.test(trimmed);
  if (shouldTreatAsRawParams) {
    const params = new URLSearchParams(withoutHash);
    if (!hasOAuthPayload(params)) {
      return null;
    }

    return createTauriOAuthCallbackUrl(params);
  }

  const tauriPayload = parseOAuthCallbackPayload(trimmed);
  if (tauriPayload?.hasAuthPayload) {
    return createTauriOAuthCallbackUrl(tauriPayload.params);
  }

  const webBridgePayload = parseOAuthCallbackPayload(trimmed, webCallbackOrigin);
  if (webBridgePayload?.hasAuthPayload) {
    return createTauriOAuthCallbackUrl(webBridgePayload.params);
  }

  return null;
}

export function createTauriOAuthCallbackUrl(params: URLSearchParams): string {
  const appUrl = new URL(TAURI_OAUTH_CALLBACK_URL);
  params.forEach((value, key) => {
    if (!BRIDGE_ONLY_CALLBACK_KEYS.has(key)) {
      appUrl.searchParams.append(key, value);
    }
  });

  return appUrl.toString();
}

function parseCallbackUrl(callbackUrl: string, baseUrl = "http://localhost"): URL | null {
  try {
    return new URL(callbackUrl, baseUrl);
  } catch {
    return null;
  }
}

function isExpectedCallbackLocation(parsed: URL, baseUrl?: string): boolean {
  if (isTauriCallbackLocation(parsed)) {
    return true;
  }

  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    return false;
  }

  if (!baseUrl) {
    return false;
  }

  const base = parseCallbackUrl(baseUrl);
  return parsed.origin === base?.origin && parsed.pathname === WEB_CALLBACK_PATH;
}

function isTauriCallbackLocation(parsed: URL): boolean {
  return parsed.protocol === TAURI_CALLBACK_PROTOCOL
    && parsed.hostname === TAURI_CALLBACK_HOST
    && parsed.pathname === TAURI_CALLBACK_PATH;
}

function collectCallbackParams(parsed: URL): URLSearchParams {
  const params = new URLSearchParams(parsed.search);
  const hash = parsed.hash.startsWith("#") ? parsed.hash.slice(1) : parsed.hash;

  if (hash) {
    const hashParams = new URLSearchParams(hash);
    hashParams.forEach((value, key) => {
      params.set(key, value);
    });
  }

  return params;
}

function hasOAuthPayload(params: URLSearchParams): boolean {
  return AUTH_PAYLOAD_KEYS.some((key) => params.has(key));
}

function getConfiguredWebCallbackOrigin(): string | undefined {
  if (typeof window === "undefined") {
    return undefined;
  }

  return window.location.origin;
}
