// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE

export const TAURI_OAUTH_CALLBACK_URL = "singravault://auth/callback";

const TAURI_SOURCE_VALUE = "tauri";
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
  isTauriSource: boolean;
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

  const params = collectCallbackParams(parsed);
  const error = params.get("error") || params.get("error_code");
  const accessToken = params.get("access_token");
  const refreshToken = params.get("refresh_token");
  const code = params.get("code");

  return {
    params,
    isTauriSource: isTauriOAuthSource(params),
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

export function buildTauriOAuthCallbackUrl(callbackUrl: string, baseUrl?: string): string | null {
  const parsed = parseCallbackUrl(callbackUrl, baseUrl);
  if (!parsed) {
    return null;
  }

  const params = collectCallbackParams(parsed);
  if (!isTauriOAuthSource(params) || !hasOAuthPayload(params)) {
    return null;
  }

  const appUrl = new URL(TAURI_OAUTH_CALLBACK_URL);
  params.forEach((value, key) => {
    appUrl.searchParams.append(key, value);
  });

  return appUrl.toString();
}

export function hasOAuthCallbackPayload(callbackUrl: string, baseUrl?: string): boolean {
  const payload = parseOAuthCallbackPayload(callbackUrl, baseUrl);
  return Boolean(payload?.hasAuthPayload);
}

export function normalizeOAuthCallbackInput(input: string): string | null {
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

    const appUrl = new URL(TAURI_OAUTH_CALLBACK_URL);
    params.forEach((value, key) => {
      appUrl.searchParams.append(key, value);
    });

    return appUrl.toString();
  }

  if (parseOAuthCallbackPayload(trimmed)?.hasAuthPayload) {
    return trimmed;
  }

  return null;
}

function parseCallbackUrl(callbackUrl: string, baseUrl = "http://localhost"): URL | null {
  try {
    return new URL(callbackUrl, baseUrl);
  } catch {
    return null;
  }
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

function isTauriOAuthSource(params: URLSearchParams): boolean {
  if (params.get("source") === TAURI_SOURCE_VALUE) {
    return true;
  }

  return params.get("redirect")?.includes("source=tauri") ?? false;
}

function hasOAuthPayload(params: URLSearchParams): boolean {
  return AUTH_PAYLOAD_KEYS.some((key) => params.has(key));
}
