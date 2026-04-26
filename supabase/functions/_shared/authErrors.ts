export const AUTH_ERROR_CODES = {
  ACCOUNT_ALREADY_EXISTS: "ACCOUNT_ALREADY_EXISTS",
  OPAQUE_RECORD_CONFLICT: "OPAQUE_RECORD_CONFLICT",
  OPAQUE_REGISTRATION_FAILED: "OPAQUE_REGISTRATION_FAILED",
  AUTH_EMAIL_ALREADY_IN_USE: "AUTH_EMAIL_ALREADY_IN_USE",
  AUTH_INVALID_OR_EXPIRED_CODE: "AUTH_INVALID_OR_EXPIRED_CODE",
  TOO_MANY_ATTEMPTS: "TOO_MANY_ATTEMPTS",
  AUTH_REQUIRED: "AUTH_REQUIRED",
  FORBIDDEN: "FORBIDDEN",
  SERVER_ERROR: "SERVER_ERROR",
} as const;

export type AuthErrorCode = typeof AUTH_ERROR_CODES[keyof typeof AUTH_ERROR_CODES];

export function jsonError(
  code: AuthErrorCode,
  error: string,
  status: number,
  headers: Headers,
  extra: Record<string, unknown> = {},
): Response {
  return new Response(JSON.stringify({ error, code, ...extra }), { status, headers });
}

export function isUniqueViolation(error: unknown): boolean {
  const candidate = error as { code?: unknown; message?: unknown } | null;
  return candidate?.code === "23505"
    || (typeof candidate?.message === "string" && candidate.message.includes("duplicate key"));
}
