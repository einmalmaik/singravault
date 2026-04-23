export type AuthRateLimitAction =
  | "password_login"
  | "recovery_verify"
  | "totp_verify"
  | "backup_code_verify"
  | "opaque_login";

type AccountIdentifierKind = "email" | "user";

interface AccountIdentifierInput {
  kind: AccountIdentifierKind;
  value: string;
}

interface RateLimitAttempt {
  success: boolean;
  attempted_at: string;
  locked_until: string | null;
}

interface SupabaseQueryResult<T> {
  data: T[] | null;
  error: { message?: string } | null;
}

interface SupabaseAdminClient {
  from: (table: string) => unknown;
}

interface AuthRateLimitConfig {
  maxAttempts: number;
  windowMs: number;
  lockoutMs: number;
}

export interface AuthRateLimitCheckInput {
  supabaseAdmin: SupabaseAdminClient;
  req: Request;
  action: AuthRateLimitAction;
  account: AccountIdentifierInput;
}

export interface AuthRateLimitState {
  allowed: boolean;
  status: 200 | 429 | 503;
  action: AuthRateLimitAction;
  identifier: string;
  ipAddress: string;
  attemptsRemaining: number;
  failureCount: number;
  lockedUntil: string | null;
  retryAfterSeconds: number | null;
  error: string | null;
  supabaseAdmin: SupabaseAdminClient;
  limits: AuthRateLimitConfig;
}

export interface AuthRateLimitFailureResult {
  attemptsRemaining: number;
  lockedUntil: string | null;
  retryAfterSeconds: number | null;
}

const AUTH_RATE_LIMITS: Record<AuthRateLimitAction, AuthRateLimitConfig> = {
  password_login: {
    maxAttempts: 5,
    windowMs: 15 * 60 * 1000,
    lockoutMs: 15 * 60 * 1000,
  },
  recovery_verify: {
    maxAttempts: 5,
    windowMs: 15 * 60 * 1000,
    lockoutMs: 60 * 60 * 1000,
  },
  totp_verify: {
    maxAttempts: 5,
    windowMs: 5 * 60 * 1000,
    lockoutMs: 15 * 60 * 1000,
  },
  backup_code_verify: {
    maxAttempts: 5,
    windowMs: 30 * 60 * 1000,
    lockoutMs: 60 * 60 * 1000,
  },
  opaque_login: {
    maxAttempts: 5,
    windowMs: 15 * 60 * 1000,
    lockoutMs: 15 * 60 * 1000,
  },
};

export async function checkAuthRateLimit(input: AuthRateLimitCheckInput): Promise<AuthRateLimitState> {
  const limits = AUTH_RATE_LIMITS[input.action];
  const identifier = await buildAccountIdentifier(input.account);
  const ipAddress = getTrustedClientIp(input.req);
  const now = new Date();
  const windowStart = new Date(now.getTime() - limits.windowMs);
  // Lockouts can intentionally outlive the counting window (for example
  // recovery_verify: 15 minute window, 60 minute lockout). Query far enough
  // back to keep active lockouts enforceable, but count failures only inside
  // the configured window below.
  const queryStart = new Date(
    now.getTime() - Math.max(limits.windowMs, limits.lockoutMs * 8),
  ).toISOString();

  const [accountAttempts, ipAttempts] = await Promise.all([
    queryAttemptsByIdentifier(input.supabaseAdmin, identifier, input.action, queryStart),
    ipAddress === "unknown"
      ? Promise.resolve<SupabaseQueryResult<RateLimitAttempt>>({ data: [], error: null })
      : queryAttemptsByIp(input.supabaseAdmin, ipAddress, input.action, queryStart),
  ]);

  if (accountAttempts.error || ipAttempts.error) {
    console.error("Auth rate limit check failed:", accountAttempts.error || ipAttempts.error);
    return {
      allowed: false,
      status: 503,
      action: input.action,
      identifier,
      ipAddress,
      attemptsRemaining: 0,
      failureCount: limits.maxAttempts,
      lockedUntil: null,
      retryAfterSeconds: null,
      error: "Rate limit check failed",
      supabaseAdmin: input.supabaseAdmin,
      limits,
    };
  }

  const accountData = accountAttempts.data ?? [];
  const ipData = ipAttempts.data ?? [];
  const lockedUntil = getActiveLockout([...accountData, ...ipData], now);
  const accountFailures = countFailures(accountData, windowStart);
  const ipFailures = countFailures(ipData, windowStart);
  const failureCount = Math.max(accountFailures, ipFailures);
  const retryAfterSeconds = lockedUntil ? secondsUntil(lockedUntil, now) : null;

  return {
    allowed: !lockedUntil,
    status: lockedUntil ? 429 : 200,
    action: input.action,
    identifier,
    ipAddress,
    attemptsRemaining: Math.max(0, limits.maxAttempts - failureCount),
    failureCount,
    lockedUntil,
    retryAfterSeconds,
    error: lockedUntil ? "Too many attempts" : null,
    supabaseAdmin: input.supabaseAdmin,
    limits,
  };
}

export async function recordAuthRateLimitFailure(
  state: AuthRateLimitState,
): Promise<AuthRateLimitFailureResult> {
  const now = new Date();
  const failedAttempts = state.failureCount + 1;
  const lockedUntil = failedAttempts >= state.limits.maxAttempts
    ? new Date(now.getTime() + getEffectiveLockoutMs(state.limits, failedAttempts)).toISOString()
    : null;

  const insertQuery = state.supabaseAdmin.from("rate_limit_attempts") as {
    insert: (values: Record<string, unknown>) => Promise<{ error: { message?: string } | null }>;
  };
  const { error } = await insertQuery.insert({
    identifier: state.identifier,
    action: state.action,
    success: false,
    attempted_at: now.toISOString(),
    locked_until: lockedUntil,
    ip_address: state.ipAddress,
  });

  if (error) {
    console.error("Failed to record auth rate limit failure:", error);
  }

  return {
    attemptsRemaining: Math.max(0, state.limits.maxAttempts - failedAttempts),
    lockedUntil,
    retryAfterSeconds: lockedUntil ? secondsUntil(lockedUntil, now) : null,
  };
}

export async function resetAuthRateLimit(state: AuthRateLimitState): Promise<void> {
  const deleteQuery = state.supabaseAdmin.from("rate_limit_attempts") as {
    delete: () => unknown;
  };
  const query = deleteQuery.delete() as {
    eq: (column: string, value: string) => unknown;
  };

  const actionQuery = query.eq("identifier", state.identifier) as {
    eq: (column: string, value: string) => Promise<{ error: { message?: string } | null }>;
  };

  const { error } = await actionQuery.eq("action", state.action);
  if (error) {
    console.error("Failed to reset auth rate limit failures:", error);
  }
}

export function authRateLimitResponse(
  state: Pick<AuthRateLimitState, "status" | "lockedUntil" | "retryAfterSeconds" | "attemptsRemaining" | "error">,
  headers: Headers,
): Response {
  const responseHeaders = new Headers(headers);
  responseHeaders.set("Content-Type", "application/json");
  if (state.retryAfterSeconds !== null && state.retryAfterSeconds > 0) {
    responseHeaders.set("Retry-After", String(state.retryAfterSeconds));
  }

  return new Response(JSON.stringify({
    error: state.error ?? "Too many attempts",
    attemptsRemaining: state.attemptsRemaining,
    lockedUntil: state.lockedUntil,
  }), {
    status: state.status,
    headers: responseHeaders,
  });
}

export function getTrustedClientIp(req: Request): string {
  const cfConnectingIp = req.headers.get("CF-Connecting-IP");
  if (cfConnectingIp && cfConnectingIp.trim().length > 0) {
    return cfConnectingIp.trim();
  }

  const xForwardedFor = req.headers.get("X-Forwarded-For");
  if (xForwardedFor) {
    const forwardedClientIp = xForwardedFor.split(",")[0]?.trim();
    if (forwardedClientIp && forwardedClientIp.length > 0) {
      return forwardedClientIp;
    }
  }

  return "unknown";
}

async function buildAccountIdentifier(account: AccountIdentifierInput): Promise<string> {
  const normalizedValue = account.value.trim().toLowerCase();
  if (account.kind === "email") {
    return `email:${await sha256Hex(normalizedValue)}`;
  }

  return `user:${normalizedValue}`;
}

async function sha256Hex(value: string): Promise<string> {
  const data = new TextEncoder().encode(value);
  const digest = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(digest))
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

async function queryAttemptsByIdentifier(
  supabaseAdmin: SupabaseAdminClient,
  identifier: string,
  action: AuthRateLimitAction,
  windowStart: string,
): Promise<SupabaseQueryResult<RateLimitAttempt>> {
  return await chainAttemptQuery(
    (supabaseAdmin.from("rate_limit_attempts") as {
      select: (columns: string) => unknown;
    }).select("success, attempted_at, locked_until"),
    [
      ["identifier", identifier],
      ["action", action],
    ],
    windowStart,
  );
}

async function queryAttemptsByIp(
  supabaseAdmin: SupabaseAdminClient,
  ipAddress: string,
  action: AuthRateLimitAction,
  windowStart: string,
): Promise<SupabaseQueryResult<RateLimitAttempt>> {
  return await chainAttemptQuery(
    (supabaseAdmin.from("rate_limit_attempts") as {
      select: (columns: string) => unknown;
    }).select("success, attempted_at, locked_until"),
    [
      ["ip_address", ipAddress],
      ["action", action],
    ],
    windowStart,
  );
}

async function chainAttemptQuery(
  query: unknown,
  equalityFilters: Array<[string, string]>,
  windowStart: string,
): Promise<SupabaseQueryResult<RateLimitAttempt>> {
  let current = query as {
    eq: (column: string, value: string) => unknown;
    gte: (column: string, value: string) => unknown;
  };

  equalityFilters.forEach(([column, value]) => {
    current = current.eq(column, value) as typeof current;
  });

  const windowed = current.gte("attempted_at", windowStart) as {
    order: (
      column: string,
      options: { ascending: boolean },
    ) => Promise<SupabaseQueryResult<RateLimitAttempt>>;
  };

  return await windowed.order("attempted_at", { ascending: false });
}

function getActiveLockout(attempts: RateLimitAttempt[], now: Date): string | null {
  const activeLockouts = attempts
    .map((attempt) => attempt.locked_until)
    .filter((lockedUntil): lockedUntil is string => (
      Boolean(lockedUntil) && new Date(lockedUntil).getTime() > now.getTime()
    ))
    .sort();

  return activeLockouts.at(-1) ?? null;
}

function countFailures(attempts: RateLimitAttempt[], windowStart: Date): number {
  const windowStartMs = windowStart.getTime();
  return attempts.filter((attempt) => (
    !attempt.success
    && new Date(attempt.attempted_at).getTime() >= windowStartMs
  )).length;
}

function getEffectiveLockoutMs(limits: AuthRateLimitConfig, failedAttempts: number): number {
  const extraWindows = Math.max(0, Math.floor((failedAttempts - limits.maxAttempts) / limits.maxAttempts));
  const multiplier = Math.min(2 ** extraWindows, 8);
  return limits.lockoutMs * multiplier;
}

function secondsUntil(isoDate: string, now: Date): number {
  return Math.max(1, Math.ceil((new Date(isoDate).getTime() - now.getTime()) / 1000));
}
