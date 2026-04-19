import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const { mockGetSession, mockSetSession, mockRefreshSession, supabaseMock } = vi.hoisted(() => {
  const mockGetSession = vi.fn();
  const mockSetSession = vi.fn();
  const mockRefreshSession = vi.fn();

  return {
    mockGetSession,
    mockSetSession,
    mockRefreshSession,
    supabaseMock: {
      auth: {
        getSession: mockGetSession,
        setSession: mockSetSession,
        refreshSession: mockRefreshSession,
      },
    },
  };
});

vi.mock("@/integrations/supabase/client", () => ({
  supabase: supabaseMock,
}));

vi.mock("@/platform/runtime", () => ({
  isTauriRuntime: () => false,
}));

import {
  AUTH_OFFLINE_IDENTITY_STORAGE_KEY,
  clearPersistentSession,
  hydrateAuthSession,
  readOfflineIdentity,
  refreshCurrentSession,
  SESSION_FALLBACK_STORAGE_KEY,
} from "@/services/authSessionManager";

const mockUser = {
  id: "user-1",
  email: "user@example.com",
  app_metadata: {},
  user_metadata: {},
  aud: "authenticated",
  created_at: "2026-01-01T00:00:00.000Z",
};

const mockSession = {
  access_token: "access-token",
  refresh_token: "refresh-token",
  expires_in: 3600,
  token_type: "bearer",
  user: mockUser,
};

describe("authSessionManager", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.stubEnv("VITE_SUPABASE_URL", "https://example.supabase.co");
    vi.stubEnv("VITE_SUPABASE_PUBLISHABLE_KEY", "test-publishable-key");
    sessionStorage.clear();
    localStorage.clear();
    vi.stubGlobal("fetch", vi.fn());
    mockGetSession.mockResolvedValue({ data: { session: null }, error: null });
    mockSetSession.mockResolvedValue({ data: { session: mockSession }, error: null });
    mockRefreshSession.mockResolvedValue({ data: { session: mockSession }, error: null });
  });

  afterEach(() => {
    vi.unstubAllEnvs();
  });

  it("hydrates from the BFF cookie and stores only a token-free offline identity", async () => {
    vi.mocked(fetch).mockResolvedValue(
      new Response(JSON.stringify({ session: mockSession }), { status: 200 }),
    );

    const result = await hydrateAuthSession();

    expect(result.mode).toBe("online");
    expect(result.user?.id).toBe("user-1");
    expect(mockSetSession).toHaveBeenCalledWith({
      access_token: "access-token",
      refresh_token: "refresh-token",
    });
    expect(sessionStorage.getItem(SESSION_FALLBACK_STORAGE_KEY)).toBeNull();

    const offlineIdentity = await readOfflineIdentity();
    expect(offlineIdentity).toMatchObject({
      userId: "user-1",
      email: "user@example.com",
    });
    expect(localStorage.getItem(AUTH_OFFLINE_IDENTITY_STORAGE_KEY)).not.toContain("access-token");
    expect(localStorage.getItem(AUTH_OFFLINE_IDENTITY_STORAGE_KEY)).not.toContain("refresh-token");
  });

  it("deduplicates concurrent refresh calls", async () => {
    let resolveFetch: (response: Response) => void = () => undefined;
    vi.mocked(fetch).mockImplementation(
      () => new Promise<Response>((resolve) => {
        resolveFetch = resolve;
      }),
    );

    const first = refreshCurrentSession();
    const second = refreshCurrentSession();
    resolveFetch(new Response(JSON.stringify({ session: mockSession }), { status: 200 }));

    await expect(first).resolves.toMatchObject({ access_token: "access-token" });
    await expect(second).resolves.toMatchObject({ access_token: "access-token" });
    expect(fetch).toHaveBeenCalledTimes(1);
  });

  it("clears fallback tokens and offline identity on sign-out cleanup", async () => {
    sessionStorage.setItem(SESSION_FALLBACK_STORAGE_KEY, JSON.stringify({
      access_token: "old-access",
      refresh_token: "old-refresh",
    }));
    localStorage.setItem(AUTH_OFFLINE_IDENTITY_STORAGE_KEY, JSON.stringify({
      userId: "user-1",
      email: "user@example.com",
      updatedAt: new Date().toISOString(),
    }));

    await clearPersistentSession();

    expect(sessionStorage.getItem(SESSION_FALLBACK_STORAGE_KEY)).toBeNull();
    expect(localStorage.getItem(AUTH_OFFLINE_IDENTITY_STORAGE_KEY)).toBeNull();
  });
});
