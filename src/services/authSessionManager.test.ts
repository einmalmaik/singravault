import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const runtimeState = vi.hoisted(() => ({
  isTauri: false,
  deepLinks: [] as string[],
  invoke: vi.fn(),
}));

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
  isTauriRuntime: () => runtimeState.isTauri,
}));

vi.mock("@/platform/tauriInvoke", () => ({
  getTauriInvoke: async () => runtimeState.isTauri ? runtimeState.invoke : null,
}));

vi.mock("@/platform/deepLink", () => ({
  getInitialDeepLinks: async () => runtimeState.deepLinks,
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
    runtimeState.isTauri = false;
    runtimeState.deepLinks = [];
    runtimeState.invoke.mockReset();
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

  it("does not hydrate a desktop session from token-free offline identity alone", async () => {
    runtimeState.isTauri = true;
    runtimeState.invoke.mockResolvedValue(null);
    localStorage.setItem(AUTH_OFFLINE_IDENTITY_STORAGE_KEY, JSON.stringify({
      userId: "offline-user",
      email: "offline@example.com",
      updatedAt: new Date().toISOString(),
    }));

    const result = await hydrateAuthSession();

    expect(result.mode).toBe("unauthenticated");
    expect(result.user).toBeNull();
    expect(result.offlineIdentity).toBeNull();
  });

  it("keeps the desktop callback path unauthenticated until the deep link is applied", async () => {
    runtimeState.isTauri = true;
    runtimeState.deepLinks = ["singravault://auth/callback?code=desktop-code"];
    localStorage.setItem(AUTH_OFFLINE_IDENTITY_STORAGE_KEY, JSON.stringify({
      userId: "offline-user",
      email: "offline@example.com",
      updatedAt: new Date().toISOString(),
    }));

    const result = await hydrateAuthSession();

    expect(result.mode).toBe("unauthenticated");
    expect(mockRefreshSession).not.toHaveBeenCalled();
  });
});
