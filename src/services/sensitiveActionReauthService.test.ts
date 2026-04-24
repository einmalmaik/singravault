// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 — see LICENSE
import { beforeEach, describe, expect, it, vi } from 'vitest';

const {
  mockGetSession,
  mockGetUser,
  mockSetSession,
  mockRefreshSession,
  mockOpaqueStartLogin,
  mockOpaqueFinishLogin,
  mockVerifyOpaqueSessionBinding,
  mockAssertOpaqueServerKeyPinConfigured,
  supabaseMock,
} = vi.hoisted(() => {
  const mockGetSession = vi.fn();
  const mockGetUser = vi.fn();
  const mockSetSession = vi.fn();
  const mockRefreshSession = vi.fn();
  const mockOpaqueStartLogin = vi.fn();
  const mockOpaqueFinishLogin = vi.fn();
  const mockVerifyOpaqueSessionBinding = vi.fn();
  const mockAssertOpaqueServerKeyPinConfigured = vi.fn();

  return {
    mockGetSession,
    mockGetUser,
    mockSetSession,
    mockRefreshSession,
    mockOpaqueStartLogin,
    mockOpaqueFinishLogin,
    mockVerifyOpaqueSessionBinding,
    mockAssertOpaqueServerKeyPinConfigured,
    supabaseMock: {
      auth: {
        getSession: mockGetSession,
        getUser: mockGetUser,
        setSession: mockSetSession,
        refreshSession: mockRefreshSession,
      },
    },
  };
});

vi.mock('@/integrations/supabase/client', () => ({
  supabase: supabaseMock,
}));

vi.mock('@/services/opaqueService', () => ({
  assertOpaqueServerKeyPinConfigured: mockAssertOpaqueServerKeyPinConfigured,
  normalizeOpaqueIdentifier: (value: string) => value.trim().toLowerCase(),
  startLogin: mockOpaqueStartLogin,
  finishLogin: mockOpaqueFinishLogin,
  verifyOpaqueSessionBinding: mockVerifyOpaqueSessionBinding,
}));

import {
  getSensitiveActionReauthMethod,
  isSensitiveActionSessionFresh,
  reauthenticateWithAccountPassword,
  reauthenticateWithSessionRefresh,
} from '@/services/sensitiveActionReauthService';

let fetchMock: ReturnType<typeof vi.fn>;

function createJwtWithIssuedAt(iat: number): string {
  const header = btoa(JSON.stringify({ alg: 'HS256', typ: 'JWT' }))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '');
  const payload = btoa(JSON.stringify({ iat }))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '');
  return `${header}.${payload}.signature`;
}

describe('sensitiveActionReauthService', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    fetchMock = vi.fn();
    vi.stubGlobal('fetch', fetchMock);
    mockSetSession.mockResolvedValue({ error: null });
    mockRefreshSession.mockResolvedValue({ data: { session: null }, error: null });
    mockOpaqueStartLogin.mockResolvedValue({
      clientLoginState: 'client-login-state',
      startLoginRequest: 'start-login-request',
    });
    mockOpaqueFinishLogin.mockResolvedValue({
      finishLoginRequest: 'finish-login-request',
      sessionKey: 'opaque-session-key',
    });
    mockVerifyOpaqueSessionBinding.mockResolvedValue(undefined);
  });

  it('treats sessions with recent iat as fresh', async () => {
    const issuedAt = Math.floor(Date.now() / 1000) - 120;
    mockGetSession.mockResolvedValue({
      data: { session: { access_token: createJwtWithIssuedAt(issuedAt) } },
      error: null,
    });

    const result = await isSensitiveActionSessionFresh(300);

    expect(result).toBe(true);
  });

  it('treats sessions older than ttl as stale', async () => {
    const issuedAt = Math.floor(Date.now() / 1000) - 1200;
    mockGetSession.mockResolvedValue({
      data: { session: { access_token: createJwtWithIssuedAt(issuedAt) } },
      error: null,
    });

    const result = await isSensitiveActionSessionFresh(300);

    expect(result).toBe(false);
  });

  it('returns auth required when no authenticated user is present', async () => {
    mockGetUser.mockResolvedValue({
      data: { user: null },
      error: null,
    });

    const result = await reauthenticateWithAccountPassword('secret');

    expect(result).toEqual({
      success: false,
      error: 'AUTH_REQUIRED',
    });
  });

  it('uses password reauth for email provider accounts', async () => {
    mockGetUser.mockResolvedValue({
      data: {
        user: {
          email: 'user@example.com',
          app_metadata: {
            provider: 'email',
            providers: ['email'],
          },
        },
      },
      error: null,
    });

    const method = await getSensitiveActionReauthMethod();

    expect(method).toBe('password');
  });

  it('uses confirmation reauth for social-only accounts', async () => {
    mockGetUser.mockResolvedValue({
      data: {
        user: {
          email: 'user@example.com',
          app_metadata: {
            provider: 'google',
            providers: ['google'],
          },
        },
      },
      error: null,
    });

    const method = await getSensitiveActionReauthMethod();

    expect(method).toBe('confirmation');
  });

  it('refreshes session for non-password reauth fallback', async () => {
    const now = Math.floor(Date.now() / 1000);
    mockGetSession.mockResolvedValue({
      data: {
        session: {
          access_token: createJwtWithIssuedAt(now - 100),
          refresh_token: 'refresh-token',
        },
      },
      error: null,
    });
    mockRefreshSession.mockResolvedValue({
      data: {
        session: {
          access_token: createJwtWithIssuedAt(now),
          refresh_token: 'new-refresh-token',
        },
      },
      error: null,
    });

    const result = await reauthenticateWithSessionRefresh();

    expect(result).toEqual({ success: true });
    expect(mockRefreshSession).toHaveBeenCalledWith({
      refresh_token: 'refresh-token',
    });
  });

  it('returns auth required when no refresh token is available', async () => {
    mockGetSession.mockResolvedValue({
      data: {
        session: {
          access_token: createJwtWithIssuedAt(Math.floor(Date.now() / 1000)),
        },
      },
      error: null,
    });

    const result = await reauthenticateWithSessionRefresh();

    expect(result).toEqual({
      success: false,
      error: 'AUTH_REQUIRED',
    });
  });

  it('maps 401 reauth response to invalid credentials', async () => {
    mockGetUser.mockResolvedValue({
      data: { user: { email: 'user@example.com' } },
      error: null,
    });
    fetchMock.mockResolvedValueOnce(
      new Response(JSON.stringify({ error: 'Invalid credentials' }), { status: 401 }),
    );

    const result = await reauthenticateWithAccountPassword('wrong-pass');

    expect(result).toEqual({
      success: false,
      error: 'INVALID_CREDENTIALS',
    });
    expect(mockSetSession).not.toHaveBeenCalled();
  });

  it('maps two-factor challenge response explicitly', async () => {
    mockGetUser.mockResolvedValue({
      data: { user: { email: 'user@example.com' } },
      error: null,
    });
    fetchMock
      .mockResolvedValueOnce(new Response(JSON.stringify({
        loginResponse: 'login-response',
        loginId: 'login-id',
      }), { status: 200 }))
      .mockResolvedValueOnce(new Response(JSON.stringify({ requires2FA: true }), { status: 200 }));

    const result = await reauthenticateWithAccountPassword('valid-pass');

    expect(result).toEqual({
      success: false,
      error: 'TWO_FACTOR_REQUIRED',
    });
    expect(mockSetSession).not.toHaveBeenCalled();
  });

  it('sets session when reauthentication succeeds', async () => {
    mockGetUser.mockResolvedValue({
      data: { user: { email: 'user@example.com' } },
      error: null,
    });
    fetchMock
      .mockResolvedValueOnce(new Response(JSON.stringify({
        loginResponse: 'login-response',
        loginId: 'login-id',
      }), { status: 200 }))
      .mockResolvedValueOnce(new Response(JSON.stringify({
        session: {
          access_token: 'new-access-token',
          refresh_token: 'new-refresh-token',
          user: { id: 'user-id' },
        },
        opaqueSessionBinding: {
          version: 'opaque-session-binding-v1',
          userId: 'user-id',
          proof: 'proof',
        },
      }), { status: 200 }));

    const result = await reauthenticateWithAccountPassword('valid-pass');

    expect(result).toEqual({ success: true });
    expect(mockSetSession).toHaveBeenCalledWith({
      access_token: 'new-access-token',
      refresh_token: 'new-refresh-token',
    });
  });
});
