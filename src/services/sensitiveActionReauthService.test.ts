// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 — see LICENSE
import { beforeEach, describe, expect, it, vi } from 'vitest';

const {
  mockGetSession,
  mockGetUser,
  mockSetSession,
  supabaseMock,
} = vi.hoisted(() => {
  const mockGetSession = vi.fn();
  const mockGetUser = vi.fn();
  const mockSetSession = vi.fn();

  return {
    mockGetSession,
    mockGetUser,
    mockSetSession,
    supabaseMock: {
      auth: {
        getSession: mockGetSession,
        getUser: mockGetUser,
        setSession: mockSetSession,
      },
    },
  };
});

vi.mock('@/integrations/supabase/client', () => ({
  supabase: supabaseMock,
}));

import {
  isSensitiveActionSessionFresh,
  reauthenticateWithAccountPassword,
} from '@/services/sensitiveActionReauthService';

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
    vi.stubGlobal('fetch', vi.fn());
    mockSetSession.mockResolvedValue({ error: null });
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

  it('maps 401 reauth response to invalid credentials', async () => {
    mockGetUser.mockResolvedValue({
      data: { user: { email: 'user@example.com' } },
      error: null,
    });
    (globalThis.fetch as any).mockResolvedValue(
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
    (globalThis.fetch as any).mockResolvedValue(
      new Response(JSON.stringify({ requires2FA: true }), { status: 200 }),
    );

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
    (globalThis.fetch as any).mockResolvedValue(
      new Response(JSON.stringify({
        session: {
          access_token: 'new-access-token',
          refresh_token: 'new-refresh-token',
        },
      }), { status: 200 }),
    );

    const result = await reauthenticateWithAccountPassword('valid-pass');

    expect(result).toEqual({ success: true });
    expect(mockSetSession).toHaveBeenCalledWith({
      access_token: 'new-access-token',
      refresh_token: 'new-refresh-token',
    });
  });
});
