// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 — see LICENSE
/**
 * @fileoverview Tests for AuthContext (BFF Pattern)
 * 
 * Phase 6: Context Provider and Hook Tests
 * Tests authentication context, state management, and auth methods.
 * 
 * The AuthContext now uses a BFF (Backend-for-Frontend) pattern:
 * - Session hydration via fetch() to auth-session edge function
 * - State changes via supabase.auth.onAuthStateChange
 * - No direct supabase.auth.getSession() calls
 */

import { describe, it, expect, beforeEach, vi, afterEach } from "vitest";
import { renderHook, act, waitFor } from "@testing-library/react";
import { AuthProvider, useAuth } from "./AuthContext";
import { ReactNode } from "react";

// ============ Mocks ============

const mockSupabase = vi.hoisted(() => ({
    auth: {
        onAuthStateChange: vi.fn(),
        signOut: vi.fn(),
        setSession: vi.fn(),
        getSession: vi.fn(),
    },
}));

vi.mock("@/integrations/supabase/client", () => ({
    supabase: mockSupabase,
}));

// Mock fetch for BFF calls
const mockFetch = vi.fn();
vi.stubGlobal("fetch", mockFetch);

// ============ Test Setup ============

const mockUser = {
    id: "test-user-id",
    email: "test@example.com",
    app_metadata: {},
    user_metadata: {},
    aud: "authenticated",
    created_at: "2024-01-01T00:00:00Z",
};

const mockSession = {
    access_token: "test-token",
    refresh_token: "test-refresh",
    expires_in: 3600,
    token_type: "bearer",
    user: mockUser,
};

let authCallback: (event: string, session: unknown) => void;

beforeEach(() => {
    vi.clearAllMocks();
    vi.stubEnv("VITE_SUPABASE_URL", "https://example.supabase.co");
    vi.stubEnv("VITE_SUPABASE_PUBLISHABLE_KEY", "test-publishable-key");
    sessionStorage.clear();
    localStorage.clear();

    // Default: auth state listener returns unsubscribe fn and captures callback
    mockSupabase.auth.onAuthStateChange.mockImplementation((callback) => {
        authCallback = callback;
        return {
            data: {
                subscription: {
                    unsubscribe: vi.fn(),
                },
            },
        };
    });

    // Default: BFF fetch returns no session (iframe environment in jsdom)
    // In jsdom, window.self === window.top, so isInIframe() returns false
    // and it tries to fetch from BFF.
    mockFetch.mockResolvedValue({
        ok: false,
        status: 401,
    });

    mockSupabase.auth.setSession.mockResolvedValue({
        data: { session: null },
        error: null,
    });
    mockSupabase.auth.getSession.mockResolvedValue({
        data: { session: null },
        error: null,
    });
});

afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllEnvs();
    sessionStorage.clear();
    localStorage.clear();
});

// ============ Helper: Wrapper Component ============

function wrapper({ children }: { children: ReactNode }) {
    return <AuthProvider>{children}</AuthProvider>;
}

// ============ Tests ============

describe("AuthContext", () => {
    describe("useAuth hook", () => {
        it("throws error when used outside AuthProvider", () => {
            // Suppress console.error for this test
            const consoleError = vi.spyOn(console, "error").mockImplementation(() => { });

            expect(() => {
                renderHook(() => useAuth());
            }).toThrow("useAuth must be used within an AuthProvider");

            consoleError.mockRestore();
        });
    });

    describe("Initial state", () => {
        it("starts with user=null, session=null, loading=true", async () => {
            const { result } = renderHook(() => useAuth(), { wrapper });

            // Initially loading
            expect(result.current.loading).toBe(true);
            expect(result.current.user).toBeNull();
            expect(result.current.session).toBeNull();

            // Wait for BFF hydration to complete
            await waitFor(() => {
                expect(result.current.loading).toBe(false);
            });
        });

        it("sets loading=false after BFF hydration completes", async () => {
            const { result } = renderHook(() => useAuth(), { wrapper });

            await waitFor(() => {
                expect(result.current.loading).toBe(false);
            });

            // BFF fetch was attempted (not iframe in jsdom)
            expect(result.current.authReady).toBe(true);
        });
    });

    // NOTE: signUp, signIn, signInWithOAuth were removed from AuthContext
    // during BFF refactoring. Auth is now handled via edge functions.

    describe("signOut", () => {
        it("calls supabase.auth.signOut", async () => {
            mockSupabase.auth.signOut.mockResolvedValue({ error: null });

            const { result } = renderHook(() => useAuth(), { wrapper });

            await waitFor(() => expect(result.current.loading).toBe(false));

            await act(async () => {
                await result.current.signOut();
            });

            expect(mockSupabase.auth.signOut).toHaveBeenCalled();
        });

        it("throws when supabase signOut returns an error", async () => {
            const mockError = new Error("Network error");
            mockSupabase.auth.signOut.mockResolvedValue({ error: mockError });

            const consoleError = vi.spyOn(console, "error").mockImplementation(() => { });

            const { result } = renderHook(() => useAuth(), { wrapper });

            await waitFor(() => expect(result.current.loading).toBe(false));

            let errorThrown;
            try {
                await act(async () => {
                    await result.current.signOut();
                });
            } catch (e) {
                errorThrown = e;
            }

            expect(errorThrown).toBe(mockError);
            expect(consoleError).toHaveBeenCalledWith(
                expect.stringContaining("[AuthContext] Failed to terminate GoTrue session"),
                mockError,
            );

            consoleError.mockRestore();
        });
    });

    describe("Auth state changes", () => {
        it("updates user and session on SIGNED_IN event", async () => {
            const { result } = renderHook(() => useAuth(), { wrapper });

            await waitFor(() => expect(result.current.loading).toBe(false));

            // Simulate SIGNED_IN event
            act(() => {
                authCallback("SIGNED_IN", mockSession);
            });

            await waitFor(() => {
                expect(result.current.user).toEqual(mockUser);
                expect(result.current.session).toEqual(mockSession);
            });
        });

        it("clears user and session on SIGNED_OUT event", async () => {
            const { result } = renderHook(() => useAuth(), { wrapper });

            await waitFor(() => expect(result.current.loading).toBe(false));

            // First set a session via SIGNED_IN
            act(() => {
                authCallback("SIGNED_IN", mockSession);
            });

            await waitFor(() => {
                expect(result.current.user).toEqual(mockUser);
            });

            // Simulate SIGNED_OUT event
            act(() => {
                authCallback("SIGNED_OUT", null);
            });

            await waitFor(() => {
                expect(result.current.user).toBeNull();
                expect(result.current.session).toBeNull();
            });
        });

        it("updates session on TOKEN_REFRESHED event", async () => {
            const { result } = renderHook(() => useAuth(), { wrapper });

            await waitFor(() => expect(result.current.loading).toBe(false));

            const newSession = {
                ...mockSession,
                access_token: "new-token",
            };

            // Simulate TOKEN_REFRESHED event
            act(() => {
                authCallback("TOKEN_REFRESHED", newSession);
            });

            await waitFor(() => {
                expect(result.current.session?.access_token).toBe("new-token");
            });
        });
    });

    describe("Session restoration", () => {
        it("restores session via BFF cookie hydration", async () => {
            // BFF returns a valid session
            mockFetch.mockResolvedValue({
                ok: true,
                json: async () => ({ session: mockSession }),
            });

            mockSupabase.auth.setSession.mockResolvedValue({
                data: { session: mockSession },
                error: null,
            });

            const { result } = renderHook(() => useAuth(), { wrapper });

            await waitFor(() => {
                expect(result.current.loading).toBe(false);
                expect(result.current.authReady).toBe(true);
            });

            // setSession should have been called with the BFF session tokens
            expect(mockSupabase.auth.setSession).toHaveBeenCalledWith({
                access_token: "test-token",
                refresh_token: "test-refresh",
            });
        });

        it("sets authReady=true and loading=false after BFF hydration succeeds", async () => {
            mockFetch.mockResolvedValue({
                ok: true,
                json: async () => ({ session: mockSession }),
            });

            mockSupabase.auth.setSession.mockResolvedValue({
                data: { session: mockSession },
                error: null,
            });

            const { result } = renderHook(() => useAuth(), { wrapper });

            await waitFor(() => {
                expect(result.current.authReady).toBe(true);
                expect(result.current.loading).toBe(false);
            });
        });

        it("sets authReady=true and loading=false even when BFF fetch fails (no permanent spinner)", async () => {
            mockFetch.mockRejectedValue(new Error("Network error"));

            const consoleWarn = vi.spyOn(console, "warn").mockImplementation(() => { });

            const { result } = renderHook(() => useAuth(), { wrapper });

            await waitFor(() => {
                // Auth state must resolve — no permanent spinner
                expect(result.current.authReady).toBe(true);
                expect(result.current.loading).toBe(false);
            });

            // Rejection treated as unauthenticated — user must sign in again
            expect(result.current.user).toBeNull();
            expect(result.current.session).toBeNull();

            consoleWarn.mockRestore();
        });

        it("preserves valid session from onAuthStateChange when BFF returns no session", async () => {
            // BFF returns 401 (no cookie)
            mockFetch.mockResolvedValue({
                ok: false,
                status: 401,
            });

            const { result } = renderHook(() => useAuth(), { wrapper });

            // INITIAL_SESSION fires with a valid session (e.g. from OAuth redirect)
            act(() => {
                authCallback("INITIAL_SESSION", mockSession);
            });

            await waitFor(() => {
                expect(result.current.authReady).toBe(true);
                expect(result.current.loading).toBe(false);
            });

            // Session from onAuthStateChange should be preserved
            expect(result.current.user).toEqual(mockUser);
            expect(result.current.session).toEqual(mockSession);
        });

        it("preserves valid session when BFF fetch rejects after INITIAL_SESSION (no false-positive logout)", async () => {
            // BFF fetch will reject (transient error)
            mockFetch.mockRejectedValue(new Error("Network timeout"));

            const consoleWarn = vi.spyOn(console, "warn").mockImplementation(() => { });

            const { result } = renderHook(() => useAuth(), { wrapper });

            // INITIAL_SESSION fires with a valid session before BFF settles
            act(() => {
                authCallback("INITIAL_SESSION", mockSession);
            });

            await waitFor(() => {
                expect(result.current.authReady).toBe(true);
                expect(result.current.loading).toBe(false);
            });

            // CRITICAL: user must NOT be null — BFF failure must not have
            // overwritten the valid session from INITIAL_SESSION
            expect(result.current.user).toEqual(mockUser);
            expect(result.current.session).toEqual(mockSession);

            consoleWarn.mockRestore();
        });

        it("restores the tab fallback session when BFF cookie hydration returns 401", async () => {
            sessionStorage.setItem("singra-auth-session-fallback", JSON.stringify({
                access_token: "fallback-token",
                refresh_token: "fallback-refresh",
            }));

            mockFetch.mockResolvedValue({
                ok: false,
                status: 401,
            });

            mockSupabase.auth.setSession.mockResolvedValue({
                data: { session: mockSession },
                error: null,
            });

            const { result } = renderHook(() => useAuth(), { wrapper });

            await waitFor(() => {
                expect(result.current.authReady).toBe(true);
                expect(result.current.loading).toBe(false);
            });

            expect(mockSupabase.auth.setSession).toHaveBeenCalledWith({
                access_token: "fallback-token",
                refresh_token: "fallback-refresh",
            });
        });
    });

    describe("Session fallback persistence", () => {
        it("does not store session tokens in sessionStorage for normal web sessions", async () => {
            renderHook(() => useAuth(), { wrapper });

            act(() => {
                authCallback("SIGNED_IN", mockSession);
            });

            await waitFor(() => {
                expect(sessionStorage.getItem("singra-auth-session-fallback")).toBeNull();
            });
        });

        it("clears the tab fallback session on signOut", async () => {
            sessionStorage.setItem("singra-auth-session-fallback", JSON.stringify({
                access_token: "test-token",
                refresh_token: "test-refresh",
            }));

            mockSupabase.auth.signOut.mockResolvedValue({ error: null });

            const { result } = renderHook(() => useAuth(), { wrapper });

            await waitFor(() => expect(result.current.loading).toBe(false));

            await act(async () => {
                await result.current.signOut();
            });

            expect(sessionStorage.getItem("singra-auth-session-fallback")).toBeNull();
        });
    });
});
