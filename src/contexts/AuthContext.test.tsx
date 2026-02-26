// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 — see LICENSE
/**
 * @fileoverview Tests for AuthContext
 * 
 * Phase 6: Context Provider and Hook Tests
 * Tests authentication context, state management, and auth methods.
 */

import { describe, it, expect, beforeEach, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import { renderHook, act } from "@testing-library/react";
import { AuthProvider, useAuth } from "./AuthContext";
import { ReactNode } from "react";

// ============ Mocks ============

const mockSupabase = vi.hoisted(() => ({
    auth: {
        getSession: vi.fn(),
        onAuthStateChange: vi.fn(),
        signUp: vi.fn(),
        signInWithPassword: vi.fn(),
        signInWithOAuth: vi.fn(),
        signOut: vi.fn(),
    },
}));

vi.mock("@/integrations/supabase/client", () => ({
    supabase: mockSupabase,
}));

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

beforeEach(() => {
    vi.clearAllMocks();

    // Default: no session, auth state listener returns unsubscribe fn
    mockSupabase.auth.getSession.mockResolvedValue({
        data: { session: null },
        error: null,
    });

    mockSupabase.auth.onAuthStateChange.mockReturnValue({
        data: {
            subscription: {
                unsubscribe: vi.fn(),
            },
        },
    });
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

            // Wait for getSession to resolve
            await waitFor(() => {
                expect(result.current.loading).toBe(false);
            });
        });

        it("sets loading=false after getSession resolves", async () => {
            const { result } = renderHook(() => useAuth(), { wrapper });

            await waitFor(() => {
                expect(result.current.loading).toBe(false);
            });

            expect(mockSupabase.auth.getSession).toHaveBeenCalled();
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
                expect.stringContaining("[AuthContext] signOut failed"),
                mockError,
            );

            consoleError.mockRestore();
        });
    });

    describe("Auth state changes", () => {
        it("updates user and session on SIGNED_IN event", async () => {
            let authCallback: (event: string, session: unknown) => void;

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
            let authCallback: (event: string, session: unknown) => void;

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

            // Start with a session
            mockSupabase.auth.getSession.mockResolvedValue({
                data: { session: mockSession },
                error: null,
            });

            const { result } = renderHook(() => useAuth(), { wrapper });

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
            let authCallback: (event: string, session: unknown) => void;

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
        it("restores existing session on mount", async () => {
            mockSupabase.auth.getSession.mockResolvedValue({
                data: { session: mockSession },
                error: null,
            });

            const { result } = renderHook(() => useAuth(), { wrapper });

            await waitFor(() => {
                expect(result.current.user).toEqual(mockUser);
                expect(result.current.session).toEqual(mockSession);
                expect(result.current.loading).toBe(false);
            });
        });

        it("sets authReady=true and loading=false after getSession resolves (success path)", async () => {
            // Regression test for Bug 5:
            // authReady and loading must be resolved via the finally block,
            // ensuring they are set even if only the success path runs.
            mockSupabase.auth.getSession.mockResolvedValue({
                data: { session: mockSession },
                error: null,
            });

            const { result } = renderHook(() => useAuth(), { wrapper });

            await waitFor(() => {
                expect(result.current.authReady).toBe(true);
                expect(result.current.loading).toBe(false);
                expect(result.current.user).toEqual(mockUser);
            });
        });

        it("sets authReady=true and loading=false even when getSession rejects (no permanent spinner)", async () => {
            // Regression test for Bug 5 (P1): without .catch().finally(), a
            // getSession() rejection (storage corruption, IndexedDB lock,
            // network timeout) left loading=true and authReady=false forever.
            // The app showed a permanent spinner with no recovery path.
            const storageError = new Error("QuotaExceededError: localStorage is full");
            mockSupabase.auth.getSession.mockRejectedValue(storageError);

            const consoleError = vi.spyOn(console, "error").mockImplementation(() => { });

            const { result } = renderHook(() => useAuth(), { wrapper });

            await waitFor(() => {
                // Auth state must resolve — no permanent spinner
                expect(result.current.authReady).toBe(true);
                expect(result.current.loading).toBe(false);
            });

            // Rejection treated as unauthenticated — user must sign in again
            expect(result.current.user).toBeNull();
            expect(result.current.session).toBeNull();

            // Error must be logged (not silently swallowed)
            expect(consoleError).toHaveBeenCalledWith(
                expect.stringContaining("[AuthContext] getSession() failed"),
                storageError,
            );

            consoleError.mockRestore();
        });

        it("preserves valid session when getSession resolves with soft-error", async () => {
            let authCallback: (event: string, session: unknown) => void = () => { };
            mockSupabase.auth.onAuthStateChange.mockImplementation((callback) => {
                authCallback = callback;
                return {
                    data: { subscription: { unsubscribe: vi.fn() } },
                };
            });

            const softError = new Error("Auth session missing");
            mockSupabase.auth.getSession.mockResolvedValue({
                data: { session: null },
                error: softError,
            });

            const consoleWarn = vi.spyOn(console, "warn").mockImplementation(() => { });

            const { result } = renderHook(() => useAuth(), { wrapper });

            act(() => {
                authCallback("INITIAL_SESSION", mockSession);
            });

            await waitFor(() => {
                expect(result.current.authReady).toBe(true);
                expect(result.current.loading).toBe(false);
            });

            expect(result.current.user).toEqual(mockUser);
            expect(result.current.session).toEqual(mockSession);

            expect(consoleWarn).toHaveBeenCalledWith(
                expect.stringContaining("[AuthContext] getSession() resolved with error"),
                softError,
            );

            consoleWarn.mockRestore();
        });

        it("preserves valid session when getSession rejects after INITIAL_SESSION (no false-positive logout)", async () => {
            // Regression test for Bug 6 (P1): the catch block from Bug 5 fix
            // unconditionally called setUser(null)/setSession(null), logging out
            // an already-authenticated user when getSession() had a transient
            // rejection AFTER onAuthStateChange had already delivered INITIAL_SESSION.

            // Step 1: Set up onAuthStateChange to fire INITIAL_SESSION with a valid session.
            let authCallback: (event: string, session: unknown) => void = () => { };
            mockSupabase.auth.onAuthStateChange.mockImplementation((callback) => {
                authCallback = callback;
                return {
                    data: { subscription: { unsubscribe: vi.fn() } },
                };
            });

            // Step 2: getSession() will reject (transient storage error).
            const transientError = new Error("IndexedDB: lock timeout");
            mockSupabase.auth.getSession.mockRejectedValue(transientError);

            const consoleError = vi.spyOn(console, "error").mockImplementation(() => { });

            const { result } = renderHook(() => useAuth(), { wrapper });

            // Step 3: Simulate INITIAL_SESSION firing BEFORE getSession() settles.
            // In the real browser, this happens synchronously during the listener
            // setup — here we fire it immediately after mount.
            act(() => {
                authCallback("INITIAL_SESSION", mockSession);
            });

            // Step 4: Wait for finally to flip authReady + loading.
            await waitFor(() => {
                expect(result.current.authReady).toBe(true);
                expect(result.current.loading).toBe(false);
            });

            // CRITICAL: user must NOT be null — catch must not have overwritten
            // the valid session that INITIAL_SESSION delivered.
            expect(result.current.user).toEqual(mockUser);
            expect(result.current.session).toEqual(mockSession);

            // Error must still be logged (catch still runs, just no state change)
            expect(consoleError).toHaveBeenCalledWith(
                expect.stringContaining("[AuthContext] getSession() failed"),
                transientError,
            );

            consoleError.mockRestore();
        });
    });
});
