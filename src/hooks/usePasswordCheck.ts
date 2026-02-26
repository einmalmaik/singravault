// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 — see LICENSE
/**
 * @fileoverview React Hook für zentrale Passwort-Prüfung
 *
 * Kapselt zxcvbn Lazy-Loading, debounced lokale Prüfung und HIBP-Check.
 * Keine statischen @zxcvbn-ts Imports — alles über passwordStrengthService.
 */

import { useState, useRef, useCallback } from 'react';

import {
    preloadZxcvbn,
    checkPasswordStrength,
    checkPasswordPwned,
    checkPassword,
    type StrengthResult,
    type PwnedResult,
    type PasswordCheckResult,
} from '@/services/passwordStrengthService';

// ============ Type Definitions ============

interface UsePasswordCheckOptions {
    /** If true, isAcceptable must be true for submission (Master-Passwort, Signup). */
    enforceStrong?: boolean;
}

interface UsePasswordCheckReturn {
    strengthResult: StrengthResult | null;
    pwnedResult: PwnedResult | null;
    isChecking: boolean;
    isZxcvbnReady: boolean;
    onFieldFocus: () => void;
    onPasswordChange: (password: string) => void;
    onPasswordBlur: (password: string) => void;
    onPasswordSubmit: (password: string) => Promise<PasswordCheckResult>;
}

// ============ Hook ============

/**
 * Hook for centralized password checking with lazy-loaded zxcvbn + HIBP.
 *
 * @param options - Configuration options
 * @returns State and handlers for password strength checking
 */
export function usePasswordCheck(options?: UsePasswordCheckOptions): UsePasswordCheckReturn {
    const [strengthResult, setStrengthResult] = useState<StrengthResult | null>(null);
    const [pwnedResult, setPwnedResult] = useState<PwnedResult | null>(null);
    const [isChecking, setIsChecking] = useState(false);
    const [isZxcvbnReady, setIsZxcvbnReady] = useState(false);

    const debounceTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
    const lastCheckedPasswordRef = useRef<string>('');

    /**
     * Call on password field focus to preload zxcvbn (~400KB) in the background.
     */
    const onFieldFocus = useCallback(() => {
        if (!isZxcvbnReady) {
            preloadZxcvbn().then(() => setIsZxcvbnReady(true)).catch(() => {});
        }
    }, [isZxcvbnReady]);

    /**
     * Call on password change — debounced 300ms local strength check.
     */
    const onPasswordChange = useCallback((password: string) => {
        if (debounceTimerRef.current) {
            clearTimeout(debounceTimerRef.current);
        }

        if (!password) {
            setStrengthResult(null);
            setPwnedResult(null);
            return;
        }

        debounceTimerRef.current = setTimeout(async () => {
            const result = await checkPasswordStrength(password);
            setStrengthResult(result);
            if (!isZxcvbnReady) setIsZxcvbnReady(true);
        }, 300);
    }, [isZxcvbnReady]);

    /**
     * Call on password field blur — triggers one-time HIBP check.
     */
    const onPasswordBlur = useCallback((password: string) => {
        if (!password || password === lastCheckedPasswordRef.current) return;

        lastCheckedPasswordRef.current = password;
        setIsChecking(true);

        checkPasswordPwned(password)
            .then((result) => setPwnedResult(result))
            .catch(() => setPwnedResult({ isPwned: false, pwnedCount: 0 }))
            .finally(() => setIsChecking(false));
    }, []);

    /**
     * Call on form submit — runs full check (strength + HIBP) and returns result.
     */
    const onPasswordSubmit = useCallback(async (password: string): Promise<PasswordCheckResult> => {
        setIsChecking(true);
        try {
            const result = await checkPassword(password);
            setStrengthResult({
                score: result.score,
                isStrong: result.isStrong,
                feedback: result.feedback,
                crackTimeDisplay: result.crackTimeDisplay,
            });
            setPwnedResult({
                isPwned: result.isPwned,
                pwnedCount: result.pwnedCount,
            });
            return result;
        } finally {
            setIsChecking(false);
        }
    }, []);

    return {
        strengthResult,
        pwnedResult,
        isChecking,
        isZxcvbnReady,
        onFieldFocus,
        onPasswordChange,
        onPasswordBlur,
        onPasswordSubmit,
    };
}
