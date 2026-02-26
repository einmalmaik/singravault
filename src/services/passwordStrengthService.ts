// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 — see LICENSE
/**
 * @fileoverview Zentrale Passwort-Prüfung (zxcvbn-ts + HIBP k-Anonymity)
 *
 * PFLICHT: Alle @zxcvbn-ts/* Imports sind dynamisch (lazy loaded).
 * Kein statischer Import von @zxcvbn-ts/* irgendwo in der Codebase.
 * Die ~400KB werden erst geladen, wenn der Nutzer ein Passwort-Feld fokussiert.
 */

// ============ Type Definitions ============

export interface PasswordCheckResult {
    score: 0 | 1 | 2 | 3 | 4;
    isStrong: boolean;
    isPwned: boolean;
    pwnedCount: number;
    feedback: string[];
    crackTimeDisplay: string;
    isAcceptable: boolean;
}

export interface StrengthResult {
    score: 0 | 1 | 2 | 3 | 4;
    isStrong: boolean;
    feedback: string[];
    crackTimeDisplay: string;
}

export interface PwnedResult {
    isPwned: boolean;
    pwnedCount: number;
}

// ============ Lazy-Loaded zxcvbn Module ============

let zxcvbnModule: { zxcvbn: (password: string) => ZxcvbnResult } | null = null;
let loadPromise: Promise<typeof zxcvbnModule> | null = null;

/**
 * Internal zxcvbn result shape (subset we use).
 */
interface ZxcvbnResult {
    score: 0 | 1 | 2 | 3 | 4;
    feedback: {
        warning: string;
        suggestions: string[];
    };
    crackTimesDisplay: {
        offlineSlowHashing1e4PerSecond: string;
    };
}

/**
 * Dynamically loads zxcvbn-ts core + dictionaries.
 * Cached after first load — subsequent calls return immediately.
 */
async function loadZxcvbn(): Promise<typeof zxcvbnModule> {
    if (zxcvbnModule) return zxcvbnModule;
    if (loadPromise) return loadPromise;

    loadPromise = (async () => {
        const [core, common, de] = await Promise.all([
            import('@zxcvbn-ts/core'),
            import('@zxcvbn-ts/language-common'),
            import('@zxcvbn-ts/language-de'),
        ]);

        core.zxcvbnOptions.setOptions({
            translations: de.translations,
            graphs: common.adjacencyGraphs,
            dictionary: { ...common.dictionary, ...de.dictionary },
        });

        zxcvbnModule = { zxcvbn: core.zxcvbn };
        return zxcvbnModule;
    })();

    return loadPromise;
}

// ============ Public API ============

/**
 * Pre-loads zxcvbn in the background. Call on field focus.
 * Non-blocking — resolves when module is ready.
 */
export async function preloadZxcvbn(): Promise<void> {
    await loadZxcvbn();
}

/**
 * Checks password strength locally using zxcvbn-ts.
 * ASYNC because the first call triggers lazy loading.
 *
 * @param password - The password to check
 * @returns Strength result with score, feedback, and crack time
 */
export async function checkPasswordStrength(password: string): Promise<StrengthResult> {
    if (!password) {
        return { score: 0, isStrong: false, feedback: [], crackTimeDisplay: '' };
    }

    const mod = await loadZxcvbn();
    if (!mod) {
        return { score: 0, isStrong: false, feedback: [], crackTimeDisplay: '' };
    }

    const result = mod.zxcvbn(password);

    const feedback: string[] = [];
    if (result.feedback.warning) {
        feedback.push(result.feedback.warning);
    }
    feedback.push(...result.feedback.suggestions);

    return {
        score: result.score,
        isStrong: result.score >= 3,
        feedback,
        crackTimeDisplay: result.crackTimesDisplay.offlineSlowHashing1e4PerSecond,
    };
}

/**
 * Checks if a password has been found in data breaches via HIBP k-Anonymity API.
 * Only sends the first 5 characters of the SHA-1 hash — the full password never leaves the client.
 *
 * @param password - The password to check
 * @returns Whether the password is pwned and how often
 */
export async function checkPasswordPwned(password: string): Promise<PwnedResult> {
    if (!password) {
        return { isPwned: false, pwnedCount: 0 };
    }

    try {
        // SHA-1 hash
        const encoder = new TextEncoder();
        const data = encoder.encode(password);
        const hashBuffer = await crypto.subtle.digest('SHA-1', data);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        const hashHex = hashArray.map((b) => b.toString(16).padStart(2, '0')).join('').toUpperCase();

        const prefix = hashHex.slice(0, 5);
        const suffix = hashHex.slice(5);

        // k-Anonymity: only send 5-char prefix
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 5000);

        const response = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`, {
            signal: controller.signal,
            headers: {
                'User-Agent': 'Singra-Vault/1.0 Password-Safety-Check',
            },
        });

        clearTimeout(timeoutId);

        if (!response.ok) {
            return { isPwned: false, pwnedCount: 0 };
        }

        const text = await response.text();
        const lines = text.split('\n');

        for (const line of lines) {
            const [hashSuffix, count] = line.trim().split(':');
            if (hashSuffix === suffix) {
                return { isPwned: true, pwnedCount: parseInt(count, 10) || 1 };
            }
        }

        return { isPwned: false, pwnedCount: 0 };
    } catch {
        // Silent fail on network error — don't block the user
        return { isPwned: false, pwnedCount: 0 };
    }
}

/**
 * Combined password check: strength (zxcvbn) + breach (HIBP) in parallel.
 *
 * @param password - The password to check
 * @returns Full check result including acceptability
 */
export async function checkPassword(password: string): Promise<PasswordCheckResult> {
    const [strengthResult, pwnedResult] = await Promise.all([
        checkPasswordStrength(password),
        checkPasswordPwned(password),
    ]);

    return {
        ...strengthResult,
        ...pwnedResult,
        isAcceptable: strengthResult.score >= 3 && pwnedResult.pwnedCount === 0,
    };
}
