// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 — see LICENSE
/**
 * @fileoverview Tests for `mapRpIdToFriendlyLabel`.
 *
 * The label helper is purely cosmetic, but it is the only piece of core
 * code that maps stored RP-IDs to user-facing strings, so a regression
 * here would mislead users about which device a passkey is registered
 * on. The whitelist must stay aligned with the WebAuthn edge function's
 * `isCredentialAvailableForRp` logic and `_shared/desktopOrigins.ts`.
 */

import { describe, expect, it } from 'vitest';

import { mapRpIdToFriendlyLabel } from '@/services/passkeyService';

describe('mapRpIdToFriendlyLabel', () => {
    it('treats null/undefined RP-IDs as the production web surface', () => {
        // Legacy rows registered before RP scoping was introduced are
        // attributed to the hosted web surface server-side.
        expect(mapRpIdToFriendlyLabel(null)).toBe('Web (Produktion)');
        expect(mapRpIdToFriendlyLabel(undefined)).toBe('Web (Produktion)');
    });

    it('labels the production web RP-ID as "Web (Produktion)"', () => {
        expect(mapRpIdToFriendlyLabel('singravault.mauntingstudios.de')).toBe('Web (Produktion)');
    });

    it('labels every Tauri RP-ID variant as "Desktop (Tauri)"', () => {
        expect(mapRpIdToFriendlyLabel('tauri.localhost')).toBe('Desktop (Tauri)');
        expect(mapRpIdToFriendlyLabel('asset.localhost')).toBe('Desktop (Tauri)');
        expect(mapRpIdToFriendlyLabel('ipc.localhost')).toBe('Desktop (Tauri)');
    });

    it('labels local dev RP-IDs explicitly so they cannot be confused with Tauri', () => {
        expect(mapRpIdToFriendlyLabel('localhost')).toBe('Lokale Entwicklung');
        expect(mapRpIdToFriendlyLabel('127.0.0.1')).toBe('Lokale Entwicklung');
    });

    it('falls back to the raw RP-ID for unknown values so users still recognise them', () => {
        expect(mapRpIdToFriendlyLabel('staging.singravault.example')).toBe('staging.singravault.example');
    });
});
