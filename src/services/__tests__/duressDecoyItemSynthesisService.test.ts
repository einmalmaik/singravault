// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 — see LICENSE
/**
 * @fileoverview Tests for the duress decoy item synthesis service.
 *
 * The synthesis service is the only piece of core code that turns the
 * premium `getDuressDecoyItems` hook into renderable `VaultItem`s. These
 * tests pin down the security-relevant invariants the rest of the duress
 * vault depends on:
 *
 *  - Output items always carry the `_duress: true` marker (otherwise the
 *    visibility filter in `useVisibleVaultEntries` would happily render
 *    them in the real vault).
 *  - Output items use the sentinel `vault_id` so any accidental persistence
 *    attempt would fail the FK constraint instead of silently writing.
 *  - A missing or throwing premium hook degrades gracefully to an empty
 *    duress vault — never to a stale fallback or a thrown exception that
 *    would break unlock.
 */

import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest';

import {
    DURESS_DECOY_VAULT_ID,
    synthesizeDuressVaultItems,
} from '@/services/duressDecoyItemSynthesisService';

const mockGetServiceHooks = vi.fn();

vi.mock('@/extensions/registry', () => ({
    getServiceHooks: () => mockGetServiceHooks(),
}));

beforeEach(() => {
    mockGetServiceHooks.mockReset();
});

afterEach(() => {
    vi.restoreAllMocks();
});

describe('synthesizeDuressVaultItems', () => {
    it('returns an empty array when the premium hook is not registered', () => {
        mockGetServiceHooks.mockReturnValue({});

        expect(synthesizeDuressVaultItems()).toEqual([]);
    });

    it('returns an empty array when the premium hook throws', () => {
        const consoleSpy = vi.spyOn(console, 'warn').mockImplementation(() => undefined);
        mockGetServiceHooks.mockReturnValue({
            getDuressDecoyItems: () => {
                throw new Error('boom');
            },
        });

        expect(synthesizeDuressVaultItems()).toEqual([]);
        expect(consoleSpy).toHaveBeenCalledTimes(1);
    });

    it('marks every synthesised item with _duress: true', () => {
        mockGetServiceHooks.mockReturnValue({
            getDuressDecoyItems: () => [
                { title: 'Gmail', username: 'foo@example.com', password: 'p1', websiteUrl: 'https://mail.google.com' },
                { title: 'Spotify', username: 'foo@example.com', password: 'p2' },
            ],
        });

        const items = synthesizeDuressVaultItems();

        expect(items).toHaveLength(2);
        for (const item of items) {
            expect(item.decryptedData?._duress).toBe(true);
        }
    });

    it('uses the synthetic vault_id sentinel so accidental persistence would fail FK', () => {
        mockGetServiceHooks.mockReturnValue({
            getDuressDecoyItems: () => [{ title: 'Decoy' }],
        });

        const [item] = synthesizeDuressVaultItems();

        expect(item.vault_id).toBe(DURESS_DECOY_VAULT_ID);
        // Sanity check: the sentinel is intentionally a non-UUID string so
        // the database FK on `vault_items.vault_id` would reject it.
        expect(item.vault_id).not.toMatch(/^[0-9a-f-]{36}$/i);
    });

    it('emits unique ids for every synthesised item to avoid React key collisions', () => {
        mockGetServiceHooks.mockReturnValue({
            getDuressDecoyItems: () => Array.from({ length: 5 }, (_, index) => ({
                title: `Decoy ${index}`,
            })),
        });

        const items = synthesizeDuressVaultItems();
        const idSet = new Set(items.map((item) => item.id));

        expect(idSet.size).toBe(items.length);
    });

    it('falls back to a placeholder title when the hook returns empty titles', () => {
        mockGetServiceHooks.mockReturnValue({
            getDuressDecoyItems: () => [{ title: '   ' }, { title: '' }],
        });

        const items = synthesizeDuressVaultItems();

        expect(items.map((item) => item.title)).toEqual(['Eintrag', 'Eintrag']);
    });

    it('maps websiteUrl through to the VaultItem for display', () => {
        mockGetServiceHooks.mockReturnValue({
            getDuressDecoyItems: () => [{
                title: 'Netflix',
                websiteUrl: 'https://netflix.com',
            }],
        });

        const [item] = synthesizeDuressVaultItems();

        expect(item.website_url).toBe('https://netflix.com');
        expect(item.decryptedData?.websiteUrl).toBe('https://netflix.com');
    });
});
