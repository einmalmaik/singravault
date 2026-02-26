// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 — see LICENSE
/**
 * @fileoverview Tests for Duress (Panic) Password Service
 *
 * Tests the cryptographic operations and helper functions for the
 * duress password feature. Database operations are mocked.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import {
    isDecoyItem,
    markAsDecoyItem,
    stripDecoyMarker,
    getDefaultDecoyItems,
    DURESS_MARKER_FIELD,
} from '../duressService';

describe('duressService', () => {
    describe('isDecoyItem', () => {
        it('should return true for items with duress marker', () => {
            const item = { title: 'Test', password: 'secret', _duress: true };
            expect(isDecoyItem(item)).toBe(true);
        });

        it('should return false for items without duress marker', () => {
            const item = { title: 'Test', password: 'secret' };
            expect(isDecoyItem(item)).toBe(false);
        });

        it('should return false for items with _duress set to false', () => {
            const item = { title: 'Test', password: 'secret', _duress: false };
            expect(isDecoyItem(item as unknown as ReturnType<typeof markAsDecoyItem>)).toBe(false);
        });

        it('should return false for items with _duress set to non-boolean', () => {
            const item = { title: 'Test', password: 'secret', _duress: 'yes' };
            expect(isDecoyItem(item as unknown as ReturnType<typeof markAsDecoyItem>)).toBe(false);
        });
    });

    describe('markAsDecoyItem', () => {
        it('should add duress marker to item', () => {
            const item = { title: 'Test', password: 'secret' };
            const marked = markAsDecoyItem(item);

            expect(marked._duress).toBe(true);
            expect(marked.title).toBe('Test');
            expect(marked.password).toBe('secret');
        });

        it('should not mutate original item', () => {
            const item = { title: 'Test', password: 'secret' };
            const marked = markAsDecoyItem(item);

            expect(item).not.toHaveProperty('_duress');
            expect(marked).not.toBe(item);
        });

        it('should preserve all existing fields', () => {
            const item = {
                title: 'Test',
                username: 'user@example.com',
                password: 'secret',
                website: 'https://example.com',
                notes: 'Some notes',
                customField: 'custom value',
            };
            const marked = markAsDecoyItem(item);

            expect(marked.title).toBe(item.title);
            expect(marked.username).toBe(item.username);
            expect(marked.password).toBe(item.password);
            expect(marked.website).toBe(item.website);
            expect(marked.notes).toBe(item.notes);
            expect(marked.customField).toBe(item.customField);
        });
    });

    describe('stripDecoyMarker', () => {
        it('should remove duress marker from item', () => {
            const item = { title: 'Test', password: 'secret', _duress: true };
            const stripped = stripDecoyMarker(item);

            expect(stripped).not.toHaveProperty('_duress');
            expect(stripped.title).toBe('Test');
            expect(stripped.password).toBe('secret');
        });

        it('should handle items without duress marker', () => {
            const item = { title: 'Test', password: 'secret' };
            const stripped = stripDecoyMarker(item);

            expect(stripped.title).toBe('Test');
            expect(stripped.password).toBe('secret');
        });

        it('should not mutate original item', () => {
            const item = { title: 'Test', password: 'secret', _duress: true };
            const stripped = stripDecoyMarker(item);

            expect(item._duress).toBe(true);
            expect(stripped).not.toBe(item);
        });
    });

    describe('getDefaultDecoyItems', () => {
        it('should return an array of default items', () => {
            const items = getDefaultDecoyItems();

            expect(Array.isArray(items)).toBe(true);
            expect(items.length).toBeGreaterThan(0);
        });

        it('should return items with required fields', () => {
            const items = getDefaultDecoyItems();

            for (const item of items) {
                expect(item).toHaveProperty('title');
                expect(typeof item.title).toBe('string');
            }
        });

        it('should return items with plausible content', () => {
            const items = getDefaultDecoyItems();

            // Should have valid titles
            const titles = items.map(i => i.title);
            expect(titles.every(t => typeof t === 'string' && t.length > 0)).toBe(true);
        });

        it('should return a copy, not a reference', () => {
            const items1 = getDefaultDecoyItems();
            const items2 = getDefaultDecoyItems();

            expect(items1).not.toBe(items2);

            // Modifying one should not affect the other
            items1[0].title = 'Modified';
            expect(items2[0].title).not.toBe('Modified');
        });
    });

    describe('DURESS_MARKER_FIELD', () => {
        it('should be defined as _duress', () => {
            expect(DURESS_MARKER_FIELD).toBe('_duress');
        });
    });

    describe('round-trip: mark and strip', () => {
        it('should preserve data through mark and strip cycle', () => {
            const original = {
                title: 'My Bank',
                username: 'john.doe@bank.com',
                password: 'sup3rS3cur3!',
                website: 'https://bank.example.com',
                notes: 'Important banking credentials',
            };

            const marked = markAsDecoyItem(original);
            expect(isDecoyItem(marked)).toBe(true);

            const stripped = stripDecoyMarker(marked);
            expect(isDecoyItem(stripped as unknown as ReturnType<typeof markAsDecoyItem>)).toBe(false);

            // All original fields should be preserved
            expect(stripped.title).toBe(original.title);
            expect(stripped.username).toBe(original.username);
            expect(stripped.password).toBe(original.password);
            expect(stripped.website).toBe(original.website);
            expect(stripped.notes).toBe(original.notes);
        });
    });
});
