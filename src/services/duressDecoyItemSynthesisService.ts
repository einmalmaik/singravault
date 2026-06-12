// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 — see LICENSE
/**
 * @fileoverview Duress decoy item synthesis (in-memory only)
 *
 * The duress (panic) vault no longer stores decoy items in the database.
 * Persisting decoys to `vault_items` was removed because it broke the
 * OpLog migration gate (every account that ever enabled duress mode ended
 * up with `hasLegacyRows > 0` and a `migration_required` lockout) and it
 * also leaked the existence of decoys to anyone reading the legacy table.
 *
 * Instead, the duress vault is rebuilt purely in memory on every unlock:
 *   1. The premium hook `getDuressDecoyItems` returns plaintext decoys.
 *   2. This service wraps each decoy in a synthetic `VaultItem`, marked
 *      with `_duress: true` so the existing visibility filter in
 *      `useVisibleVaultEntries` keeps them on screen in duress mode and
 *      hides them in the real vault — same contract as before, just
 *      sourced from RAM instead of the database.
 *   3. Synthetic items use `randomUuid()` for `id` and a fixed
 *      synthetic `vault_id` so they never collide with real vault rows.
 *      They are never written back, so no migration / sync code path
 *      can accidentally promote them to persisted state.
 *
 * Security invariants preserved here:
 *   - The synthesised items never touch Supabase, the snapshot cache or
 *     the OpLog runtime. The function is pure: input → array.
 *   - The synthetic `vault_id` is a stable sentinel string (`duress-decoy`)
 *     so any code path that accidentally tries to persist these items
 *     would fail loudly against the real `vaults.id` foreign key.
 *   - `_duress: true` is set on every entry. Callers MUST NOT strip it,
 *     otherwise the visibility filter would show decoys in the real vault
 *     and hide real items in the duress vault.
 */

import { randomUuid } from '@dis/shield/random';
import type { VaultItem } from '@/components/vault/vaultItemList/vaultItemModel';
import type { DuressDecoyItemPlaintext } from '@/extensions/types';
import { getServiceHooks } from '@/extensions/registry';

/**
 * Sentinel `vault_id` for synthesised decoy rows. Using a fixed non-UUID
 * value ensures that any unexpected persistence attempt fails the FK
 * constraint on `vault_items.vault_id` instead of silently succeeding.
 */
export const DURESS_DECOY_VAULT_ID = 'duress-decoy';

/**
 * Synthesises an in-memory `VaultItem[]` for the duress vault by calling
 * the premium `getDuressDecoyItems` hook. Returns an empty array if the
 * premium package is not installed or the hook returns no entries.
 *
 * Pure with respect to global state: only depends on the value returned
 * by the premium hook at call time. Safe to call on every duress unlock.
 */
export function synthesizeDuressVaultItems(): VaultItem[] {
    const hooks = getServiceHooks();
    const provider = hooks.getDuressDecoyItems;
    if (!provider) {
        // Premium not loaded → empty duress vault. This is the safe
        // default: better an empty vault than fake/static decoys baked
        // into the open-source core.
        return [];
    }

    let plaintextEntries: DuressDecoyItemPlaintext[];
    try {
        plaintextEntries = provider();
    } catch (error) {
        // A broken premium hook must not break vault unlock. Logging here
        // is intentional — duress unlocks are rare and we want to know
        // when decoy synthesis fails so the user does not silently end up
        // with an empty panic vault on every unlock.
        console.warn('[duress] getDuressDecoyItems hook threw; rendering empty decoy vault.', error);
        return [];
    }

    if (!Array.isArray(plaintextEntries) || plaintextEntries.length === 0) {
        return [];
    }

    const nowIso = new Date().toISOString();
    return plaintextEntries.map((entry) => wrapDecoyEntryAsVaultItem(entry, nowIso));
}

function wrapDecoyEntryAsVaultItem(
    entry: DuressDecoyItemPlaintext,
    nowIso: string,
): VaultItem {
    const id = randomUuid();
    const title = entry.title?.trim() || 'Eintrag';

    return {
        id,
        vault_id: DURESS_DECOY_VAULT_ID,
        title,
        website_url: entry.websiteUrl ?? null,
        icon_url: null,
        item_type: 'password',
        is_favorite: false,
        category_id: null,
        created_at: nowIso,
        updated_at: nowIso,
        decryptedData: {
            title,
            websiteUrl: entry.websiteUrl,
            itemType: 'password',
            isFavorite: false,
            categoryId: null,
            username: entry.username,
            password: entry.password,
            notes: entry.notes,
            // The visibility filter in `useVisibleVaultEntries` relies on
            // this marker to keep decoys segregated from real items. The
            // marker is intentionally set on the decrypted-data object
            // because that is what `isDecoyItem` inspects.
            _duress: true,
        },
    };
}
