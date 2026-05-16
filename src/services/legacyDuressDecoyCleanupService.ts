// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE
/**
 * Recovery service for the pre-OpLog Premium duress (panic password)
 * activation bug.
 *
 * Background:
 *   Older Premium builds of `setupDuressPassword` write the default decoy
 *   items directly into the `vault_items` legacy table, encrypted with the
 *   duress key (which is not the user's primary `vaultKey`). For modern
 *   USK-based vaults that path is wrong on three counts:
 *
 *   1. The legacy rows are never registered in the OpLog manifest, so the
 *      Phase-12 migration gate counts them as "legacy rows + OpLog head"
 *      and blocks unlock with `preflightFailed` ("Tresor-Migration
 *      erforderlich"), even though the real vault is healthy.
 *   2. `vaultIntegrityV2` flags them as `orphan_remote`, which the runtime
 *      bridge surfaces as `mode: 'integrity_unknown'` /
 *      `nonTamperReason: 'snapshot_source_not_authoritative'`.
 *   3. They are not encrypted with the user's vault key, so they cannot be
 *      verified or decrypted by the normal unlock path.
 *
 * Long-term fix: Premium must create decoy items via the signed OpLog path
 * (`attemptDuressUnlockOnly` + a dedicated decoy-item-creation flow), not
 * through direct `vault_items` inserts. This service is a one-shot recovery
 * tool for vaults that already have the broken legacy decoys.
 *
 * Safety properties of the cleanup:
 *   - Never touches a row whose ciphertext authenticates against the
 *     user's current `vaultKey`. Real items (legacy or migrated) stay.
 *   - Cross-checks against the OpLog manifest: items that ARE part of the
 *     authenticated manifest are never deleted, even if their ciphertext
 *     happens to fail decryption locally (e.g. transient corruption).
 *   - Returns a typed candidate list before deletion so the UI can show
 *     ids and timestamps and ask for explicit user confirmation.
 *   - Deletes only by primary key + user_id; RLS at the server still
 *     enforces ownership.
 */

import { supabase } from '@/integrations/supabase/client';
import { decryptProductVaultItem } from './vaultIntegrityV2/productItemEnvelope';
import {
    LegacyVaultRuntimeWriteBlockedError,
    blockLegacyVaultRuntimeWrite,
} from './vaultOpLog/vaultLegacyWriteBlocker';

export interface LegacyDuressDecoyCandidate {
    /** Primary key of the row in `vault_items`. */
    readonly id: string;
    /** ISO timestamp; useful so the UI can show recency to the user. */
    readonly updatedAt: string | null;
    /**
     * Why the row is a candidate. `decryption_failed` means the row's
     * ciphertext does not authenticate against the current vault key; this
     * is the strong signal that the row is encrypted with a different key
     * (e.g. the duress key) and is a stale Premium decoy artifact.
     */
    readonly reason: 'decryption_failed';
}

export interface FindLegacyDuressDecoyCandidatesInput {
    readonly userId: string;
    /** The currently unlocked, authenticated vault key (UserKey-bound). */
    readonly vaultKey: CryptoKey;
    /**
     * Optional set of record ids that are part of the verified OpLog
     * manifest. Rows whose id is in this set are never reported as
     * candidates, even on decryption failure, because they belong to the
     * authenticated working set.
     */
    readonly opLogVerifiedRecordIds?: ReadonlySet<string>;
}

export interface FindLegacyDuressDecoyCandidatesResult {
    readonly candidates: ReadonlyArray<LegacyDuressDecoyCandidate>;
    readonly inspectedRowCount: number;
    /**
     * Number of rows that authenticated against the current vault key. The
     * UI can use this to communicate that the cleanup will not touch
     * legitimate legacy items.
     */
    readonly authenticatedRowCount: number;
}

export interface PurgeLegacyDuressDecoyItemsInput {
    readonly userId: string;
    readonly itemIds: ReadonlyArray<string>;
}

export interface PurgeLegacyDuressDecoyItemsResult {
    readonly deletedCount: number;
}

/**
 * Scans `vault_items` for rows that almost certainly belong to a stale
 * Premium duress decoy population. Does NOT mutate anything; the caller
 * (Settings UI) is responsible for showing the candidates and asking for
 * confirmation before invoking `purgeLegacyDuressDecoyItems`.
 */
export async function findLegacyDuressDecoyCandidates(
    input: FindLegacyDuressDecoyCandidatesInput,
): Promise<FindLegacyDuressDecoyCandidatesResult> {
    const { data, error } = await supabase
        .from('vault_items')
        .select('id, encrypted_data, updated_at')
        .eq('user_id', input.userId);
    if (error) {
        throw new Error(`Failed to load legacy vault items: ${error.message}`);
    }

    const rows = (data ?? []) as ReadonlyArray<{
        id: string;
        encrypted_data: string;
        updated_at: string | null;
    }>;

    const verifiedIds = input.opLogVerifiedRecordIds ?? new Set<string>();
    const candidates: LegacyDuressDecoyCandidate[] = [];
    let authenticatedRowCount = 0;

    for (const row of rows) {
        if (verifiedIds.has(row.id)) {
            // Part of the authenticated OpLog working set — never a duress
            // decoy by definition. Leave it alone.
            authenticatedRowCount += 1;
            continue;
        }

        try {
            await decryptProductVaultItem({
                encryptedData: row.encrypted_data,
                vaultKey: input.vaultKey,
                entryId: row.id,
            });
            authenticatedRowCount += 1;
        } catch {
            candidates.push({
                id: row.id,
                updatedAt: row.updated_at,
                reason: 'decryption_failed',
            });
        }
    }

    return {
        candidates,
        inspectedRowCount: rows.length,
        authenticatedRowCount,
    };
}

/**
 * Deletes the supplied rows from `vault_items`. Caller must have already
 * obtained an explicit user confirmation. Returns the number of rows the
 * server reports as deleted.
 *
 * Throws `LegacyVaultRuntimeWriteBlockedError` if the caller did not
 * actually pass any ids — defensive guard so an empty list cannot wipe
 * the entire table by accident.
 */
export async function purgeLegacyDuressDecoyItems(
    input: PurgeLegacyDuressDecoyItemsInput,
): Promise<PurgeLegacyDuressDecoyItemsResult> {
    if (input.itemIds.length === 0) {
        // Hard guard: never call DELETE without an explicit id list.
        blockLegacyVaultRuntimeWrite('purgeLegacyDuressDecoyItems:empty-id-list');
    }

    if (!input.userId) {
        throw new LegacyVaultRuntimeWriteBlockedError('purgeLegacyDuressDecoyItems:missing-user-id');
    }

    const { error, count } = await supabase
        .from('vault_items')
        .delete({ count: 'exact' })
        .in('id', [...input.itemIds])
        .eq('user_id', input.userId);
    if (error) {
        throw new Error(`Failed to delete legacy duress decoy items: ${error.message}`);
    }

    return { deletedCount: count ?? 0 };
}
