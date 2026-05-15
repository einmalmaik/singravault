// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE
/**
 * @fileoverview Vault Item Model
 *
 * Local domain shape of a decrypted vault list entry plus accessors and
 * formatters used by the list, dashboard sections and preview panel.
 *
 * Keeping this file UI-free lets the list component, hooks and tests share
 * one canonical "what is a vault item row?" definition without pulling in
 * React.
 */

import type { VaultItemData } from '@/services/cryptoService';
import type { QuarantinedVaultItem } from '@/services/vaultIntegrityService';
import { assertItemDecryptable } from '@/services/vaultQuarantineOrchestrator';

export interface VaultItem {
  id: string;
  vault_id: string;
  title: string;
  website_url: string | null;
  icon_url: string | null;
  item_type: 'password' | 'note' | 'totp' | 'card';
  is_favorite: boolean | null;
  category_id: string | null;
  created_at: string;
  updated_at: string;
  decryptedData?: VaultItemData;
}

export type RenderableVaultListEntry =
  | { kind: 'item'; item: VaultItem }
  | { kind: 'quarantined'; item: VaultItem; quarantine: QuarantinedVaultItem };

export type RenderableVaultItemEntry = Extract<RenderableVaultListEntry, { kind: 'item' }>;

export interface VaultItemListIntegrityGate {
  readonly mode?: string;
  readonly quarantinedItems: QuarantinedVaultItem[];
  readonly isFirstCheck?: boolean;
}

/**
 * Drops items that the current integrity result keeps out of the decrypt path.
 *
 * Used both by the data hook (before calling `decryptItem`) and the visible
 * entries hook (when grouping inline quarantine cards). The function defers to
 * `assertItemDecryptable` so list rendering never disagrees with the central
 * vault quarantine orchestrator policy.
 */
export function canDecryptFromIntegrityResult(
  result: VaultItemListIntegrityGate | null | undefined,
  itemId: string,
): boolean {
  if (!result?.mode) {
    return false;
  }

  if (
    result.mode === 'quarantine'
    && result.quarantinedItems.some((item) => item.id === itemId)
  ) {
    return false;
  }

  try {
    assertItemDecryptable({
      mode: result.mode,
      quarantinedItems: result.quarantinedItems,
      itemId,
    });
    return true;
  } catch {
    return false;
  }
}

export function getItemTitle(item: VaultItem): string {
  return item.decryptedData?.title || item.title || 'Ohne Titel';
}

export function getItemWebsiteUrl(item: VaultItem): string | null {
  return item.decryptedData?.websiteUrl || item.website_url || null;
}

export function getItemUsername(item: VaultItem): string | null {
  return item.decryptedData?.username || null;
}

export function getItemCategoryId(item: VaultItem): string | null {
  return item.decryptedData?.categoryId ?? item.category_id ?? null;
}

export function isItemFavorite(item: VaultItem): boolean {
  return typeof item.decryptedData?.isFavorite === 'boolean'
    ? item.decryptedData.isFavorite
    : !!item.is_favorite;
}

/**
 * Human-friendly relative time for the table "letzte Verwendung" column.
 * Falls back to "kürzlich" if the input timestamp is unusable so the UI never
 * leaks NaN/Invalid Date into the dashboard.
 */
export function formatRelativeUpdatedAt(value: string): string {
  const timestamp = new Date(value).getTime();
  if (!Number.isFinite(timestamp)) {
    return 'kürzlich';
  }

  const diffMs = Date.now() - timestamp;
  const minuteMs = 60_000;
  const hourMs = 60 * minuteMs;
  const dayMs = 24 * hourMs;

  if (diffMs < minuteMs) return 'gerade eben';
  if (diffMs < hourMs) {
    const minutes = Math.max(1, Math.round(diffMs / minuteMs));
    return `vor ${minutes} Min`;
  }
  if (diffMs < dayMs) {
    const hours = Math.max(1, Math.round(diffMs / hourMs));
    return `vor ${hours} Std`;
  }

  const days = Math.max(1, Math.round(diffMs / dayMs));
  return `vor ${days} Tag${days === 1 ? '' : 'en'}`;
}

export function formatVaultItemMetaDate(value: string | null | undefined): string {
  if (!value) {
    return '—';
  }

  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return '—';
  }

  return new Intl.DateTimeFormat('de-DE', {
    day: '2-digit',
    month: '2-digit',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  }).format(date);
}

export function isVaultItemType(value: unknown): value is VaultItem['item_type'] {
  return value === 'password' || value === 'note' || value === 'totp' || value === 'card';
}

export function isTotpAlgorithm(value: unknown): value is NonNullable<VaultItemData['totpAlgorithm']> {
  return value === 'SHA1' || value === 'SHA256' || value === 'SHA512';
}

export function isStringRecord(value: unknown): value is Record<string, string> {
  return !!value
    && typeof value === 'object'
    && !Array.isArray(value)
    && Object.values(value).every((entry) => typeof entry === 'string');
}

/**
 * Token used to remember which quarantine state the user already dismissed.
 *
 * Tying the token to `reason` + `updatedAt` guarantees that a fresh quarantine
 * event (different reason or new timestamp) is not silently ignored just
 * because an older incident for the same id was acknowledged before.
 */
export function getQuarantineIgnoreToken(item: QuarantinedVaultItem): string {
  return `${item.reason}:${item.updatedAt ?? ''}`;
}

/**
 * Sequential batched mapper that yields the event loop between batches.
 *
 * The vault list decrypts many items eagerly on open. Batching keeps the main
 * thread responsive on large vaults and the inter-batch `setTimeout(0)` lets
 * paint frames run between expensive crypto chunks.
 */
export async function mapInBatches<TInput, TOutput>(
  items: TInput[],
  batchSize: number,
  mapper: (item: TInput) => Promise<TOutput>,
): Promise<TOutput[]> {
  const results: TOutput[] = [];

  for (let start = 0; start < items.length; start += batchSize) {
    const batch = items.slice(start, start + batchSize);
    results.push(...await Promise.all(batch.map(mapper)));

    if (start + batchSize < items.length) {
      await new Promise<void>((resolve) => {
        globalThis.setTimeout(resolve, 0);
      });
    }
  }

  return results;
}
