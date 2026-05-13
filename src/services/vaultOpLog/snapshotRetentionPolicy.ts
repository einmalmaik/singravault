// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE
/**
 * Deterministic snapshot retention policy.
 *
 * Rules (in order of protection):
 * 1. Keep the latest snapshot.
 * 2. Keep the last snapshot before any migration.
 * 3. Keep the last snapshot before any rekey.
 * 4. Keep daily snapshots for 7 days.
 * 5. Keep weekly snapshots for 4 weeks.
 *
 * Retention never deletes *all* snapshots.  If a rule would remove
 * every envelope, the oldest envelope is protected as a fallback.
 */

import type { TrustedSnapshotEnvelopeV1 } from './trustedSnapshotTypes';

export interface RetentionDiagnosis {
  readonly kept: readonly string[];
  readonly removed: readonly string[];
}

/**
 * Apply retention rules to a list of envelopes for a single vault.
 *
 * @param envelopes — all envelopes for the vault; must share the same vaultId.
 * @param now — deterministic clock input (ISO-8601 UTC instant).
 * @returns diagnosis of which snapshotIds are kept / removed.
 */
export function applySnapshotRetentionPolicy(
  envelopes: readonly TrustedSnapshotEnvelopeV1[],
  now: string,
): RetentionDiagnosis {
  if (envelopes.length === 0) {
    return { kept: [], removed: [] };
  }

  // Sort by creation time descending (newest first).
  const sorted = [...envelopes].sort((a, b) => {
    const ta = Date.parse(a.createdAt);
    const tb = Date.parse(b.createdAt);
    if (Number.isNaN(ta) || Number.isNaN(tb)) {
      // Fallback to string compare if dates are malformed (should not happen).
      return b.createdAt.localeCompare(a.createdAt);
    }
    return tb - ta;
  });

  const keepSet = new Set<string>();

  // Rule 1: always keep the latest snapshot.
  keepSet.add(sorted[0].snapshotId);

  // Rule 4: keep daily snapshots for 7 days.
  const dailyCutoff = subtractDays(now, 7);
  const dailyBuckets = bucketByDay(sorted.filter((e) => e.createdAt >= dailyCutoff));
  for (const day of dailyBuckets.values()) {
    if (day.length > 0) {
      // Keep the newest of that day.
      keepSet.add(day[0].snapshotId);
    }
  }

  // Rule 5: keep weekly snapshots for 4 weeks (excluding daily window).
  const weeklyCutoff = subtractDays(now, 28);
  const weeklyEligible = sorted.filter((e) => e.createdAt >= weeklyCutoff && e.createdAt < dailyCutoff);
  const weekBuckets = bucketByWeek(weeklyEligible);
  for (const week of weekBuckets.values()) {
    if (week.length > 0) {
      keepSet.add(week[0].snapshotId);
    }
  }

  // Rule 2 & 3: pre-migration and pre-rekey snapshots.
  // We do not have migration/rekey markers on envelopes in Phase 6,
  // so these are placeholders.  Callers that know a migration or
  // rekey occurred should tag the nearest snapshot and protect it
  // before calling this function.  For now we protect the oldest
  // snapshot as a conservative fallback (covers unknown migration).
  keepSet.add(sorted[sorted.length - 1].snapshotId);

  // Safety: never delete all snapshots.
  if (keepSet.size === 0 && sorted.length > 0) {
    keepSet.add(sorted[sorted.length - 1].snapshotId);
  }

  const kept: string[] = [];
  const removed: string[] = [];
  for (const env of sorted) {
    if (keepSet.has(env.snapshotId)) {
      kept.push(env.snapshotId);
    } else {
      removed.push(env.snapshotId);
    }
  }

  return { kept, removed };
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

function subtractDays(iso: string, days: number): string {
  const d = new Date(iso);
  d.setUTCDate(d.getUTCDate() - days);
  return d.toISOString();
}

function toDayKey(iso: string): string {
  return iso.slice(0, 10); // YYYY-MM-DD
}

function toWeekKey(iso: string): string {
  const d = new Date(iso);
  const year = d.getUTCFullYear();
  const start = new Date(Date.UTC(year, 0, 1));
  const diff = d.getTime() - start.getTime();
  const oneDay = 86400000;
  const dayOfYear = Math.floor(diff / oneDay);
  const week = Math.floor(dayOfYear / 7);
  return `${year}-W${String(week).padStart(2, '0')}`;
}

function bucketByDay(
  envelopes: readonly TrustedSnapshotEnvelopeV1[],
): Map<string, TrustedSnapshotEnvelopeV1[]> {
  const buckets = new Map<string, TrustedSnapshotEnvelopeV1[]>();
  for (const env of envelopes) {
    const key = toDayKey(env.createdAt);
    const list = buckets.get(key) ?? [];
    list.push(env);
    buckets.set(key, list);
  }
  // Sort each bucket descending by time.
  for (const list of buckets.values()) {
    list.sort((a, b) => {
      const ta = Date.parse(a.createdAt);
      const tb = Date.parse(b.createdAt);
      return tb - ta;
    });
  }
  return buckets;
}

function bucketByWeek(
  envelopes: readonly TrustedSnapshotEnvelopeV1[],
): Map<string, TrustedSnapshotEnvelopeV1[]> {
  const buckets = new Map<string, TrustedSnapshotEnvelopeV1[]>();
  for (const env of envelopes) {
    const key = toWeekKey(env.createdAt);
    const list = buckets.get(key) ?? [];
    list.push(env);
    buckets.set(key, list);
  }
  for (const list of buckets.values()) {
    list.sort((a, b) => {
      const ta = Date.parse(a.createdAt);
      const tb = Date.parse(b.createdAt);
      return tb - ta;
    });
  }
  return buckets;
}
