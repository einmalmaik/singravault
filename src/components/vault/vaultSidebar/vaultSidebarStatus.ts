// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE
/**
 * @fileoverview Vault Sidebar Status Summary
 *
 * Pure derivation layer for the "Tresor-Status" card in the sidebar. Takes
 * the integrity result + the lazy health summary and decides which tone
 * (success / warning / danger) and which copy to show.
 *
 * Kept UI-free so the priority order between integrity-blocked, quarantine,
 * critical/review health, healthy and "still loading" is testable without
 * mounting the component.
 */

import type { VaultHealthSidebarSummary } from '@/extensions/types';

export type VaultSidebarStatusTone = 'success' | 'warning' | 'danger';

export interface VaultSidebarStatusSummary {
  readonly label: string;
  readonly description: string;
  readonly tone: VaultSidebarStatusTone;
}

export interface VaultSidebarStatusToneClasses {
  readonly card: string;
  readonly icon: string;
  readonly text: string;
  readonly button: string;
}

function formatHealthCountParts(stats: VaultHealthSidebarSummary['stats']): string {
  const parts = [
    stats.pwned > 0 ? `${stats.pwned} geleakt` : null,
    stats.weak > 0 ? `${stats.weak} schwach` : null,
    stats.duplicate > 0 ? `${stats.duplicate} doppelt` : null,
    stats.old > 0 ? `${stats.old} alt` : null,
    stats.strong > 0 ? `${stats.strong} stark` : null,
  ].filter((part): part is string => Boolean(part));

  return parts.length > 0 ? parts.join(' · ') : 'keine Auffälligkeiten';
}

function formatEntryCount(count: number): string {
  return `${count} Eintr${count === 1 ? 'ag' : 'äge'}`;
}

/**
 * Priority order for the sidebar status:
 *  1. Integrity `blocked`     → danger
 *  2. Quarantine present      → warning
 *  3. Health critical         → danger
 *  4. Health review           → warning
 *  5. Health healthy          → success
 *  6. Health still loading    → warning ("Analyse läuft")
 *  7. Integrity `healthy`     → success
 *  8. Fallback                → warning ("Analyse läuft" / "Analyse bereit")
 *
 * Note: integrity issues always win over health issues. Health analysis
 * is paused entirely when the vault is `blocked`/`quarantine` because the
 * sidebar already surfaces those as more urgent signals.
 */
export function getVaultSidebarStatusSummary(
  result: { mode?: string; quarantinedItems?: unknown[] } | null | undefined,
  healthSummary: VaultHealthSidebarSummary | null,
  healthLoading: boolean,
): VaultSidebarStatusSummary {
  const quarantinedCount = result?.quarantinedItems?.length ?? 0;

  if (result?.mode === 'blocked') {
    return {
      label: 'Kritisch',
      description: 'Tresorzugriff ist durch eine Integritätsprüfung blockiert.',
      tone: 'danger',
    };
  }

  if (quarantinedCount > 0 || result?.mode === 'quarantine') {
    const count = Math.max(quarantinedCount, 1);
    return {
      label: `${count} Fall${count === 1 ? '' : 'e'}`,
      description: 'Einzelne Einträge brauchen Aufmerksamkeit.',
      tone: 'warning',
    };
  }

  if (healthSummary?.status === 'critical') {
    return {
      label: 'Kritisch',
      description: `Bitte Tresor überprüfen: ${formatEntryCount(healthSummary.affectedItems)} brauchen Aufmerksamkeit (${formatHealthCountParts(healthSummary.stats)}).`,
      tone: 'danger',
    };
  }

  if (healthSummary?.status === 'review') {
    return {
      label: 'Bitte prüfen',
      description: `Bitte Tresor überprüfen: ${formatEntryCount(healthSummary.affectedItems)} mit Hinweisen (${formatHealthCountParts(healthSummary.stats)}).`,
      tone: 'warning',
    };
  }

  if (healthSummary?.status === 'healthy') {
    return {
      label: 'Stark',
      description: `${formatEntryCount(healthSummary.passwordItems)} analysiert (${formatHealthCountParts(healthSummary.stats)}).`,
      tone: 'success',
    };
  }

  if (healthLoading) {
    return {
      label: 'Analyse läuft',
      description: 'Tresorgesundheit wird lokal aus dem entsperrten Tresor berechnet.',
      tone: 'warning',
    };
  }

  if (result?.mode === 'healthy') {
    return {
      label: 'Unauffällig',
      description: 'Keine aktuellen Integritätsfälle erkannt.',
      tone: 'success',
    };
  }

  return {
    label: healthLoading ? 'Analyse läuft' : 'Analyse bereit',
    description: healthLoading
      ? 'Tresorgesundheit wird lokal aus dem entsperrten Tresor berechnet.'
      : 'Aktueller Zustand wird geladen, sobald Tresordaten verfügbar sind.',
    tone: 'warning',
  };
}

export function getVaultSidebarStatusToneClasses(tone: VaultSidebarStatusTone): VaultSidebarStatusToneClasses {
  if (tone === 'danger') {
    return {
      card: 'border-red-400/18 bg-[linear-gradient(135deg,hsl(var(--destructive)/0.12),hsl(var(--el-1)/0.78))]',
      icon: 'border-red-300/25 bg-red-400/10 text-red-300',
      text: 'text-red-300',
      button: 'border-red-300/20 bg-background/35',
    };
  }

  if (tone === 'warning') {
    return {
      card: 'border-amber-400/18 bg-[linear-gradient(135deg,hsl(var(--warning)/0.12),hsl(var(--el-1)/0.78))]',
      icon: 'border-amber-300/25 bg-amber-400/10 text-amber-300',
      text: 'text-amber-300',
      button: 'border-amber-300/20 bg-background/35',
    };
  }

  return {
    card: 'border-emerald-400/18 bg-[linear-gradient(135deg,hsl(var(--success)/0.12),hsl(var(--el-1)/0.78))]',
    icon: 'border-emerald-300/25 bg-emerald-400/10 text-emerald-300',
    text: 'text-emerald-300',
    button: 'border-emerald-300/20 bg-background/35',
  };
}
