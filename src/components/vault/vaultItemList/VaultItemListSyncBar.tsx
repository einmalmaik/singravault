// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE
/**
 * @fileoverview Vault Item List Sync Bar
 *
 * Top-right indicator row that surfaces ambient state during list rendering:
 * background cloud sync activity, the loading state of the OpLog security
 * check, and the optional integrity re-validation button.
 *
 * Each indicator is conditional and the whole bar collapses when there is
 * nothing to show so the layout stays calm on a quiet vault.
 */

import { useTranslation } from 'react-i18next';
import { Cloud, ShieldCheck } from 'lucide-react';

import { cn } from '@/lib/utils';

interface VaultItemListSyncBarProps {
  readonly backgroundSyncing: boolean;
  readonly lastCloudSyncAt: Date | null;
  readonly securityStatusLoading: boolean;
  readonly showRevalidationButton: boolean;
  readonly revalidating: boolean;
  readonly onRevalidate: () => void;
}

export function VaultItemListSyncBar({
  backgroundSyncing,
  lastCloudSyncAt,
  securityStatusLoading,
  showRevalidationButton,
  revalidating,
  onRevalidate,
}: VaultItemListSyncBarProps) {
  const { t } = useTranslation();

  const showCloud = backgroundSyncing || lastCloudSyncAt;
  if (!showCloud && !securityStatusLoading && !showRevalidationButton) {
    return null;
  }

  return (
    <div className="flex items-center justify-end gap-2">
      {showCloud && (
        <span
          className="inline-flex h-9 w-9 items-center justify-center rounded-full border border-[hsl(var(--border)/0.35)] bg-[hsl(var(--el-1)/0.78)] text-primary shadow-[0_0_24px_hsl(var(--primary)/0.08)]"
          title={backgroundSyncing
            ? t('vault.items.cloudSyncing', { defaultValue: 'Synchronisiere mit Cloud...' })
            : t('vault.items.cloudSyncedRecently', { defaultValue: 'Zuletzt synchronisiert vor wenigen Sekunden' })}
          aria-label={backgroundSyncing
            ? t('vault.items.cloudSyncing', { defaultValue: 'Synchronisiere mit Cloud...' })
            : t('vault.items.cloudSyncedRecently', { defaultValue: 'Zuletzt synchronisiert vor wenigen Sekunden' })}
        >
          <Cloud className={cn('h-4 w-4', backgroundSyncing && 'animate-pulse')} />
          <span className="sr-only">
            {backgroundSyncing
              ? t('vault.items.cloudSyncing', { defaultValue: 'Synchronisiere mit Cloud...' })
              : t('vault.items.cloudSyncedRecently', { defaultValue: 'Zuletzt synchronisiert vor wenigen Sekunden' })}
          </span>
        </span>
      )}
      {securityStatusLoading && (
        <span
          className="inline-flex h-9 w-9 items-center justify-center rounded-full border border-emerald-300/25 bg-[hsl(var(--el-1)/0.78)] text-emerald-300 shadow-[0_0_24px_hsl(var(--success)/0.08)]"
          title={t('vault.oplog.loading', { defaultValue: 'Sicherheitsstatus wird geladen...' })}
          aria-label={t('vault.oplog.loading', { defaultValue: 'Sicherheitsstatus wird geladen...' })}
        >
          <ShieldCheck className="h-4 w-4 animate-pulse" />
          <span className="sr-only">
            {t('vault.oplog.loading', { defaultValue: 'Sicherheitsstatus wird geladen...' })}
          </span>
        </span>
      )}
      {showRevalidationButton && (
        <button
          type="button"
          disabled={revalidating}
          onClick={onRevalidate}
          className="inline-flex h-9 w-9 items-center justify-center rounded-full border border-[hsl(var(--border)/0.35)] bg-[hsl(var(--el-1)/0.78)] text-emerald-300 shadow-[0_0_24px_hsl(var(--success)/0.08)] transition-colors hover:border-emerald-300/40 hover:bg-emerald-400/10 disabled:cursor-wait"
          title={revalidating
            ? t('vault.integrity.revalidatingEntries', { defaultValue: 'Prüfe Einträge...' })
            : t('vault.integrity.revalidationHint', { defaultValue: 'Die Liste nutzt zuerst den lokalen Stand und prüft danach kurz gegen den Server.' })}
          aria-label={revalidating
            ? t('vault.integrity.revalidatingEntries', { defaultValue: 'Prüfe Einträge...' })
            : t('vault.integrity.revalidationHint', { defaultValue: 'Die Liste nutzt zuerst den lokalen Stand und prüft danach kurz gegen den Server.' })}
        >
          <ShieldCheck className={cn('h-4 w-4', revalidating && 'animate-pulse')} />
        </button>
      )}
    </div>
  );
}
