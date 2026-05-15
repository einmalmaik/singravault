// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE
/**
 * @fileoverview Vault Item Preview Panel
 *
 * Side panel + delete confirmation dialog the list shows when the user
 * activates a row. Pure presentation: receives the resolved preview item plus
 * the action callbacks the parent list owns, never reads vault context itself.
 *
 * Keeping the JSX out of `VaultItemList.tsx` lets the main component stay
 * focused on data flow. Copy actions are gated by `canCopySecrets` so that
 * locked or unverified OpLog states never expose copy buttons.
 */

import { useTranslation } from 'react-i18next';
import { Copy, Edit, KeyRound, Loader2, Star, Trash2, X } from 'lucide-react';

import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from '@/components/ui/alert-dialog';
import { Button } from '@/components/ui/button';
import { VaultIcon } from '@/components/icons/VaultIcon';
import { cn } from '@/lib/utils';

import { VaultItemPreviewPanel as VaultItemPreviewPanelSurface } from '../VaultItemPreviewPanel';
import {
  formatVaultItemMetaDate,
  getItemTitle,
  getItemUsername,
  getItemWebsiteUrl,
  isItemFavorite,
  type VaultItem,
} from './vaultItemModel';

interface VaultItemListPreviewPanelProps {
  readonly previewItem: VaultItem | null;
  readonly deletePreviewItem: VaultItem | null;
  readonly deletingPreviewItem: boolean;
  readonly canCopySecrets: boolean;
  readonly onClose: () => void;
  readonly onCopyUsername: (item: VaultItem) => void;
  readonly onCopyPassword: (item: VaultItem) => void;
  readonly onToggleFavorite: (item: VaultItem) => void;
  readonly onEdit: (itemId: string) => void;
  readonly onRequestDelete: (itemId: string) => void;
  readonly onCancelDelete: () => void;
  readonly onConfirmDelete: () => void;
}

export function VaultItemListPreviewPanel({
  previewItem,
  deletePreviewItem,
  deletingPreviewItem,
  canCopySecrets,
  onClose,
  onCopyUsername,
  onCopyPassword,
  onToggleFavorite,
  onEdit,
  onRequestDelete,
  onCancelDelete,
  onConfirmDelete,
}: VaultItemListPreviewPanelProps) {
  const { t } = useTranslation();

  return (
    <>
      {previewItem && (
        <VaultItemPreviewPanelSurface>
          <div className="flex items-start justify-between gap-3 rounded-2xl border border-border/30 bg-white/[0.015] p-3 shadow-[0_14px_34px_hsl(0_0%_0%/0.18)]">
            <div className="flex min-w-0 items-center gap-3">
              <VaultIcon
                title={getItemTitle(previewItem)}
                websiteUrl={getItemWebsiteUrl(previewItem)}
                className="h-12 w-12 rounded-xl"
                iconClassName="h-6 w-6"
              />
              <div className="min-w-0">
                <h3 className="truncate text-base font-semibold">{getItemTitle(previewItem)}</h3>
                <p className="truncate text-xs text-muted-foreground">
                  {getItemUsername(previewItem) || getItemWebsiteUrl(previewItem) || '—'}
                </p>
              </div>
            </div>
            <Button
              type="button"
              variant="ghost"
              size="icon"
              className="h-8 w-8 shrink-0 text-muted-foreground hover:text-foreground"
              aria-label={t('common.close', { defaultValue: 'Schließen' })}
              onClick={onClose}
            >
              <X className="h-4 w-4" />
            </Button>
          </div>

          <div className="mt-5 space-y-2 rounded-2xl border border-border/25 bg-white/[0.012] p-2">
            {getItemUsername(previewItem) && canCopySecrets && (
              <Button
                type="button"
                variant="outline"
                className="w-full justify-start"
                onClick={() => onCopyUsername(previewItem)}
              >
                <Copy className="mr-2 h-4 w-4" />
                {t('vault.actions.copyUsername')}
              </Button>
            )}
            {previewItem.decryptedData?.password && canCopySecrets && (
              <Button
                type="button"
                variant="outline"
                className="w-full justify-start"
                onClick={() => onCopyPassword(previewItem)}
              >
                <KeyRound className="mr-2 h-4 w-4" />
                {t('vault.actions.copyPassword')}
              </Button>
            )}
            <Button type="button" variant="outline" className="w-full justify-start" onClick={() => onToggleFavorite(previewItem)}>
              <Star className={cn('mr-2 h-4 w-4 text-amber-400', isItemFavorite(previewItem) && 'fill-current')} />
              {isItemFavorite(previewItem)
                ? t('vault.actions.removeFavorite', { defaultValue: 'Favorit entfernen' })
                : t('vault.actions.addFavorite', { defaultValue: 'Als Favorit markieren' })}
            </Button>
            <Button type="button" variant="outline" className="w-full justify-start" onClick={() => onEdit(previewItem.id)}>
              <Edit className="mr-2 h-4 w-4" />
              {t('vault.actions.editEntry', { defaultValue: 'Eintrag bearbeiten' })}
            </Button>
            <Button type="button" variant="ghost" className="w-full justify-start text-destructive hover:text-destructive" onClick={() => onRequestDelete(previewItem.id)}>
              <Trash2 className="mr-2 h-4 w-4" />
              {t('vault.actions.deleteEntry', { defaultValue: 'Eintrag löschen' })}
            </Button>
          </div>

          <div className="mt-5 rounded-2xl border border-border/25 bg-white/[0.012] p-3">
            <details>
              <summary className="cursor-pointer list-none text-sm font-medium text-foreground">
                {t('authenticator.details', { defaultValue: 'Details anzeigen' })}
              </summary>
              <dl className="mt-3 space-y-2 text-xs text-muted-foreground">
                <div className="flex justify-between gap-3">
                  <dt>{t('common.created', { defaultValue: 'Erstellt' })}</dt>
                  <dd className="text-right">{formatVaultItemMetaDate(previewItem.created_at)}</dd>
                </div>
                <div className="flex justify-between gap-3">
                  <dt>{t('common.updated', { defaultValue: 'Geändert' })}</dt>
                  <dd className="text-right">{formatVaultItemMetaDate(previewItem.updated_at)}</dd>
                </div>
              </dl>
            </details>
          </div>
        </VaultItemPreviewPanelSurface>
      )}

      <AlertDialog
        open={!!deletePreviewItem}
        onOpenChange={(open) => {
          if (!open) {
            onCancelDelete();
          }
        }}
      >
        <AlertDialogContent className="w-[calc(100vw-2rem)] max-w-xl">
          <AlertDialogHeader>
            <AlertDialogTitle>
              {t('vault.confirmDeleteTitle', { defaultValue: 'Eintrag löschen?' })}
            </AlertDialogTitle>
            <AlertDialogDescription className="leading-relaxed">
              {t('vault.confirmDeleteDescription', {
                defaultValue: 'Dieser Eintrag wird aus dem Tresor entfernt. Diese Aktion kann nicht direkt rückgängig gemacht werden.',
              })}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={deletingPreviewItem}>
              {t('common.cancel', { defaultValue: 'Abbrechen' })}
            </AlertDialogCancel>
            <AlertDialogAction
              disabled={deletingPreviewItem}
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
              onClick={(event) => {
                event.preventDefault();
                onConfirmDelete();
              }}
            >
              {deletingPreviewItem && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
              {t('common.delete', { defaultValue: 'Löschen' })}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  );
}
