// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE
/**
 * @fileoverview Vault Item List Bulk Restore Dialogs
 *
 * Two dialogs that gate and report on bulk quarantine restoration. The
 * confirmation only fires the bulk restore — the progress dialog watches the
 * external operation reported through `progress`.
 *
 * The bulk restore relies on the central quarantine orchestrator; this
 * component only renders user-visible confirmation and progress copy.
 */

import { useTranslation } from 'react-i18next';

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

import {
  VaultQuarantineRestoreProgressDialog,
  type VaultQuarantineRestoreProgressStatus,
} from '../VaultQuarantineRestoreProgressDialog';

export interface BulkRestoreProgress {
  open: boolean;
  status: VaultQuarantineRestoreProgressStatus;
  total: number;
  completed: number;
  failed: number;
  currentItemId: string | null;
  lastError: string | null;
}

interface VaultItemListBulkRestoreDialogsProps {
  readonly confirmOpen: boolean;
  readonly onConfirmOpenChange: (open: boolean) => void;
  readonly restorableCount: number;
  readonly onConfirmRestoreAll: () => void;
  readonly progress: BulkRestoreProgress;
  readonly onProgressContinue: () => void;
}

export function VaultItemListBulkRestoreDialogs({
  confirmOpen,
  onConfirmOpenChange,
  restorableCount,
  onConfirmRestoreAll,
  progress,
  onProgressContinue,
}: VaultItemListBulkRestoreDialogsProps) {
  const { t } = useTranslation();

  return (
    <>
      <AlertDialog open={confirmOpen} onOpenChange={onConfirmOpenChange}>
        <AlertDialogContent className="w-[calc(100vw-2rem)] max-w-xl">
          <AlertDialogHeader>
            <AlertDialogTitle>
              {t('vault.integrity.confirmBulkRestoreTitle', {
                defaultValue: '{{count}} Einträge wiederherstellen?',
                count: restorableCount,
              })}
            </AlertDialogTitle>
            <AlertDialogDescription className="leading-relaxed">
              {t('vault.integrity.confirmBulkRestoreDescription', {
                defaultValue: 'Es werden nur Einträge wiederhergestellt, für die auf diesem Gerät eine vertrauenswürdige lokale Kopie verfügbar ist. Jeder Eintrag wird einzeln geprüft und danach verifiziert.',
              })}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>
              {t('common.cancel', { defaultValue: 'Abbrechen' })}
            </AlertDialogCancel>
            <AlertDialogAction
              onClick={(event) => {
                event.preventDefault();
                onConfirmRestoreAll();
              }}
            >
              {t('vault.integrity.confirmBulkRestoreAction', {
                defaultValue: 'Wiederherstellen',
              })}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      <VaultQuarantineRestoreProgressDialog
        open={progress.open}
        status={progress.status}
        total={progress.total}
        completed={progress.completed}
        failed={progress.failed}
        currentItemId={progress.currentItemId}
        lastError={progress.lastError}
        onContinue={onProgressContinue}
      />
    </>
  );
}
