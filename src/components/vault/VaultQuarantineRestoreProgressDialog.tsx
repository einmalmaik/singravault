import { CheckCircle2, Loader2, TriangleAlert } from 'lucide-react';
import { useTranslation } from 'react-i18next';

import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from '@/components/ui/alert-dialog';

export type VaultQuarantineRestoreProgressStatus = 'running' | 'success' | 'failed';

interface VaultQuarantineRestoreProgressDialogProps {
  open: boolean;
  status: VaultQuarantineRestoreProgressStatus;
  total: number;
  completed: number;
  failed: number;
  currentItemId: string | null;
  lastError: string | null;
  onContinue: () => void;
}

function getRestoreProgressTitle(input: {
  status: VaultQuarantineRestoreProgressStatus;
  total: number;
  t: ReturnType<typeof useTranslation>['t'];
}): string {
  const { status, total, t } = input;
  const isBulk = total > 1;

  if (status === 'success') {
    return isBulk
      ? t('vault.integrity.bulkRestoreSuccessTitle', {
        defaultValue: '{{count}} Einträge wurden wiederhergestellt',
        count: total,
      })
      : t('vault.integrity.restoreSuccessTitle', {
        defaultValue: 'Eintrag wurde wiederhergestellt',
      });
  }

  if (status === 'failed') {
    return isBulk
      ? t('vault.integrity.bulkRestoreFailedTitle', {
        defaultValue: 'Wiederherstellung teilweise fehlgeschlagen',
      })
      : t('vault.integrity.restoreFailedTitle', {
        defaultValue: 'Wiederherstellung fehlgeschlagen',
      });
  }

  return isBulk
    ? t('vault.integrity.bulkRestoreRunningTitle', {
      defaultValue: '{{count}} Einträge werden wiederhergestellt',
      count: total,
    })
    : t('vault.integrity.restoreRunningTitle', {
      defaultValue: 'Manipulierter Eintrag wird wiederhergestellt',
    });
}

export function VaultQuarantineRestoreProgressDialog({
  open,
  status,
  total,
  completed,
  failed,
  currentItemId,
  lastError,
  onContinue,
}: VaultQuarantineRestoreProgressDialogProps) {
  const { t } = useTranslation();
  const isRunning = status === 'running';
  const isBulk = total > 1;
  const title = getRestoreProgressTitle({ status, total, t });
  const processed = completed + failed;

  return (
    <AlertDialog open={open}>
      <AlertDialogContent className="w-[calc(100vw-2rem)] max-w-md">
        <AlertDialogHeader className="items-center text-center">
          <div className="mb-2 rounded-full border border-amber-500/30 bg-amber-500/10 p-3 text-amber-700 dark:text-amber-300">
            {status === 'running' && <Loader2 className="h-7 w-7 animate-spin" />}
            {status === 'success' && <CheckCircle2 className="h-7 w-7 text-emerald-600" />}
            {status === 'failed' && <TriangleAlert className="h-7 w-7 text-destructive" />}
          </div>
          <AlertDialogTitle className="leading-snug">{title}</AlertDialogTitle>
          <AlertDialogDescription className="space-y-2">
            {isRunning ? (
              <>
                <span className="block">
                  {isBulk
                    ? t('vault.integrity.bulkRestoreRunningDescription', {
                      defaultValue: '{{completed}} von {{count}} Einträgen wurden verarbeitet.',
                      completed: processed,
                      count: total,
                    })
                    : t('vault.integrity.restoreRunningDescription', {
                      defaultValue: 'Die letzte vertrauenswürdige lokale Version wird geprüft und zurückgeschrieben.',
                    })}
                </span>
                {currentItemId && (
                  <span className="block break-all text-xs text-muted-foreground/80">
                    {currentItemId}
                  </span>
                )}
              </>
            ) : status === 'success' ? (
              <span className="block">
                {isBulk
                  ? t('vault.integrity.bulkRestoreSuccessDescription', {
                    defaultValue: 'Alle ausgewählten wiederherstellbaren Einträge sind wieder verfügbar.',
                  })
                  : t('vault.integrity.restoreSuccessDescription', {
                    defaultValue: 'Der Eintrag ist wieder verfügbar.',
                  })}
              </span>
            ) : (
              <>
                <span className="block">
                  {isBulk
                    ? t('vault.integrity.bulkRestoreFailedDescription', {
                      defaultValue: '{{completed}} Einträge wurden wiederhergestellt, {{failed}} konnten nicht wiederhergestellt werden.',
                      completed,
                      failed,
                    })
                    : t('vault.integrity.restoreFailedDescription', {
                      defaultValue: 'Der Eintrag bleibt in Quarantäne.',
                    })}
                </span>
                {lastError && (
                  <span className="block text-destructive">{lastError}</span>
                )}
              </>
            )}
          </AlertDialogDescription>
        </AlertDialogHeader>
        {!isRunning && (
          <AlertDialogFooter>
            <AlertDialogAction onClick={onContinue}>
              {t('common.continue', {
                defaultValue: 'Weiter',
              })}
            </AlertDialogAction>
          </AlertDialogFooter>
        )}
      </AlertDialogContent>
    </AlertDialog>
  );
}
