import { useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Loader2, RotateCcw, Trash2 } from 'lucide-react';

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
import { useVault } from '@/contexts/VaultContext';
import { useToast } from '@/hooks/use-toast';
import type { QuarantinedVaultItem } from '@/services/vaultIntegrityService';
import {
  VaultQuarantineRestoreProgressDialog,
  type VaultQuarantineRestoreProgressStatus,
} from './VaultQuarantineRestoreProgressDialog';

type PendingConfirmation = 'delete' | null;

interface VaultQuarantineActionsProps {
  item: QuarantinedVaultItem;
  compact?: boolean;
}

export function VaultQuarantineActions({
  item,
  compact = false,
}: VaultQuarantineActionsProps) {
  const { t } = useTranslation();
  const { toast } = useToast();
  const {
    opLogDeleteUntrustedRecord,
    opLogRestoreRecord,
    quarantineResolutionById,
  } = useVault();
  const [pendingConfirmation, setPendingConfirmation] = useState<PendingConfirmation>(null);
  const [restoreProgress, setRestoreProgress] = useState<{
    open: boolean;
    status: VaultQuarantineRestoreProgressStatus;
    lastError: string | null;
  }>({
    open: false,
    status: 'running',
    lastError: null,
  });

  const resolution = quarantineResolutionById[item.id];
  const buttonSize = compact ? 'sm' : 'default';
  const buttonClassName = compact ? 'h-8' : undefined;

  const confirmationCopy = useMemo(() => {
    if (pendingConfirmation !== 'delete') {
      return null;
    }

    return {
      title: t('vault.integrity.confirmDeleteTitle', {
        defaultValue: 'Eintrag endgültig löschen?',
      }),
      description: t('vault.integrity.confirmDeleteDescription', {
        defaultValue: 'Der verdächtige Eintrag wird über eine signierte Löschoperation entfernt. Diese Aktion kann nicht rückgängig gemacht werden.',
      }),
      actionLabel: t('vault.integrity.deleteEntry', {
        defaultValue: 'Endgültig löschen',
      }),
    };
  }, [pendingConfirmation, t]);

  if (!resolution) {
    return null;
  }

  const handleRestore = async () => {
    setRestoreProgress({
      open: true,
      status: 'running',
      lastError: null,
    });

    const result = await opLogRestoreRecord(item.id);
    if (result.error) {
      setRestoreProgress({
        open: true,
        status: 'failed',
        lastError: result.error.message,
      });
      toast({
        variant: 'destructive',
        title: t('common.error'),
        description: result.error.message,
      });
      return;
    }

    setRestoreProgress({
      open: true,
      status: 'success',
      lastError: null,
    });
    toast({
      title: t('common.success'),
      description: t('vault.integrity.restoreSuccess', {
        defaultValue: 'Die letzte verifizierte Version wurde über das Operation Log wiederhergestellt.',
      }),
    });
  };

  const handleDelete = async () => {
    setPendingConfirmation(null);
    const result = await opLogDeleteUntrustedRecord(item.id);
    if (result.error) {
      toast({
        variant: 'destructive',
        title: t('common.error'),
        description: result.error.message,
      });
      return;
    }

    toast({
      title: t('common.success'),
      description: t('vault.integrity.deleteSuccess', {
        defaultValue: 'Der Quarantäne-Eintrag wurde über eine signierte Tombstone-Operation entfernt.',
      }),
    });
  };

  return (
    <>
      <div className="flex flex-wrap items-center gap-2">
        {resolution.canRestore && (
          <Button
            type="button"
            size={buttonSize}
            className={buttonClassName}
            disabled={resolution.isBusy}
            onClick={() => { void handleRestore(); }}
          >
            {resolution.isBusy ? (
              <Loader2 className="mr-2 h-4 w-4 animate-spin" />
            ) : (
              <RotateCcw className="mr-2 h-4 w-4" />
            )}
            {t('vault.integrity.restoreAction', {
              defaultValue: 'Wiederherstellen',
            })}
          </Button>
        )}

        {resolution.canDelete && (
          <Button
            type="button"
            size={buttonSize}
            className={buttonClassName}
            variant="outline"
            disabled={resolution.isBusy}
            onClick={() => setPendingConfirmation('delete')}
          >
            {resolution.isBusy ? (
              <Loader2 className="mr-2 h-4 w-4 animate-spin" />
            ) : (
              <Trash2 className="mr-2 h-4 w-4" />
            )}
            {t('vault.integrity.deleteEntry', {
              defaultValue: 'Endgültig löschen',
            })}
          </Button>
        )}
      </div>

      {!resolution.hasTrustedLocalCopy && item.reason !== 'unknown_on_server' && (
        <p className="text-xs text-muted-foreground">
          {t('vault.integrity.noTrustedLocalCopy', {
            defaultValue: 'Auf diesem Gerät ist keine verifizierte lokale Kopie für eine Wiederherstellung verfügbar.',
          })}
        </p>
      )}

      {resolution.lastError && (
        <p className="text-xs text-destructive">
          {resolution.lastError}
        </p>
      )}

      <AlertDialog
        open={pendingConfirmation !== null && confirmationCopy !== null}
        onOpenChange={(open) => {
          if (!open) {
            setPendingConfirmation(null);
          }
        }}
      >
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{confirmationCopy?.title}</AlertDialogTitle>
            <AlertDialogDescription>{confirmationCopy?.description}</AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>
              {t('common.cancel', {
                defaultValue: 'Abbrechen',
              })}
            </AlertDialogCancel>
            <AlertDialogAction
              onClick={(event) => {
                event.preventDefault();
                void handleDelete();
              }}
            >
              {confirmationCopy?.actionLabel}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      <VaultQuarantineRestoreProgressDialog
        open={restoreProgress.open}
        status={restoreProgress.status}
        total={1}
        completed={restoreProgress.status === 'success' ? 1 : 0}
        failed={restoreProgress.status === 'failed' ? 1 : 0}
        currentItemId={item.id}
        lastError={restoreProgress.lastError}
        onContinue={() => {
          setRestoreProgress((current) => ({
            ...current,
            open: false,
          }));
        }}
      />
    </>
  );
}
