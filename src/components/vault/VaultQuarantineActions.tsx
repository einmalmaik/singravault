import { useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { CheckCircle2, Loader2, RotateCcw, Trash2 } from 'lucide-react';

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

type PendingConfirmation = 'delete' | 'accept-missing' | null;

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
    acceptMissingQuarantinedItem,
    deleteQuarantinedItem,
    quarantineResolutionById,
    restoreQuarantinedItem,
  } = useVault();
  const [pendingConfirmation, setPendingConfirmation] = useState<PendingConfirmation>(null);

  const resolution = quarantineResolutionById[item.id];
  const buttonSize = compact ? 'sm' : 'default';
  const buttonClassName = compact ? 'h-8' : undefined;

  const confirmationCopy = useMemo(() => {
    if (pendingConfirmation === 'delete') {
      return {
        title: t('vault.integrity.confirmDeleteTitle', {
          defaultValue: 'Eintrag endgültig löschen?',
        }),
        description: t('vault.integrity.confirmDeleteDescription', {
          defaultValue: 'Der verdächtige Eintrag wird aus dem aktuellen Tresorstand entfernt. Diese Aktion kann nicht rückgängig gemacht werden.',
        }),
        actionLabel: t('vault.integrity.deleteEntry', {
          defaultValue: 'Endgültig löschen',
        }),
      };
    }

    return {
      title: t('vault.integrity.confirmAcceptMissingTitle', {
        defaultValue: 'Löschung akzeptieren?',
      }),
      description: t('vault.integrity.confirmAcceptMissingDescription', {
        defaultValue: 'Der fehlende Eintrag wird aus der vertrauenswürdigen lokalen Baseline entfernt. Danach ist keine Wiederherstellung mehr möglich, solange keine andere lokale Kopie existiert.',
      }),
      actionLabel: t('vault.integrity.acceptMissingAction', {
        defaultValue: 'Löschung akzeptieren',
      }),
    };
  }, [pendingConfirmation, t]);

  if (!resolution) {
    return null;
  }

  const handleRestore = async () => {
    const result = await restoreQuarantinedItem(item.id);
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
      description: t('vault.integrity.restoreSuccess', {
        defaultValue: 'Die letzte vertrauenswürdige lokale Version wurde wiederhergestellt.',
      }),
    });
  };

  const handleDelete = async () => {
    setPendingConfirmation(null);
    const result = await deleteQuarantinedItem(item.id);
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
        defaultValue: 'Der Quarantäne-Eintrag wurde entfernt.',
      }),
    });
  };

  const handleAcceptMissing = async () => {
    setPendingConfirmation(null);
    const result = await acceptMissingQuarantinedItem(item.id);
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
      description: t('vault.integrity.acceptMissingSuccess', {
        defaultValue: 'Die Löschung wurde akzeptiert und die lokale Vertrauensbasis aktualisiert.',
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

        {resolution.canAcceptMissing && (
          <Button
            type="button"
            size={buttonSize}
            className={buttonClassName}
            variant="outline"
            disabled={resolution.isBusy}
            onClick={() => setPendingConfirmation('accept-missing')}
          >
            {resolution.isBusy ? (
              <Loader2 className="mr-2 h-4 w-4 animate-spin" />
            ) : (
              <CheckCircle2 className="mr-2 h-4 w-4" />
            )}
            {t('vault.integrity.acceptMissingAction', {
              defaultValue: 'Löschung akzeptieren',
            })}
          </Button>
        )}
      </div>

      {!resolution.hasTrustedLocalCopy && item.reason !== 'unknown_on_server' && (
        <p className="text-xs text-muted-foreground">
          {t('vault.integrity.noTrustedLocalCopy', {
            defaultValue: 'Auf diesem Gerät ist keine vertrauenswürdige lokale Kopie für eine Wiederherstellung verfügbar.',
          })}
        </p>
      )}

      {resolution.lastError && (
        <p className="text-xs text-destructive">
          {resolution.lastError}
        </p>
      )}

      <AlertDialog
        open={pendingConfirmation !== null}
        onOpenChange={(open) => {
          if (!open) {
            setPendingConfirmation(null);
          }
        }}
      >
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{confirmationCopy.title}</AlertDialogTitle>
            <AlertDialogDescription>{confirmationCopy.description}</AlertDialogDescription>
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
                if (pendingConfirmation === 'delete') {
                  void handleDelete();
                  return;
                }
                void handleAcceptMissing();
              }}
            >
              {confirmationCopy.actionLabel}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  );
}
