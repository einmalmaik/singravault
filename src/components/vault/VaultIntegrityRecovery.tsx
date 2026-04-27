import { useEffect, useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import {
  Download,
  Loader2,
  RotateCcw,
  ShieldAlert,
  TriangleAlert,
  Vault,
} from 'lucide-react';

import { SensitiveActionReauthDialog } from '@/components/security/SensitiveActionReauthDialog';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { useAuth } from '@/contexts/AuthContext';
import { useVault } from '@/contexts/VaultContext';
import { useToast } from '@/hooks/use-toast';
import type { VaultItemData } from '@/services/cryptoService';
import { saveExportFile } from '@/services/exportFileService';
import { getTrustedOfflineSnapshot } from '@/services/offlineVaultService';
import { isSensitiveActionSessionFresh } from '@/services/sensitiveActionReauthService';
import { buildVaultExportPayload } from '@/services/vaultExportService';
import { VaultRecoveryResetError } from '@/services/vaultRecoveryService';
import { VaultItemCard } from '@/components/vault/VaultItemCard';
import { VaultQuarantinePanel } from '@/components/vault/VaultQuarantinePanel';

type SafeModeItem = {
  id: string;
  title: string;
  website_url: string | null;
  item_type: 'password' | 'note' | 'totp' | 'card';
  is_favorite: boolean | null;
  decryptedData?: VaultItemData;
};

function getBlockedReasonMessage(reason: ReturnType<typeof useVault>['integrityBlockedReason']): string {
  switch (reason) {
    case 'baseline_unreadable':
      return 'Die lokale Integritäts-Baseline ist unlesbar oder beschädigt.';
    case 'legacy_baseline_mismatch':
      return 'Die alte Integritäts-Baseline passt nicht mehr zum aktuellen Tresorstand.';
    case 'category_structure_mismatch':
      return 'Die verschlüsselten Kategorien wurden außerhalb des vertrauenswürdigen Änderungswegs verändert.';
    case 'snapshot_malformed':
      return 'Der aktuelle Tresorstand ist strukturell inkonsistent und wurde blockiert.';
    default:
      return 'Der aktuelle Tresorstand konnte nicht mehr als vertrauenswürdig bestätigt werden.';
  }
}

export function VaultIntegrityRecovery() {
  const { t } = useTranslation();
  const { toast } = useToast();
  const { user } = useAuth();
  const {
    decryptItem,
    enterSafeMode,
    exitSafeMode,
    integrityBlockedReason,
    integrityMode,
    quarantinedItems,
    resetVaultAfterIntegrityFailure,
    trustedRecoveryAvailable,
  } = useVault();

  const [isPreparingSafeMode, setIsPreparingSafeMode] = useState(false);
  const [isResetting, setIsResetting] = useState(false);
  const [isExporting, setIsExporting] = useState(false);
  const [isLoadingSnapshot, setIsLoadingSnapshot] = useState(false);
  const [safeModeItems, setSafeModeItems] = useState<SafeModeItem[]>([]);
  const [showReauthDialog, setShowReauthDialog] = useState(false);

  useEffect(() => {
    let cancelled = false;

    const loadSafeSnapshot = async () => {
      if (integrityMode !== 'safe' || !user) {
        setSafeModeItems([]);
        return;
      }

      setIsLoadingSnapshot(true);
      try {
        const snapshot = await getTrustedOfflineSnapshot(user.id);
        if (!snapshot) {
          throw new Error('No trusted recovery snapshot available');
        }

        const decryptedItems = await Promise.all(
          snapshot.items.map(async (item) => {
            try {
              const decryptedData = await decryptItem(item.encrypted_data, item.id);
              return {
                id: item.id,
                title: decryptedData.title || item.title,
                website_url: decryptedData.websiteUrl || item.website_url,
                item_type: decryptedData.itemType || item.item_type || 'password',
                is_favorite: typeof decryptedData.isFavorite === 'boolean'
                  ? decryptedData.isFavorite
                  : !!item.is_favorite,
                decryptedData,
              } as SafeModeItem;
            } catch {
              return null;
            }
          }),
        );

        if (!cancelled) {
          setSafeModeItems(
            decryptedItems
              .filter((item): item is SafeModeItem => item !== null)
              .sort((left, right) => left.title.localeCompare(right.title)),
          );
        }
      } catch (error) {
        if (!cancelled) {
          console.error('Failed to load trusted recovery snapshot:', error);
          toast({
            variant: 'destructive',
            title: t('common.error'),
            description: t('vault.integrity.safeModeLoadFailed', {
              defaultValue: 'Der vertrauenswürdige lokale Snapshot konnte nicht geladen werden.',
            }),
          });
        }
      } finally {
        if (!cancelled) {
          setIsLoadingSnapshot(false);
        }
      }
    };

    void loadSafeSnapshot();
    return () => {
      cancelled = true;
    };
  }, [decryptItem, integrityMode, t, toast, user]);

  const safeModeDescription = useMemo(
    () => t('vault.integrity.safeModeDescription', {
      defaultValue: 'Safe Mode arbeitet ausschließlich mit dem letzten vertrauenswürdigen lokalen Snapshot. Änderungen sind deaktiviert.',
    }),
    [t],
  );

  const handleEnterSafeMode = async () => {
    setIsPreparingSafeMode(true);
    const result = await enterSafeMode();
    setIsPreparingSafeMode(false);

    if (result.error) {
      toast({
        variant: 'destructive',
        title: t('common.error'),
        description: result.error.message,
      });
    }
  };

  const handleExport = async () => {
    if (!user) {
      return;
    }

    setIsExporting(true);
    try {
      const trustedSnapshot = await getTrustedOfflineSnapshot(user.id);
      if (!trustedSnapshot) {
        throw new Error('No trusted recovery snapshot available');
      }

      const exportPayload = await buildVaultExportPayload(trustedSnapshot.items, decryptItem, {
        mode: 'safe',
        quarantinedItems,
      });

      const saved = await saveExportFile({
        name: `singra-vault-safe-mode-export-${new Date().toISOString().split('T')[0]}.json`,
        mime: 'application/json',
        content: JSON.stringify(exportPayload, null, 2),
      });

      if (!saved) {
        return;
      }

      toast({
        title: t('common.success'),
        description: t('vault.integrity.safeModeExportSuccess', {
          defaultValue: '{{count}} vertrauenswürdige Einträge exportiert.',
          count: exportPayload.itemCount,
        }),
      });
    } catch (error) {
      console.error('Safe mode export failed:', error);
      toast({
        variant: 'destructive',
        title: t('common.error'),
        description: t('vault.integrity.safeModeExportFailed', {
          defaultValue: 'Der Safe-Mode-Export konnte nicht erstellt werden.',
        }),
      });
    } finally {
      setIsExporting(false);
    }
  };

  const getResetErrorDescription = (error: Error): string => {
    if (error instanceof VaultRecoveryResetError) {
      switch (error.code) {
        case 'REAUTH_REQUIRED':
          return t('reauth.vaultResetContext');
        case 'RECOVERY_CHALLENGE_REQUIRED':
          return t('vault.integrity.resetChallengeExpired', {
            defaultValue: 'Die Sicherheitsbestätigung für den Tresor-Reset ist abgelaufen. Bitte versuche es erneut.',
          });
        default:
          return t('vault.integrity.resetFailed', {
            defaultValue: 'Der Tresor konnte nicht zurückgesetzt werden.',
          });
      }
    }

    return error.message;
  };

  const executeResetVault = async (): Promise<boolean> => {
    setIsResetting(true);
    const result = await resetVaultAfterIntegrityFailure();
    setIsResetting(false);

    if (result.error) {
      if (result.error instanceof VaultRecoveryResetError && result.error.code === 'REAUTH_REQUIRED') {
        toast({
          title: t('common.error'),
          description: t('reauth.vaultResetContext'),
        });
        setShowReauthDialog(true);
        return false;
      }

      toast({
        variant: 'destructive',
        title: t('common.error'),
        description: getResetErrorDescription(result.error),
      });
      return false;
    }

    toast({
      title: t('common.success'),
      description: t('vault.integrity.resetSuccess', {
        defaultValue: 'Der Tresor wurde zurückgesetzt und kann jetzt neu eingerichtet werden.',
      }),
    });
    return true;
  };

  const handleResetVault = async () => {
    if (isResetting) {
      return;
    }

    const hasFreshSession = await isSensitiveActionSessionFresh(300);
    if (!hasFreshSession) {
      setShowReauthDialog(true);
      return;
    }

    await executeResetVault();
  };

  return (
    <>
      <main className="min-h-screen bg-background px-4 py-10 lg:px-8">
        <div className="mx-auto flex max-w-5xl flex-col gap-6">
          <Card className="border-amber-500/35">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <ShieldAlert className="w-5 h-5 text-amber-600" />
                {integrityMode === 'safe'
                  ? t('vault.integrity.safeModeTitle', { defaultValue: 'Safe Mode' })
                  : t('vault.integrity.blockedTitle', { defaultValue: 'Tresorzugriff blockiert' })}
              </CardTitle>
              <CardDescription>
                {integrityMode === 'safe'
                  ? safeModeDescription
                  : t('vault.integrity.blockedDescription', {
                    defaultValue: 'Der normale Zugriff wurde blockiert, weil der aktuelle Tresorstand nicht mehr vollständig vertrauenswürdig ist.',
                  })}
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <Alert className="border-amber-500/35 bg-amber-500/5">
                <TriangleAlert className="h-4 w-4 text-amber-600" />
                <AlertDescription>
                  {integrityMode === 'safe'
                    ? t('vault.integrity.safeModeNotice', {
                      defaultValue: 'Safe Mode ist schreibgeschützt. Prüfe deine Einträge und exportiere sie bei Bedarf, bevor du den Tresor zurücksetzt.',
                    })
                    : getBlockedReasonMessage(integrityBlockedReason)}
                </AlertDescription>
              </Alert>

              <div className="flex flex-wrap gap-3">
                {integrityMode !== 'safe' && trustedRecoveryAvailable && (
                  <Button onClick={handleEnterSafeMode} disabled={isPreparingSafeMode}>
                    {isPreparingSafeMode ? (
                      <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                    ) : (
                      <Vault className="mr-2 h-4 w-4" />
                    )}
                    {t('vault.integrity.enterSafeMode', { defaultValue: 'Safe Mode starten' })}
                  </Button>
                )}

                {integrityMode === 'safe' && (
                  <>
                    <Button variant="outline" onClick={handleExport} disabled={isExporting || isLoadingSnapshot}>
                      {isExporting ? (
                        <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                      ) : (
                        <Download className="mr-2 h-4 w-4" />
                      )}
                      {t('vault.integrity.exportTrustedData', { defaultValue: 'Vertrauenswürdige Daten exportieren' })}
                    </Button>
                    <Button variant="outline" onClick={exitSafeMode}>
                      {t('common.back', { defaultValue: 'Zurück' })}
                    </Button>
                  </>
                )}

                <Button variant="destructive" onClick={handleResetVault} disabled={isResetting}>
                  {isResetting ? (
                    <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                  ) : (
                    <RotateCcw className="mr-2 h-4 w-4" />
                  )}
                  {t('vault.integrity.resetVault', { defaultValue: 'Tresor zurücksetzen' })}
                </Button>
              </div>
            </CardContent>
          </Card>

          <VaultQuarantinePanel
            items={quarantinedItems}
            description={t('vault.integrity.quarantineRecoveryDescription', {
              defaultValue: 'Diese Einträge wurden aus dem normalen Tresor entfernt und bleiben bis zur Neuinitialisierung gesperrt.',
            })}
          />

          {integrityMode === 'safe' && (
            <Card>
              <CardHeader>
                <CardTitle>
                  {t('vault.integrity.safeModeItemsTitle', {
                    defaultValue: 'Vertrauenswürdige lokale Einträge',
                  })}
                </CardTitle>
                <CardDescription>{safeModeDescription}</CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                {isLoadingSnapshot ? (
                  <div className="flex items-center justify-center py-10 text-muted-foreground">
                    <Loader2 className="mr-2 h-5 w-5 animate-spin" />
                    {t('common.loading')}
                  </div>
                ) : safeModeItems.length === 0 ? (
                  <p className="text-sm text-muted-foreground">
                    {t('vault.integrity.safeModeEmpty', {
                      defaultValue: 'Für diesen Safe Mode sind keine vertrauenswürdigen lokalen Einträge verfügbar.',
                    })}
                  </p>
                ) : (
                  <div className="flex flex-col gap-3">
                    {safeModeItems.map((item) => (
                      <VaultItemCard
                        key={item.id}
                        item={item}
                        viewMode="list"
                        readOnly
                        onEdit={() => undefined}
                      />
                    ))}
                  </div>
                )}
              </CardContent>
            </Card>
          )}
        </div>
      </main>

      <SensitiveActionReauthDialog
        open={showReauthDialog}
        onOpenChange={setShowReauthDialog}
        description={t('reauth.vaultResetContext')}
        confirmationKeyword={t('reauth.resetKeyword')}
        onSuccess={executeResetVault}
      />
    </>
  );
}
