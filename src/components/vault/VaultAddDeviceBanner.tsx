import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { ShieldAlert, Key, Loader2 } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { useVault } from '@/contexts/VaultContext';
import { useAuth } from '@/contexts/AuthContext';
import {
  loadBrowserDeviceIdentity,
  createBrowserDeviceIdentity,
  generateBrowserDeviceName,
  generatePairingNonce,
  getCurrentPlatform,
  getBrowserDeviceTrustStatus,
} from '@/services/vaultOpLog/addDeviceFlowService';
import { createPendingDeviceRequest } from '@/services/vaultOpLog/vaultOpLogRepository';
import type { SupabaseRpcClient } from '@/services/vaultOpLog/vaultOpLogRepository';
import { useToast } from '@/hooks/use-toast';
import { supabase } from '@/integrations/supabase/client';

export function VaultAddDeviceBanner() {
  const { t } = useTranslation();
  const { toast } = useToast();
  const { user } = useAuth();
  const { opLogUiView, opLogVaultId, opLogUiRefresh } = useVault();

  const [locallyMarkedTrusted, setLocallyMarkedTrusted] = useState(false);
  const [isPending, setIsPending] = useState(false);
  const [isLoading, setIsLoading] = useState(false);

  const trustStatus = opLogUiView
    ? getBrowserDeviceTrustStatus(opLogUiView.trustedDeviceIds)
    : { trusted: true as const, deviceId: '' };

  if (locallyMarkedTrusted || trustStatus.trusted || !user || !opLogVaultId) {
    return null;
  }

  const handleStartPairing = async () => {
    setIsLoading(true);
    try {
      let identity = loadBrowserDeviceIdentity();
      if (!identity) {
        const generated = await createBrowserDeviceIdentity(
          user.id,
          opLogVaultId,
        );
        identity = generated.identity;
      }

      const nonce = generatePairingNonce();

      const result = await createPendingDeviceRequest(
        supabase as unknown as SupabaseRpcClient,
        {
          vaultId: opLogVaultId,
          requestedDeviceId: identity.deviceId,
          requestedDeviceName: generateBrowserDeviceName(),
          requestedPublicSigningKey: identity.publicSigningKeyB64Url,
          requestedDevicePlatform: getCurrentPlatform(),
          pairingNonce: nonce,
        },
      );

      if (result.kind === 'created') {
        setIsPending(true);
        toast({
          title: t('vault.addDevice.requestSent', { defaultValue: 'Geräte-Anfrage gesendet' }),
          description: t('vault.addDevice.requestSentDesc', { defaultValue: 'Bitte bestätige dieses Gerät auf einem bereits vertrauenswürdigen Gerät.' }),
        });
      } else if (result.kind === 'alreadyTrusted') {
        setLocallyMarkedTrusted(true);
        await opLogUiRefresh();
      } else {
        throw new Error(result.kind);
      }
    } catch {
      toast({
        variant: 'destructive',
        title: t('common.error'),
        description: t('vault.addDevice.error', { defaultValue: 'Die Anfrage konnte nicht gesendet werden.' }),
      });
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 rounded-lg border border-amber-500/35 bg-amber-500/5 p-4 mb-4">
      <div className="flex items-start gap-3">
        <ShieldAlert className="mt-0.5 h-5 w-5 shrink-0 text-amber-600" />
        <div className="space-y-1">
          <h3 className="font-medium text-amber-800 dark:text-amber-300">
            {t('vault.addDevice.untrustedTitle', { defaultValue: 'Gerät nicht vertrauenswürdig' })}
          </h3>
          <p className="text-sm text-amber-700/80 dark:text-amber-400/80">
            {isPending
              ? t('vault.addDevice.pendingDesc', { defaultValue: 'Anfrage ausstehend. Bitte auf einem bestehenden Gerät bestätigen.' })
              : t('vault.addDevice.untrustedDesc', { defaultValue: 'Dieses Gerät ist angemeldet, aber noch nicht für diesen Tresor bestätigt. Bestätige es auf einem bereits vertrauenswürdigen Gerät, bevor Inhalte angezeigt oder Änderungen erlaubt werden.' })}
          </p>
        </div>
      </div>
      <div className="shrink-0 w-full sm:w-auto">
        {isPending ? (
          <Button variant="outline" className="w-full sm:w-auto" disabled>
            <Loader2 className="mr-2 h-4 w-4 animate-spin" />
            {t('vault.addDevice.waiting', { defaultValue: 'Warte auf Bestätigung...' })}
          </Button>
        ) : (
          <Button onClick={handleStartPairing} disabled={isLoading} className="w-full sm:w-auto">
            {isLoading ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Key className="mr-2 h-4 w-4" />}
            {t('vault.addDevice.startPairing', { defaultValue: 'Gerät koppeln' })}
          </Button>
        )}
      </div>
    </div>
  );
}
