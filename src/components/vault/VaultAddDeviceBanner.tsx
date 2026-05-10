import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Key, Loader2, ShieldAlert } from 'lucide-react';

import { Button } from '@/components/ui/button';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { Input } from '@/components/ui/input';
import { useAuth } from '@/contexts/AuthContext';
import { useVault } from '@/contexts/VaultContext';
import { useToast } from '@/hooks/use-toast';
import { supabase } from '@/integrations/supabase/client';
import {
  createBrowserDeviceIdentity,
  generateBrowserDeviceName,
  generatePairingNonce,
  getBrowserDeviceTrustStatus,
  getCurrentPlatform,
  loadBrowserDeviceIdentity,
  loadBrowserDevicePrivateKey,
} from '@/services/vaultOpLog/addDeviceFlowService';
import {
  buildRecoverDeviceOperation,
  toVaultOperationRowFromSigned,
} from '@/services/vaultOpLog/vaultOpLogOperationBuilder';
import { createPendingDeviceRequest } from '@/services/vaultOpLog/vaultOpLogRepository';
import type { SupabaseRpcClient } from '@/services/vaultOpLog/vaultOpLogRepository';
import {
  computeVaultRecoveryCodeCommitment,
  getVaultRecoveryCodeStatus,
  redeemVaultRecoveryCode,
} from '@/services/vaultOpLog/vaultRecoveryCodeService';
import type { VaultOpLogDeviceIdentity } from '@/services/vaultOpLog/vaultOpLogDeviceStore';

export function VaultAddDeviceBanner() {
  const { t } = useTranslation();
  const { toast } = useToast();
  const { user } = useAuth();
  const { opLogUiView, opLogVaultId, opLogLocalVaultState, opLogUiRefresh } = useVault();

  const [locallyMarkedTrusted, setLocallyMarkedTrusted] = useState(false);
  const [isPending, setIsPending] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [recoveryDialogOpen, setRecoveryDialogOpen] = useState(false);
  const [recoveryCode, setRecoveryCode] = useState('');
  const [isRecovering, setIsRecovering] = useState(false);

  const trustStatus = opLogUiView
    ? getBrowserDeviceTrustStatus(opLogUiView.trustedDeviceIds)
    : { trusted: true as const, deviceId: '' };

  if (locallyMarkedTrusted || trustStatus.trusted || !user || !opLogVaultId) {
    return null;
  }

  const ensurePendingDeviceRequest = async (): Promise<{
    readonly identity: VaultOpLogDeviceIdentity;
    readonly requestId: string | null;
  }> => {
    let identity = loadBrowserDeviceIdentity();
    if (!identity) {
      const generated = await createBrowserDeviceIdentity(user.id, opLogVaultId);
      identity = generated.identity;
    }

    const result = await createPendingDeviceRequest(
      supabase as unknown as SupabaseRpcClient,
      {
        vaultId: opLogVaultId,
        requestedDeviceId: identity.deviceId,
        requestedDeviceName: generateBrowserDeviceName(),
        requestedPublicSigningKey: identity.publicSigningKeyB64Url,
        requestedDevicePlatform: getCurrentPlatform(),
        pairingNonce: generatePairingNonce(),
      },
    );

    if (result.kind === 'alreadyTrusted') {
      setLocallyMarkedTrusted(true);
      await opLogUiRefresh();
      return { identity, requestId: null };
    }
    if (result.kind !== 'created') {
      throw new Error(result.kind);
    }

    setIsPending(true);
    return { identity, requestId: result.requestId };
  };

  const handleStartPairing = async () => {
    setIsLoading(true);
    try {
      await ensurePendingDeviceRequest();
      toast({
        title: t('vault.addDevice.requestSent', { defaultValue: 'Geräte-Anfrage gesendet' }),
        description: t('vault.addDevice.requestSentDesc', { defaultValue: 'Bitte bestätige dieses Gerät auf einem bereits vertrauenswürdigen Gerät.' }),
      });
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

  const handleRecoverWithCode = async () => {
    if (!opLogLocalVaultState) {
      return;
    }
    setIsRecovering(true);
    try {
      const status = await getVaultRecoveryCodeStatus(opLogVaultId);
      if (!status.hasActiveSet || !status.activeSetId) {
        throw new Error('Für diesen Tresor ist kein aktives Recovery-Code-Set vorhanden.');
      }

      const pending = await ensurePendingDeviceRequest();
      if (!pending.requestId) {
        return;
      }

      const privateKey = await loadBrowserDevicePrivateKey(
        user.id,
        opLogVaultId,
        pending.identity.deviceId,
      );
      if (!privateKey) {
        throw new Error('Der lokale Device-Signing-Key fehlt.');
      }

      const commitment = await computeVaultRecoveryCodeCommitment({
        vaultId: opLogVaultId,
        setId: status.activeSetId,
        recoveryCode,
      });
      const built = await buildRecoverDeviceOperation({
        opId: crypto.randomUUID(),
        intentId: crypto.randomUUID(),
        rebasedFromOpId: null,
        vaultId: opLogVaultId,
        deviceId: pending.identity.deviceId,
        deviceSigningKey: privateKey,
        targetPublicSigningKey: pending.identity.publicSigningKeyB64Url,
        baseVaultHead: opLogLocalVaultState.lastVerifiedVaultHead,
        recoveryCodeSetId: status.activeSetId,
        recoveryCodeCommitment: commitment,
      });

      await redeemVaultRecoveryCode({
        vaultId: opLogVaultId,
        requestId: pending.requestId,
        recoveryCode,
        operation: toVaultOperationRowFromSigned(built.signedOperation, built.resultingVaultHead),
      });

      setRecoveryCode('');
      setRecoveryDialogOpen(false);
      await opLogUiRefresh();
      setLocallyMarkedTrusted(true);
      toast({
        title: 'Gerät wiederhergestellt',
        description: 'Dieses Gerät ist nach der verifizierten Synchronisierung wieder vertrauenswürdig.',
      });
    } catch (error) {
      toast({
        variant: 'destructive',
        title: 'Recovery fehlgeschlagen',
        description: error instanceof Error ? error.message : 'Bitte prüfe den Code und versuche es erneut.',
      });
    } finally {
      setIsRecovering(false);
    }
  };

  return (
    <div className="mb-4 flex flex-col items-start justify-between gap-4 rounded-lg border border-amber-500/35 bg-amber-500/5 p-4 sm:flex-row sm:items-center">
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
      <div className="flex w-full shrink-0 flex-col gap-2 sm:w-auto">
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
        <Button
          type="button"
          variant="ghost"
          onClick={() => setRecoveryDialogOpen(true)}
          disabled={isRecovering}
          className="w-full sm:w-auto"
        >
          Mit Recovery-Code wiederherstellen
        </Button>
      </div>
      <Dialog open={recoveryDialogOpen} onOpenChange={setRecoveryDialogOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Gerät per Recovery-Code freischalten</DialogTitle>
            <DialogDescription>
              Nutze einen einmaligen Recovery-Code nur, wenn kein vertrauenswürdiges Gerät verfügbar ist.
            </DialogDescription>
          </DialogHeader>
          <Input
            value={recoveryCode}
            onChange={(event) => setRecoveryCode(event.target.value)}
            placeholder="SVR-..."
            autoComplete="one-time-code"
            disabled={isRecovering}
          />
          <DialogFooter>
            <Button variant="outline" onClick={() => setRecoveryDialogOpen(false)} disabled={isRecovering}>
              Abbrechen
            </Button>
            <Button onClick={handleRecoverWithCode} disabled={isRecovering || recoveryCode.trim().length === 0}>
              {isRecovering && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
              Wiederherstellen
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
