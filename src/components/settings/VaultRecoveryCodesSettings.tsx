import { randomUuid } from '@dis/shield/random';
import { useEffect, useState } from 'react';
import { Download, KeyRound, Loader2, RotateCw } from 'lucide-react';
import { useTranslation } from 'react-i18next';

import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Checkbox } from '@/components/ui/checkbox';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { useAuth } from '@/contexts/AuthContext';
import { useVault } from '@/contexts/VaultContext';
import { useToast } from '@/hooks/use-toast';
import { saveExportFile } from '@/services/exportFileService';
import { supabase } from '@/integrations/supabase/client';
import {
  activateVaultRecoveryCodeSet,
  formatVaultRecoveryCodesDownload,
  getVaultRecoveryCodeStatus,
  prepareVaultRecoveryCodes,
  type VaultRecoveryCodeStatus,
} from '@/services/vaultOpLog/vaultRecoveryCodeService';
import {
  buildRecoveryCodesRotateOperation,
  toVaultOperationRowFromSigned,
} from '@/services/vaultOpLog/vaultOpLogOperationBuilder';
import { loadVerifiedVaultOpLogDeviceContext } from '@/services/vaultOpLog/vaultOpLogDeviceIdentityRecovery';
import { loadVaultOpLogDeviceSigningKey } from '@/services/vaultOpLog/vaultOpLogDeviceSigningKeyStore';
import type { VaultOpLogTrustReadClient } from '@/services/vaultOpLog/vaultOpLogUiOrchestrator';

export function VaultRecoveryCodesSettings() {
  const { user } = useAuth();
  const { i18n } = useTranslation();
  const { toast } = useToast();
  const { opLogVaultId, opLogLocalVaultState, opLogUiRefresh } = useVault();
  const [status, setStatus] = useState<VaultRecoveryCodeStatus | null>(null);
  const [dialogOpen, setDialogOpen] = useState(false);
  const [confirmedLoss, setConfirmedLoss] = useState(false);
  const [confirmedSingleView, setConfirmedSingleView] = useState(false);
  const [isBusy, setIsBusy] = useState(false);

  const canCreateCodes = Boolean(user && opLogVaultId && opLogLocalVaultState);
  const canConfirm = confirmedLoss && confirmedSingleView && !isBusy;

  useEffect(() => {
    let cancelled = false;
    async function loadStatus() {
      if (!opLogVaultId) {
        setStatus(null);
        return;
      }
      try {
        const nextStatus = await getVaultRecoveryCodeStatus(opLogVaultId);
        if (!cancelled) {
          setStatus(nextStatus);
        }
      } catch {
        if (!cancelled) {
          setStatus(null);
        }
      }
    }
    void loadStatus();
    return () => {
      cancelled = true;
    };
  }, [opLogVaultId]);

  async function handleCreateCodes() {
    if (!user || !opLogVaultId || !opLogLocalVaultState) {
      return;
    }
    setIsBusy(true);
    try {
      const prepared = await prepareVaultRecoveryCodes(opLogVaultId);
      const fileSaved = await saveExportFile({
        name: `singra-vault-recovery-codes-${new Date().toISOString().slice(0, 10)}.txt`,
        mime: 'text/plain;charset=utf-8',
        content: formatVaultRecoveryCodesDownload({
          vaultId: opLogVaultId,
          setId: prepared.setId,
          codes: prepared.codes,
          createdAt: prepared.createdAt,
          language: i18n.language,
        }),
      });

      if (!fileSaved) {
        toast({
          title: 'Download abgebrochen',
          description: 'Das neue Recovery-Code-Set wurde nicht aktiviert.',
        });
        return;
      }

      const deviceContext = await loadVerifiedVaultOpLogDeviceContext({
        userId: user.id,
        vaultId: opLogVaultId,
        trustClient: supabase as unknown as VaultOpLogTrustReadClient,
      });
      if (!deviceContext) {
        throw new Error('Dieses Gerät ist für die Aktivierung nicht verifiziert.');
      }
      const signingKey = await loadVaultOpLogDeviceSigningKey({
        userId: user.id,
        vaultId: opLogVaultId,
        deviceId: deviceContext.identity.deviceId,
      });
      if (!signingKey) {
        throw new Error('Der lokale Device-Signing-Key fehlt.');
      }

      const built = await buildRecoveryCodesRotateOperation({
        opId: randomUuid(),
        intentId: randomUuid(),
        rebasedFromOpId: null,
        vaultId: opLogVaultId,
        deviceId: deviceContext.identity.deviceId,
        deviceSigningKey: signingKey,
        trustEpoch: deviceContext.trustEpoch,
        baseVaultHead: opLogLocalVaultState.lastVerifiedVaultHead,
        recoveryCodeSetId: prepared.setId,
        recoveryCodeCommitments: prepared.commitments,
      });

      await activateVaultRecoveryCodeSet({
        vaultId: opLogVaultId,
        setId: prepared.setId,
        operation: toVaultOperationRowFromSigned(built.signedOperation, built.resultingVaultHead),
      });
      await opLogUiRefresh();
      setStatus(await getVaultRecoveryCodeStatus(opLogVaultId));
      setDialogOpen(false);
      setConfirmedLoss(false);
      setConfirmedSingleView(false);
      toast({
        title: 'Recovery-Codes aktiviert',
        description: 'Das neue Set ersetzt ältere unbenutzte Codes.',
      });
    } catch (error) {
      toast({
        variant: 'destructive',
        title: 'Recovery-Codes konnten nicht erstellt werden',
        description: error instanceof Error ? error.message : 'Bitte versuche es erneut.',
      });
    } finally {
      setIsBusy(false);
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <KeyRound className="h-5 w-5" />
          Recovery-Codes für Gerätezugriff
        </CardTitle>
        <CardDescription>
          Einmalcodes, um ein neues Gerät freizuschalten, falls kein vertrauenswürdiges Gerät mehr verfügbar ist.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="rounded-md border p-3 text-sm">
          {status?.hasActiveSet ? (
            <p>
              Aktives Set vorhanden. Verbleibende Codes: <strong>{status.remainingCodes}</strong>
            </p>
          ) : (
            <p className="text-muted-foreground">
              Es ist kein aktives Recovery-Code-Set vorhanden.
            </p>
          )}
        </div>
        <Button onClick={() => setDialogOpen(true)} disabled={!canCreateCodes || isBusy}>
          {status?.hasActiveSet ? (
            <RotateCw className="mr-2 h-4 w-4" />
          ) : (
            <Download className="mr-2 h-4 w-4" />
          )}
          {status?.hasActiveSet ? 'Neue Codes erzeugen' : 'Recovery-Codes herunterladen'}
        </Button>
        <Dialog open={dialogOpen} onOpenChange={setDialogOpen}>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>Recovery-Codes erzeugen?</DialogTitle>
              <DialogDescription>
                Die Codes werden nur einmal heruntergeladen. Ein neues Set ersetzt alle alten unbenutzten Codes.
              </DialogDescription>
            </DialogHeader>
            <div className="space-y-3 text-sm">
              <label className="flex gap-3">
                <Checkbox
                  checked={confirmedLoss}
                  onCheckedChange={(checked) => setConfirmedLoss(checked === true)}
                />
                <span>Ich verstehe, dass Singra Support diese Codes nicht wiederherstellen kann.</span>
              </label>
              <label className="flex gap-3">
                <Checkbox
                  checked={confirmedSingleView}
                  onCheckedChange={(checked) => setConfirmedSingleView(checked === true)}
                />
                <span>Ich speichere die Datei sicher, weil die Codes danach nicht erneut angezeigt werden.</span>
              </label>
            </div>
            <DialogFooter>
              <Button variant="outline" onClick={() => setDialogOpen(false)} disabled={isBusy}>
                Abbrechen
              </Button>
              <Button onClick={handleCreateCodes} disabled={!canConfirm}>
                {isBusy ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Download className="mr-2 h-4 w-4" />}
                Herunterladen und aktivieren
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      </CardContent>
    </Card>
  );
}
