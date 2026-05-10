import { useMemo, useState } from 'react';
import { Laptop, Loader2, ShieldCheck, Trash2 } from 'lucide-react';

import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
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
import { useToast } from '@/hooks/use-toast';
import { useVault } from '@/contexts/VaultContext';
import { loadVaultOpLogDeviceIdentity } from '@/services/vaultOpLog/vaultOpLogDeviceStore';
import type { TrustedDeviceRecordV1 } from '@/services/vaultOpLog/types';

function formatDeviceLabel(device: TrustedDeviceRecordV1): string {
  if (device.deviceNameEncrypted.trim().length > 0) {
    return device.deviceNameEncrypted;
  }
  return `Gerät ${device.deviceId.slice(0, 8)}`;
}

function formatDate(value: string | null): string {
  if (!value) {
    return 'Unbekannt';
  }
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return 'Unbekannt';
  }
  return date.toLocaleString();
}

export function TrustedDevicesSettings() {
  const { toast } = useToast();
  const { opLogLocalVaultState, opLogRevokeDevice, opLogUiRefresh, vaultMigrationStatus } = useVault();
  const [busyDeviceId, setBusyDeviceId] = useState<string | null>(null);
  const [devicePendingRemoval, setDevicePendingRemoval] = useState<TrustedDeviceRecordV1 | null>(null);
  const localDeviceId = loadVaultOpLogDeviceIdentity()?.deviceId ?? null;

  const devices = useMemo(() => {
    const records = Array.from(opLogLocalVaultState?.trustedDevicesById.values() ?? []);
    return records.sort((left, right) => {
      if (left.status !== right.status) {
        return left.status === 'trusted' ? -1 : 1;
      }
      return right.addedAt.localeCompare(left.addedAt);
    });
  }, [opLogLocalVaultState]);

  const trustedDeviceCount = devices.filter((device) => device.status === 'trusted').length;
  const canManageDevices = vaultMigrationStatus === 'verified' && Boolean(opLogLocalVaultState);

  const handleRevoke = async (device: TrustedDeviceRecordV1) => {
    setBusyDeviceId(device.deviceId);
    try {
      const result = await opLogRevokeDevice(device.deviceId);
      if (result.error) {
        throw result.error;
      }
      await opLogUiRefresh();
      setDevicePendingRemoval(null);
      toast({
        title: 'Gerät entfernt',
        description: 'Das Gerät ist für diesen Tresor nicht mehr vertrauenswürdig.',
      });
    } catch (error) {
      toast({
        variant: 'destructive',
        title: 'Gerät konnte nicht entfernt werden',
        description: error instanceof Error ? error.message : 'Bitte versuche es erneut.',
      });
    } finally {
      setBusyDeviceId(null);
    }
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <ShieldCheck className="h-5 w-5" />
          Vertrauenswürdige Geräte
        </CardTitle>
        <CardDescription>
          Geräte, die für diesen Tresor Änderungen signieren dürfen.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        {!canManageDevices ? (
          <p className="text-sm text-muted-foreground">
            Die Geräteverwaltung ist verfügbar, sobald dieser Tresor auf den verifizierten Operation-Log migriert wurde.
          </p>
        ) : devices.length === 0 ? (
          <p className="text-sm text-muted-foreground">
            Für diesen Tresor wurden noch keine vertrauenswürdigen Geräte geladen.
          </p>
        ) : (
          <div className="space-y-3">
            {devices.map((device) => {
              const isCurrentDevice = device.deviceId === localDeviceId;
              const isTrusted = device.status === 'trusted';
              const canRevoke = isTrusted && !isCurrentDevice && trustedDeviceCount > 1;
              return (
                <div key={device.deviceId} className="flex flex-col gap-3 rounded-md border p-3 sm:flex-row sm:items-center sm:justify-between">
                  <div className="flex min-w-0 items-start gap-3">
                    <div className="rounded-md bg-primary/10 p-2 text-primary">
                      <Laptop className="h-4 w-4" />
                    </div>
                    <div className="min-w-0 space-y-1">
                      <div className="flex flex-wrap items-center gap-2">
                        <p className="font-medium">{formatDeviceLabel(device)}</p>
                        {isCurrentDevice && (
                          <span className="rounded-full bg-primary/10 px-2 py-0.5 text-xs text-primary">
                            Dieses Gerät
                          </span>
                        )}
                        {!isTrusted && (
                          <span className="rounded-full bg-muted px-2 py-0.5 text-xs text-muted-foreground">
                            Entfernt
                          </span>
                        )}
                      </div>
                      <p className="text-xs text-muted-foreground">
                        Hinzugefügt: {formatDate(device.addedAt)}
                      </p>
                      <p className="font-mono text-xs text-muted-foreground">
                        {device.deviceId}
                      </p>
                    </div>
                  </div>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => setDevicePendingRemoval(device)}
                    disabled={!canRevoke || busyDeviceId === device.deviceId}
                    className="w-full sm:w-auto"
                  >
                    {busyDeviceId === device.deviceId ? (
                      <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                    ) : (
                      <Trash2 className="mr-2 h-4 w-4" />
                    )}
                    Entfernen
                  </Button>
                </div>
              );
            })}
          </div>
        )}
        <p className="text-xs text-muted-foreground">
          Aus Datenschutzgründen werden hier keine IP-Adressen gespeichert oder angezeigt.
        </p>
      </CardContent>
      <AlertDialog open={Boolean(devicePendingRemoval)} onOpenChange={(open) => !open && setDevicePendingRemoval(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Gerät entfernen?</AlertDialogTitle>
            <AlertDialogDescription>
              Dieses Gerät verliert danach seine Schreibberechtigung für den Tresor und muss erneut bestätigt werden.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={Boolean(busyDeviceId)}>Abbrechen</AlertDialogCancel>
            <AlertDialogAction
              onClick={(event) => {
                event.preventDefault();
                if (devicePendingRemoval) {
                  void handleRevoke(devicePendingRemoval);
                }
              }}
              disabled={!devicePendingRemoval || Boolean(busyDeviceId)}
            >
              {busyDeviceId ? (
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
              ) : (
                <Trash2 className="mr-2 h-4 w-4" />
              )}
              Entfernen
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </Card>
  );
}
