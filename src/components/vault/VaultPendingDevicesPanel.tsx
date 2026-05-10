import { useState, useEffect } from 'react';
import { useTranslation } from 'react-i18next';
import { ShieldCheck, Loader2, MonitorSmartphone, Check, X } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { useVault } from '@/contexts/VaultContext';
import { useAuth } from '@/contexts/AuthContext';
import { loadBrowserDeviceIdentity } from '@/services/vaultOpLog/addDeviceFlowService';
import { getPendingDeviceRequests } from '@/services/vaultOpLog/vaultOpLogRepository';
import { useToast } from '@/hooks/use-toast';
import { supabase } from '@/integrations/supabase/client';
import type { PendingDeviceRequestRow } from '@/services/vaultOpLog/addDeviceFlowTypes';

export function VaultPendingDevicesPanel() {
  const { t } = useTranslation();
  const { toast } = useToast();
  const { user } = useAuth();
  const { opLogUiView, vaultMigrationKeyContext, opLogApproveDeviceRequest, opLogRejectDeviceRequest } = useVault();

  const [isTrusted, setIsTrusted] = useState<boolean>(false);
  const [requests, setRequests] = useState<PendingDeviceRequestRow[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [isActionLoading, setIsActionLoading] = useState<string | null>(null);

  useEffect(() => {
    if (!opLogUiView || !user) return;
    const identity = loadBrowserDeviceIdentity();
    if (!identity) return;
    setIsTrusted(opLogUiView.trustedDeviceIds.includes(identity.deviceId));
  }, [opLogUiView, user]);

  const loadRequests = async () => {
    if (!vaultMigrationKeyContext?.vaultId) return;
    setIsLoading(true);
    try {
      const result = await getPendingDeviceRequests(supabase as any, {
        vaultId: vaultMigrationKeyContext.vaultId,
      });
      if (result.kind === 'success') {
        setRequests(result.requests);
      }
    } catch (e) {
      console.error('Failed to load pending device requests', e);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    if (isTrusted && vaultMigrationKeyContext?.vaultId) {
      void loadRequests();
      // Polling could be added here
    }
  }, [isTrusted, vaultMigrationKeyContext?.vaultId]);

  if (!isTrusted || requests.length === 0) {
    return null;
  }

  const handleApprove = async (requestId: string) => {
    setIsActionLoading(requestId);
    try {
      const result = await opLogApproveDeviceRequest(requestId);
      if (result.error) throw result.error;
      
      toast({
        title: t('common.success'),
        description: t('vault.addDevice.approved', { defaultValue: 'Gerät wurde erfolgreich autorisiert.' }),
      });
      await loadRequests();
    } catch (e) {
      toast({
        variant: 'destructive',
        title: t('common.error'),
        description: e instanceof Error ? e.message : 'Konnte Gerät nicht genehmigen.',
      });
    } finally {
      setIsActionLoading(null);
    }
  };

  const handleReject = async (requestId: string) => {
    setIsActionLoading(requestId);
    try {
      const result = await opLogRejectDeviceRequest(requestId);
      if (result.error) throw result.error;

      toast({
        title: t('common.success'),
        description: t('vault.addDevice.rejected', { defaultValue: 'Anfrage wurde abgelehnt.' }),
      });
      await loadRequests();
    } catch (e) {
      toast({
        variant: 'destructive',
        title: t('common.error'),
        description: e instanceof Error ? e.message : 'Konnte Anfrage nicht ablehnen.',
      });
    } finally {
      setIsActionLoading(null);
    }
  };

  return (
    <div className="rounded-lg border border-primary/20 bg-primary/5 p-4 mb-4">
      <div className="flex items-center gap-2 mb-4">
        <ShieldCheck className="h-5 w-5 text-primary" />
        <h3 className="font-medium text-primary">
          {t('vault.addDevice.pendingRequestsTitle', { defaultValue: 'Neue Geräteanfragen' })}
        </h3>
      </div>
      
      <div className="space-y-3">
        {isLoading && requests.length === 0 ? (
          <div className="flex items-center justify-center p-4">
            <Loader2 className="h-5 w-5 animate-spin text-muted-foreground" />
          </div>
        ) : (
          requests.map((req) => (
            <div key={req.id} className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 p-3 bg-background rounded-md border">
              <div className="flex items-center gap-3">
                <div className="bg-primary/10 p-2 rounded-full">
                  <MonitorSmartphone className="h-4 w-4 text-primary" />
                </div>
                <div>
                  <p className="text-sm font-medium">{req.requested_device_name}</p>
                  <p className="text-xs text-muted-foreground">{new Date(req.created_at).toLocaleString()}</p>
                </div>
              </div>
              <div className="flex gap-2 w-full sm:w-auto">
                <Button 
                  variant="outline" 
                  size="sm" 
                  className="w-full sm:w-auto"
                  onClick={() => handleReject(req.id)}
                  disabled={isActionLoading === req.id}
                >
                  <X className="h-4 w-4 mr-1" />
                  {t('common.reject', { defaultValue: 'Ablehnen' })}
                </Button>
                <Button 
                  size="sm" 
                  className="w-full sm:w-auto"
                  onClick={() => handleApprove(req.id)}
                  disabled={isActionLoading === req.id}
                >
                  {isActionLoading === req.id ? (
                    <Loader2 className="h-4 w-4 animate-spin mr-1" />
                  ) : (
                    <Check className="h-4 w-4 mr-1" />
                  )}
                  {t('common.approve', { defaultValue: 'Genehmigen' })}
                </Button>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
}
