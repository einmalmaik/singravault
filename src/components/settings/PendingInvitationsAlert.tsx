// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 — see LICENSE
import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { Button } from '@/components/ui/button';
import { Users, Check, X } from 'lucide-react';
import { toast } from 'sonner';
import {
  getPendingInvitations,
  acceptFamilyInvitation,
  declineFamilyInvitation,
  type FamilyMember,
} from '@/services/familyService';

export function PendingInvitationsAlert() {
  const { t } = useTranslation();
  const [invitations, setInvitations] = useState<FamilyMember[]>([]);
  const [loading, setLoading] = useState(true);
  const [processingId, setProcessingId] = useState<string | null>(null);

  useEffect(() => {
    loadInvitations();
  }, []);

  async function loadInvitations() {
    try {
      const data = await getPendingInvitations();
      setInvitations(data);
    } catch (error) {
      console.error('Failed to load invitations:', error);
    } finally {
      setLoading(false);
    }
  }

  async function handleAccept(invitationId: string) {
    setProcessingId(invitationId);
    try {
      await acceptFamilyInvitation(invitationId);
      toast.success(t('family.invitationAccepted'));
      await loadInvitations();
    } catch (error) {
      console.error('Failed to accept invitation:', error);
      toast.error(t('family.invitationAcceptError'));
    } finally {
      setProcessingId(null);
    }
  }

  async function handleDecline(invitationId: string) {
    setProcessingId(invitationId);
    try {
      await declineFamilyInvitation(invitationId);
      toast.success(t('family.invitationDeclined'));
      await loadInvitations();
    } catch (error) {
      console.error('Failed to decline invitation:', error);
      toast.error(t('family.invitationDeclineError'));
    } finally {
      setProcessingId(null);
    }
  }

  if (loading || invitations.length === 0) {
    return null;
  }

  return (
    <div className="space-y-3">
      {invitations.map((invitation) => (
        <Alert key={invitation.id} className="border-blue-200 bg-blue-50 dark:border-blue-900 dark:bg-blue-950">
          <Users className="h-4 w-4" />
          <AlertTitle>{t('family.pendingInvitation')}</AlertTitle>
          <AlertDescription className="mt-2">
            <p className="mb-3">
              {t('family.invitationMessage', { count: invitations.length })}
            </p>
            <div className="flex gap-2">
              <Button
                size="sm"
                onClick={() => handleAccept(invitation.id)}
                disabled={processingId === invitation.id}
              >
                <Check className="mr-2 h-4 w-4" />
                {t('family.accept')}
              </Button>
              <Button
                size="sm"
                variant="outline"
                onClick={() => handleDecline(invitation.id)}
                disabled={processingId === invitation.id}
              >
                <X className="mr-2 h-4 w-4" />
                {t('family.decline')}
              </Button>
            </div>
          </AlertDescription>
        </Alert>
      ))}
    </div>
  );
}
