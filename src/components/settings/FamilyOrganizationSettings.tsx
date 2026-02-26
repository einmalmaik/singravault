// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 — see LICENSE
import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Users, UserPlus, Trash2, Loader2 } from 'lucide-react';

import { useAuth } from '@/contexts/AuthContext';
import { useToast } from '@/hooks/use-toast';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { FeatureGate } from '@/components/Subscription/FeatureGate';
import { PendingInvitationsAlert } from '@/components/settings/PendingInvitationsAlert';
import { isEdgeFunctionServiceError } from '@/services/edgeFunctionService';
import { getFamilyMembers, inviteFamilyMember, removeFamilyMember, type FamilyMember } from '@/services/familyService';

interface FamilyOrganizationSettingsProps {
  bypassFeatureGate?: boolean;
}

export function FamilyOrganizationSettings({ bypassFeatureGate = false }: FamilyOrganizationSettingsProps) {
  const { t } = useTranslation();
  const { user } = useAuth();
  const { toast } = useToast();

  const [loading, setLoading] = useState(true);
  const [members, setMembers] = useState<FamilyMember[]>([]);
  const [email, setEmail] = useState('');
  const [saving, setSaving] = useState(false);

  const resolveErrorMessage = (error: unknown, fallbackMessage: string) => {
    if (isEdgeFunctionServiceError(error)) {
      if (error.status === 401) {
        return t('common.authRequired');
      }

      if (error.status === 403) {
        return t('common.forbidden');
      }

      if (error.status && error.status >= 500) {
        return t('common.serviceUnavailable');
      }
    }

    return error instanceof Error ? error.message : fallbackMessage;
  };

  const load = async () => {
    if (!user) return;
    setLoading(true);
    try {
      setMembers(await getFamilyMembers(user.id));
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : 'Failed to load family members.';
      toast({ variant: 'destructive', title: t('common.error'), description: msg });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [user?.id]);

  const onInvite = async () => {
    if (!user || !email.trim()) return;
    setSaving(true);
    try {
      await inviteFamilyMember(user.id, email.trim().toLowerCase());
      setEmail('');
      toast({ title: t('common.success'), description: t('settings.family.inviteSent') });
      await load();
    } catch (e: unknown) {
      const msg = resolveErrorMessage(e, t('settings.family.inviteError'));
      toast({ variant: 'destructive', title: t('common.error'), description: msg });
    } finally {
      setSaving(false);
    }
  };

  const onRemove = async (id: string) => {
    try {
      await removeFamilyMember(id);
      await load();
      toast({ title: t('common.success'), description: t('settings.family.removed', { defaultValue: 'Family member removed.' }) });
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : t('settings.family.removeError', { defaultValue: 'Failed to remove family member.' });
      toast({ variant: 'destructive', title: t('common.error'), description: msg });
    }
  };

  const content = (
    <>
      <PendingInvitationsAlert />
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Users className="w-5 h-5" />
            {t('settings.family.title', { defaultValue: 'Family Organization' })}
          </CardTitle>
          <CardDescription>
            {t('settings.family.description', { defaultValue: 'Invite and manage up to 6 premium family members.' })}
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex gap-2">
            <Input
              placeholder={t('settings.family.emailPlaceholder', { defaultValue: 'family@example.com' })}
              value={email}
              onChange={(e) => setEmail(e.target.value)}
            />
            <Button onClick={onInvite} disabled={saving || !email.trim()}>
              {saving ? <Loader2 className="w-4 h-4 animate-spin" /> : <UserPlus className="w-4 h-4" />}
            </Button>
          </div>

          {loading ? (
            <div className="flex justify-center py-4"><Loader2 className="w-5 h-5 animate-spin" /></div>
          ) : members.length === 0 ? (
            <p className="text-sm text-muted-foreground">{t('settings.family.empty', { defaultValue: 'No family members yet.' })}</p>
          ) : (
            <div className="space-y-2">
              {members.map((m) => (
                <div key={m.id} className="flex items-center justify-between border rounded-lg p-3">
                  <div>
                    <p className="font-medium text-sm">{m.member_email}</p>
                    <p className="text-xs text-muted-foreground">{m.role}</p>
                  </div>
                  <div className="flex items-center gap-2">
                    <Badge variant={m.status === 'active' ? 'default' : 'outline'}>{m.status}</Badge>
                    <Button variant="ghost" size="icon" onClick={() => onRemove(m.id)}>
                      <Trash2 className="w-4 h-4 text-destructive" />
                    </Button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>
    </>
  );

  if (bypassFeatureGate) {
    return content;
  }

  return (
    <FeatureGate feature="family_members" featureLabel={t('subscription.features.family_organization')}>
      {content}
    </FeatureGate>
  );
}
