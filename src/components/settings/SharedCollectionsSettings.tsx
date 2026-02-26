// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE
/**
 * @fileoverview Shared Collections settings UI.
 *
 * Creates/deletes shared collections and provisions missing hybrid key
 * material (RSA + PQ) on first use.
 */

import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { FolderOpen, Loader2, Plus, Trash2 } from 'lucide-react';

import { FeatureGate } from '@/components/Subscription/FeatureGate';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { useAuth } from '@/contexts/AuthContext';
import { useToast } from '@/hooks/use-toast';
import { createCollectionWithHybridKey } from '@/services/collectionService';
import {
  getSharedCollections,
  deleteSharedCollection,
  type SharedCollection,
} from '@/services/familyService';
import {
  ensureHybridKeyMaterial,
  isMasterPasswordRequiredError,
} from '@/services/keyMaterialService';

interface SharedCollectionsSettingsProps {
  bypassFeatureGate?: boolean;
}

export function SharedCollectionsSettings({ bypassFeatureGate = false }: SharedCollectionsSettingsProps) {
  const { t } = useTranslation();
  const { user } = useAuth();
  const { toast } = useToast();

  const [loading, setLoading] = useState(true);
  const [items, setItems] = useState<SharedCollection[]>([]);
  const [name, setName] = useState('');
  const [saving, setSaving] = useState(false);
  const [masterPassword, setMasterPassword] = useState('');
  const [masterPasswordDialogOpen, setMasterPasswordDialogOpen] = useState(false);

  const load = async () => {
    if (!user) return;
    setLoading(true);
    try {
      setItems(await getSharedCollections(user.id));
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : 'Failed to load collections.';
      toast({ variant: 'destructive', title: t('common.error'), description: msg });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [user?.id]);

  const createCollection = async (providedMasterPassword?: string) => {
    if (!user || !name.trim()) {
      return;
    }

    setSaving(true);
    try {
      const keyMaterial = await ensureHybridKeyMaterial({
        userId: user.id,
        masterPassword: providedMasterPassword,
      });

      await createCollectionWithHybridKey(
        name.trim(),
        null,
        keyMaterial.rsaPublicKey,
        keyMaterial.pqPublicKey,
      );

      setName('');
      setMasterPassword('');
      setMasterPasswordDialogOpen(false);
      await load();
      toast({
        title: t('common.success'),
        description: t('settings.sharedCollections.created', { defaultValue: 'Collection created.' }),
      });
    } catch (e: unknown) {
      if (isMasterPasswordRequiredError(e)) {
        setMasterPasswordDialogOpen(true);
        return;
      }

      const msg = e instanceof Error
        ? e.message
        : t('settings.sharedCollections.createError', { defaultValue: 'Failed to create collection.' });
      toast({ variant: 'destructive', title: t('common.error'), description: msg });
    } finally {
      setSaving(false);
    }
  };

  const onCreate = async () => {
    await createCollection();
  };

  const onConfirmMasterPassword = async () => {
    if (!masterPassword) {
      toast({
        variant: 'destructive',
        title: t('common.error'),
        description: t('settings.sharedCollections.masterPasswordRequired', {
          defaultValue: 'Master password is required to provision key material.',
        }),
      });
      return;
    }

    await createCollection(masterPassword);
  };

  const onDelete = async (id: string) => {
    try {
      await deleteSharedCollection(id);
      await load();
      toast({
        title: t('common.success'),
        description: t('settings.sharedCollections.deleted', { defaultValue: 'Collection deleted.' }),
      });
    } catch (e: unknown) {
      const msg = e instanceof Error
        ? e.message
        : t('settings.sharedCollections.deleteError', { defaultValue: 'Failed to delete collection.' });
      toast({ variant: 'destructive', title: t('common.error'), description: msg });
    }
  };

  const content = (
    <>
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <FolderOpen className="w-5 h-5" />
            {t('settings.sharedCollections.title', { defaultValue: 'Shared Collections' })}
          </CardTitle>
          <CardDescription>
            {t('settings.sharedCollections.description', { defaultValue: 'Create collections for sharing vault items with family members.' })}
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex gap-2">
            <Input
              placeholder={t('settings.sharedCollections.namePlaceholder', { defaultValue: 'Collection name' })}
              value={name}
              onChange={(event) => setName(event.target.value)}
            />
            <Button type="button" onClick={onCreate} disabled={saving || !name.trim()}>
              {saving ? <Loader2 className="w-4 h-4 animate-spin" /> : <Plus className="w-4 h-4" />}
            </Button>
          </div>

          {loading ? (
            <div className="flex justify-center py-4"><Loader2 className="w-5 h-5 animate-spin" /></div>
          ) : items.length === 0 ? (
            <p className="text-sm text-muted-foreground">
              {t('settings.sharedCollections.empty', { defaultValue: 'No shared collections yet.' })}
            </p>
          ) : (
            <div className="space-y-2">
              {items.map((collection) => (
                <div key={collection.id} className="flex items-center justify-between border rounded-lg p-3">
                  <div>
                    <p className="font-medium text-sm">{collection.name}</p>
                    <p className="text-xs text-muted-foreground">
                      {collection.description || t('settings.sharedCollections.noDescription', { defaultValue: 'No description' })}
                    </p>
                  </div>
                  <Button
                    type="button"
                    variant="ghost"
                    size="icon"
                    onClick={() => onDelete(collection.id)}
                  >
                    <Trash2 className="w-4 h-4 text-destructive" />
                  </Button>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      <Dialog
        open={masterPasswordDialogOpen}
        onOpenChange={(open) => {
          setMasterPasswordDialogOpen(open);
          if (!open) {
            setMasterPassword('');
          }
        }}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle>
              {t('settings.sharedCollections.masterPasswordTitle', {
                defaultValue: 'Confirm master password',
              })}
            </DialogTitle>
            <DialogDescription>
              {t('settings.sharedCollections.masterPasswordDescription', {
                defaultValue: 'To create your first shared collection, we need to provision hybrid key material for your account.',
              })}
            </DialogDescription>
          </DialogHeader>

          <div className="grid gap-2 py-2">
            <Label htmlFor="shared-collections-master-password">
              {t('auth.masterPassword.password', { defaultValue: 'Master Password' })}
            </Label>
            <Input
              id="shared-collections-master-password"
              type="password"
              value={masterPassword}
              onChange={(event) => setMasterPassword(event.target.value)}
              placeholder={t('settings.sharedCollections.masterPasswordPlaceholder', {
                defaultValue: 'Enter your master password',
              })}
            />
          </div>

          <DialogFooter>
            <Button
              type="button"
              variant="outline"
              onClick={() => {
                setMasterPasswordDialogOpen(false);
                setMasterPassword('');
              }}
            >
              {t('common.cancel')}
            </Button>
            <Button type="button" onClick={onConfirmMasterPassword} disabled={saving || !masterPassword}>
              {saving && <Loader2 className="w-4 h-4 mr-2 animate-spin" />}
              {t('common.confirm', { defaultValue: 'Confirm' })}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );

  if (bypassFeatureGate) {
    return content;
  }

  return (
    <FeatureGate feature="shared_collections" featureLabel={t('subscription.features.shared_collections')}>
      {content}
    </FeatureGate>
  );
}
