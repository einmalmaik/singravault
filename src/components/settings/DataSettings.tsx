// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 — see LICENSE
/**
 * @fileoverview Data Settings Component
 * 
 * Data export and import functionality
 */

import { useState, useRef } from 'react';
import { useTranslation } from 'react-i18next';
import { Database, Download, Upload, Loader2, FileJson } from 'lucide-react';

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Label } from '@/components/ui/label';
import { Input } from '@/components/ui/input';
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

import { useAuth } from '@/contexts/AuthContext';
import { useVault } from '@/contexts/VaultContext';
import { useToast } from '@/hooks/use-toast';
import { supabase } from '@/integrations/supabase/client';
import { saveExportFile } from '@/services/exportFileService';
import { buildVaultExportPayload } from '@/services/vaultExportService';
import {
  getVerifiedRecordIdsForEgress,
  isVaultSecurityModeBlockingEgress,
} from '@/services/vaultOpLog';
import { LEGACY_VAULT_WRITE_BLOCKED_MESSAGE } from '@/services/vaultOpLog/vaultLegacyWriteBlocker';

export function DataSettings() {
    const { t } = useTranslation();
    const { user } = useAuth();
    const {
        decryptItem,
        isLocked,
        opLogUiView,
    } = useVault();
    const { toast } = useToast();
    const fileInputRef = useRef<HTMLInputElement>(null);

    const [isExporting, setIsExporting] = useState(false);
    const [isImporting, setIsImporting] = useState(false);
    const [showImportDialog, setShowImportDialog] = useState(false);
    const [importFile, setImportFile] = useState<File | null>(null);

    const handleExport = async () => {
        if (!user || isLocked) {
            toast({
                variant: 'destructive',
                title: t('common.error'),
                description: t('settings.data.unlockRequired'),
            });
            return;
        }

        setIsExporting(true);
        try {
            // Get user's vault
            const { data: vault } = await supabase
                .from('vaults')
                .select('id')
                .eq('user_id', user.id)
                .eq('is_default', true)
                .single();

            if (!vault) {
                throw new Error('No vault found');
            }

            // Get all vault items
            const { data: items } = await supabase
                .from('vault_items')
                .select('*')
                .eq('vault_id', vault.id);

            if (!items) {
                throw new Error('Failed to fetch items');
            }

            // Phase 10: apply central egress policy.
            if (opLogUiView && isVaultSecurityModeBlockingEgress(opLogUiView.vaultSecurityMode)) {
                toast({
                    variant: 'destructive',
                    title: t('common.error'),
                    description: t('vault.export.blockedBySecurityMode', {
                        defaultValue: 'Export ist aufgrund des aktuellen Tresor-Sicherheitsmodus nicht erlaubt.',
                    }),
                });
                return;
            }
            const allowedItemIds = getVerifiedRecordIdsForEgress(opLogUiView);

            const exportData = await buildVaultExportPayload(items, decryptItem, {
                allowedItemIds: allowedItemIds ?? undefined,
            });

            const saved = await saveExportFile({
                name: `singra-vault-export-${new Date().toISOString().split('T')[0]}.json`,
                mime: 'application/json',
                content: JSON.stringify(exportData, null, 2),
            });

            if (!saved) {
                return;
            }

            toast({
                title: t('common.success'),
                description: t('settings.data.exportSuccess', { count: exportData.itemCount }),
            });
        } catch (error) {
            console.error('Export failed:', error);
            toast({
                variant: 'destructive',
                title: t('common.error'),
                description: t('settings.data.exportFailed'),
            });
        } finally {
            setIsExporting(false);
        }
    };

    const handleFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
        const file = e.target.files?.[0];
        if (file) {
            setImportFile(file);
            setShowImportDialog(true);
        }
    };

    const handleImport = async () => {
        if (!user || !importFile || isLocked) return;

        setIsImporting(true);
        try {
            toast({
                variant: 'destructive',
                title: t('common.error'),
                description: LEGACY_VAULT_WRITE_BLOCKED_MESSAGE,
            });
        } catch (error) {
            console.error('Import failed:', error);
            toast({
                variant: 'destructive',
                title: t('common.error'),
                description: t('settings.data.importFailed'),
            });
        } finally {
            setIsImporting(false);
            setShowImportDialog(false);
            setImportFile(null);
            if (fileInputRef.current) {
                fileInputRef.current.value = '';
            }
        }
    };

    return (
        <>
            <Card>
                <CardHeader>
                    <CardTitle className="flex items-center gap-2">
                        <Database className="w-5 h-5" />
                        {t('settings.data.title')}
                    </CardTitle>
                    <CardDescription>
                        {t('settings.data.description')}
                    </CardDescription>
                </CardHeader>
                <CardContent className="space-y-6">
                    {/* Export */}
                    <div className="space-y-2">
                        <Label className="flex items-center gap-2">
                            <Download className="w-4 h-4" />
                            {t('settings.data.export')}
                        </Label>
                        <p className="text-sm text-muted-foreground mb-2">
                            {t('settings.data.exportDesc')}
                        </p>
                        <Button
                            variant="outline"
                            onClick={handleExport}
                            disabled={isExporting || isLocked}
                            className="flex items-center gap-2"
                        >
                            {isExporting ? (
                                <Loader2 className="w-4 h-4 animate-spin" />
                            ) : (
                                <FileJson className="w-4 h-4" />
                            )}
                            {t('settings.data.exportButton')}
                        </Button>
                    </div>

                    <div className="space-y-2">
                        <Label className="flex items-center gap-2">
                            <Upload className="w-4 h-4" />
                            {t('settings.data.import')}
                        </Label>
                        <p className="text-sm text-muted-foreground mb-2">
                            {t('settings.data.importDesc')}
                        </p>
                        <Input
                            ref={fileInputRef}
                            type="file"
                            accept=".json"
                            onChange={handleFileSelect}
                            disabled={isLocked}
                            className="max-w-xs"
                        />
                    </div>
                </CardContent>
            </Card>

            <AlertDialog open={showImportDialog} onOpenChange={setShowImportDialog}>
                <AlertDialogContent>
                    <AlertDialogHeader>
                        <AlertDialogTitle>
                            {t('settings.data.importConfirmTitle')}
                        </AlertDialogTitle>
                        <AlertDialogDescription>
                            {t('settings.data.importConfirmDesc')}
                        </AlertDialogDescription>
                    </AlertDialogHeader>
                    <AlertDialogFooter>
                        <AlertDialogCancel>
                            {t('common.cancel')}
                        </AlertDialogCancel>
                        <AlertDialogAction onClick={handleImport} disabled={isImporting}>
                            {isImporting && <Loader2 className="w-4 h-4 mr-2 animate-spin" />}
                            {t('settings.data.importButton')}
                        </AlertDialogAction>
                    </AlertDialogFooter>
                </AlertDialogContent>
            </AlertDialog>
        </>
    );
}
