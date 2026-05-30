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
import { saveExportFile } from '@/services/exportFileService';
import {
  buildVaultOpLogExportPayload,
  importVaultExportPayload,
  parseVaultImportPayload,
} from '@/services/vaultExportService';
import {
  isVaultSecurityModeBlockingEgress,
} from '@/services/vaultOpLog';

export function DataSettings() {
    const { t } = useTranslation();
    const { user } = useAuth();
    const {
        isLocked,
        opLogCreateCategory,
        opLogCreateItem,
        opLogLocalVaultState,
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
            if (!opLogUiView || !opLogLocalVaultState) {
                toast({
                    variant: 'destructive',
                    title: t('common.error'),
                    description: t('vault.export.blockedBySecurityMode', {
                        defaultValue: 'Export ist ohne verifizierten Tresor-Zustand nicht erlaubt.',
                    }),
                });
                return;
            }

            const exportData = buildVaultOpLogExportPayload(opLogLocalVaultState, opLogUiView);

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
            console.error('Export failed');
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
            if (!opLogUiView || !opLogLocalVaultState || isVaultSecurityModeBlockingEgress(opLogUiView.vaultSecurityMode)) {
                toast({
                    variant: 'destructive',
                    title: t('common.error'),
                    description: t('vault.export.blockedBySecurityMode', {
                        defaultValue: 'Import ist ohne verifizierten Tresor-Zustand nicht erlaubt.',
                    }),
                });
                return;
            }

            const payload = parseVaultImportPayload(await importFile.text());
            const result = await importVaultExportPayload(payload, {
                createCategory: opLogCreateCategory,
                createItem: opLogCreateItem,
            });

            toast({
                title: t('common.success'),
                description: t('settings.data.importSuccess', { count: result.itemCount }),
            });
        } catch (error) {
            console.error('Import failed');
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
