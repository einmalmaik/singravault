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

const ENCRYPTED_ITEM_TITLE_PLACEHOLDER = 'Encrypted Item';

interface DataSettingsProps {
    mode?: 'full' | 'export-only';
}

export function DataSettings({ mode = 'full' }: DataSettingsProps) {
    const { t } = useTranslation();
    const { user } = useAuth();
    const { decryptItem, encryptItem, isLocked } = useVault();
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

            // Decrypt all items
            const decryptedItems = await Promise.all(
                items.map(async (item) => {
                    try {
                        const decrypted = await decryptItem(item.encrypted_data, item.id);
                        const resolvedTitle = decrypted.title || item.title;
                        const resolvedWebsiteUrl = decrypted.websiteUrl || item.website_url;
                        const resolvedItemType = decrypted.itemType || item.item_type || 'password';
                        const resolvedFavorite = typeof decrypted.isFavorite === 'boolean'
                            ? decrypted.isFavorite
                            : !!item.is_favorite;
                        const resolvedCategoryId = decrypted.categoryId ?? item.category_id ?? null;
                        return {
                            title: resolvedTitle,
                            website_url: resolvedWebsiteUrl,
                            item_type: resolvedItemType,
                            is_favorite: resolvedFavorite,
                            category_id: resolvedCategoryId,
                            data: decrypted,
                        };
                    } catch {
                        return null;
                    }
                })
            );

            // Filter out failed decryptions
            const validItems = decryptedItems.filter(Boolean);

            // Create export object
            const exportData = {
                version: '1.0',
                exportedAt: new Date().toISOString(),
                itemCount: validItems.length,
                items: validItems,
            };

            // Download as JSON
            const blob = new Blob([JSON.stringify(exportData, null, 2)], {
                type: 'application/json',
            });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `singra-vault-export-${new Date().toISOString().split('T')[0]}.json`;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);

            toast({
                title: t('common.success'),
                description: t('settings.data.exportSuccess', { count: validItems.length }),
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
            const content = await importFile.text();
            const data = JSON.parse(content);

            if (!data.items || !Array.isArray(data.items)) {
                throw new Error('Invalid format');
            }

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

            let imported = 0;

            // Import each item
            for (const item of data.items) {
                try {
                    // SECURITY: Generate ID client-side for AAD binding
                    const newItemId = crypto.randomUUID();

                    // Encrypt the data (with entry ID as AAD)
                    const encryptedData = await encryptItem({
                        ...item.data,
                        title: item.title || item.data?.title || 'Imported Item',
                        websiteUrl: item.website_url || item.data?.websiteUrl || undefined,
                        itemType: item.item_type || item.data?.itemType || 'password',
                        isFavorite: typeof item.is_favorite === 'boolean'
                            ? item.is_favorite
                            : !!item.data?.isFavorite,
                        categoryId: item.category_id ?? item.data?.categoryId ?? null,
                    }, newItemId);

                    // Insert into database
                    await supabase.from('vault_items').insert({
                        id: newItemId,
                        user_id: user.id,
                        vault_id: vault.id,
                        title: ENCRYPTED_ITEM_TITLE_PLACEHOLDER,
                        website_url: null,
                        icon_url: null,
                        item_type: 'password',
                        is_favorite: false,
                        category_id: null,
                        encrypted_data: encryptedData,
                    });

                    imported++;
                } catch (err) {
                    console.error('Failed to import item:', err);
                }
            }

            toast({
                title: t('common.success'),
                description: t('settings.data.importSuccess', { count: imported }),
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
                        {mode === 'export-only'
                            ? t('settings.data.exportOnlyDescription')
                            : t('settings.data.description')}
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

                    {mode === 'full' && (
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
                    )}
                </CardContent>
            </Card>

            {mode === 'full' && (
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
            )}
        </>
    );
}
