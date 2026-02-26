// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 — see LICENSE
/**
 * @fileoverview Authenticator Page
 *
 * Dedicated dashboard for TOTP codes.
 * Features:
 * - Grid view of all TOTP items
 * - Real-time code generation and countdown
 * - Search/Filter
 * - Quick add with scanner support
 * - Premium feature gated
 */

import { useState, useEffect, useMemo } from 'react';
import { useTranslation } from 'react-i18next';
import { useNavigate } from 'react-router-dom';
import { Plus, Search, Shield, Loader2, Edit, ArrowLeft } from 'lucide-react';
import { supabase } from '@/integrations/supabase/client';

import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { useAuth } from '@/contexts/AuthContext';
import { useVault } from '@/contexts/VaultContext';
import { FeatureGate } from '@/components/Subscription/FeatureGate';
import { VaultItemDialog } from '@/components/vault/VaultItemDialog';
import { TOTPDisplay } from '@/components/vault/TOTPDisplay';
import { Footer } from '@/components/landing/Footer';
import { useToast } from '@/hooks/use-toast';
import { isValidTOTPSecret } from '@/services/totpService';

// Reusing VaultItemData from cryptoService but adding id
import { VaultItemData } from '@/services/cryptoService';

interface AuthenticatorItem extends VaultItemData {
    id: string;
    totpSecret: string; // Guaranteed to exist for this view
}

export default function AuthenticatorPage() {
    const { t } = useTranslation();
    const navigate = useNavigate();
    const { user } = useAuth();
    const { decryptItem } = useVault();
    const { toast } = useToast();

    const [items, setItems] = useState<AuthenticatorItem[]>([]);
    const [loading, setLoading] = useState(true);
    const [searchQuery, setSearchQuery] = useState('');

    // Dialog states
    const [dialogOpen, setDialogOpen] = useState(false);
    const [editingItemId, setEditingItemId] = useState<string | null>(null);

    // Fetch and decrypt items
    const loadItems = async () => {
        if (!user) return;
        setLoading(true);

        try {
            const { data: rawItems, error } = await supabase
                .from('vault_items')
                .select('*')
                .eq('user_id', user.id)


            if (error) throw error;

            const decryptedItems: AuthenticatorItem[] = [];

            for (const item of rawItems || []) {
                try {
                    const decrypted = await decryptItem(item.encrypted_data, item.id);
                    // Filter for items with valid TOTP secrets
                    if (decrypted.totpSecret && isValidTOTPSecret(decrypted.totpSecret)) {
                        decryptedItems.push({
                            ...decrypted,
                            id: item.id,
                            totpSecret: decrypted.totpSecret,
                        });
                    }
                } catch (err) {
                    console.error('Failed to decrypt item:', item.id, err);
                    // Skip failed items
                }
            }

            setItems(decryptedItems);
        } catch (err) {
            console.error('Failed to load vault items:', err);
            toast({
                title: t('common.error'),
                description: t('vault.loadError'),
                variant: 'destructive',
            });
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        loadItems();
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [user]);

    const filteredItems = useMemo(() => {
        if (!searchQuery) return items;
        const lowerQuery = searchQuery.toLowerCase();
        return items.filter(
            (item) =>
                item.title.toLowerCase().includes(lowerQuery) ||
                (item.username && item.username.toLowerCase().includes(lowerQuery))
        );
    }, [items, searchQuery]);

    const handleEdit = (id: string) => {
        setEditingItemId(id);
        setDialogOpen(true);
    };

    const handleCloseDialog = (open: boolean) => {
        setDialogOpen(open);
        if (!open) {
            setEditingItemId(null);
            loadItems(); // Refresh on close
        }
    };

    return (
        <div className="min-h-screen flex flex-col bg-gradient-to-br from-primary/5 via-background to-primary/10">
            <header className="sticky top-0 z-50 bg-background/80 backdrop-blur-lg border-b">
                <div className="container max-w-6xl mx-auto px-4 py-4">
                    <div className="flex items-center gap-4">
                        <Button variant="ghost" size="icon" onClick={() => navigate('/vault')}>
                            <ArrowLeft className="w-5 h-5" />
                        </Button>
                        <div className="flex items-center gap-2">
                            <Shield className="w-6 h-6 text-primary" />
                            <h1 className="text-xl font-bold">{t('authenticator.title')}</h1>
                        </div>
                    </div>
                </div>
            </header>

            <main className="container flex-1 py-6 px-4 md:px-6 max-w-6xl mx-auto space-y-6">
                <FeatureGate feature="builtin_authenticator" featureLabel={t('authenticator.title')}>
                    <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
                        <div>
                            <h2 className="text-3xl font-bold tracking-tight">{t('authenticator.title')}</h2>
                            <p className="text-muted-foreground mt-1">{t('authenticator.subtitle')}</p>
                        </div>
                        <Button onClick={() => setDialogOpen(true)} className="gap-2">
                            <Plus className="w-4 h-4" />
                            {t('common.add')}
                        </Button>
                    </div>

                    <div className="relative max-w-md">
                        <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
                        <Input
                            placeholder={t('common.search')}
                            className="pl-9"
                            value={searchQuery}
                            onChange={(e) => setSearchQuery(e.target.value)}
                        />
                    </div>

                    {loading ? (
                        <div className="flex justify-center py-12">
                            <Loader2 className="w-8 h-8 animate-spin text-primary" />
                        </div>
                    ) : filteredItems.length === 0 ? (
                        <div className="text-center py-12 border rounded-lg bg-muted/20">
                            <Shield className="w-12 h-12 mx-auto text-muted-foreground/50 mb-3" />
                            <h3 className="text-lg font-medium">{t('authenticator.emptyTitle')}</h3>
                            <p className="text-muted-foreground mt-1 mb-4">
                                {searchQuery ? t('common.noResults') : t('authenticator.emptyDesc')}
                            </p>
                            {!searchQuery && (
                                <Button variant="outline" onClick={() => setDialogOpen(true)}>
                                    <Plus className="w-4 h-4 mr-2" />
                                    {t('authenticator.addFirst')}
                                </Button>
                            )}
                        </div>
                    ) : (
                        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
                            {filteredItems.map((item) => (
                                <Card key={item.id} className="overflow-hidden hover:border-primary/50 transition-all">
                                    <CardHeader className="pb-2 flex flex-row items-start justify-between space-y-0">
                                        <div className="min-w-0 pr-2">
                                            <CardTitle className="text-base font-semibold truncate" title={item.title}>
                                                {item.title}
                                            </CardTitle>
                                            <CardDescription className="truncate text-xs">{item.username || '\u00A0'}</CardDescription>
                                        </div>
                                        <Button
                                            variant="ghost"
                                            size="icon"
                                            className="h-8 w-8 -mt-1 -mr-2 text-muted-foreground hover:text-primary"
                                            onClick={() => handleEdit(item.id)}
                                        >
                                            <Edit className="w-4 h-4" />
                                        </Button>
                                    </CardHeader>
                                    <CardContent>
                                        <TOTPDisplay secret={item.totpSecret} className="mt-2" />
                                    </CardContent>
                                </Card>
                            ))}
                        </div>
                    )}

                    <VaultItemDialog
                        open={dialogOpen}
                        onOpenChange={handleCloseDialog}
                        itemId={editingItemId}
                        initialType="totp"
                        onSave={() => {
                            handleCloseDialog(false);
                            loadItems();
                        }}
                    />
                </FeatureGate>
            </main>

            <Footer />
        </div>
    );
}
