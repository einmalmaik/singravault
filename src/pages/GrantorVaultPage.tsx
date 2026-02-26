// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 — see LICENSE

import { useEffect, useState, useMemo } from 'react';
import { useTranslation } from 'react-i18next';
import { useLocation, useNavigate } from 'react-router-dom';
import {
    ArrowLeft,
    Search,
    Loader2,
    Shield,
    Key,
    FileText,
    Star,
    Grid3X3,
    List,
    AlertTriangle
} from 'lucide-react';

import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Tabs, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { useToast } from '@/hooks/use-toast';
import { supabase } from '@/integrations/supabase/client';
import {
    importMasterKey,
    decryptVaultItem,
    VaultItemData
} from '@/services/cryptoService';
import { VaultItemCard } from '@/components/vault/VaultItemCard';
import { cn } from '@/lib/utils';
import { ItemFilter, ViewMode } from './VaultPage';
import { Footer } from '@/components/landing/Footer';

interface GrantorVaultState {
    masterKey: number[]; // Raw bytes from JSON.parse()
    grantorName: string;
    grantorId: string;
}

interface VaultItem {
    id: string;
    vault_id: string;
    title: string;
    website_url: string | null;
    icon_url: string | null;
    item_type: 'password' | 'note' | 'totp' | 'card';
    is_favorite: boolean | null;
    created_at: string;
    updated_at: string;
    encrypted_data: string;
    // Decrypted data
    decryptedData?: VaultItemData;
}

export default function GrantorVaultPage() {
    const { t } = useTranslation();
    const navigate = useNavigate();
    const location = useLocation();
    const { toast } = useToast();

    // State
    const [loading, setLoading] = useState(true);
    const [items, setItems] = useState<VaultItem[]>([]);
    const [searchQuery, setSearchQuery] = useState('');
    const [activeFilter, setActiveFilter] = useState<ItemFilter>('all');
    const [viewMode, setViewMode] = useState<ViewMode>('grid');
    const [decrypting, setDecrypting] = useState(false);

    // Get state from navigation
    const state = location.state as GrantorVaultState | null;

    useEffect(() => {
        if (!state?.masterKey || !state?.grantorId) {
            toast({
                variant: 'destructive',
                title: t('common.error'),
                description: t('emergency.invalidLink', 'Invalid access link. Please try again from settings.')
            });
            navigate('/settings');
            return;
        }

        fetchAndDecryptItems();
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [state, navigate, t]);

    const fetchAndDecryptItems = async () => {
        if (!state) return;

        try {
            setLoading(true);

            // 1. Import the Master Key
            const masterKeyBytes = new Uint8Array(state.masterKey);
            const cryptoKey = await importMasterKey(masterKeyBytes);

            // 2. Fetch Grantor's Vault Items
            // We fetch items belonging to the grantor
            // Note: RLS must allow this because we have an accepted emergency access record
            // The RLS policy for 'vault_items' likely checks 'emergency_access' table.
            const { data: vaultItems, error } = await supabase
                .from('vault_items')
                .select('*')
                .eq('user_id', state.grantorId);

            if (error) throw error;

            // 3. Decrypt Items
            setDecrypting(true);
            const decryptedItems = await Promise.all(
                (vaultItems || []).map(async (item) => {
                    try {
                        const decryptedData = await decryptVaultItem(item.encrypted_data, cryptoKey);
                        return {
                            ...item,
                            decryptedData
                        } as VaultItem;
                    } catch (err) {
                        console.error(`Failed to decrypt item ${item.id}`, err);
                        return {
                            ...item,
                            decryptedData: undefined
                        } as VaultItem;
                    }
                })
            );

            setItems(decryptedItems);

        } catch (error) {
            console.error('Error fetching grantor vault:', error);
            toast({
                variant: 'destructive',
                title: t('common.error'),
                description: t('emergency.fetchError', 'Failed to load vault items.')
            });
        } finally {
            setLoading(false);
            setDecrypting(false);
        }
    };

    // Filter items
    const filteredItems = useMemo(() => {
        return items.filter((item) => {
            if (!item.decryptedData) return false; // Hide items that failed decryption

            const resolvedItemType = item.decryptedData.itemType || 'password';
            const resolvedIsFavorite = !!item.decryptedData.isFavorite;

            // Filter by type
            if (activeFilter === 'passwords' && resolvedItemType !== 'password') return false;
            if (activeFilter === 'notes' && resolvedItemType !== 'note') return false;
            if (activeFilter === 'totp' && resolvedItemType !== 'totp') return false;
            if (activeFilter === 'favorites' && !resolvedIsFavorite) return false;

            // Filter by search
            if (searchQuery) {
                const query = searchQuery.toLowerCase();
                const title = (item.decryptedData.title || item.title).toLowerCase();
                const username = (item.decryptedData.username || '').toLowerCase();
                const url = (item.decryptedData.websiteUrl || '').toLowerCase();

                if (!title.includes(query) && !username.includes(query) && !url.includes(query)) {
                    return false;
                }
            }

            return true;
        });
    }, [items, activeFilter, searchQuery]);

    const handleCopy = () => {
        toast({
            title: t('vault.copied'),
            description: t('vault.copiedHelpers.readOnly', 'Item copied to clipboard.')
        });
    };

    if (!state) return null;

    return (
        <div className="min-h-screen bg-background flex flex-col">
            {/* Header with Warning Banner */}
            <div className="bg-amber-500/10 border-b border-amber-500/20 px-4 py-2 flex items-center justify-center text-amber-700 dark:text-amber-400 text-sm font-medium">
                <AlertTriangle className="w-4 h-4 mr-2" />
                {t('emergency.readOnlyMode', 'You are viewing {name}\'s vault in Read-Only mode via Emergency Access.', { name: state.grantorName })}
            </div>

            {/* Main Header */}
            <header className="sticky top-0 z-10 bg-background/95 backdrop-blur border-b px-4 lg:px-6 py-4">
                <div className="flex flex-col gap-3 sm:flex-row sm:gap-4 items-start sm:items-center justify-between">
                    <div className="flex items-center gap-2">
                        <Button variant="ghost" size="icon" onClick={() => navigate('/settings')}>
                            <ArrowLeft className="w-5 h-5" />
                        </Button>
                        <h1 className="text-xl font-bold truncate">
                            {state.grantorName}'s Vault
                        </h1>
                    </div>

                    {/* Search */}
                    <div className="relative w-full sm:max-w-md min-w-0">
                        <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
                        <Input
                            placeholder={t('vault.search.placeholder')}
                            value={searchQuery}
                            onChange={(e) => setSearchQuery(e.target.value)}
                            className="pl-10"
                        />
                    </div>

                    {/* View Filters */}
                    <div className="flex items-center gap-2">
                        <div className="hidden sm:flex border rounded-lg p-0.5">
                            <Button
                                variant={viewMode === 'grid' ? 'secondary' : 'ghost'}
                                size="icon"
                                className="h-8 w-8"
                                onClick={() => setViewMode('grid')}
                            >
                                <Grid3X3 className="w-4 h-4" />
                            </Button>
                            <Button
                                variant={viewMode === 'list' ? 'secondary' : 'ghost'}
                                size="icon"
                                className="h-8 w-8"
                                onClick={() => setViewMode('list')}
                            >
                                <List className="w-4 h-4" />
                            </Button>
                        </div>
                    </div>
                </div>

                {/* Type Filters */}
                <Tabs value={activeFilter} onValueChange={(v) => setActiveFilter(v as ItemFilter)} className="mt-4">
                    <TabsList>
                        <TabsTrigger value="all" className="flex items-center gap-1.5">
                            <Shield className="w-4 h-4" />
                            {t('vault.filters.all')}
                        </TabsTrigger>
                        <TabsTrigger value="passwords" className="flex items-center gap-1.5">
                            <Key className="w-4 h-4" />
                            {t('vault.filters.passwords')}
                        </TabsTrigger>
                        <TabsTrigger value="notes" className="flex items-center gap-1.5">
                            <FileText className="w-4 h-4" />
                            {t('vault.filters.notes')}
                        </TabsTrigger>
                        <TabsTrigger value="favorites" className="flex items-center gap-1.5">
                            <Star className="w-4 h-4" />
                            {t('vault.filters.favorites')}
                        </TabsTrigger>
                    </TabsList>
                </Tabs>
            </header>

            {/* Content */}
            <main className="flex-1 p-4 lg:p-6 overflow-auto">
                {loading || decrypting ? (
                    <div className="flex flex-col items-center justify-center h-64 text-muted-foreground">
                        <Loader2 className="w-8 h-8 animate-spin mb-4" />
                        <p>{decrypting ? t('vault.items.decrypting') : t('common.loading')}</p>
                    </div>
                ) : items.length === 0 ? (
                    <div className="flex flex-col items-center justify-center h-64 text-center text-muted-foreground">
                        <Shield className="w-12 h-12 mb-4 opacity-20" />
                        <p>{t('vault.empty.description', 'This vault is empty.')}</p>
                    </div>
                ) : filteredItems.length === 0 ? (
                    <div className="flex flex-col items-center justify-center h-64 text-center text-muted-foreground">
                        <Search className="w-12 h-12 mb-4 opacity-20" />
                        <p>{t('vault.search.noResults')}</p>
                    </div>
                ) : (
                    <div
                        className={cn(
                            viewMode === 'grid'
                                ? 'grid gap-4 grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4'
                                : 'flex flex-col gap-2'
                        )}
                    >
                        {filteredItems.map((item) => (
                            // We use cast to any to fit the props if strict types mismatch slightly
                            // simpler to reconstruct object if needed
                            <VaultItemCard
                                key={item.id}
                                item={{
                                    id: item.id,
                                    title: item.title,
                                    website_url: item.website_url,
                                    item_type: item.item_type,
                                    is_favorite: item.is_favorite,
                                    decryptedData: item.decryptedData
                                }}
                                viewMode={viewMode}
                                onEdit={() => {
                                    toast({
                                        description: t('emergency.readOnlyToast', 'Read-only mode. Items cannot be edited.')
                                    });
                                }}
                            />
                        ))}
                    </div>
                )}
            </main>
            <Footer />
        </div>
    );
}
