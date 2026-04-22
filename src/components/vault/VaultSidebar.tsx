// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE
/**
 * @fileoverview Vault Sidebar Component
 * 
 * Navigation sidebar showing categories, quick filters,
 * and vault stats.
 */

import { useState, useEffect, useCallback, useRef } from 'react';
import { useTranslation } from 'react-i18next';
import {
    ChevronLeft,
    ChevronRight,
    Folder,
    Plus,
    Settings,
    Lock,
    Home,
    MoreHorizontal,
    Pencil,
    Activity,
    QrCode,
    Shield,
} from 'lucide-react';

import { Button } from '@/components/ui/button';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Separator } from '@/components/ui/separator';
import {
    Tooltip,
    TooltipContent,
    TooltipTrigger,
} from '@/components/ui/tooltip';
import {
    DropdownMenu,
    DropdownMenuContent,
    DropdownMenuItem,
    DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import { cn } from '@/lib/utils';
import { useVault } from '@/contexts/VaultContext';
import { useAuth } from '@/contexts/AuthContext';
import { useLocation, useNavigate } from 'react-router-dom';
import { supabase } from '@/integrations/supabase/client';
import { CategoryIcon } from './CategoryIcon';
import { CategoryDialog } from './CategoryDialog';
import {
    isAppOnline,
    loadVaultSnapshot,
    upsertOfflineCategoryRow,
    upsertOfflineItemRow,
} from '@/services/offlineVaultService';
import { isPremiumActive } from '@/extensions/registry';
import { buildReturnState } from '@/services/returnNavigationState';

interface Category {
    id: string;
    name: string;
    icon: string | null;
    color: string | null;
    count?: number;
}

interface VaultSidebarProps {
    selectedCategory: string | null;
    onSelectCategory: (categoryId: string | null) => void;
    compactMode?: boolean;
    onActionComplete?: () => void;
}

const ENCRYPTED_CATEGORY_PREFIX = 'enc:cat:v1:';
const ENCRYPTED_ITEM_TITLE_PLACEHOLDER = 'Encrypted Item';

export function VaultSidebar({
    selectedCategory,
    onSelectCategory,
    compactMode = false,
    onActionComplete,
}: VaultSidebarProps) {
    const { t } = useTranslation();
    const navigate = useNavigate();
    const location = useLocation();
    const {
        lock,
        encryptData,
        decryptData,
        decryptItem,
        encryptItem,
        isDuressMode,
        refreshIntegrityBaseline,
        verifyIntegrity,
    } = useVault();
    const { user } = useAuth();
    const [collapsed, setCollapsed] = useState(false);

    // Categories state
    const [categories, setCategories] = useState<Category[]>([]);
    const [loading, setLoading] = useState(true);

    // Dialog state
    const [dialogOpen, setDialogOpen] = useState(false);
    const [editingCategory, setEditingCategory] = useState<Category | null>(null);
    const failedDecryptPayloadByItemIdRef = useRef<Map<string, string>>(new Map());
    const loggedDecryptFailuresRef = useRef<Set<string>>(new Set());

    useEffect(() => {
        failedDecryptPayloadByItemIdRef.current.clear();
        loggedDecryptFailuresRef.current.clear();
    }, [user?.id, isDuressMode]);

    // Fetch categories
    const fetchCategories = useCallback(async () => {
        if (!user) return;

        try {
            const { snapshot, source } = await loadVaultSnapshot(user.id);
            const integrityResult = await verifyIntegrity(snapshot);
            if (integrityResult?.mode === 'blocked') {
                setCategories([]);
                return;
            }
            const canPersistMigrations = integrityResult?.mode === 'healthy'
                && integrityResult.isFirstCheck
                && source === 'remote'
                && isAppOnline();
            const counts: Record<string, number> = {};
            let integrityBaselineDirty = false;
            const trustedItemIds = new Set<string>();
            const trustedCategoryIds = new Set<string>();

            await Promise.all(
                snapshot.items.map(async (item) => {
                    const cachedFailedPayload = failedDecryptPayloadByItemIdRef.current.get(item.id);
                    if (cachedFailedPayload === item.encrypted_data) {
                        if (item.category_id) {
                            counts[item.category_id] = (counts[item.category_id] || 0) + 1;
                        }
                        return;
                    }

                    try {
                        const decryptedData = await decryptItem(item.encrypted_data, item.id);
                        failedDecryptPayloadByItemIdRef.current.delete(item.id);
                        const resolvedCategoryId = decryptedData.categoryId ?? item.category_id;
                        const resolvedTitle = decryptedData.title || item.title;
                        const resolvedWebsiteUrl = decryptedData.websiteUrl || item.website_url || undefined;
                        const resolvedItemType = decryptedData.itemType || item.item_type || 'password';
                        const resolvedIsFavorite = typeof decryptedData.isFavorite === 'boolean'
                            ? decryptedData.isFavorite
                            : !!item.is_favorite;
                        const hasLegacyPlaintextMeta =
                            (!decryptedData.title && item.title && item.title !== ENCRYPTED_ITEM_TITLE_PLACEHOLDER) ||
                            (!decryptedData.websiteUrl && !!item.website_url) ||
                            (!decryptedData.itemType && !!item.item_type) ||
                            (typeof decryptedData.isFavorite !== 'boolean' && item.is_favorite !== null) ||
                            (typeof decryptedData.categoryId === 'undefined' && item.category_id !== null);
                        const hasPlaintextColumnsToCleanup =
                            item.title !== ENCRYPTED_ITEM_TITLE_PLACEHOLDER ||
                            item.website_url !== null ||
                            item.icon_url !== null ||
                            item.item_type !== 'password' ||
                            !!item.is_favorite ||
                            item.category_id !== null;

                        if (canPersistMigrations && (hasLegacyPlaintextMeta || hasPlaintextColumnsToCleanup)) {
                            const migratedEncryptedData = await encryptItem({
                                ...decryptedData,
                                title: resolvedTitle,
                                websiteUrl: resolvedWebsiteUrl,
                                itemType: resolvedItemType,
                                isFavorite: resolvedIsFavorite,
                                categoryId: resolvedCategoryId,
                            }, item.id);

                            await supabase
                                .from('vault_items')
                                .update({
                                    encrypted_data: migratedEncryptedData,
                                    title: ENCRYPTED_ITEM_TITLE_PLACEHOLDER,
                                    website_url: null,
                                    icon_url: null,
                                    item_type: 'password',
                                    is_favorite: false,
                                    category_id: null,
                                })
                                .eq('id', item.id);

                            await upsertOfflineItemRow(user.id, {
                                ...item,
                                encrypted_data: migratedEncryptedData,
                                title: ENCRYPTED_ITEM_TITLE_PLACEHOLDER,
                                website_url: null,
                                icon_url: null,
                                item_type: 'password',
                                is_favorite: false,
                                category_id: null,
                                updated_at: new Date().toISOString(),
                            }, snapshot.vaultId);
                            integrityBaselineDirty = true;
                            trustedItemIds.add(item.id);
                        }

                        if (resolvedCategoryId) {
                            counts[resolvedCategoryId] = (counts[resolvedCategoryId] || 0) + 1;
                        }
                    } catch (err) {
                        failedDecryptPayloadByItemIdRef.current.set(item.id, item.encrypted_data);
                        const logKey = `${item.id}:${item.updated_at}`;
                        if (!loggedDecryptFailuresRef.current.has(logKey)) {
                            loggedDecryptFailuresRef.current.add(logKey);
                            console.debug(
                                isDuressMode
                                    ? 'Failed to decrypt vault item for category counts (Duress Mode - expected):'
                                    : 'Failed to decrypt vault item for category counts (key mismatch or corrupt):',
                                item.id
                            );
                        }
                        if (item.category_id) {
                            counts[item.category_id] = (counts[item.category_id] || 0) + 1;
                        }
                    }
                }),
            );

            const resolvedCategories = await Promise.all(
                snapshot.categories.map(async (cat) => {
                    let resolvedName = cat.name;
                    let resolvedIcon = cat.icon;
                    let resolvedColor = cat.color;
                    let migratedName = cat.name;
                    let migratedIcon = cat.icon;
                    let migratedColor = cat.color;

                    if (cat.name.startsWith(ENCRYPTED_CATEGORY_PREFIX)) {
                        try {
                            resolvedName = await decryptData(cat.name.slice(ENCRYPTED_CATEGORY_PREFIX.length));
                        } catch (err) {
                            console.debug(
                                isDuressMode
                                    ? 'Failed to decrypt category name (Duress Mode - expected):'
                                    : 'Failed to decrypt category name (key mismatch or corrupt):',
                                cat.id
                            );
                            resolvedName = 'Beschädigte Kategorie';
                        }
                    } else if (canPersistMigrations) {
                        try {
                            const encryptedName = await encryptData(cat.name);
                            migratedName = `${ENCRYPTED_CATEGORY_PREFIX}${encryptedName}`;
                            await supabase
                                .from('categories')
                                .update({ name: migratedName })
                                .eq('id', cat.id);
                        } catch (err) {
                            console.error('Failed to migrate category name:', cat.id, err);
                        }
                    }

                    if (cat.icon && cat.icon.startsWith(ENCRYPTED_CATEGORY_PREFIX)) {
                        try {
                            resolvedIcon = await decryptData(cat.icon.slice(ENCRYPTED_CATEGORY_PREFIX.length));
                        } catch (err) {
                            console.debug(
                                isDuressMode
                                    ? 'Failed to decrypt category icon (Duress Mode - expected):'
                                    : 'Failed to decrypt category icon (key mismatch or corrupt):',
                                cat.id
                            );
                            resolvedIcon = null;
                        }
                    } else if (cat.icon && canPersistMigrations) {
                        try {
                            const encryptedIcon = await encryptData(cat.icon);
                            migratedIcon = `${ENCRYPTED_CATEGORY_PREFIX}${encryptedIcon}`;
                            await supabase
                                .from('categories')
                                .update({ icon: migratedIcon })
                                .eq('id', cat.id);
                        } catch (err) {
                            console.error('Failed to migrate category icon:', cat.id, err);
                        }
                    }

                    if (cat.color && cat.color.startsWith(ENCRYPTED_CATEGORY_PREFIX)) {
                        try {
                            resolvedColor = await decryptData(cat.color.slice(ENCRYPTED_CATEGORY_PREFIX.length));
                        } catch (err) {
                            console.debug(
                                isDuressMode
                                    ? 'Failed to decrypt category color (Duress Mode - expected):'
                                    : 'Failed to decrypt category color (key mismatch or corrupt):',
                                cat.id
                            );
                            resolvedColor = '#3b82f6';
                        }
                    } else if (cat.color && canPersistMigrations) {
                        try {
                            const encryptedColor = await encryptData(cat.color);
                            migratedColor = `${ENCRYPTED_CATEGORY_PREFIX}${encryptedColor}`;
                            await supabase
                                .from('categories')
                                .update({ color: migratedColor })
                                .eq('id', cat.id);
                        } catch (err) {
                            console.error('Failed to migrate category color:', cat.id, err);
                        }
                    }

                    if (canPersistMigrations && (migratedName !== cat.name || migratedIcon !== cat.icon || migratedColor !== cat.color)) {
                        await upsertOfflineCategoryRow(user.id, {
                            ...cat,
                            name: migratedName,
                            icon: migratedIcon,
                            color: migratedColor,
                            updated_at: new Date().toISOString(),
                        });
                        integrityBaselineDirty = true;
                        trustedCategoryIds.add(cat.id);
                    }

                    return {
                        ...cat,
                        name: resolvedName,
                        icon: resolvedIcon,
                        color: resolvedColor,
                        count: counts[cat.id] || 0,
                    };
                }),
            );

            if (integrityBaselineDirty && canPersistMigrations) {
                await refreshIntegrityBaseline({
                    itemIds: trustedItemIds,
                    categoryIds: trustedCategoryIds,
                });
            }

            setCategories(resolvedCategories);
        } catch (err) {
            console.error('Error fetching categories:', err);
        } finally {
            setLoading(false);
        }
    }, [user, encryptData, decryptData, decryptItem, encryptItem, isDuressMode, refreshIntegrityBaseline, verifyIntegrity]);

    useEffect(() => {
        if (compactMode) {
            setCollapsed(false);
        }
    }, [compactMode]);

    useEffect(() => {
        fetchCategories();
    }, [fetchCategories, t]);

    const handleAddCategory = () => {
        setEditingCategory(null);
        setDialogOpen(true);
    };

    const handleEditCategory = (category: Category) => {
        setEditingCategory(category);
        setDialogOpen(true);
    };

    const handleCategoryChange = () => {
        fetchCategories();
    };

    return (
        <>
            <aside
                className={cn(
                    'flex flex-col border-r',
                    'bg-[hsl(var(--sidebar-background))] border-[hsl(var(--sidebar-border)/0.55)]',
                    compactMode
                        ? 'h-full w-full'
                        : cn('self-stretch min-h-full transition-all duration-300', collapsed ? 'w-16' : 'w-64')
                )}
            >
                {/* Header */}
                <div className="p-4 flex items-center justify-between border-b border-[hsl(var(--sidebar-border)/0.45)]">
                    {!collapsed && (
                        <h2 className="font-semibold text-lg">
                            {t('vault.sidebar.title')}
                        </h2>
                    )}
                    {!compactMode && (
                        <Button
                            variant="ghost"
                            size="icon"
                            className="h-8 w-8"
                            onClick={() => setCollapsed(!collapsed)}
                        >
                            {collapsed ? <ChevronRight className="w-4 h-4" /> : <ChevronLeft className="w-4 h-4" />}
                        </Button>
                    )}
                </div>

                {/* Quick Navigation */}
                <div className="p-2">
                    <SidebarItem
                        icon={<Home className="w-4 h-4" />}
                        label={t('vault.sidebar.allItems')}
                        collapsed={collapsed}
                        active={!selectedCategory && location.pathname === '/vault'}
                        onClick={() => {
                            onSelectCategory(null);
                            onActionComplete?.();
                            navigate('/vault');
                        }}
                    />
                    {isPremiumActive() && (
                        <SidebarItem
                            icon={<Activity className="w-4 h-4" />}
                            label={t('vaultHealth.title')}
                            collapsed={collapsed}
                            active={location.pathname === '/vault-health'}
                            onClick={() => {
                                navigate('/vault-health');
                                onActionComplete?.();
                            }}
                        />
                    )}
                    {isPremiumActive() && (
                        <SidebarItem
                            icon={<QrCode className="w-4 h-4" />}
                            label={t('authenticator.title')}
                            collapsed={collapsed}
                            active={location.pathname === '/authenticator'}
                            onClick={() => {
                                navigate('/authenticator');
                                onActionComplete?.();
                            }}
                        />
                    )}
                </div>

                <Separator />

                {/* Categories */}
                <ScrollArea className="flex-1 p-2">
                    <div className="space-y-1">
                        {!collapsed && (
                            <div className="flex items-center justify-between px-2 py-1.5">
                                <span className="text-xs font-medium text-muted-foreground uppercase">
                                    {t('vault.sidebar.categories')}
                                </span>
                                <Button
                                    variant="ghost"
                                    size="icon"
                                    className="h-6 w-6"
                                    onClick={handleAddCategory}
                                >
                                    <Plus className="w-3 h-3" />
                                </Button>
                            </div>
                        )}

                        {loading ? (
                            <div className="px-3 py-2 text-sm text-muted-foreground">
                                {t('common.loading')}...
                            </div>
                        ) : categories.length === 0 ? (
                            !collapsed && (
                                <div className="px-3 py-4 text-center">
                                    <Folder className="w-8 h-8 mx-auto mb-2 text-muted-foreground" />
                                    <p className="text-sm text-muted-foreground">
                                        {t('categories.empty')}
                                    </p>
                                    <Button
                                        variant="link"
                                        size="sm"
                                        onClick={handleAddCategory}
                                        className="mt-1"
                                    >
                                        {t('categories.addFirst')}
                                    </Button>
                                </div>
                            )
                        ) : (
                            categories.map((category) => (
                                <div key={category.id} className="group relative">
                                    <SidebarItem
                                        icon={
                                            collapsed ? (
                                                <Folder className="w-4 h-4" />
                                            ) : (
                                                <CategoryIcon icon={category.icon} />
                                            )
                                        }
                                        label={category.name}
                                        count={category.count}
                                        collapsed={collapsed}
                                        active={selectedCategory === category.id}
                                        onClick={() => {
                                            onSelectCategory(category.id);
                                            onActionComplete?.();
                                        }}
                                        color={category.color}
                                    />

                                    {/* Edit menu (visible on hover) */}
                                    {!collapsed && (
                                        <div className="absolute right-2 top-1/2 -translate-y-1/2 opacity-0 group-hover:opacity-100 transition-opacity">
                                            <DropdownMenu>
                                                <DropdownMenuTrigger asChild>
                                                    <Button variant="ghost" size="icon" className="h-6 w-6">
                                                        <MoreHorizontal className="w-3 h-3" />
                                                    </Button>
                                                </DropdownMenuTrigger>
                                                <DropdownMenuContent align="end">
                                                    <DropdownMenuItem onClick={() => handleEditCategory(category)}>
                                                        <Pencil className="w-4 h-4 mr-2" />
                                                        {t('common.edit')}
                                                    </DropdownMenuItem>
                                                </DropdownMenuContent>
                                            </DropdownMenu>
                                        </div>
                                    )}
                                </div>
                            ))
                        )}
                    </div>
                </ScrollArea>

                <Separator />

                {/* Footer Actions */}
                <div className="p-2 space-y-1">
                    <SidebarItem
                        icon={<Settings className="w-4 h-4" />}
                        label={t('settings.accountPage.title')}
                        collapsed={collapsed}
                        active={location.pathname === '/settings'}
                        onClick={() => {
                            onActionComplete?.();
                            navigate('/settings', { state: buildReturnState(location) });
                        }}
                    />
                    <SidebarItem
                        icon={<Shield className="w-4 h-4" />}
                        label={t('settings.vaultPage.title')}
                        collapsed={collapsed}
                        active={location.pathname === '/vault/settings'}
                        onClick={() => {
                            onActionComplete?.();
                            navigate('/vault/settings', { state: buildReturnState(location) });
                        }}
                    />
                    <SidebarItem
                        icon={<Lock className="w-4 h-4" />}
                        label={t('vault.sidebar.lock')}
                        collapsed={collapsed}
                        onClick={() => {
                            lock();
                            onActionComplete?.();
                            navigate('/vault', { replace: true });
                        }}
                        variant="destructive"
                    />
                </div>
            </aside>

            {/* Category Dialog */}
            <CategoryDialog
                open={dialogOpen}
                onOpenChange={setDialogOpen}
                category={editingCategory}
                onSave={handleCategoryChange}
            />
        </>
    );
}

interface SidebarItemProps {
    icon: React.ReactNode;
    label: string;
    count?: number;
    collapsed?: boolean;
    active?: boolean;
    variant?: 'default' | 'destructive';
    color?: string | null;
    onClick?: () => void;
}

function SidebarItem({
    icon,
    label,
    count,
    collapsed,
    active,
    variant = 'default',
    color,
    onClick
}: SidebarItemProps) {
    const content = (
        <button
            onClick={onClick}
            className={cn(
                'w-full flex items-center gap-3 px-3 py-2 rounded-lg transition-all duration-150',
                'text-[hsl(var(--sidebar-foreground)/0.72)] hover:text-[hsl(var(--sidebar-foreground))]',
                'hover:bg-[hsl(var(--el-2))]',
                active && 'bg-[hsl(var(--el-3))] text-[hsl(var(--sidebar-primary))]',
                variant === 'destructive' && 'text-destructive hover:bg-destructive/10 hover:text-destructive',
                collapsed && 'justify-center px-0'
            )}
        >
            <span style={color ? { color } : undefined}>{icon}</span>
            {!collapsed && (
                <>
                    <span className="flex-1 text-left text-sm truncate">{label}</span>
                    {count !== undefined && count > 0 && (
                        <span className="text-xs text-muted-foreground">{count}</span>
                    )}
                </>
            )}
        </button>
    );

    if (collapsed) {
        return (
            <Tooltip>
                <TooltipTrigger asChild>
                    {content}
                </TooltipTrigger>
                <TooltipContent side="right">
                    <p>{label}</p>
                </TooltipContent>
            </Tooltip>
        );
    }

    return content;
}
