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
    User,
    ChevronDown,
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
import {
    AlertDialog,
    AlertDialogAction,
    AlertDialogCancel,
    AlertDialogContent,
    AlertDialogDescription,
    AlertDialogFooter,
    AlertDialogHeader,
    AlertDialogTitle,
    AlertDialogTrigger,
} from '@/components/ui/alert-dialog';
import { cn } from '@/lib/utils';
import { useVault } from '@/contexts/VaultContext';
import { useAuth } from '@/contexts/AuthContext';
import { useFeatureGate } from '@/hooks/useFeatureGate';
import { useLocation, useNavigate } from 'react-router-dom';
import { CategoryIcon } from './CategoryIcon';
import { CategoryDialog, type CategoryChangeEvent } from './CategoryDialog';
import {
    loadVaultSnapshot,
} from '@/services/offlineVaultService';
import { migrateLegacyVaultItemMetadata } from '@/services/legacyVaultMetadataMigrationService';
import { isPremiumActive } from '@/extensions/registry';
import { buildReturnState } from '@/services/returnNavigationState';
import type { LocalVerifiedRecord } from '@/services/vaultOpLog/vaultStateMachine';

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

function getAccountLabel(email: string | undefined): string {
    return email || 'Singra Vault';
}

function getAccountInitials(email: string | undefined): string {
    const label = getAccountLabel(email).trim();
    if (!label.includes('@')) {
        return label.slice(0, 2).toUpperCase();
    }
    const [name, domain] = label.split('@');
    return `${name.charAt(0)}${domain.charAt(0)}`.toUpperCase();
}

function getVaultStatusSummary(result: { mode?: string; quarantinedItems?: unknown[] } | null | undefined): {
    label: string;
    description: string;
    tone: 'success' | 'warning' | 'danger';
} {
    const quarantinedCount = result?.quarantinedItems?.length ?? 0;

    if (result?.mode === 'blocked') {
        return {
            label: 'Kritisch',
            description: 'Tresorzugriff ist durch eine Integritätsprüfung blockiert.',
            tone: 'danger',
        };
    }

    if (quarantinedCount > 0 || result?.mode === 'quarantine') {
        const count = Math.max(quarantinedCount, 1);
        return {
            label: `${count} Fall${count === 1 ? '' : 'e'}`,
            description: 'Einzelne Einträge brauchen Aufmerksamkeit.',
            tone: 'warning',
        };
    }

    if (result?.mode === 'healthy') {
        return {
            label: 'Unauffällig',
            description: 'Keine aktuellen Integritätsfälle erkannt.',
            tone: 'success',
        };
    }

    return {
        label: 'Analyse bereit',
        description: 'Bericht öffnen, um den aktuellen Stand zu laden.',
        tone: 'warning',
    };
}

function getVaultStatusToneClasses(tone: 'success' | 'warning' | 'danger'): {
    card: string;
    icon: string;
    text: string;
    button: string;
} {
    if (tone === 'danger') {
        return {
            card: 'border-red-400/18 bg-[linear-gradient(135deg,hsl(var(--destructive)/0.12),hsl(var(--el-1)/0.78))]',
            icon: 'border-red-300/25 bg-red-400/10 text-red-300',
            text: 'text-red-300',
            button: 'border-red-300/20 bg-background/35',
        };
    }

    if (tone === 'warning') {
        return {
            card: 'border-amber-400/18 bg-[linear-gradient(135deg,hsl(var(--warning)/0.12),hsl(var(--el-1)/0.78))]',
            icon: 'border-amber-300/25 bg-amber-400/10 text-amber-300',
            text: 'text-amber-300',
            button: 'border-amber-300/20 bg-background/35',
        };
    }

    return {
        card: 'border-emerald-400/18 bg-[linear-gradient(135deg,hsl(var(--success)/0.12),hsl(var(--el-1)/0.78))]',
        icon: 'border-emerald-300/25 bg-emerald-400/10 text-emerald-300',
        text: 'text-emerald-300',
        button: 'border-emerald-300/20 bg-background/35',
    };
}

function parseVerifiedRecordPlaintext(record: LocalVerifiedRecord): Record<string, unknown> | null {
    if (
        (record.recordState !== 'verified' && record.recordState !== 'restoredFromSnapshot')
        || !record.plaintext
    ) {
        return null;
    }

    try {
        const parsed = JSON.parse(new TextDecoder().decode(record.plaintext)) as unknown;
        if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
            return null;
        }

        return parsed as Record<string, unknown>;
    } catch {
        return null;
    }
}

function getVerifiedItemCategoryId(record: LocalVerifiedRecord): string | null {
    if (record.record.recordType !== 'item') {
        return null;
    }

    const plaintext = parseVerifiedRecordPlaintext(record);
    const categoryRecordId = plaintext?.categoryRecordId;
    return typeof categoryRecordId === 'string' ? categoryRecordId : null;
}

function mapVerifiedCategoryRecord(record: LocalVerifiedRecord, count: number): Category | null {
    if (record.record.recordType !== 'category') {
        return null;
    }

    const plaintext = parseVerifiedRecordPlaintext(record);
    if (!plaintext) {
        return null;
    }

    const name = plaintext.name;
    return {
        id: record.record.recordId,
        name: typeof name === 'string' ? name : '',
        icon: typeof plaintext.icon === 'string' ? plaintext.icon : null,
        color: typeof plaintext.color === 'string' ? plaintext.color : null,
        count,
    };
}

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
        decryptData,
        decryptItem,
        isDuressMode,
        lastIntegrityResult,
        verifyIntegrity,
        vaultDataVersion,
        vaultMigrationStatus,
        opLogLocalVaultState,
    } = useVault();
    const useOpLogVerifiedRuntime = vaultMigrationStatus === 'verified';
    const vaultHealthAccess = useFeatureGate('vault_health_reports');
    const authenticatorAccess = useFeatureGate('builtin_authenticator');
    const premiumFeaturesAvailable = isPremiumActive();
    const { user } = useAuth();
    const userId = user?.id ?? null;
    const accountEmail = user?.email ?? undefined;
    const [collapsed, setCollapsed] = useState(false);

    // Categories state
    const [categories, setCategories] = useState<Category[]>([]);
    const [loading, setLoading] = useState(true);

    // Dialog state
    const [dialogOpen, setDialogOpen] = useState(false);
    const [editingCategory, setEditingCategory] = useState<Category | null>(null);
    const vaultStatusSummary = getVaultStatusSummary(lastIntegrityResult);
    const vaultStatusToneClasses = getVaultStatusToneClasses(vaultStatusSummary.tone);
    const failedDecryptPayloadByItemIdRef = useRef<Map<string, string>>(new Map());
    const loggedDecryptFailuresRef = useRef<Set<string>>(new Set());
    const fetchRequestIdRef = useRef(0);
    const fetchingCategoriesRef = useRef(false);
    const decryptDataRef = useRef(decryptData);
    const decryptItemRef = useRef(decryptItem);
    const verifyIntegrityRef = useRef(verifyIntegrity);
    const quarantinedItemIdsRef = useRef<Set<string>>(new Set());

    useEffect(() => {
        decryptDataRef.current = decryptData;
        decryptItemRef.current = decryptItem;
        verifyIntegrityRef.current = verifyIntegrity;
    }, [decryptData, decryptItem, verifyIntegrity]);

    useEffect(() => {
        failedDecryptPayloadByItemIdRef.current.clear();
        loggedDecryptFailuresRef.current.clear();
    }, [userId, isDuressMode]);

    useEffect(() => {
        quarantinedItemIdsRef.current = new Set((lastIntegrityResult?.quarantinedItems ?? []).map((item) => item.id));
    }, [lastIntegrityResult]);

    // Fetch categories
    const fetchCategories = useCallback(async () => {
        if (!userId || fetchingCategoriesRef.current) return;

        const requestId = fetchRequestIdRef.current + 1;
        fetchRequestIdRef.current = requestId;
        fetchingCategoriesRef.current = true;

        try {
            if (useOpLogVerifiedRuntime) {
                if (!opLogLocalVaultState) {
                    if (fetchRequestIdRef.current === requestId) {
                        setCategories([]);
                    }
                    return;
                }

                const counts: Record<string, number> = {};
                for (const record of opLogLocalVaultState.recordsById.values()) {
                    const categoryId = getVerifiedItemCategoryId(record);
                    if (categoryId) {
                        counts[categoryId] = (counts[categoryId] || 0) + 1;
                    }
                }

                const resolvedCategories = Array.from(opLogLocalVaultState.recordsById.values())
                    .map((record) => mapVerifiedCategoryRecord(record, counts[record.record.recordId] || 0))
                    .filter((category): category is Category => category !== null);

                if (fetchRequestIdRef.current === requestId) {
                    setCategories(resolvedCategories);
                }
                return;
            }

            const { snapshot, source } = await loadVaultSnapshot(userId);
            const integrityResult = await verifyIntegrityRef.current(snapshot, { source });
            if (integrityResult?.mode === 'blocked') {
                if (fetchRequestIdRef.current === requestId) {
                    setCategories([]);
                }
                return;
            }
            const counts: Record<string, number> = {};

            await Promise.all(
                snapshot.items.map(async (item) => {
                    const cachedFailedPayload = failedDecryptPayloadByItemIdRef.current.get(item.id);
                    if (cachedFailedPayload === item.encrypted_data) {
                        if (item.category_id) {
                            counts[item.category_id] = (counts[item.category_id] || 0) + 1;
                        }
                        return;
                    }

                    if (quarantinedItemIdsRef.current.has(item.id)) {
                        if (quarantinedItemIdsRef.current.size >= 2) {
                            return;
                        }
                        if (item.category_id) {
                            counts[item.category_id] = (counts[item.category_id] || 0) + 1;
                        }
                        return;
                    }

                    try {
                        const decryptedData = await decryptItemRef.current(item.encrypted_data, item.id);
                        failedDecryptPayloadByItemIdRef.current.delete(item.id);

                        const migration = await migrateLegacyVaultItemMetadata({
                            userId,
                            vaultId: snapshot.vaultId,
                            item,
                            decryptedData,
                            canPersistRemote: false,
                            encryptItem: async () => {
                                throw new Error('legacy metadata writes are disabled');
                            },
                        });

                        const resolvedCategoryId = migration.decryptedData.categoryId ?? migration.item.category_id;

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

                    if (cat.name.startsWith(ENCRYPTED_CATEGORY_PREFIX)) {
                        try {
                            resolvedName = await decryptDataRef.current(cat.name.slice(ENCRYPTED_CATEGORY_PREFIX.length));
                        } catch (err) {
                            console.debug(
                                isDuressMode
                                    ? 'Failed to decrypt category name (Duress Mode - expected):'
                                    : 'Failed to decrypt category name (key mismatch or corrupt):',
                                cat.id
                            );
                            resolvedName = 'Beschädigte Kategorie';
                        }
                    }

                    if (cat.icon && cat.icon.startsWith(ENCRYPTED_CATEGORY_PREFIX)) {
                        try {
                            resolvedIcon = await decryptDataRef.current(cat.icon.slice(ENCRYPTED_CATEGORY_PREFIX.length));
                        } catch (err) {
                            console.debug(
                                isDuressMode
                                    ? 'Failed to decrypt category icon (Duress Mode - expected):'
                                    : 'Failed to decrypt category icon (key mismatch or corrupt):',
                                cat.id
                            );
                            resolvedIcon = null;
                        }
                    }

                    if (cat.color && cat.color.startsWith(ENCRYPTED_CATEGORY_PREFIX)) {
                        try {
                            resolvedColor = await decryptDataRef.current(cat.color.slice(ENCRYPTED_CATEGORY_PREFIX.length));
                        } catch (err) {
                            console.debug(
                                isDuressMode
                                    ? 'Failed to decrypt category color (Duress Mode - expected):'
                                    : 'Failed to decrypt category color (key mismatch or corrupt):',
                                cat.id
                            );
                            resolvedColor = '#3b82f6';
                        }
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

            if (fetchRequestIdRef.current === requestId) {
                setCategories(resolvedCategories);
            }
        } catch (err) {
            console.error('Error fetching categories:', err);
        } finally {
            fetchingCategoriesRef.current = false;
            if (fetchRequestIdRef.current === requestId) {
                setLoading(false);
            }
        }
    }, [
        isDuressMode,
        opLogLocalVaultState,
        useOpLogVerifiedRuntime,
        userId,
    ]);

    useEffect(() => {
        if (compactMode) {
            setCollapsed(false);
        }
    }, [compactMode]);

    useEffect(() => {
        fetchCategories();
    }, [fetchCategories, vaultDataVersion]);

    const handleAddCategory = () => {
        setEditingCategory(null);
        setDialogOpen(true);
    };

    const handleEditCategory = (category: Category) => {
        setEditingCategory(category);
        setDialogOpen(true);
    };

    const handleCategoryChange = (event?: CategoryChangeEvent) => {
        if (event?.type === 'deleted' && selectedCategory === event.categoryId) {
            onSelectCategory(null);
        }
        fetchCategories();
    };

    return (
        <>
            <aside
                className={cn(
                    'flex flex-col border-r bg-[hsl(var(--sidebar-background)/0.86)] backdrop-blur-xl',
                    'border-[hsl(var(--sidebar-border)/0.55)] shadow-[inset_-1px_0_0_hsl(var(--foreground)/0.03)]',
                    compactMode
                        ? 'h-full w-full'
                        : cn('self-stretch min-h-full transition-all duration-300', collapsed ? 'w-16' : 'w-72')
                )}
            >
                {/* Header */}
                <div className="flex items-center justify-between border-b border-[hsl(var(--sidebar-border)/0.45)] p-4">
                    {!collapsed && (
                        <h2 className="text-lg font-semibold">
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
                    {premiumFeaturesAvailable && (
                        <SidebarItem
                            icon={<Activity className="w-4 h-4" />}
                            label={t('vaultHealth.title')}
                            badge={!vaultHealthAccess.allowed ? t('subscription.premiumFeatureLockedShort') : undefined}
                            collapsed={collapsed}
                            active={location.pathname === '/vault-health'}
                            disabled={!vaultHealthAccess.allowed}
                            disabledReason={t('subscription.premiumFeatureLockedDescription')}
                            onClick={() => {
                                if (!vaultHealthAccess.allowed) return;
                                navigate('/vault-health');
                                onActionComplete?.();
                            }}
                        />
                    )}
                    {premiumFeaturesAvailable && (
                        <SidebarItem
                            icon={<QrCode className="w-4 h-4" />}
                            label={t('authenticator.title')}
                            badge={!authenticatorAccess.allowed ? t('subscription.premiumFeatureLockedShort') : undefined}
                            collapsed={collapsed}
                            active={location.pathname === '/authenticator'}
                            disabled={!authenticatorAccess.allowed}
                            disabledReason={t('subscription.premiumFeatureLockedDescription')}
                            onClick={() => {
                                if (!authenticatorAccess.allowed) return;
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

                {!collapsed && vaultHealthAccess.allowed && (
                    <div className={cn(
                        'mx-3 mb-3 rounded-2xl border p-4 shadow-[0_18px_42px_hsl(0_0%_0%/0.28)]',
                        vaultStatusToneClasses.card,
                    )}>
                        <div className="flex items-start gap-3">
                            <div className={cn('rounded-xl border p-2', vaultStatusToneClasses.icon)}>
                                <Activity className="h-4 w-4" />
                            </div>
                            <div className="min-w-0 space-y-1">
                                <p className="text-sm font-semibold text-foreground">Tresor-Status</p>
                                <p className={cn('text-sm font-medium', vaultStatusToneClasses.text)}>
                                    {vaultStatusSummary.label}
                                </p>
                                <p className="text-xs leading-5 text-muted-foreground">
                                    {vaultStatusSummary.description}
                                </p>
                            </div>
                        </div>
                        <Button
                            variant="outline"
                            size="sm"
                            className={cn('mt-3 w-full', vaultStatusToneClasses.button)}
                            onClick={() => {
                                navigate('/vault-health');
                                onActionComplete?.();
                            }}
                        >
                            Bericht anzeigen
                        </Button>
                    </div>
                )}

                <Separator />

                {/* Footer Actions */}
                <div className="p-2 space-y-1">
                    {!collapsed && (
                        <DropdownMenu>
                            <DropdownMenuTrigger asChild>
                                <button
                                    type="button"
                                    className="mb-1 flex w-full items-center gap-3 rounded-xl border border-border/45 bg-[hsl(var(--el-1)/0.74)] px-3 py-3 text-left transition-colors hover:border-border/70 hover:bg-[hsl(var(--el-2)/0.82)]"
                                >
                                    <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-full border border-primary/25 bg-primary/10 text-xs font-semibold text-primary">
                                        {getAccountInitials(accountEmail)}
                                    </span>
                                    <span className="min-w-0 flex-1">
                                        <span className="block truncate text-sm font-medium text-foreground">
                                            {getAccountLabel(accountEmail)}
                                        </span>
                                        <span className="block text-xs text-muted-foreground">Einstellungen</span>
                                    </span>
                                    <ChevronDown className="h-4 w-4 text-muted-foreground" />
                                </button>
                            </DropdownMenuTrigger>
                            <DropdownMenuContent align="end" side="top" className="w-64">
                                <DropdownMenuItem onClick={() => {
                                    onActionComplete?.();
                                    navigate('/settings', { state: buildReturnState(location) });
                                }}>
                                    <User className="mr-2 h-4 w-4" />
                                    {t('settings.accountPage.title')}
                                </DropdownMenuItem>
                                <DropdownMenuItem onClick={() => {
                                    onActionComplete?.();
                                    navigate('/vault/settings', { state: buildReturnState(location) });
                                }}>
                                    <Shield className="mr-2 h-4 w-4" />
                                    {t('settings.vaultPage.title')}
                                </DropdownMenuItem>
                            </DropdownMenuContent>
                        </DropdownMenu>
                    )}
                    {collapsed && (
                        <SidebarItem
                            icon={<Settings className="w-4 h-4" />}
                            label={t('settings.accountPage.title')}
                            collapsed={collapsed}
                            active={location.pathname === '/settings' || location.pathname === '/vault/settings'}
                            onClick={() => {
                                onActionComplete?.();
                                navigate('/settings', { state: buildReturnState(location) });
                            }}
                        />
                    )}
                    <AlertDialog>
                        <AlertDialogTrigger asChild>
                            <button
                                type="button"
                                className={cn(
                                    'w-full flex items-center gap-3 px-3 py-2.5 rounded-lg transition-all duration-150',
                                    'text-destructive hover:bg-destructive/10 hover:text-destructive',
                                    collapsed && 'justify-center px-0',
                                )}
                            >
                                <Lock className="w-4 h-4" />
                                {!collapsed && <span className="flex-1 text-left text-sm truncate">{t('vault.sidebar.lock')}</span>}
                            </button>
                        </AlertDialogTrigger>
                        <AlertDialogContent>
                            <AlertDialogHeader>
                                <AlertDialogTitle>Tresor sperren?</AlertDialogTitle>
                                <AlertDialogDescription>
                                    Der Tresor wird geschlossen und muss danach erneut mit Masterpasswort und gegebenenfalls Device Key entsperrt werden.
                                </AlertDialogDescription>
                            </AlertDialogHeader>
                            <AlertDialogFooter>
                                <AlertDialogCancel>Abbrechen</AlertDialogCancel>
                                <AlertDialogAction
                                    onClick={() => {
                                        lock();
                                        onActionComplete?.();
                                        navigate('/vault', { replace: true });
                                    }}
                                >
                                    Tresor sperren
                                </AlertDialogAction>
                            </AlertDialogFooter>
                        </AlertDialogContent>
                    </AlertDialog>
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
    badge?: string;
    collapsed?: boolean;
    active?: boolean;
    disabled?: boolean;
    disabledReason?: string;
    variant?: 'default' | 'destructive';
    color?: string | null;
    onClick?: () => void;
}

function SidebarItem({
    icon,
    label,
    count,
    badge,
    collapsed,
    active,
    disabled,
    disabledReason,
    variant = 'default',
    color,
    onClick
}: SidebarItemProps) {
    const content = (
        <button
            onClick={onClick}
            aria-disabled={disabled}
            className={cn(
                'w-full flex items-center gap-3 px-3 py-2.5 rounded-lg transition-all duration-150',
                'text-[hsl(var(--sidebar-foreground)/0.72)] hover:text-[hsl(var(--sidebar-foreground))]',
                'hover:bg-[hsl(var(--el-2)/0.82)]',
                active && 'border border-primary/25 bg-[hsl(var(--primary)/0.12)] text-[hsl(var(--sidebar-primary))] shadow-[0_0_24px_hsl(var(--primary)/0.08)]',
                variant === 'destructive' && 'text-destructive hover:bg-destructive/10 hover:text-destructive',
                disabled && 'cursor-not-allowed opacity-45 hover:bg-transparent hover:text-[hsl(var(--sidebar-foreground)/0.72)]',
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
                    {badge && (
                        <span className="rounded-full border border-primary/20 bg-primary/10 px-2 py-0.5 text-[0.65rem] font-medium text-primary">
                            {badge}
                        </span>
                    )}
                </>
            )}
        </button>
    );

    if (collapsed || disabledReason) {
        return (
            <Tooltip>
                <TooltipTrigger asChild>
                    {content}
                </TooltipTrigger>
                <TooltipContent side="right">
                    <p>{label}</p>
                    {disabledReason && <p className="text-xs text-muted-foreground">{disabledReason}</p>}
                </TooltipContent>
            </Tooltip>
        );
    }

    return content;
}
