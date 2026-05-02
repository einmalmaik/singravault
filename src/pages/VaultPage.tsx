// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE
/**
 * @fileoverview Vault Page - Main Dashboard
 *
 * Central hub for managing all vault items including passwords,
 * secure notes, and TOTP entries.
 */

import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Link, useLocation, useNavigate } from 'react-router-dom';
import {
    Plus,
    Search,
    Key,
    FileText,
    Shield,
    Star,
    Grid3X3,
    List,
    Loader2,
    Menu,
    WifiOff,
    RefreshCw,
    Wrench,
} from 'lucide-react';

import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Tabs, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { useAuth } from '@/contexts/AuthContext';
import { useVault } from '@/contexts/VaultContext';
import { MasterPasswordSetup } from '@/components/vault/MasterPasswordSetup';
import { VaultUnlock } from '@/components/vault/VaultUnlock';
import { VaultSidebar } from '@/components/vault/VaultSidebar';
import { VaultItemList } from '@/components/vault/VaultItemList';
import { VaultItemDialog } from '@/components/vault/VaultItemDialog';
import { VaultIntegrityRecovery } from '@/components/vault/VaultIntegrityRecovery';
import { Sheet, SheetContent, SheetTitle } from '@/components/ui/sheet';
import { useIsMobile } from '@/hooks/use-mobile';
import { isPremiumActive } from '@/extensions/registry';
import { syncOfflineMutations } from '@/services/offlineVaultService';
import { useToast } from '@/hooks/use-toast';
import { getAdminEntryPath, shouldShowWebsiteChrome } from '@/platform/appShell';
import { buildReturnState } from '@/services/returnNavigationState';
import { useAdminPanelAccess } from '@/hooks/use-admin-panel-access';
import type { VaultIntegrityMode, VaultIntegrityNonTamperReason } from '@/services/vaultIntegrityService';

export type ItemFilter = 'all' | 'passwords' | 'notes' | 'favorites';
export type ViewMode = 'grid' | 'list';

const NON_DECRYPTABLE_INTEGRITY_MODES = new Set<VaultIntegrityMode>([
    'revalidation_failed',
    'integrity_unknown',
    'migration_required',
    'scope_incomplete',
]);

function getIntegrityWarningText(
    mode: VaultIntegrityMode | 'safe',
    reason?: VaultIntegrityNonTamperReason,
): string {
    if (reason === 'manifest_persist_failed') {
        return 'Der Manifest-V2-Status konnte noch nicht dauerhaft gespeichert werden. Ein erneuter Integritätscheck ist erforderlich.';
    }
    if (reason === 'rollback_check_unavailable') {
        return 'Der lokale Rollback-Schutz ist aktuell nicht verfügbar. Der normale Tresorzugriff bleibt gesperrt.';
    }
    if (reason === 'manifest_snapshot_conflict') {
        return 'Der lokale vertrauenswürdige Snapshot widerspricht dem Server-Manifest. Bitte synchronisiere oder nutze die Wiederherstellung.';
    }
    if (reason === 'snapshot_source_not_authoritative') {
        return 'Es konnte kein frischer Server-Snapshot autoritativ geprüft werden. Prüfe die Verbindung und versuche es erneut.';
    }
    if (reason === 'snapshot_completeness_unknown') {
        return 'Der lokale Snapshot enthält keine vollständigen Prüfinformationen. Ein frischer Server-Abgleich ist erforderlich.';
    }
    if (reason === 'revalidation_failed') {
        return 'Die erneute Integritätsprüfung konnte den aktuellen Serverzustand noch nicht bestätigen.';
    }
    if (mode === 'migration_required') {
        return 'Dieser Tresor benötigt eine Integritätsmigration. Der normale Zugriff bleibt bis zum Abschluss gesperrt.';
    }
    if (mode === 'scope_incomplete') {
        return 'Der aktuelle Tresor-Snapshot ist unvollständig. Der normale Zugriff bleibt bis zur vollständigen Prüfung gesperrt.';
    }
    return 'Der Integritätszustand konnte nicht vollständig bestätigt werden. Der normale Tresorzugriff bleibt gesperrt.';
}

export default function VaultPage() {
    const { t } = useTranslation();
    const navigate = useNavigate();
    const location = useLocation();
    const { toast } = useToast();
    const isMobile = useIsMobile();
    const { user, isOfflineSession } = useAuth();
    const {
        integrityMode,
        isLocked,
        isSetupRequired,
        isLoading: vaultLoading,
        lastIntegrityResult,
        refreshIntegrityBaseline,
    } = useVault();

    const [searchQuery, setSearchQuery] = useState('');
    const [activeFilter, setActiveFilter] = useState<ItemFilter>('all');
    const [selectedCategory, setSelectedCategory] = useState<string | null>(null);
    const [viewMode, setViewMode] = useState<ViewMode>('grid');
    const [dialogOpen, setDialogOpen] = useState(false);
    const [editingItemId, setEditingItemId] = useState<string | null>(null);
    const [refreshKey, setRefreshKey] = useState(0);
    const [sidebarOpen, setSidebarOpen] = useState(false);
    const [isOnline, setIsOnline] = useState(() => navigator.onLine);
    const [isSyncing, setIsSyncing] = useState(false);
    const [isRecheckingIntegrity, setIsRecheckingIntegrity] = useState(false);

    const showWebsiteChrome = shouldShowWebsiteChrome();
    const adminEntryPath = getAdminEntryPath();
    const { showAdminButton } = useAdminPanelAccess({
        enabled: isPremiumActive() && !isOfflineSession && !isLocked && !isSetupRequired,
    });

    useEffect(() => {
        const goOnline = () => setIsOnline(true);
        const goOffline = () => setIsOnline(false);
        window.addEventListener('online', goOnline);
        window.addEventListener('offline', goOffline);
        return () => {
            window.removeEventListener('online', goOnline);
            window.removeEventListener('offline', goOffline);
        };
    }, []);

    useEffect(() => {
        if (!user || isLocked || isSetupRequired || !isOnline) return;
        let cancelled = false;

        const syncQueuedChanges = async () => {
            setIsSyncing(true);
            try {
                const result = await syncOfflineMutations(user.id);
                if (cancelled) return;
                if (result.processed > 0) {
                    setRefreshKey((prev) => prev + 1);
                    toast({
                        title: t('common.success'),
                        description: t('vault.syncedAfterOffline', {
                            defaultValue: '{{count}} Offline-Änderungen synchronisiert.',
                            count: result.processed,
                        }),
                    });
                }
            } catch (err) {
                if (!cancelled) {
                    console.error('Failed to sync offline changes:', err);
                }
            } finally {
                if (!cancelled) {
                    setIsSyncing(false);
                }
            }
        };

        void syncQueuedChanges();
        return () => {
            cancelled = true;
        };
    }, [user, isLocked, isSetupRequired, isOnline, toast, t]);

    if (vaultLoading) {
        return (
            <div className="min-h-screen flex items-center justify-center bg-background">
                <div className="text-center space-y-4">
                    <Loader2 className="w-8 h-8 animate-spin mx-auto text-primary" />
                    <p className="text-muted-foreground">{t('common.loading')}</p>
                </div>
            </div>
        );
    }

    if (isSetupRequired) {
        return <MasterPasswordSetup />;
    }

    if (integrityMode === 'blocked' || integrityMode === 'safe') {
        return <VaultIntegrityRecovery />;
    }

    if (isLocked) {
        return <VaultUnlock />;
    }

    if (NON_DECRYPTABLE_INTEGRITY_MODES.has(integrityMode as VaultIntegrityMode)) {
        const handleIntegrityRecheck = async () => {
            setIsRecheckingIntegrity(true);
            try {
                const recheckResult = await refreshIntegrityBaseline();
                if (!recheckResult) {
                    toast({
                        variant: 'destructive',
                        title: t('common.error'),
                        description: t('vault.integrity.recheckUnavailable', {
                            defaultValue: 'Der Tresor-Schlüssel oder Snapshot ist nicht verfügbar. Sperre den Tresor und entsperre ihn erneut.',
                        }),
                    });
                    return;
                }
                if (NON_DECRYPTABLE_INTEGRITY_MODES.has(recheckResult.mode)) {
                    toast({
                        variant: 'destructive',
                        title: t('vault.integrity.revalidationTitle', {
                            defaultValue: 'Integritätsprüfung erforderlich',
                        }),
                        description: getIntegrityWarningText(
                            recheckResult.mode,
                            recheckResult.nonTamperReason,
                        ),
                    });
                }
            } catch {
                toast({
                    variant: 'destructive',
                    title: t('common.error'),
                    description: t('vault.integrity.recheckFailed', {
                        defaultValue: 'Der Integritätscheck konnte nicht abgeschlossen werden.',
                    }),
                });
            } finally {
                setIsRecheckingIntegrity(false);
            }
        };

        return (
            <main className="min-h-screen bg-background px-4 py-10 lg:px-8">
                <div className="mx-auto flex max-w-3xl flex-col gap-5 rounded-lg border border-amber-500/35 bg-amber-500/5 p-6">
                    <div className="flex items-start gap-3">
                        <Shield className="mt-1 h-5 w-5 shrink-0 text-amber-600" />
                        <div className="space-y-2">
                            <h1 className="text-lg font-semibold">
                                {t('vault.integrity.revalidationTitle', {
                                    defaultValue: 'Integritätsprüfung erforderlich',
                                })}
                            </h1>
                            <p className="text-sm text-muted-foreground">
                                {getIntegrityWarningText(
                                    integrityMode,
                                    lastIntegrityResult?.nonTamperReason,
                                )}
                            </p>
                        </div>
                    </div>
                    <div>
                        <Button onClick={handleIntegrityRecheck} disabled={isRecheckingIntegrity}>
                            {isRecheckingIntegrity ? (
                                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                            ) : (
                                <RefreshCw className="mr-2 h-4 w-4" />
                            )}
                            {t('vault.integrity.retryCheck', { defaultValue: 'Erneut prüfen' })}
                        </Button>
                    </div>
                </div>
            </main>
        );
    }

    const handleOpenNewItem = () => {
        setEditingItemId(null);
        setDialogOpen(true);
    };

    const handleEditItem = (itemId: string) => {
        setEditingItemId(itemId);
        setDialogOpen(true);
    };

    const handleItemSaved = () => {
        setRefreshKey((prev) => prev + 1);
    };

    return (
        <div className="min-h-screen flex overflow-hidden bg-background">
            {!isMobile && (
                <VaultSidebar
                    selectedCategory={selectedCategory}
                    onSelectCategory={setSelectedCategory}
                />
            )}

            {isMobile && (
                <Sheet open={sidebarOpen} onOpenChange={setSidebarOpen}>
                    <SheetContent side="left" className="p-0 w-[88vw] max-w-[20rem]">
                        <SheetTitle className="sr-only">{t('vault.sidebar.title')}</SheetTitle>
                        <VaultSidebar
                            compactMode
                            selectedCategory={selectedCategory}
                            onSelectCategory={setSelectedCategory}
                            onActionComplete={() => setSidebarOpen(false)}
                        />
                    </SheetContent>
                </Sheet>
            )}

            <div className="flex-1 flex flex-col min-w-0">
                <header className="sticky top-0 z-10 border-b border-border/55 bg-background/90 backdrop-blur-xl px-4 lg:px-6 py-4">
                    <div className="flex flex-col gap-3 sm:flex-row sm:gap-4 items-start sm:items-center justify-between">
                        <div className="relative w-full sm:max-w-md min-w-0">
                            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
                            <Input
                                placeholder={t('vault.search.placeholder')}
                                value={searchQuery}
                                onChange={(e) => setSearchQuery(e.target.value)}
                                className="pl-10"
                            />
                        </div>

                        <div className="flex w-full sm:w-auto items-center gap-2 flex-wrap sm:flex-nowrap">
                            {isMobile && (
                                <Button
                                    variant="outline"
                                    size="icon"
                                    onClick={() => setSidebarOpen(true)}
                                    aria-label={t('vault.sidebar.title')}
                                >
                                    <Menu className="w-4 h-4" />
                                </Button>
                            )}

                            {showWebsiteChrome && (
                                <Button asChild variant="outline">
                                    <Link to="/">{t('nav.home')}</Link>
                                </Button>
                            )}

                            {showAdminButton && adminEntryPath && (
                                <Button
                                    variant="outline"
                                    onClick={() => navigate(adminEntryPath, { state: buildReturnState(location) })}
                                    className="flex items-center gap-2"
                                >
                                    <Wrench className="w-4 h-4" />
                                    <span className="hidden md:inline">{t('admin.title')}</span>
                                </Button>
                            )}

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

                            <Button onClick={handleOpenNewItem} className="ml-auto sm:ml-0">
                                <Plus className="w-4 h-4 mr-2" />
                                {t('vault.actions.add')}
                            </Button>
                        </div>
                    </div>

                    <Tabs value={activeFilter} onValueChange={(v) => setActiveFilter(v as ItemFilter)} className="mt-4">
                        <div className="-mx-1 overflow-x-auto px-1 pb-1">
                            <TabsList className="inline-flex w-max min-w-full sm:min-w-0">
                                <TabsTrigger value="all" className="flex items-center gap-1.5 whitespace-nowrap">
                                    <Shield className="w-4 h-4" />
                                    <span className="hidden sm:inline">{t('vault.filters.all')}</span>
                                </TabsTrigger>
                                <TabsTrigger value="passwords" className="flex items-center gap-1.5 whitespace-nowrap">
                                    <Key className="w-4 h-4" />
                                    <span className="hidden sm:inline">{t('vault.filters.passwords')}</span>
                                </TabsTrigger>
                                <TabsTrigger value="notes" className="flex items-center gap-1.5 whitespace-nowrap">
                                    <FileText className="w-4 h-4" />
                                    <span className="hidden sm:inline">{t('vault.filters.notes')}</span>
                                </TabsTrigger>
                                <TabsTrigger value="favorites" className="flex items-center gap-1.5 whitespace-nowrap">
                                    <Star className="w-4 h-4" />
                                    <span className="hidden sm:inline">{t('vault.filters.favorites')}</span>
                                </TabsTrigger>
                            </TabsList>
                        </div>
                    </Tabs>

                    <div className="mt-2 flex flex-wrap items-center gap-2 text-xs">
                        {!isOnline && (
                            <p className="inline-flex items-center gap-1 rounded-md border border-amber-500/40 bg-amber-500/10 px-2 py-1 text-amber-700 dark:text-amber-300">
                                <WifiOff className="w-3 h-3" />
                                {t('vault.offlineMode', {
                                    defaultValue: 'Offline-Modus aktiv: Änderungen werden lokal gespeichert.',
                                })}
                            </p>
                        )}
                        {isOnline && isSyncing && (
                            <p className="inline-flex items-center gap-1 rounded-md border border-primary/40 bg-primary/10 px-2 py-1 text-primary">
                                <RefreshCw className="w-3 h-3 animate-spin" />
                                {t('vault.syncingOfflineChanges', {
                                    defaultValue: 'Synchronisiere Offline-Änderungen...',
                                })}
                            </p>
                        )}
                    </div>
                </header>

                <main className="flex-1 p-3 sm:p-4 lg:p-6 min-w-0">
                    <VaultItemList
                        searchQuery={searchQuery}
                        filter={activeFilter}
                        categoryId={selectedCategory}
                        viewMode={viewMode}
                        onEditItem={handleEditItem}
                        refreshKey={refreshKey}
                    />
                </main>

                {showWebsiteChrome && (
                    <footer className="border-t border-border/40 px-4 lg:px-6 py-3 text-xs text-muted-foreground">
                        <nav className="flex flex-wrap items-center gap-3">
                            <Link to="/privacy" className="hover:text-foreground transition-colors">
                                {t('landing.footer.privacy')}
                            </Link>
                            <Link to="/impressum" className="hover:text-foreground transition-colors">
                                {t('landing.footer.imprint')}
                            </Link>
                            <button
                                type="button"
                                onClick={() => window.dispatchEvent(new Event('singra:open-cookie-settings'))}
                                className="hover:text-foreground transition-colors"
                            >
                                {t('landing.footer.cookies')}
                            </button>
                        </nav>
                    </footer>
                )}
            </div>

            <VaultItemDialog
                open={dialogOpen}
                onOpenChange={setDialogOpen}
                itemId={editingItemId}
                onSave={handleItemSaved}
            />
        </div>
    );
}

