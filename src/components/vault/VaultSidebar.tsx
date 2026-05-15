// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE
/**
 * @fileoverview Vault Sidebar Component
 *
 * Composition root for the vault sidebar:
 *  - quick navigation (All items, Vault Health, Authenticator)
 *  - categories list with drag-to-move + per-row edit/delete menu
 *  - "Tresor-Status" health card
 *  - account dropdown + lock confirmation footer
 *
 * Read paths (categories, health summary) and pure derivations (status
 * label/tone, plaintext mapping) live in `./vaultSidebar/*`. This file is
 * intentionally a thin orchestration of presentational sub-components.
 */

import { useCallback, useState, useEffect } from 'react';
import { useTranslation } from 'react-i18next';
import { Activity, ChevronLeft, ChevronRight, Home, QrCode } from 'lucide-react';
import { useLocation, useNavigate } from 'react-router-dom';

import { Button } from '@/components/ui/button';
import { Separator } from '@/components/ui/separator';
import { cn } from '@/lib/utils';
import { useVault } from '@/contexts/VaultContext';
import { useAuth } from '@/contexts/AuthContext';
import { useFeatureGate } from '@/hooks/useFeatureGate';
import { isPremiumActive } from '@/extensions/registry';
import { buildReturnState } from '@/services/returnNavigationState';

import { CategoryDialog, type CategoryChangeEvent } from './CategoryDialog';
import { VaultSidebarItem } from './vaultSidebar/VaultSidebarItem';
import { VaultSidebarStatusCard } from './vaultSidebar/VaultSidebarStatusCard';
import { VaultSidebarFooter } from './vaultSidebar/VaultSidebarFooter';
import { VaultSidebarCategoryList } from './vaultSidebar/VaultSidebarCategoryList';
import { useVaultSidebarCategories } from './vaultSidebar/useVaultSidebarCategories';
import { useVaultSidebarHealth } from './vaultSidebar/useVaultSidebarHealth';
import {
  getVaultSidebarStatusSummary,
  getVaultSidebarStatusToneClasses,
} from './vaultSidebar/vaultSidebarStatus';
import {
  getVerifiedItemCategoryId,
  mapVerifiedItemRecordToPlaintext,
} from './vaultSidebar/vaultSidebarPlaintextMapper';
import type { Category } from './vaultSidebar/vaultSidebarTypes';

interface VaultSidebarProps {
  selectedCategory: string | null;
  onSelectCategory: (categoryId: string | null) => void;
  compactMode?: boolean;
  onActionComplete?: () => void;
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
  const { user } = useAuth();
  const userId = user?.id ?? null;
  const accountEmail = user?.email ?? undefined;

  const {
    lock,
    decryptData,
    decryptItem,
    isDuressMode,
    lastIntegrityResult,
    getVaultHealthAnalysisItems,
    verifyIntegrity,
    vaultDataVersion,
    vaultMigrationStatus,
    opLogLocalVaultState,
    opLogUpdateItem,
  } = useVault();
  const useOpLogVerifiedRuntime = vaultMigrationStatus === 'verified';

  const vaultHealthAccess = useFeatureGate('vault_health_reports');
  const authenticatorAccess = useFeatureGate('builtin_authenticator');
  const premiumFeaturesAvailable = isPremiumActive();

  const [collapsed, setCollapsed] = useState(false);

  // Force the sidebar open in compact (mobile drawer) mode so the user does
  // not see a half-collapsed drawer when they reopen it on a phone.
  useEffect(() => {
    if (compactMode) {
      setCollapsed(false);
    }
  }, [compactMode]);

  const [dialogOpen, setDialogOpen] = useState(false);
  const [editingCategory, setEditingCategory] = useState<Category | null>(null);
  const [categoryDialogInitialAction, setCategoryDialogInitialAction] =
    useState<'delete' | undefined>(undefined);

  const { categories, loading, refetch: refetchCategories } = useVaultSidebarCategories({
    userId,
    isDuressMode,
    useOpLogVerifiedRuntime,
    opLogLocalVaultState,
    vaultDataVersion,
    lastIntegrityResult,
    decryptData,
    decryptItem,
    verifyIntegrity,
  });

  const { summary: vaultHealthSummary, loading: vaultHealthLoading } = useVaultSidebarHealth({
    enabled: vaultHealthAccess.allowed,
    userId,
    lastIntegrityResult,
    vaultDataVersion,
    getVaultHealthAnalysisItems,
  });

  const vaultStatusSummary = getVaultSidebarStatusSummary(
    lastIntegrityResult,
    vaultHealthSummary,
    vaultHealthLoading,
  );
  const vaultStatusToneClasses = getVaultSidebarStatusToneClasses(vaultStatusSummary.tone);

  const handleAddCategory = useCallback(() => {
    setEditingCategory(null);
    setCategoryDialogInitialAction(undefined);
    setDialogOpen(true);
  }, []);

  const handleEditCategory = useCallback((category: Category) => {
    setEditingCategory(category);
    setCategoryDialogInitialAction(undefined);
    setDialogOpen(true);
  }, []);

  const handleDeleteCategoryFromMenu = useCallback((category: Category) => {
    setEditingCategory(category);
    setCategoryDialogInitialAction('delete');
    setDialogOpen(true);
  }, []);

  const handleCategoryChange = useCallback((event?: CategoryChangeEvent) => {
    if (event?.type === 'deleted' && selectedCategory === event.categoryId) {
      onSelectCategory(null);
    }
    void refetchCategories();
  }, [onSelectCategory, refetchCategories, selectedCategory]);

  const handleSelectCategory = useCallback((categoryId: string) => {
    onSelectCategory(categoryId);
    onActionComplete?.();
  }, [onActionComplete, onSelectCategory]);

  const handleCategoryDrop = useCallback(async (categoryId: string, itemId: string) => {
    if (!opLogLocalVaultState) {
      return;
    }

    const record = opLogLocalVaultState.recordsById.get(itemId);
    // Skip the write when the item already lives in the target category;
    // we do not want to bump updatedAt for a no-op move.
    if (getVerifiedItemCategoryId(record) === categoryId) {
      return;
    }

    const plaintext = mapVerifiedItemRecordToPlaintext(record, categoryId);
    if (!plaintext) {
      return;
    }

    const result = await opLogUpdateItem(itemId, plaintext);
    if (!result.error) {
      onActionComplete?.();
      await refetchCategories();
    }
  }, [onActionComplete, opLogLocalVaultState, opLogUpdateItem, refetchCategories]);

  const handleLockConfirmed = useCallback(() => {
    lock();
    onActionComplete?.();
    navigate('/vault', { replace: true });
  }, [lock, navigate, onActionComplete]);

  return (
    <>
      <aside
        className={cn(
          'flex flex-col border-r bg-[hsl(var(--sidebar-background)/0.86)] backdrop-blur-xl',
          'border-[hsl(var(--sidebar-border)/0.55)] shadow-[inset_-1px_0_0_hsl(var(--foreground)/0.03)]',
          compactMode
            ? 'h-full w-full'
            : cn('self-stretch min-h-full transition-all duration-300', collapsed ? 'w-16' : 'w-64 lg:w-72'),
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
              className="h-10 w-10 lg:h-8 lg:w-8"
              onClick={() => setCollapsed(!collapsed)}
            >
              {collapsed ? <ChevronRight className="w-4 h-4" /> : <ChevronLeft className="w-4 h-4" />}
            </Button>
          )}
        </div>

        {/* Quick Navigation */}
        <div className="p-2">
          <VaultSidebarItem
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
            <VaultSidebarItem
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
            <VaultSidebarItem
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

        <VaultSidebarCategoryList
          collapsed={collapsed}
          loading={loading}
          categories={categories}
          selectedCategory={selectedCategory}
          onAddCategory={handleAddCategory}
          onSelectCategory={handleSelectCategory}
          onEditCategory={handleEditCategory}
          onDeleteCategory={handleDeleteCategoryFromMenu}
          onCategoryDrop={(categoryId, itemId) => { void handleCategoryDrop(categoryId, itemId); }}
        />

        {!collapsed && vaultHealthAccess.allowed && (
          <VaultSidebarStatusCard
            summary={vaultStatusSummary}
            toneClasses={vaultStatusToneClasses}
            onOpenReport={() => {
              navigate('/vault-health');
              onActionComplete?.();
            }}
          />
        )}

        <Separator />

        <VaultSidebarFooter
          collapsed={collapsed}
          accountEmail={accountEmail}
          active={{ account: location.pathname === '/settings' || location.pathname === '/vault/settings' }}
          onOpenAccountSettings={() => {
            onActionComplete?.();
            navigate('/settings', { state: buildReturnState(location) });
          }}
          onOpenVaultSettings={() => {
            onActionComplete?.();
            navigate('/vault/settings', { state: buildReturnState(location) });
          }}
          onLockConfirmed={handleLockConfirmed}
        />
      </aside>

      <CategoryDialog
        open={dialogOpen}
        onOpenChange={(open) => {
          setDialogOpen(open);
          if (!open) {
            setCategoryDialogInitialAction(undefined);
          }
        }}
        category={editingCategory}
        initialAction={categoryDialogInitialAction}
        onSave={handleCategoryChange}
      />
    </>
  );
}
