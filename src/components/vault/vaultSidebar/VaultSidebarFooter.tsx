// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE
/**
 * @fileoverview Sidebar Footer
 *
 * Account/Settings entry point and "Tresor sperren" action at the bottom of
 * the sidebar.
 *
 * The lock confirmation explicitly mentions both master password and device
 * key so the user is not surprised by `device_key_required` after re-open.
 * The action is centralised here so any sidebar entry point reuses the same
 * confirmation copy and side effects (`onLockConfirmed`).
 */

import { useTranslation } from 'react-i18next';
import { ChevronDown, Lock, Settings, Shield, User } from 'lucide-react';

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
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import { cn } from '@/lib/utils';

import { VaultSidebarItem } from './VaultSidebarItem';

interface VaultSidebarFooterProps {
  readonly collapsed: boolean;
  readonly accountEmail: string | undefined;
  readonly active: { account: boolean };
  readonly onOpenAccountSettings: () => void;
  readonly onOpenVaultSettings: () => void;
  readonly onLockConfirmed: () => void;
}

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

export function VaultSidebarFooter({
  collapsed,
  accountEmail,
  active,
  onOpenAccountSettings,
  onOpenVaultSettings,
  onLockConfirmed,
}: VaultSidebarFooterProps) {
  const { t } = useTranslation();

  return (
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
            <DropdownMenuItem onClick={onOpenAccountSettings}>
              <User className="mr-2 h-4 w-4" />
              {t('settings.accountPage.title')}
            </DropdownMenuItem>
            <DropdownMenuItem onClick={onOpenVaultSettings}>
              <Shield className="mr-2 h-4 w-4" />
              {t('settings.vaultPage.title')}
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      )}
      {collapsed && (
        <VaultSidebarItem
          icon={<Settings className="w-4 h-4" />}
          label={t('settings.accountPage.title')}
          collapsed={collapsed}
          active={active.account}
          onClick={onOpenAccountSettings}
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
            <AlertDialogAction onClick={onLockConfirmed}>
              Tresor sperren
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}
