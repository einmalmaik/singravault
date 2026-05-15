// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE
/**
 * @fileoverview Vault Item List Empty / Loading States
 *
 * Three placeholder views the list uses before, instead of, or alongside the
 * actual rows. Extracted so the main component's render only branches on
 * "loading vs. empty vs. content" without inlining the marketing copy.
 */

import { useTranslation } from 'react-i18next';
import { KeyRound, Loader2, Plus, Shield } from 'lucide-react';

import { Button } from '@/components/ui/button';

interface VaultItemListLoadingStateProps {
  readonly decrypting: boolean;
}

export function VaultItemListLoadingState({ decrypting }: VaultItemListLoadingStateProps) {
  const { t } = useTranslation();
  return (
    <div className="flex h-64 flex-col items-center justify-center text-muted-foreground">
      <Loader2 className="mb-4 h-8 w-8 animate-spin" />
      <p>{decrypting ? t('vault.items.decrypting') : t('common.loading')}</p>
    </div>
  );
}

interface VaultItemListEmptyVaultProps {
  readonly onAddItem: () => void;
}

export function VaultItemListEmptyVault({ onAddItem }: VaultItemListEmptyVaultProps) {
  const { t } = useTranslation();
  return (
    <div className="flex h-64 flex-col items-center justify-center text-center">
      <div className="mb-4 rounded-full border border-[hsl(var(--border)/0.35)] bg-[hsl(var(--el-2))] p-4">
        <Shield className="h-8 w-8 text-primary/60" />
      </div>
      <h3 className="mb-2 text-lg font-medium">{t('vault.empty.title')}</h3>
      <p className="mb-4 max-w-sm text-muted-foreground">
        {t('vault.empty.description')}
      </p>
      <Button onClick={onAddItem}>
        <Plus className="mr-2 h-4 w-4" />
        {t('vault.empty.action')}
      </Button>
    </div>
  );
}

export function VaultItemListNoSearchResults() {
  const { t } = useTranslation();
  return (
    <div className="flex h-64 flex-col items-center justify-center text-center">
      <div className="mb-4 rounded-full border border-[hsl(var(--border)/0.35)] bg-[hsl(var(--el-2))] p-4">
        <KeyRound className="h-8 w-8 text-primary/60" />
      </div>
      <h3 className="mb-2 text-lg font-medium">{t('vault.search.noResults')}</h3>
      <p className="max-w-sm text-muted-foreground">
        {t('vault.search.noResultsDescription')}
      </p>
    </div>
  );
}

interface VaultItemListEmptyVisibleProps {
  readonly hasAnyDecryptableItem: boolean;
}

/**
 * Shown when the visible-entries filter rejected every renderable row.
 * Distinguishes two important cases for the user: "only quarantine left" and
 * "search has no matches", because the recovery path differs.
 */
export function VaultItemListEmptyVisible({ hasAnyDecryptableItem }: VaultItemListEmptyVisibleProps) {
  const { t } = useTranslation();
  return (
    <div className="flex h-48 flex-col items-center justify-center text-center">
      <div className="mb-4 rounded-full border border-[hsl(var(--border)/0.35)] bg-[hsl(var(--el-2))] p-4">
        <KeyRound className="h-8 w-8 text-primary/60" />
      </div>
      {!hasAnyDecryptableItem ? (
        <>
          <h3 className="mb-2 text-lg font-medium">
            {t('vault.integrity.onlyQuarantinedTitle', {
              defaultValue: 'Derzeit sind nur Einträge in Quarantäne vorhanden',
            })}
          </h3>
          <p className="max-w-sm text-muted-foreground">
            {t('vault.integrity.onlyQuarantinedDescription', {
              defaultValue: 'Normale Einträge sind aktuell nicht verfügbar. Prüfe die Quarantänehinweise oben.',
            })}
          </p>
        </>
      ) : (
        <>
          <h3 className="mb-2 text-lg font-medium">{t('vault.search.noResults')}</h3>
          <p className="max-w-sm text-muted-foreground">
            {t('vault.search.noResultsDescription')}
          </p>
        </>
      )}
    </div>
  );
}
