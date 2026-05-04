// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE
/**
 * `VaultOpLogConflictPanel` — Phase 9 conflict panel.
 *
 * Displays records that have two or more valid but conflicting
 * operation versions.  The panel shows only metadata (record ID,
 * operation count, operation IDs).  No plaintext is rendered.
 *
 * Actions:
 * - ResolveConflict triggers a concrete signed resolve/update operation.
 *   If the concrete operation type is not yet implemented, the action
 *   remains deactivated.
 */

import { GitCompare } from 'lucide-react';
import { useTranslation } from 'react-i18next';

import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent } from '@/components/ui/card';
import type { VaultOpLogConflictUi } from '@/services/vaultOpLog/vaultOpLogUiAdapter';

interface VaultOpLogConflictPanelProps {
  items: readonly VaultOpLogConflictUi[];
  onResolve?: (recordId: string) => void;
}

export function VaultOpLogConflictPanel({
  items,
  onResolve,
}: VaultOpLogConflictPanelProps) {
  const { t } = useTranslation();

  if (items.length === 0) {
    return null;
  }

  return (
    <div className="space-y-3">
      <h3 className="text-sm font-semibold uppercase tracking-wide text-muted-foreground">
        {t('vault.oplog.conflictPanelTitle', { defaultValue: 'Konflikte' })}
      </h3>

      <div className="space-y-2">
        {items.map((item) => (
          <Card
            key={item.recordId}
            className="border-rose-500/30 bg-rose-500/5"
          >
            <CardContent className="flex items-start gap-3 p-3">
              <div className="flex-shrink-0 rounded-md border border-rose-500/30 bg-rose-500/10 p-1.5 text-rose-700 dark:text-rose-300">
                <GitCompare className="h-4 w-4" />
              </div>
              <div className="min-w-0 flex-1 space-y-1">
                <div className="flex flex-wrap items-center gap-2">
                  <Badge
                    variant="outline"
                    className="border-rose-500/40 text-rose-700 dark:text-rose-300"
                  >
                    {t('vault.oplog.conflictBadge', { defaultValue: 'Konflikt' })}
                  </Badge>
                  <span className="text-xs text-muted-foreground">
                    {t('vault.oplog.conflictOperationCount', {
                      defaultValue: '{{count}} Operationen',
                      count: item.operationCount,
                    })}
                  </span>
                </div>
                <p className="break-all text-xs text-muted-foreground">
                  {item.recordId}
                </p>
                {item.operationIds.length > 0 && (
                  <p className="break-all text-xs text-muted-foreground/70">
                    {item.operationIds.join(', ')}
                  </p>
                )}
                {onResolve && (
                  <div className="pt-1">
                    <Button
                      type="button"
                      size="sm"
                      variant="outline"
                      onClick={() => { onResolve(item.recordId); }}
                    >
                      {t('vault.oplog.resolveAction', { defaultValue: 'Auflösen' })}
                    </Button>
                  </div>
                )}
              </div>
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  );
}
