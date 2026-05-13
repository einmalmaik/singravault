// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE
/**
 * `VaultOpLogQuarantinePanel` — Phase 9 quarantine panel.
 *
 * Displays quarantined records from the operation-log state machine.
 * Each card shows ONLY the record ID and the security-state reason.
 * NO plaintext titles, passwords, URLs or notes are rendered.
 *
 * Invariants:
 * - No decryption of quarantined records.
 * - No logging of record IDs or reasons to the console.
 * - Actions trigger concrete signed operations (restore / delete).
 */

import { ShieldAlert } from 'lucide-react';
import { useTranslation } from 'react-i18next';

import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent } from '@/components/ui/card';
import type { VaultOpLogQuarantinedItemUi } from '@/services/vaultOpLog/vaultOpLogUiAdapter';
import { getRecordSecurityStateUiLabel } from '@/services/vaultOpLog/vaultOpLogUiAdapter';

interface VaultOpLogQuarantinePanelProps {
  items: readonly VaultOpLogQuarantinedItemUi[];
  onRestore?: (recordId: string) => void;
  onDelete?: (recordId: string) => void;
  actionsDisabled?: boolean;
}

export function VaultOpLogQuarantinePanel({
  items,
  onRestore,
  onDelete,
  actionsDisabled = false,
}: VaultOpLogQuarantinePanelProps) {
  const { t } = useTranslation();

  if (items.length === 0) {
    return null;
  }

  return (
    <div className="space-y-3">
      <h3 className="text-sm font-semibold uppercase tracking-wide text-muted-foreground">
        {t('vault.oplog.quarantinePanelTitle', { defaultValue: 'Quarantäne' })}
      </h3>

      <div className="space-y-2">
        {items.map((item) => (
          <Card
            key={item.recordId}
            className="border-amber-500/30 bg-amber-500/5"
          >
            <CardContent className="flex items-start gap-3 p-3">
              <div className="flex-shrink-0 rounded-md border border-amber-500/30 bg-amber-500/10 p-1.5 text-amber-700 dark:text-amber-300">
                <ShieldAlert className="h-4 w-4" />
              </div>
              <div className="min-w-0 flex-1 space-y-1">
                <div className="flex flex-wrap items-center gap-2">
                  <Badge
                    variant="outline"
                    className="border-amber-500/40 text-amber-700 dark:text-amber-300"
                  >
                    {getRecordSecurityStateUiLabel(item.recordState)}
                  </Badge>
                </div>
                <p className="break-all text-xs text-muted-foreground">
                  {item.recordId}
                </p>
                {item.reason && (
                  <p className="text-xs text-muted-foreground/80">
                    {item.reason}
                  </p>
                )}
                <div className="flex flex-wrap gap-2 pt-1">
                  {onRestore && (
                    <Button
                      type="button"
                      size="sm"
                      variant="outline"
                      disabled={actionsDisabled}
                      title={actionsDisabled ? t('vault.oplog.actionUnavailable', { defaultValue: 'Signierte OpLog-Aktion noch nicht verfügbar' }) : undefined}
                      onClick={() => { onRestore(item.recordId); }}
                    >
                      {t('vault.oplog.restoreAction', { defaultValue: 'Wiederherstellen' })}
                    </Button>
                  )}
                  {onDelete && (
                    <Button
                      type="button"
                      size="sm"
                      variant="outline"
                      disabled={actionsDisabled}
                      title={actionsDisabled ? t('vault.oplog.actionUnavailable', { defaultValue: 'Signierte OpLog-Aktion noch nicht verfügbar' }) : undefined}
                      onClick={() => { onDelete(item.recordId); }}
                    >
                      {t('vault.oplog.deleteAction', { defaultValue: 'Löschen' })}
                    </Button>
                  )}
                </div>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  );
}
