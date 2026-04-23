import { ShieldAlert, TriangleAlert } from 'lucide-react';
import { useTranslation } from 'react-i18next';

import { Badge } from '@/components/ui/badge';
import { Card, CardContent } from '@/components/ui/card';
import { cn } from '@/lib/utils';
import { ViewMode } from '@/pages/VaultPage';
import type { QuarantinedVaultItem } from '@/services/vaultIntegrityService';
import { VaultQuarantineActions } from './VaultQuarantineActions';
import { getQuarantineReasonLabel } from './vaultQuarantineLabels';

interface VaultQuarantinedItemCardProps {
  itemId: string;
  reason: QuarantinedVaultItem['reason'];
  viewMode: ViewMode;
}

export function VaultQuarantinedItemCard({
  itemId,
  reason,
  viewMode,
}: VaultQuarantinedItemCardProps) {
  const { t } = useTranslation();
  const title = t('vault.integrity.quarantineItemTitle', {
    defaultValue: 'Manipulierter Eintrag',
  });
  const badgeLabel = t('vault.integrity.quarantineBadge', {
    defaultValue: 'Quarantäne',
  });
  const reasonLabel = getQuarantineReasonLabel(reason, t);

  if (viewMode === 'list') {
    return (
      <Card className="border-amber-500/35 bg-amber-500/6">
        <CardContent className="space-y-3 p-3">
          <div className="flex items-start gap-3">
            <div className="flex-shrink-0 rounded-lg border border-amber-500/35 bg-amber-500/10 p-2 text-amber-700 dark:text-amber-300">
              <ShieldAlert className="h-5 w-5" />
            </div>
            <div className="min-w-0 flex-1 space-y-1">
              <div className="flex flex-wrap items-center gap-2">
                <p className="font-medium">{title}</p>
                <Badge
                  variant="outline"
                  className="border-amber-500/45 text-amber-700 dark:text-amber-300"
                >
                  {badgeLabel}
                </Badge>
              </div>
              <p className="text-sm text-muted-foreground">{reasonLabel}</p>
              <p className="break-all text-xs text-muted-foreground/80">{itemId}</p>
            </div>
          </div>
          <VaultQuarantineActions
            item={{ id: itemId, reason, updatedAt: null }}
            compact
          />
        </CardContent>
      </Card>
    );
  }

  return (
    <Card className={cn('border-amber-500/35 bg-amber-500/6 transition-colors')}>
      <CardContent className="space-y-3 p-4">
        <div className="flex items-start justify-between gap-3">
          <div className="flex items-center gap-3">
            <div className="rounded-lg border border-amber-500/35 bg-amber-500/10 p-2 text-amber-700 dark:text-amber-300">
              <TriangleAlert className="h-5 w-5" />
            </div>
            <div>
              <h3 className="line-clamp-1 font-medium">{title}</h3>
              <p className="text-xs text-muted-foreground">
                {t('vault.integrity.untrustedEntryLabel', {
                  defaultValue: 'Nicht vertrauenswürdig',
                })}
              </p>
            </div>
          </div>
          <Badge
            variant="outline"
            className="border-amber-500/45 text-amber-700 dark:text-amber-300"
          >
            {badgeLabel}
          </Badge>
        </div>

        <p className="text-sm text-muted-foreground">{reasonLabel}</p>
        <p className="break-all text-xs text-muted-foreground/80">{itemId}</p>
        <VaultQuarantineActions item={{ id: itemId, reason, updatedAt: null }} />
      </CardContent>
    </Card>
  );
}
