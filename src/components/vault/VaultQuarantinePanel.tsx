import { useTranslation } from 'react-i18next';
import { ShieldAlert, TriangleAlert } from 'lucide-react';

import { Badge } from '@/components/ui/badge';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import type { QuarantinedVaultItem } from '@/services/vaultIntegrityService';
import { VaultQuarantineActions } from './VaultQuarantineActions';
import { getQuarantineReasonLabel } from './vaultQuarantineLabels';

interface VaultQuarantinePanelProps {
  items: QuarantinedVaultItem[];
  title?: string;
  description?: string;
}

export function VaultQuarantinePanel({
  items,
  title,
  description,
}: VaultQuarantinePanelProps) {
  const { t } = useTranslation();

  if (items.length === 0) {
    return null;
  }

  return (
    <Card className="border-amber-500/35 bg-amber-500/5">
      <CardHeader className="space-y-2">
        <CardTitle className="flex items-center gap-2 text-base">
          <ShieldAlert className="w-5 h-5 text-amber-600" />
          {title || t('vault.integrity.quarantineTitle', {
            defaultValue: 'Einträge in Quarantäne',
          })}
        </CardTitle>
        <p className="text-sm text-muted-foreground">
          {description || t('vault.integrity.quarantineDescription', {
            defaultValue: 'Diese Einträge wurden nicht entschlüsselt oder nicht vertraut, weil ihre Integritätsbasis nicht mehr stimmt.',
          })}
        </p>
      </CardHeader>
      <CardContent className="space-y-3">
        {items.map((item) => (
          <div
            key={item.id}
            className="rounded-md border border-amber-500/25 bg-background/70 px-4 py-3"
          >
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div className="min-w-0">
                <div className="flex items-center gap-2">
                  <TriangleAlert className="w-4 h-4 text-amber-600" />
                  <p className="font-medium">
                    {t('vault.integrity.quarantineItemTitle', {
                      defaultValue: 'Manipulierter Eintrag',
                    })}
                  </p>
                </div>
                <p className="mt-1 break-all text-sm text-muted-foreground">
                  {item.id}
                </p>
              </div>
              <Badge
                variant="outline"
                className="border-amber-500/40 text-amber-700 dark:text-amber-300"
              >
                {t('vault.integrity.quarantineBadge', {
                  defaultValue: 'Quarantäne',
                })}
              </Badge>
            </div>
            <p className="mt-2 text-sm text-muted-foreground">
              {getQuarantineReasonLabel(item.reason, t)}
            </p>
            <div className="mt-3">
              <VaultQuarantineActions item={item} compact />
            </div>
          </div>
        ))}
      </CardContent>
    </Card>
  );
}
