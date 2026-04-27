import { useTranslation } from 'react-i18next';
import { EyeOff, ShieldAlert, TriangleAlert } from 'lucide-react';

import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import type { QuarantinedVaultItem } from '@/services/vaultIntegrityService';
import { VaultQuarantineActions } from './VaultQuarantineActions';
import { getQuarantineReasonLabel } from './vaultQuarantineLabels';

interface VaultQuarantinePanelProps {
  items: QuarantinedVaultItem[];
  title?: string;
  description?: string;
  ignoredItems?: QuarantinedVaultItem[];
  onIgnoreItem?: (item: QuarantinedVaultItem) => void;
  onIgnoreAll?: () => void;
}

function VaultQuarantineEntry({
  item,
  onIgnoreItem,
}: {
  item: QuarantinedVaultItem;
  onIgnoreItem?: (item: QuarantinedVaultItem) => void;
}) {
  const { t } = useTranslation();

  return (
    <div className="rounded-md border border-amber-500/25 bg-background/70 px-4 py-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            <TriangleAlert className="h-4 w-4 text-amber-600" />
            <p className="font-medium">
              {item.itemType === 'totp'
                ? t('vault.integrity.quarantineAuthenticatorItemTitle', {
                  defaultValue: 'Manipulierter Authenticator-Eintrag',
                })
                : t('vault.integrity.quarantineItemTitle', {
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
      <div className="mt-3 flex flex-wrap items-center gap-2">
        <VaultQuarantineActions item={item} compact />
        {onIgnoreItem && (
          <Button
            type="button"
            size="sm"
            variant="ghost"
            className="h-8 text-amber-800 hover:bg-amber-500/10 dark:text-amber-200"
            onClick={() => onIgnoreItem(item)}
          >
            <EyeOff className="mr-2 h-4 w-4" />
            {t('vault.integrity.ignoreEntryAction', {
              defaultValue: 'Ignorieren',
            })}
          </Button>
        )}
      </div>
    </div>
  );
}

export function VaultQuarantinePanel({
  items,
  title,
  description,
  ignoredItems = [],
  onIgnoreItem,
  onIgnoreAll,
}: VaultQuarantinePanelProps) {
  const { t } = useTranslation();
  const hasIgnoredItems = ignoredItems.length > 0;

  if (items.length === 0 && !hasIgnoredItems) {
    return null;
  }

  return (
    <Card className="border-amber-500/35 bg-amber-500/5">
      <CardHeader className="space-y-2">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <CardTitle className="flex items-center gap-2 text-base">
            <ShieldAlert className="h-5 w-5 text-amber-600" />
            {title || t('vault.integrity.quarantineTitle', {
              defaultValue: 'Einträge in Quarantäne',
            })}
          </CardTitle>
          {onIgnoreAll && items.length > 0 && (
            <Button
              type="button"
              variant="outline"
              size="sm"
              className="border-amber-500/35 bg-background/70 text-amber-800 hover:bg-amber-500/10 dark:text-amber-200"
              onClick={onIgnoreAll}
            >
              {t('vault.integrity.ignoreSummaryAction', {
                defaultValue: 'Alle sichtbaren ignorieren',
              })}
            </Button>
          )}
        </div>
        <p className="text-sm text-muted-foreground">
          {description || t('vault.integrity.quarantineDescription', {
            defaultValue: 'Mehrere deiner Einträge wurden manipuliert und können nicht mehr vertrauenswürdig entschlüsselt werden.',
          })}
        </p>
      </CardHeader>
      <CardContent className="space-y-3">
        {items.length >= 2 && (
          <p className="rounded-md border border-amber-500/25 bg-background/70 px-4 py-3 text-sm text-muted-foreground">
            {t('vault.integrity.quarantineSummary', {
              defaultValue: '{{count}} betroffene Einträge wurden zusammengefasst.',
              count: items.length,
            })}
          </p>
        )}
        {items.map((item) => (
          <VaultQuarantineEntry
            key={item.id}
            item={item}
            onIgnoreItem={onIgnoreItem}
          />
        ))}
        {hasIgnoredItems && (
          <div className="space-y-3 rounded-md border border-amber-500/20 bg-background/50 px-4 py-3">
            <p className="font-medium text-amber-800 dark:text-amber-200">
              {t('vault.integrity.ignoredEntriesTitle', {
                defaultValue: 'Ignorierte Quarantäne-Einträge',
              })}
            </p>
            {ignoredItems.map((item) => (
              <VaultQuarantineEntry key={item.id} item={item} />
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  );
}
