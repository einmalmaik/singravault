// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE
/**
 * @fileoverview Vault Status Card
 *
 * "Tresor-Status" card at the bottom of the sidebar. Pure presentation: the
 * status summary + tone classes are computed upstream in
 * `vaultSidebarStatus.ts` so the card itself only renders text and styling
 * and delegates the "open report" action to the parent.
 */

import { Activity } from 'lucide-react';

import { Button } from '@/components/ui/button';
import { cn } from '@/lib/utils';

import type {
  VaultSidebarStatusSummary,
  VaultSidebarStatusToneClasses,
} from './vaultSidebarStatus';

interface VaultSidebarStatusCardProps {
  readonly summary: VaultSidebarStatusSummary;
  readonly toneClasses: VaultSidebarStatusToneClasses;
  readonly onOpenReport: () => void;
}

export function VaultSidebarStatusCard({
  summary,
  toneClasses,
  onOpenReport,
}: VaultSidebarStatusCardProps) {
  return (
    <div className={cn(
      'mx-3 mb-3 rounded-2xl border p-3 shadow-[0_18px_42px_hsl(0_0%_0%/0.28)] lg:p-4',
      toneClasses.card,
    )}>
      <div className="flex items-start gap-3">
        <div className={cn('rounded-xl border p-2', toneClasses.icon)}>
          <Activity className="h-4 w-4" />
        </div>
        <div className="min-w-0 space-y-1">
          <p className="text-sm font-semibold text-foreground">Tresor-Status</p>
          <p className={cn('text-sm font-medium', toneClasses.text)}>
            {summary.label}
          </p>
          <p className="text-xs leading-5 text-muted-foreground">
            {summary.description}
          </p>
        </div>
      </div>
      <Button
        variant="outline"
        size="sm"
        className={cn('mt-3 w-full', toneClasses.button)}
        onClick={onOpenReport}
      >
        Bericht anzeigen
      </Button>
    </div>
  );
}
