// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE
/**
 * `VaultOpLogSecurityModeBanner` — Phase 9 security mode banner.
 *
 * Displays the current `VaultSecurityMode` prominently so the user
 * always knows whether the vault is in `normal`, `restricted`,
 * `safeMode`, `safeModeRecommended` or `lockedCritical`.
 *
 * No security decisions are made here; the mode is received from
 * the vault context / state machine.
 */

import { Shield, ShieldAlert, ShieldCheck, ShieldX } from 'lucide-react';
import { useTranslation } from 'react-i18next';

import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { cn } from '@/lib/utils';
import type { VaultSecurityMode } from '@/services/vaultOpLog/vaultSecurityStates';

interface VaultOpLogSecurityModeBannerProps {
  mode: VaultSecurityMode;
}

export function VaultOpLogSecurityModeBanner({ mode }: VaultOpLogSecurityModeBannerProps) {
  const { t } = useTranslation();

  if (mode === 'normal') {
    return (
      <Alert className="border-emerald-500/25 bg-emerald-500/8">
        <ShieldCheck className="h-4 w-4 text-emerald-600 dark:text-emerald-400" />
        <AlertTitle>
          {t('vault.oplog.mode.normalTitle', { defaultValue: 'Tresor verifiziert' })}
        </AlertTitle>
        <AlertDescription>
          {t('vault.oplog.mode.normalDescription', {
            defaultValue: 'Alle Einträge wurden kryptographisch verifiziert.',
          })}
        </AlertDescription>
      </Alert>
    );
  }

  if (mode === 'restricted') {
    return (
      <Alert className="border-amber-500/30 bg-amber-500/8">
        <ShieldAlert className="h-4 w-4 text-amber-600 dark:text-amber-400" />
        <AlertTitle>
          {t('vault.oplog.mode.restrictedTitle', { defaultValue: 'Eingeschränkter Modus' })}
        </AlertTitle>
        <AlertDescription>
          {t('vault.oplog.mode.restrictedDescription', {
            defaultValue: 'Einige Einträge sind unter Quarantäne oder in Konflikt. Autofill, Export, Suche und Clipboard sind für nicht-verifizierte Daten deaktiviert.',
          })}
        </AlertDescription>
      </Alert>
    );
  }

  if (mode === 'safeMode' || mode === 'safeModeRecommended') {
    return (
      <Alert
        className={cn(
          'border-orange-500/30 bg-orange-500/8',
          mode === 'safeModeRecommended' && 'border-orange-500/20 bg-orange-500/5',
        )}
      >
        <Shield className="h-4 w-4 text-orange-600 dark:text-orange-400" />
        <AlertTitle>
          {t('vault.oplog.mode.safeModeTitle', { defaultValue: 'Safe Mode' })}
        </AlertTitle>
        <AlertDescription>
          {t('vault.oplog.mode.safeModeDescription', {
            defaultValue: 'Der Tresor arbeitet auf einem lokal verifizierten Snapshot, weil der Remote-Status als nicht vertrauenswürdig eingestuft wurde. Keine automatische Remote-Reparatur erfolgt.',
          })}
        </AlertDescription>
      </Alert>
    );
  }

  // lockedCritical
  return (
    <Alert variant="destructive">
      <ShieldX className="h-4 w-4" />
      <AlertTitle>
        {t('vault.oplog.mode.lockedCriticalTitle', { defaultValue: 'Kritische Sperre' })}
      </AlertTitle>
      <AlertDescription>
        {t('vault.oplog.mode.lockedCriticalDescription', {
          defaultValue: 'Der Tresor ist vollständig gesperrt, weil grundlegende Vertrauensannahmen (Manifest, Schlüssel oder Gerätetrust) verletzt wurden.',
        })}
      </AlertDescription>
    </Alert>
  );
}
