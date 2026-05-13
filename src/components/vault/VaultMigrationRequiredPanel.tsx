// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE
/**
 * Minimal Phase-12 migration consent panel.
 *
 * This panel is rendered instead of the normal vault while a legacy
 * migration blocks unlock. It never displays vault plaintexts or key
 * material and starts migration only after an explicit user action.
 */

import { useState } from 'react';
import { AlertTriangle, Info, Loader2, Lock, RefreshCw, ShieldCheck } from 'lucide-react';

import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { useVault } from '@/contexts/VaultContext';
import type { VaultMigrationRolloutStatus } from '@/services/vaultOpLog/vaultMigrationRolloutService';

const STARTABLE_STATUSES = new Set<VaultMigrationRolloutStatus>([
  'required',
  'ready',
]);

const RESUMABLE_STATUSES = new Set<VaultMigrationRolloutStatus>([
  'running',
  'committed',
  'failed',
  'preflightFailed',
]);

function describeStatus(status: VaultMigrationRolloutStatus | null): string {
  switch (status) {
    case 'required':
      return 'Dieser Tresor nutzt noch das alte Speicherformat und muss kontrolliert migriert werden.';
    case 'ready':
      return 'Die Migration ist vorbereitet und wartet auf deinen Start.';
    case 'running':
      return 'Eine Migration wurde begonnen. Fortsetzen prüft den letzten sicheren Checkpoint.';
    case 'committed':
      return 'Die neuen Operationen wurden geschrieben. Fortsetzen lädt den Tresor neu und verifiziert den Zustand.';
    case 'failed':
      return 'Die letzte Migration ist fehlgeschlagen. Ein erneuter Versuch nutzt den gespeicherten Checkpoint.';
    case 'preflightFailed':
      return 'Die Migrationsprüfung ist fehlgeschlagen. Bitte erneut versuchen oder Support mit dem Statuscode kontaktieren.';
    default:
      return 'Der Tresor wartet auf eine sichere Migrationsentscheidung.';
  }
}

function actionLabel(status: VaultMigrationRolloutStatus | null): string {
  if (status && STARTABLE_STATUSES.has(status)) {
    return 'Migration starten';
  }
  if (status && RESUMABLE_STATUSES.has(status)) {
    return 'Migration fortsetzen';
  }
  return 'Migration prüfen';
}

export function VaultMigrationRequiredPanel() {
  const {
    lock,
    retryVaultMigration,
    startVaultMigration,
    vaultMigrationCanStart,
    vaultMigrationError,
    vaultMigrationStatus,
  } = useVault();
  const [isRunning, setIsRunning] = useState(false);

  const canRunAction = vaultMigrationCanStart
    && vaultMigrationStatus !== 'notNeeded'
    && vaultMigrationStatus !== 'verified';

  const handleMigrationAction = async () => {
    if (!canRunAction || isRunning) {
      return;
    }

    setIsRunning(true);
    try {
      const action = vaultMigrationStatus && STARTABLE_STATUSES.has(vaultMigrationStatus)
        ? startVaultMigration
        : retryVaultMigration;
      await action();
    } finally {
      setIsRunning(false);
    }
  };

  return (
    <main className="min-h-screen bg-background px-4 py-10 lg:px-8">
      <div className="mx-auto flex max-w-xl flex-col gap-5">
        <Card className="border-amber-500/35">
          <CardHeader className="space-y-3">
            <div className="flex h-11 w-11 items-center justify-center rounded-md bg-amber-500/10 text-amber-700 dark:text-amber-300">
              <ShieldCheck className="h-5 w-5" />
            </div>
            <div>
              <CardTitle>Tresor-Migration erforderlich</CardTitle>
              <CardDescription className="mt-2">
                {describeStatus(vaultMigrationStatus)}
              </CardDescription>
            </div>
          </CardHeader>
          <CardContent className="space-y-4">
            {vaultMigrationError && (
              <div className="flex gap-3 rounded-md border border-destructive/30 bg-destructive/10 p-3 text-sm text-destructive">
                <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
                <p>{vaultMigrationError}</p>
              </div>
            )}

            <div className="rounded-md border bg-muted/40 p-3 text-sm text-muted-foreground">
              Die normale Tresoransicht bleibt gesperrt, bis Migration, Reload und State-Machine-Verifikation erfolgreich abgeschlossen sind.
            </div>

            {!vaultMigrationCanStart && (
              <div className="flex gap-3 rounded-md border border-amber-500/30 bg-amber-500/10 p-3 text-sm text-amber-800 dark:text-amber-200">
                <Info className="mt-0.5 h-4 w-4 shrink-0" />
                <p>
                  Die Migration kann erst starten, wenn der Tresor mit einem migrationsfähigen Schlüsselkontext entsperrt wurde. Sperre den Tresor und entsperre ihn mit dem Masterpasswort erneut.
                </p>
              </div>
            )}

            <div className="flex flex-col gap-2 sm:flex-row">
              <Button
                type="button"
                onClick={handleMigrationAction}
                disabled={!canRunAction || isRunning}
                className="gap-2"
              >
                {isRunning ? (
                  <Loader2 className="h-4 w-4 animate-spin" />
                ) : (
                  <RefreshCw className="h-4 w-4" />
                )}
                {actionLabel(vaultMigrationStatus)}
              </Button>
              <Button
                type="button"
                variant="outline"
                onClick={lock}
                disabled={isRunning}
                className="gap-2"
              >
                <Lock className="h-4 w-4" />
                Tresor sperren
              </Button>
            </div>
          </CardContent>
        </Card>
      </div>
    </main>
  );
}
