// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE
/**
 * Minimal Phase-12 migration consent panel.
 *
 * This panel is rendered instead of the normal vault while a legacy
 * migration blocks unlock. It never displays vault plaintexts or key
 * material and starts migration only after an explicit user action.
 *
 * It also exposes the legacy duress decoy recovery flow: when the panel
 * detects rows in `vault_items` that don't authenticate against the
 * current vault key AND are not part of the verified OpLog manifest, it
 * surfaces a "Tresor reparieren" button alongside the regular migration
 * action. This unblocks accounts whose only "legacy rows" are stale
 * Premium duress decoys from pre-OpLog releases — see
 * `legacyDuressDecoyCleanupService.ts`. The detection is intentionally
 * conservative (it requires both decryption failure AND manifest absence)
 * so real items can never be classified as decoys.
 */

import { useCallback, useEffect, useState } from 'react';
import { AlertTriangle, Info, Loader2, Lock, RefreshCw, ShieldCheck, Wrench } from 'lucide-react';

import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from '@/components/ui/alert-dialog';
import { useVault } from '@/contexts/VaultContext';
import { useToast } from '@/hooks/use-toast';
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
    findLegacyDuressDecoyCandidates,
    purgeLegacyDuressDecoys,
  } = useVault();
  const { toast } = useToast();
  const [isRunning, setIsRunning] = useState(false);
  const [repairCandidateCount, setRepairCandidateCount] = useState<number | null>(null);
  const [repairCandidateIds, setRepairCandidateIds] = useState<ReadonlyArray<string>>([]);
  const [repairScanError, setRepairScanError] = useState<string | null>(null);
  const [isRepairing, setIsRepairing] = useState(false);
  const [showRepairConfirm, setShowRepairConfirm] = useState(false);

  const canRunAction = vaultMigrationCanStart
    && vaultMigrationStatus !== 'notNeeded'
    && vaultMigrationStatus !== 'verified';

  const runRepairScan = useCallback(async () => {
    setRepairScanError(null);
    try {
      const result = await findLegacyDuressDecoyCandidates();
      if (result.error) {
        // Don't surface the error to the user when the vault key is just
        // not available yet — the migration-required state is a valid
        // place to be without a usable key context. We only show errors
        // that came from an actual scan attempt.
        if (!/Vault must be unlocked/i.test(result.error.message)) {
          setRepairScanError(result.error.message);
        }
        setRepairCandidateCount(null);
        setRepairCandidateIds([]);
        return;
      }
      setRepairCandidateCount(result.candidates.length);
      setRepairCandidateIds(result.candidates.map((c) => c.id));
    } catch (err) {
      setRepairScanError(err instanceof Error ? err.message : 'Repair-Scan fehlgeschlagen.');
      setRepairCandidateCount(null);
      setRepairCandidateIds([]);
    }
  }, [findLegacyDuressDecoyCandidates]);

  useEffect(() => {
    void runRepairScan();
  }, [runRepairScan]);

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

  const handleRepair = async () => {
    if (repairCandidateIds.length === 0 || isRepairing) {
      return;
    }
    setIsRepairing(true);
    try {
      const result = await purgeLegacyDuressDecoys(repairCandidateIds);
      if (result.error) {
        toast({
          variant: 'destructive',
          title: 'Reparatur fehlgeschlagen',
          description: result.error.message,
        });
        return;
      }
      toast({
        title: 'Legacy-Decoys entfernt',
        description: `${result.deletedCount} alte Panik-Passwort-Eintrag/-Einträge wurden entfernt. Sperre den Tresor und entsperre ihn erneut, damit der Migrations-Check neu läuft.`,
      });
      setRepairCandidateCount(0);
      setRepairCandidateIds([]);
    } catch (err) {
      toast({
        variant: 'destructive',
        title: 'Reparatur fehlgeschlagen',
        description: err instanceof Error ? err.message : 'Unbekannter Fehler.',
      });
    } finally {
      setIsRepairing(false);
      setShowRepairConfirm(false);
    }
  };

  const hasRepairableCandidates = repairCandidateCount !== null && repairCandidateCount > 0;

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

            {hasRepairableCandidates && (
              <div className="flex gap-3 rounded-md border border-amber-500/40 bg-amber-500/10 p-3 text-sm text-amber-900 dark:text-amber-100">
                <Wrench className="mt-0.5 h-4 w-4 shrink-0" />
                <div className="space-y-1">
                  <p className="font-medium">
                    {repairCandidateCount} Eintrag/Einträge sehen aus wie alte Panik-Passwort-Decoys.
                  </p>
                  <p>
                    Sie lassen sich nicht mit deinem Tresor-Schlüssel entschlüsseln und gehören nicht zum verifizierten OpLog-Manifest.
                    Echte Tresor-Einträge werden bei der Reparatur nicht angefasst.
                  </p>
                </div>
              </div>
            )}

            {repairScanError && (
              <div className="flex gap-3 rounded-md border border-destructive/30 bg-destructive/10 p-3 text-sm text-destructive">
                <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
                <p>Reparatur-Scan: {repairScanError}</p>
              </div>
            )}

            {!vaultMigrationCanStart && !hasRepairableCandidates && (
              <div className="flex gap-3 rounded-md border border-amber-500/30 bg-amber-500/10 p-3 text-sm text-amber-800 dark:text-amber-200">
                <Info className="mt-0.5 h-4 w-4 shrink-0" />
                <p>
                  Die Migration kann erst starten, wenn der Tresor mit einem migrationsfähigen Schlüsselkontext entsperrt wurde. Sperre den Tresor und entsperre ihn mit dem Masterpasswort erneut.
                </p>
              </div>
            )}

            <div className="flex flex-col gap-2 sm:flex-row sm:flex-wrap">
              <Button
                type="button"
                onClick={handleMigrationAction}
                disabled={!canRunAction || isRunning || isRepairing}
                className="gap-2"
              >
                {isRunning ? (
                  <Loader2 className="h-4 w-4 animate-spin" />
                ) : (
                  <RefreshCw className="h-4 w-4" />
                )}
                {actionLabel(vaultMigrationStatus)}
              </Button>
              {hasRepairableCandidates && (
                <Button
                  type="button"
                  variant="destructive"
                  onClick={() => setShowRepairConfirm(true)}
                  disabled={isRunning || isRepairing}
                  className="gap-2"
                >
                  <Wrench className="h-4 w-4" />
                  Tresor reparieren ({repairCandidateCount})
                </Button>
              )}
              <Button
                type="button"
                variant="outline"
                onClick={lock}
                disabled={isRunning || isRepairing}
                className="gap-2"
              >
                <Lock className="h-4 w-4" />
                Tresor sperren
              </Button>
            </div>
          </CardContent>
        </Card>
      </div>

      <AlertDialog open={showRepairConfirm} onOpenChange={setShowRepairConfirm}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Legacy-Decoys endgültig entfernen?</AlertDialogTitle>
            <AlertDialogDescription>
              {repairCandidateCount} Eintrag/Einträge werden aus der Legacy-Tabelle entfernt. Diese Items
              konnten nicht mit deinem aktuellen Tresor-Schlüssel entschlüsselt werden und sind nicht im
              verifizierten OpLog-Manifest enthalten. Echte Tresor-Einträge bleiben unangetastet. Die Aktion
              kann nicht rückgängig gemacht werden.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={isRepairing}>Abbrechen</AlertDialogCancel>
            <AlertDialogAction onClick={handleRepair} disabled={isRepairing}>
              {isRepairing && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
              Endgültig entfernen
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </main>
  );
}
