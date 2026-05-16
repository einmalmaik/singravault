// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE
/**
 * Recovery surface for the legacy Premium duress decoy artifact bug.
 *
 * Older Premium builds wrote 10 default decoy items directly into the
 * `vault_items` legacy table when the panic password was enabled. On modern
 * USK + OpLog vaults that path is wrong: the rows are not in the OpLog
 * manifest, so the migration gate flags the vault as "Migration erforderlich"
 * and IntegrityV2 reports `mode: 'integrity_unknown'` /
 * `nonTamperReason: 'snapshot_source_not_authoritative'`.
 *
 * This panel scans for orphan rows (= rows that don't authenticate against
 * the current vault key AND are not part of the verified OpLog manifest)
 * and lets the user delete them after explicit confirmation. Real items
 * are never offered for deletion.
 */
import { useCallback, useEffect, useState } from 'react';
import { AlertTriangle, Loader2, ShieldQuestion, Trash2 } from 'lucide-react';

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
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { useVault } from '@/contexts/VaultContext';
import { useToast } from '@/hooks/use-toast';

interface ScanResult {
    candidates: ReadonlyArray<{ id: string; updatedAt: string | null }>;
    inspectedRowCount: number;
    authenticatedRowCount: number;
}

function formatTimestamp(value: string | null): string {
    if (!value) {
        return '—';
    }
    try {
        return new Date(value).toLocaleString();
    } catch {
        return value;
    }
}

export function LegacyDuressDecoyCleanupSettings() {
    const {
        isLocked,
        findLegacyDuressDecoyCandidates,
        purgeLegacyDuressDecoys,
    } = useVault();
    const { toast } = useToast();

    const [isScanning, setIsScanning] = useState(false);
    const [scanResult, setScanResult] = useState<ScanResult | null>(null);
    const [scanError, setScanError] = useState<string | null>(null);
    const [isPurging, setIsPurging] = useState(false);
    const [showConfirm, setShowConfirm] = useState(false);

    const runScan = useCallback(async () => {
        setIsScanning(true);
        setScanError(null);
        try {
            const result = await findLegacyDuressDecoyCandidates();
            if (result.error) {
                setScanError(result.error.message);
                setScanResult(null);
                return;
            }
            setScanResult({
                candidates: result.candidates.map(({ id, updatedAt }) => ({ id, updatedAt })),
                inspectedRowCount: result.inspectedRowCount,
                authenticatedRowCount: result.authenticatedRowCount,
            });
        } finally {
            setIsScanning(false);
        }
    }, [findLegacyDuressDecoyCandidates]);

    useEffect(() => {
        if (isLocked) {
            setScanResult(null);
            setScanError(null);
        }
    }, [isLocked]);

    const handlePurge = async () => {
        if (!scanResult || scanResult.candidates.length === 0) {
            return;
        }
        setIsPurging(true);
        try {
            const ids = scanResult.candidates.map((c) => c.id);
            const result = await purgeLegacyDuressDecoys(ids);
            if (result.error) {
                toast({
                    variant: 'destructive',
                    title: 'Bereinigung fehlgeschlagen',
                    description: result.error.message,
                });
                return;
            }
            toast({
                title: 'Legacy-Decoys entfernt',
                description: `${result.deletedCount} alte Panik-Passwort-Eintrag/-Einträge wurden aus der Legacy-Tabelle gelöscht. Lade den Tresor neu, damit der Migrations-Check erneut läuft.`,
            });
            setScanResult(null);
        } catch (err) {
            toast({
                variant: 'destructive',
                title: 'Bereinigung fehlgeschlagen',
                description: err instanceof Error ? err.message : 'Unbekannter Fehler beim Löschen.',
            });
        } finally {
            setIsPurging(false);
            setShowConfirm(false);
        }
    };

    return (
        <>
            <Card>
                <CardHeader>
                    <CardTitle className="flex items-center gap-2">
                        <ShieldQuestion className="w-5 h-5" />
                        Tresor-Reparatur: alte Panik-Passwort-Decoys
                    </CardTitle>
                    <CardDescription>
                        Ältere Versionen des Panik-Passwort-Features haben Köder-Einträge direkt in die Legacy-Tabelle geschrieben.
                        Auf modernen, OpLog-basierten Tresoren führt das zu einer fälschlichen
                        &quot;Tresor-Migration erforderlich&quot;-Anzeige und zu Integritätsstatus
                        <code className="mx-1 rounded bg-muted px-1 py-0.5 text-xs">integrity_unknown</code>.
                        Diese Bereinigung sucht ausschließlich Einträge, die sich mit deinem aktuellen Tresor-Schlüssel
                        nicht entschlüsseln lassen UND nicht im verifizierten OpLog-Manifest stehen.
                        Echte Tresor-Einträge werden nicht angefasst.
                    </CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                    <div className="flex flex-col gap-2 sm:flex-row">
                        <Button
                            type="button"
                            onClick={runScan}
                            disabled={isLocked || isScanning || isPurging}
                            className="gap-2"
                        >
                            {isScanning ? <Loader2 className="h-4 w-4 animate-spin" /> : null}
                            Tresor scannen
                        </Button>
                        {scanResult && scanResult.candidates.length > 0 && (
                            <Button
                                type="button"
                                variant="destructive"
                                onClick={() => setShowConfirm(true)}
                                disabled={isLocked || isPurging}
                                className="gap-2"
                            >
                                <Trash2 className="h-4 w-4" />
                                {scanResult.candidates.length} Legacy-Decoy(s) entfernen
                            </Button>
                        )}
                    </div>

                    {scanError && (
                        <div className="flex gap-3 rounded-md border border-destructive/30 bg-destructive/10 p-3 text-sm text-destructive">
                            <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
                            <p>{scanError}</p>
                        </div>
                    )}

                    {scanResult && (
                        <div className="rounded-md border bg-muted/40 p-3 text-sm text-muted-foreground">
                            <p>
                                Gescannt: <strong>{scanResult.inspectedRowCount}</strong> Legacy-Eintrag/Einträge.
                                Authentifiziert (echte Items): <strong>{scanResult.authenticatedRowCount}</strong>.
                                Kandidaten zum Entfernen: <strong>{scanResult.candidates.length}</strong>.
                            </p>
                            {scanResult.candidates.length > 0 && (
                                <ul className="mt-2 max-h-48 overflow-auto rounded border bg-background/40 p-2 text-xs font-mono">
                                    {scanResult.candidates.map((candidate) => (
                                        <li key={candidate.id} className="flex justify-between gap-3 py-0.5">
                                            <span className="truncate">{candidate.id}</span>
                                            <span className="text-muted-foreground">
                                                {formatTimestamp(candidate.updatedAt)}
                                            </span>
                                        </li>
                                    ))}
                                </ul>
                            )}
                            {scanResult.candidates.length === 0 && (
                                <p className="mt-2 text-foreground">
                                    Keine Legacy-Decoys gefunden. Dein Tresor ist sauber.
                                </p>
                            )}
                        </div>
                    )}
                </CardContent>
            </Card>

            <AlertDialog open={showConfirm} onOpenChange={setShowConfirm}>
                <AlertDialogContent>
                    <AlertDialogHeader>
                        <AlertDialogTitle>Legacy-Decoys endgültig löschen?</AlertDialogTitle>
                        <AlertDialogDescription>
                            {scanResult?.candidates.length ?? 0} Eintrag/Einträge werden aus der Legacy-Tabelle entfernt.
                            Diese Items konnten nicht mit deinem aktuellen Tresor-Schlüssel entschlüsselt werden und sind auch
                            nicht im verifizierten OpLog-Manifest enthalten. Diese Aktion kann nicht rückgängig gemacht werden.
                        </AlertDialogDescription>
                    </AlertDialogHeader>
                    <AlertDialogFooter>
                        <AlertDialogCancel disabled={isPurging}>Abbrechen</AlertDialogCancel>
                        <AlertDialogAction onClick={handlePurge} disabled={isPurging}>
                            {isPurging && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                            Endgültig löschen
                        </AlertDialogAction>
                    </AlertDialogFooter>
                </AlertDialogContent>
            </AlertDialog>
        </>
    );
}
