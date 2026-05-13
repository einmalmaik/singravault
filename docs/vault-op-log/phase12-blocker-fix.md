# Phase 12 Preflight Blocker Fix

Stand: 2026-05-05

Dieser Fix ist kein Phase-12-Rollout. Er beseitigt nur Stop-Blocker, damit der spätere Rollout sicher geplant und getestet werden kann.

## Behobene Blocker

- `migrationService.ts` erstellt den Pre-Migration-Snapshot vor jedem serverseitigen Trust-/Head-/Operation-Write.
- Normaler Unlock wird durch `vaultMigrationRolloutService` blockiert, wenn eine Migration `required`, `ready`, `running`, `committed`, `failed` oder `preflightFailed` ist.
- Runtime-Schreibpfade auf `vault_items` und `categories` sind deaktiviert, solange keine vollständige signierte Operation verfügbar ist.
- OpLog Restore/Delete/Resolve-Aktionen sind sichtbar deaktiviert beziehungsweise geben einen sicheren Fehler zurück.
- Feature-Flag-Tests erwarten den Phase-11/12-Stand: neuer Pfad aktiv, Shadow Mode nicht produktiv.

## Verbleibende Nicht-Ziele

- Keine stille Migration beim Unlock.
- Keine vollständige Phase-12-UI.
- Kein Migration-Undo-Service.
- Keine Entfernung der Feature-Flag-Stubs.
- Keine Supabase-Schemaänderung.

## Supabase-local Verifikation

Supabase-local wurde für diesen Blocker-Fix nicht erzwungen. Wenn die lokale Umgebung bereit ist:

```powershell
supabase start
npx vitest run src/test/integration/vault-op-log-phase2-integration.test.ts
npx vitest run src/services/vaultOpLog/__tests__
npx vitest run src/contexts src/components/vault src/test
```

Wenn `supabase start` keine lokale DB bereitstellt, sind RPC-/RLS-Tests als `nicht ausgeführt` zu dokumentieren, nicht als bestanden.
