# CORE-P0 Hardening Plan

## Ziel dieses Branches

Dieser Branch setzt ausschließlich CORE-P0 für den Open-Source-Kern um:

1. Passkey-Unlock auf Sicherheitsparität zum Passwort-Unlock bringen
2. Web/PWA- und Tauri-Local-Secret-/Offline-Modell härten

Nicht Teil dieses Branches:

- Emergency Access V2
- signierte Mutationen
- Shared Collections / Membership-Rotation
- AlphaManu-Capability-Grenzen
- Premium-spezifische Erweiterungen

## Ausgangslage

Vor diesem Branch hatte der Core in den relevanten Pfaden mehrere strukturelle Probleme:

- `unlockWithPasskey()` konnte den Vault ohne gleichwertige Integritätsprüfung öffnen
- kryptografisch relevante Fallbacks lagen in `localStorage`
- die Integritätslogik hing im Core-Laufzeitpfad noch an optionalen Hooks
- der Passkey-Pfad wrapte teilweise KDF-Material statt sauberem Vault-Key-Material
- der Device-Key-Pfad nutzte kein belastbares Local-Secret-Modell

## Umgesetzte Arbeitspakete

### Paket 1: Unlock-Parität und Core-Integrität

Umgesetzt:

- neuer Core-Integrity-Service in `src/services/vaultIntegrityService.ts`
- lokale Integritäts-Baseline als verschlüsselte Digest-Baseline, gebunden an den aktiven Vault-Key
- gemeinsame Unlock-Finalisierung in `src/contexts/VaultContext.tsx`
- Passwort- und Passkey-Unlock laufen durch dieselbe Integritäts- und Tamper-Prüfung
- `localStorage` ist nicht mehr kryptografische Quelle für Vault-Unlock
- Passkey-Wrapping-Material wurde auf Vault-Key-Material umgestellt
- Legacy-Passkey-Envelopes werden gelesen und opportunistisch auf das neue Format rotiert

### Paket 2: Local-Secret-Store und Offline-Härtung

Umgesetzt:

- neuer gemeinsamer Local-Secret-Store in `src/platform/localSecretStore.ts`
- Tauri nutzt native Secret-Speicherung über Core-Commands
- Web/PWA nutzt IndexedDB + nicht extrahierbaren Wrapping-Key, sofern verfügbar
- `deviceKeyService` verwendet den gemeinsamen Local-Secret-Store
- Offline-Snapshot und Local Secrets sind konzeptionell getrennt
- Offline-Passwort-Unlock bleibt möglich, wenn vorher synchronisiert wurde
- frischer Passkey-Login offline bleibt bewusst nicht unterstützt

## Geänderte Kernmodule

- `src/contexts/VaultContext.tsx`
- `src/services/passkeyService.ts`
- `src/services/cryptoService.ts`
- `src/services/vaultIntegrityService.ts`
- `src/platform/localSecretStore.ts`
- `src/services/deviceKeyService.ts`
- `src/services/offlineVaultService.ts`
- `src-tauri/src/lib.rs`
- `supabase/functions/webauthn/index.ts`

## Sicherheitswirkung

### Was jetzt besser ist

- Passkey-Unlock und Passwort-Unlock haben im Core dieselben Sicherheitsanforderungen
- lokale Integritätsdaten liegen nicht mehr ungeschützt in Web Storage
- Passkey-Registrierung nutzt Vault-Key-Material statt bloßem KDF-Output
- Device-Key-Speicherung läuft über eine explizite Secret-Store-Abstraktion
- der Core kann seine minimale Vault-Integrität selbst tragen, ohne Premium-Laufzeitabhängigkeit

### Was bewusst nicht behauptet wird

- Web/PWA erreicht nicht dieselbe lokale Geheimnis-Härte wie Tauri/Desktop
- ein kompromittierter Browser-Client bleibt ein starker Angreifer
- Offline-Passkey-Login ohne bereits vorhandenen lokal vertrauenswürdigen Zustand wird nicht unterstützt

## Nächste Workstreams

### WS-03: Emergency Access V2

Noch offen. Dieses Modell muss fachlich und kryptografisch neu geschnitten werden. In diesem Branch wurde dafür absichtlich keine spekulative Dokumentation eingeführt.

### WS-04: Signierte Mutationen

Noch offen. Der aktuelle Branch bereitet den Pfad durch klarere Unlock-, Integrity- und Local-Secret-Grenzen vor, signiert aber noch keine sicherheitskritischen Mutationen.

### WS-05: weitere Entkopplung von Auth, Unlock und Sync

Teilweise verbessert, aber noch nicht vollständig abgeschlossen. Die Restarbeit betrifft vor allem spätere Evolutionsschritte der Sync- und Mutationsebene.

### WS-06 / WS-07

Nicht Bestandteil dieses Branches.

## Abnahmekriterien für diesen Branch

Der Branch gilt nur dann als erfolgreich, wenn:

- relevante Unit-Tests grün sind
- Build grün ist
- `/vault/settings` und die geänderten Laufzeitpfade ohne Hook-/Provider-Fehler rendern
- die Dokumentation das tatsächliche Verhalten ehrlich beschreibt

## Verweise

- `docs/security/SECURITY_MODEL_V2.md`
- `docs/security/WEB_PWA_THREAT_MODEL.md`
- `docs/adr/ADR-001-core-vault-integrity.md`
- `docs/adr/ADR-002-local-secret-store.md`
- `FINAL_REVIEW.md`
