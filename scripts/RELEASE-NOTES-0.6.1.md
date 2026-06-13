# Singra Vault 0.6.1 — Powered by DIS

> Patch-Release, das die bestehende Defensive Integration Shield
> Integration sichtbar macht.

## Highlights

- **Powered by DIS im Footer.** Singra Vault zeigt jetzt im
  Website-Footer einen dezenten "Powered by Defensive Integration
  Shield"-Hinweis mit dem offiziellen DIS-Logo und Link zum
  [DIS Repository](https://github.com/einmalmaik/dis). DIS ist die
  zentralisierte Crypto- und Security-Schicht, auf die Vault,
  OpLog, 2FA, TOTP, Passkey, Post-Quantum und der local Secret
  Store bereits seit 0.6.0 vollständig aufsetzen.

- **Sichtbarkeit der Security-Architektur.** Keine technische
  Änderung an Krypto, Auth, Storage oder Integrität. 0.6.1 macht
  die Partnerschaft mit DIS für Endnutzer sichtbar.

## Was ist neu

### Frontend

- Neue Footer-Sektion "Powered by DIS" mit Logo
  (`/public/DIS-logo.png`) und Link auf das DIS-Repo.
- Lokalisierte DE/EN Strings (`landing.footer.poweredBy`,
  `landing.footer.poweredByTooltip`).
- Footer-Test erweitert: prüft Link-Ziel, Alt-Text und
  Logo-Source.

### Infra

- Keine neuen Dependencies.
- Keine Build- oder Pipeline-Änderungen.

## Geänderte Dateien

```
package.json                                     |  2 +-
public/DIS-logo.png                              |  + (neu im Repo)
src/components/landing/Footer.tsx                | 22 +++++++++++++++++++++-
src/components/landing/__tests__/Footer.test.tsx | 21 ++++++++++++++++++++
src/i18n/locales/de.json                         |  4 +++-
src/i18n/locales/en.json                         |  4 +++-
```

## Sicherheit

- **Keine** Änderung an Security-Invarianten, Krypto,
  Schlüssel-Lifecycle, Auth, Storage oder Recovery.
- **Keine** neuen Dependencies.
- Vault bleibt zu 100 % "Powered by DIS" — kein Re-Import von
  WebCrypto, hash-wasm, otpauth oder anderen Crypto-Libraries
  außerhalb von `@msdis/shield`. Der ESLint-Guardrail aus 0.6.0 ist
  weiterhin aktiv.
- `@msdis/shield` wird aus dem öffentlichen npm-Registry bezogen (`^0.2.0`).

## Tests

- `npm test -- src/components/landing/__tests__/Footer.test.tsx`:
  **2/2 grün** (bestehender Test + neuer "Powered by DIS"-Test).
- Vollständige Suite (`npm test`) wurde im Vorfeld lokal gegen
  0.6.0 als grün verifiziert; das 0.6.1-Diff berührt ausschließlich
  den Footer und i18n-Strings — kein Test-Code in den Modulen, die
  unter DIS-Sicherheitsgarantie stehen.

## Migration

Keine. Reines Add-on in der UI, kein Daten-Schema-Change, kein
Migrations-Skript, keine Migrations-Orchestrator-Änderung.

## Danksagung

DIS — Defensive Integration Shield — liefert die komplette
Krypto-Schicht, die Singra Vault ermöglicht. Mehr zur Architektur
im [Singra Vault Security Whitepaper](https://singra-vault.app/security)
und im [DIS Repository](https://github.com/einmalmaik/dis).

— MauntingStudios, 2026-06-13
