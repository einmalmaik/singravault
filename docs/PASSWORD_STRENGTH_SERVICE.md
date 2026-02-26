# Password Strength Service

## Übersicht

Zentrale Passwort-Prüfung für alle Eingabefelder in Singra Vault. Kombiniert lokale Stärkeanalyse (zxcvbn-ts) mit Breach-Check (HIBP k-Anonymity).

## Architektur

```
passwordStrengthService.ts    — Core Logic (lazy-loaded zxcvbn + HIBP)
usePasswordCheck.ts           — React Hook (debounce, focus, blur)
PasswordStrengthMeter.tsx     — UI-Komponente (Score-Balken, Feedback, Pwned-Warnung)
```

## Lazy Loading (PFLICHT)

zxcvbn-ts (~400KB) wird ausschließlich über dynamische `import()` geladen:
- **Kein statischer Import** von `@zxcvbn-ts/*` irgendwo in der Codebase
- Laden wird bei Feld-Fokus getriggert (`preloadZxcvbn()`)
- Gecachtes Modul nach erstem Laden — Folgeaufrufe sind synchron-schnell

## HIBP k-Anonymity

- SHA-1 Hash des Passworts via `crypto.subtle.digest`
- Nur 5-Zeichen Prefix wird an `api.pwnedpasswords.com/range/{prefix}` gesendet
- Vergleich des Suffixes findet lokal statt
- Silent fail bei Netzwerkfehler (kein User-Blocker)
- Kein API-Key nötig

## Verwendungsstellen

| Stelle | Modus | Verhalten |
|--------|-------|-----------|
| Signup (Auth.tsx) | `enforceStrong: true` | Blockiert bei !isAcceptable |
| Master-Passwort (MasterPasswordSetup.tsx) | `enforceStrong: true` | Blockiert bei !isAcceptable |
| Vault-Eintrag (VaultItemDialog.tsx) | `enforceStrong: false` | Warnt, blockiert nicht |

## Score-Mapping

| Score | Label | Farbe |
|-------|-------|-------|
| 0-1 | Sehr schwach | Rot |
| 2 | Schwach | Orange |
| 3 | Akzeptabel | Gelb |
| 4 | Stark | Grün |

## Sicherheitsregeln

1. Nie Passwort im Klartext loggen
2. HIBP nur bei Blur/Submit, nie bei jedem Keystroke
3. Kein API-Key im Frontend (Pwned Passwords braucht keinen)
4. User-Agent: `Singra-Vault/1.0 Password-Safety-Check`
5. Timeout: 5s via AbortController

## Dependencies

- `@zxcvbn-ts/core` — TypeScript-native zxcvbn Reimplementierung
- `@zxcvbn-ts/language-common` — Gemeinsame Wörterbücher
- `@zxcvbn-ts/language-de` — Deutsche Übersetzungen + Wörterbuch
