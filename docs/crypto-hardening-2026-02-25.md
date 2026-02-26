# Crypto Hardening — 2026-02-25

## Änderungen

### Problem 1 — KRITISCH: KDF-Default auf CURRENT_KDF_VERSION

- `deriveKey`, `deriveRawKey`, `deriveRawKeySecure`: Default von `kdfVersion = 1` auf `kdfVersion = CURRENT_KDF_VERSION` geändert.
- Alle existierenden Call-Sites übergeben explizit eine Version — kein Verhalten ändert sich.
- Verhindert künftige Fehler bei neuen Aufrufen ohne explizite Version.

### Problem 2 — MITTEL: AAD-Fallback Monitoring (Phase 1)

- `decryptVaultItem` und `decryptWithSharedKey`: Fallback-Pfad loggt jetzt `console.warn` mit Entry-ID.
- Interner Zähler `_legacyDecryptCount` erfasst Anzahl Legacy-Entschlüsselungen.
- `ReEncryptionResult` um `legacyItemsFound: number` erweitert.
- `reEncryptVault()` gibt den Zähler zurück und setzt ihn zurück.

### Problem 3 — MITTEL: secureClear → clearReferences

- Funktion umbenannt: `secureClear` → `clearReferences`.
- Deprecated Wrapper `export const secureClear = clearReferences` bleibt für Abwärtskompatibilität.
- Prominenter WARNING-Block im JSDoc dokumentiert, dass JS-Strings nicht sicher gelöscht werden können.
- Aufrufstellen aktualisiert: `VaultContext.tsx`, Tests.

### Problem 4 — MINOR: Verification Hash v3

- Neue Konstante `VERIFICATION_CONSTANT_V3 = 'SINGRA_VAULT_VERIFY_V3'`.
- `createVerificationHash`: Erzeugt jetzt `v3:${encrypted}` — kein Klartext mehr in der DB.
- `verifyKey`: Neuer `v3:`-Pfad. Bestehende `v2:` und Legacy-Pfade bleiben für Abwärtskompatibilität.

### Problem 5 — MINOR: generateUserKeyPair TODO

- TODO-Kommentar mit Ticket-Referenz `SINGRA-PQ-DEFAULT` hinzugefügt.
- Default bleibt bei `version: 1` (RSA-only) bis PQ in Produktion validiert ist.

## pqCryptoService.ts — Sicherheits-Hardening (3 Probleme)

### Problem 1 — MITTEL: HKDF-v2 standardkonform + Version 0x04

- Neue Konstanten: `VERSION_HYBRID_STANDARD_V2 = 0x04`, `HYBRID_KDF_INFO_V2`.
- `HYBRID_VERSION` von `3` auf `4` erhöht.
- Neue Funktion `deriveHybridCombinedKeyV2`: IKM = `pqSharedSecret || aesKeyBytes`, Salt = zero-bytes (32), Info = `HYBRID_KDF_INFO_V2 || rsaCiphertext`.
- `hybridEncrypt`: Erzeugt jetzt Version `0x04` mit HKDF-v2.
- `decryptHybridCiphertext`: Version `0x04` → HKDF-v2, Version `0x03` → legacy HKDF-v1.
- `allowLegacyFormats=false` blockiert nur `0x01` und `0x02`, akzeptiert `0x03` und `0x04`.
- `migrateToHybrid`: Erkennt `0x03` als migrierbar → re-encrypt zu `0x04`. `0x04` wird unverändert zurückgegeben.
- Alte `deriveHybridCombinedKey` bleibt als private Funktion für Legacy-Decrypt von `0x03`.

### Problem 2 — MINOR: AAD-Support für hybridEncrypt/hybridDecrypt

- Optionaler `aad?: string` Parameter an `hybridEncrypt`, `hybridDecrypt`, `hybridWrapKey`, `hybridUnwrapKey`.
- AES-GCM `additionalData` wird gesetzt wenn AAD übergeben wird.
- Abwärtskompatibel: Bestehende Ciphertexte ohne AAD werden weiterhin korrekt entschlüsselt.
- Aufrufer übergeben vorerst kein AAD — Breaking Change für bestehende Ciphertexte wird in späterem PR mit Migration kombiniert.

### Problem 3 — MINOR: isHybridEncrypted erkennt alle Hybrid-Versionen

- `isHybridEncrypted` erkennt jetzt `0x02`, `0x03`, und `0x04`.
- Neue Funktion `isCurrentStandardEncrypted` prüft nur `0x04`.
- Bestehende Aufrufer profitieren, da `0x03` weiterhin `true` ergibt.

## Betroffene Dateien

| Datei | Änderung |
|-------|----------|
| `src/services/cryptoService.ts` | KDF-Default, AAD-Monitoring, clearReferences, Verifier v3, PQ-TODO |
| `src/services/pqCryptoService.ts` | HKDF-v2, AAD-Support, isHybridEncrypted-Split |
| `src/services/pqCryptoService.test.ts` | Tests für v4, AAD, isCurrentStandardEncrypted |
| `src/contexts/VaultContext.tsx` | Import clearReferences statt secureClear |
| `src/contexts/__tests__/VaultContext.test.tsx` | Mock aktualisiert |
| `src/test/integration-crypto-pipeline.test.ts` | clearReferences, v3-Verifier-Test |
| `docs/CRYPTO_SERVICE.md` | Dokumentation aktualisiert |
| `docs/crypto-hardening-2026-02-25.md` | Diese Datei |

## Risiken

- KDF-Default: Sicher, kein Call-Site nutzt den Default
- Verifier v3: Abwärtskompatibel
- clearReferences: Deprecated Wrapper verhindert Breaking Changes
- AAD-Phase-1: Nur Logging, keine Verhaltensänderung
- HKDF-v2 (0x04): Abwärtskompatibel — 0x03 Legacy-Pfad bleibt erhalten
- pqCryptoService AAD: Optional, kein Breaking Change

## passwordStrengthService — Zentrale Passwort-Prüfung

### Neue Dateien

- `src/services/passwordStrengthService.ts` — Lazy-loaded zxcvbn-ts + HIBP k-Anonymity
- `src/services/passwordStrengthService.test.ts` — Tests
- `src/hooks/usePasswordCheck.ts` — React Hook (debounce, focus-preload, blur-HIBP)
- `src/components/ui/PasswordStrengthMeter.tsx` — Wiederverwendbare UI-Komponente
- `docs/PASSWORD_STRENGTH_SERVICE.md` — Dokumentation

### Änderungen an bestehenden Dateien

- `src/pages/Auth.tsx`: Signup-Formular — zxcvbn Stärke-Meter + HIBP-Check, blockiert bei !isAcceptable
- `src/components/vault/MasterPasswordSetup.tsx`: `calculateStrength` durch `usePasswordCheck` ersetzt, HIBP-Check hinzugefügt
- `src/components/vault/VaultItemDialog.tsx`: Passwort-Feld — Stärke-Meter + HIBP-Warnung (nicht blockierend)
- `src/components/vault/__tests__/MasterPasswordSetup.test.tsx`: Mocks auf usePasswordCheck umgestellt
- `src/i18n/locales/de.json` + `en.json`: `passwordStrength.*` Keys hinzugefügt

### Dependencies

- `@zxcvbn-ts/core` — TypeScript-native zxcvbn (PFLICHT: nur dynamische Imports)
- `@zxcvbn-ts/language-common` — Gemeinsame Wörterbücher
- `@zxcvbn-ts/language-de` — Deutsche Übersetzungen

### Sicherheitshinweise

- Alle @zxcvbn-ts Imports sind dynamisch (lazy loaded bei Feld-Fokus, ~400KB)
- HIBP: Nur 5-Zeichen SHA-1 Prefix wird gesendet (k-Anonymity)
- Silent fail bei Netzwerkfehler — User wird nie blockiert
- Kein API-Key nötig für Pwned Passwords Endpunkt
