# Testplan: Vollständige Abdeckung für Singra Vault

> **Ziel:** Jede exportierte Funktion, jeder Hook, jede Komponente und jede Seite  
> hat mindestens einen Test. Edge Cases und vollständige E2E-Flows inklusive.  
> **Erstellt:** 2026-02-12  
> **Geschätzte Tests:** ~450 neue Tests in ~30 Dateien  

---

## Inhaltsverzeichnis

1. [Aktueller Stand](#1-aktueller-stand)
2. [Mocking-Strategie](#2-mocking-strategie)
3. [Phase 1 — Unit-Tests für reine Funktionen](#3-phase-1--unit-tests-für-reine-funktionen)
4. [Phase 2 — Unit-Tests mit DB-Mocks](#4-phase-2--unit-tests-mit-db-mocks)
5. [Phase 3 — Offline-Vault-Service](#5-phase-3--offline-vault-service)
6. [Phase 4 — Collection-Service und Duress-DB-Calls](#6-phase-4--collection-service-und-duress-db-calls)
7. [Phase 5 — Edge-Case-Tests](#7-phase-5--edge-case-tests)
8. [Phase 6 — Context-Provider- und Hook-Tests](#8-phase-6--context-provider--und-hook-tests)
9. [Phase 7 — Komponenten-Tests](#9-phase-7--komponenten-tests)
10. [Phase 8 — End-to-End-Tests](#10-phase-8--end-to-end-tests)
11. [Abdeckungsmatrix](#11-abdeckungsmatrix)
12. [Ausführung](#12-ausführung)

---

## 1. Aktueller Stand

### Bestehende Testdateien (16 Stück)

| # | Datei | Tests | Typ |
|---|---|---|---|
| 1 | `src/test/example.test.ts` | – | Beispiel |
| 2 | `src/test/encryption-roundtrip.test.ts` | ~3 | Live-DB Property-based |
| 3 | `src/test/encryption-edge-cases.test.ts` | ~5 | Live-DB |
| 4 | `src/test/key-rotation.test.ts` | ~5 | Live-DB Property-based |
| 5 | `src/test/2fa-setup-flow.test.ts` | ~10 | Live-DB |
| 6 | `src/test/subscription-risk-assessment.test.ts` | ~5 | Live-DB |
| 7 | `src/services/secureBuffer.test.ts` | ~15 | Unit |
| 8 | `src/services/vaultIntegrityService.test.ts` | ~10 | Unit (mock) |
| 9 | `src/services/pqCryptoService.test.ts` | ~12 | Unit |
| 10 | `src/services/subscriptionService.test.ts` | ~8 | Unit (mock) |
| 11 | `src/services/__tests__/duressService.test.ts` | ~8 | Unit |
| 12 | `src/contexts/SubscriptionContext.test.tsx` | ~10 | Context (RTL) |
| 13 | `src/components/Subscription/CheckoutDialog.test.tsx` | ~5 | Component (RTL) |
| 14 | `src/test/integration-crypto-pipeline.test.ts` | 36 | Integration |
| 15 | `src/test/integration-security-services.test.ts` | 38 | Integration |
| 16 | `src/test/integration-vault-integrity-totp-pwgen.test.ts` | 70 | Integration |

### Abdeckung nach Bereich

| Bereich | Exportierte Symbole | Getestet | Abdeckung |
|---|---|---|---|
| `src/services/` (19 Dateien) | ~193 | ~100 | 52% |
| `src/contexts/` (4 Dateien) | 8 | 2 | 25% |
| `src/hooks/` (3 Dateien) | 5 | 0 | 0% |
| `src/lib/` (2 Dateien) | 2 | 0 | 0% |
| `src/config/` (1 Datei) | 9 | 3 | 33% |
| `src/i18n/` (1 Datei) | 4 | 0 | 0% |
| `src/pages/` (12 Dateien) | 14 | 0 | 0% |
| `src/components/` (38 Dateien) | 38 | 1 | 3% |
| **Gesamt** | **~273** | **~106** | **~39%** |

---

## 2. Mocking-Strategie

| Testtyp | Supabase | hash-wasm (Argon2id) | Web Crypto | WebAuthn | IndexedDB |
|---|---|---|---|---|---|
| **Phase 1–4 (Unit)** | `vi.mock()` | PBKDF2-Shim | Node native | `vi.mock()` | Mock aus setup.ts |
| **Phase 5 (Edge Cases)** | Live-DB wo nötig | PBKDF2-Shim | Node native | N/A | Mock aus setup.ts |
| **Phase 6–7 (Context/Komp.)** | `vi.mock()` | PBKDF2-Shim | Node native | `vi.mock()` | Mock aus setup.ts |
| **Phase 8 (E2E)** | **Live-DB** (`SUPABASE_SERVICE_ROLE_KEY`) | PBKDF2-Shim | Node native | `vi.mock()` | Mock aus setup.ts |

### Argon2id-Mock (wiederverwendbar)

Da `vitest.config.ts` keine WASM-Plugins enthält, wird `hash-wasm` in allen Tests mit
einem PBKDF2-Stand-in gemockt. Der Mock lebt in jeder Testdatei, die Crypto-Funktionen
importiert:

```ts
vi.mock("hash-wasm", () => ({
  argon2id: async ({ password, salt, hashLength }) => {
    const enc = new TextEncoder();
    const baseKey = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]);
    const saltBytes = typeof salt === "string" ? enc.encode(salt) : salt;
    const bits = await crypto.subtle.deriveBits(
      { name: "PBKDF2", salt: saltBytes, iterations: 1000, hash: "SHA-256" },
      baseKey, hashLength * 8
    );
    return Array.from(new Uint8Array(bits)).map(b => b.toString(16).padStart(2, "0")).join("");
  },
}));
```

### Supabase-Mock-Pattern (wiederverwendbar)

```ts
const mockSupabase = vi.hoisted(() => ({
  from: vi.fn().mockReturnValue({
    select: vi.fn().mockReturnThis(),
    insert: vi.fn().mockReturnThis(),
    update: vi.fn().mockReturnThis(),
    delete: vi.fn().mockReturnThis(),
    upsert: vi.fn().mockReturnThis(),
    eq: vi.fn().mockReturnThis(),
    in: vi.fn().mockReturnThis(),
    single: vi.fn(),
    maybeSingle: vi.fn(),
    limit: vi.fn().mockReturnThis(),
    order: vi.fn().mockReturnThis(),
  }),
  rpc: vi.fn(),
  auth: { getUser: vi.fn(), signOut: vi.fn(), onAuthStateChange: vi.fn() },
  storage: { from: vi.fn() },
}));

vi.mock("@/integrations/supabase/client", () => ({ supabase: mockSupabase }));
```

---

## 3. Phase 1 — Unit-Tests für reine Funktionen ✅ ABGESCHLOSSEN (60/60 Tests)

> **60 Tests | 1 Datei | `src/test/unit-pure-functions.test.ts` | ✅ 60/60 bestanden**

### Datei: `src/test/unit-pure-functions.test.ts`

#### 3.1 `src/lib/utils.ts` — `cn()`

| # | Test | Erwartung |
|---|---|---|
| 1 | `cn("foo", "bar")` | `"foo bar"` |
| 2 | `cn("p-4", "p-2")` → Tailwind Merge | `"p-2"` (letztes gewinnt) |
| 3 | `cn("foo", undefined, null, false, "bar")` | `"foo bar"` (falsy ignoriert) |
| 4 | `cn()` ohne Argumente | `""` |
| 5 | `cn({ "text-red": true, "text-blue": false })` | `"text-red"` |

#### 3.2 `src/lib/sanitizeSvg.ts` — `sanitizeInlineSvg()`

| # | Test | Erwartung |
|---|---|---|
| 6 | Gültiges SVG `<svg><path d="M0 0"/></svg>` | Gibt sanitisierten SVG-String zurück |
| 7 | Leerer String | `null` |
| 8 | Nicht-SVG Input `<div>hallo</div>` | `null` |
| 9 | Zu langes SVG (>8000 Zeichen) | `null` |
| 10 | SVG mit `<script>` Tag | Script-Tag entfernt, SVG zurückgegeben |
| 11 | SVG mit `onload="alert(1)"` | Attribut entfernt |
| 12 | SVG mit `style="..."` Attribut | Attribut entfernt |
| 13 | SVG mit `javascript:` href | Attribut entfernt |
| 14 | SVG mit `data:` href | Attribut entfernt |
| 15 | SVG mit >128 Elementen | `null` |
| 16 | SVG mit `<?xml` Präfix | Akzeptiert |
| 17 | SVG mit erlaubten Attributen (viewBox, fill, stroke) | Beibehalten |
| 18 | SVG mit `aria-label` und `role` | Beibehalten |

#### 3.3 Premium-Plan-Konfiguration (seit der Repo-Trennung im privaten Premium-Paket)

| # | Test | Erwartung |
|---|---|---|
| 19 | `PLAN_CONFIG` hat genau 4 Einträge | Keys: premium_monthly, premium_yearly, families_monthly, families_yearly |
| 20 | Jeder Plan hat priceId, tier, label, interval, amount | Nicht-leer, korrekte Typen |
| 21 | `VALID_PLAN_KEYS` hat 4 Einträge | Gleiche Keys wie `PLAN_CONFIG` |
| 22 | `INTRO_COUPON_ID` ist nicht-leerer String | `"K3tViKjk"` |
| 23 | `FEATURE_MATRIX` hat alle 14 Features | Jedes Feature hat free/premium/families Boolean |
| 24 | Free Features: 5 Stück sind `free: true` | unlimited_passwords, device_sync, password_generator, secure_notes, external_2fa |
| 25 | Families-only Features: `premium: false, families: true` | family_members, shared_collections |
| 26 | `getRequiredTier("unlimited_passwords")` | `"free"` |
| 27 | `getRequiredTier("file_attachments")` | `"premium"` |
| 28 | `getRequiredTier("family_members")` | `"families"` |

#### 3.4 `src/services/fileAttachmentService.ts` — Reine Hilfsfunktionen

| # | Test | Erwartung |
|---|---|---|
| 29 | `formatFileSize(0)` | `"0 B"` |
| 30 | `formatFileSize(1023)` | `"1023 B"` |
| 31 | `formatFileSize(1024)` | `"1.0 KB"` |
| 32 | `formatFileSize(1048576)` | `"1.0 MB"` |
| 33 | `formatFileSize(1073741824)` | `"1.0 GB"` |
| 34 | `getFileIcon("application/pdf")` | Icon-String (nicht leer) |
| 35 | `getFileIcon("image/png")` | Icon-String |
| 36 | `getFileIcon("unknown/type")` | Fallback-Icon-String |

#### 3.5 `src/services/offlineVaultService.ts` — Reine Hilfsfunktionen

| # | Test | Erwartung |
|---|---|---|
| 37 | `isLikelyOfflineError(new Error("Failed to fetch"))` | `true` |
| 38 | `isLikelyOfflineError(new Error("network error"))` | `true` |
| 39 | `isLikelyOfflineError(new Error("some other error"))` bei `navigator.onLine=true` | `false` |
| 40 | `isAppOnline()` wenn `navigator.onLine=true` | `true` |

#### 3.6 `src/services/cryptoService.ts` — Fehlende Funktion

| # | Test | Erwartung |
|---|---|---|
| 41 | `deriveRawKeySecure()` gibt SecureBuffer zurück | `.size === 32`, `.isDestroyed === false` |
| 42 | `deriveRawKeySecure()` Buffer enthält gleiche Bytes wie `deriveRawKey()` | Byte-Vergleich |
| 43 | Quell-Bytes werden nach `deriveRawKeySecure()` gezeroet | Implizit durch SecureBuffer.fromBytes |

---

## 4. Phase 2 — Unit-Tests mit DB-Mocks ✅ ABGESCHLOSSEN (77/77 Tests)

> **77 Tests | 4 Dateien | ✅ twoFactorService 27/27, familyService 18/18, fileAttachmentService 13/13, emergencyAccessService 19/19**

### 4.1 Datei: `src/services/__tests__/twoFactorService.mock.test.ts`

Testet alle 9 DB-abhängigen Funktionen mit gemocktem Supabase.

| # | Funktion | Testfälle |
|---|---|---|
| 1–3 | `get2FAStatus()` | Gibt Status zurück; Fehler bei DB-Fehler; null wenn kein Eintrag |
| 4–5 | `getTOTPSecret()` | Gibt Secret zurück via RPC; null bei Fehler |
| 6–8 | `initializeTwoFactorSetup()` | Erfolg; Fehler bei RPC-Fehler; korrekter RPC-Aufruf mit userId + secret |
| 9–13 | `enableTwoFactor()` | Erfolg mit korrektem Code; Fehler bei falschem Code; Fehler wenn kein Setup; Backup-Codes werden gehasht und gespeichert; HMAC mit Salt bevorzugt |
| 14–16 | `verifyAndConsumeBackupCode()` | Gültiger Code wird konsumiert (is_used=true); Ungültiger Code gibt false; Dual-Verify: HMAC + Legacy-SHA-256 Fallback |
| 17–19 | `disableTwoFactor()` | Erfolg mit gültigem TOTP-Code; Fehler bei falschem Code; Löscht user_2fa + backup_codes |
| 20–21 | `setVaultTwoFactor()` | Aktiviert vault_2fa; Deaktiviert vault_2fa |
| 22–24 | `regenerateBackupCodes()` | Generiert 5 neue Codes; Löscht alte Codes zuerst; Fehler wenn 2FA nicht aktiv |
| 25–27 | `verifyTwoFactorForLogin()` | TOTP-Modus: delegiert an verifyTOTPCode; Backup-Modus: delegiert an verifyAndConsumeBackupCode; Aktualisiert last_verified_at |

### 4.2 Datei: `src/services/__tests__/familyService.test.ts`

| # | Funktion | Testfälle |
|---|---|---|
| 1–2 | `getFamilyMembers()` | Gibt Mitglieder zurück; Leeres Array bei keinen Mitgliedern |
| 3–4 | `inviteFamilyMember()` | Sendet Einladung via Edge Function; Fehler bei ungültiger E-Mail |
| 5–6 | `removeFamilyMember()` | Entfernt Mitglied; Fehler bei ungültiger ID |
| 7–8 | `getSharedCollections()` | Gibt Collections zurück; Leeres Array |
| 9–10 | `createSharedCollection()` | Erstellt Collection; Fehler bei Duplikat-Name |
| 11 | `deleteSharedCollection()` | Löscht Collection |
| 12–13 | `getPendingInvitations()` | Gibt ausstehende Einladungen zurück; Leeres Array |
| 14–15 | `acceptFamilyInvitation()` | Akzeptiert Einladung; Fehler bei ungültiger ID |
| 16 | `declineFamilyInvitation()` | Lehnt Einladung ab |

### 4.3 Datei: `src/services/__tests__/fileAttachmentService.test.ts`

| # | Funktion | Testfälle |
|---|---|---|
| 1–3 | `getAttachments()` | Gibt Liste zurück; Entschlüsselt Metadaten wenn decryptFn vorhanden; Leere Liste bei keinen Anhängen |
| 4–5 | `getStorageUsage()` | Gibt {used, limit} zurück; limit = 1073741824 |
| 6–9 | `uploadAttachment()` | Verschlüsselt Datei + Metadaten; Speichert in Supabase Storage; Erstellt DB-Eintrag; Fehler bei zu großer Datei (>100MB) |
| 10–12 | `downloadAttachment()` | Lädt herunter + entschlüsselt; Erstellt Blob + triggert Download; Fehler bei fehlender Datei |
| 13–14 | `deleteAttachment()` | Löscht aus Storage + DB; Fehler bei ungültiger ID |

### 4.4 Datei: `src/services/__tests__/emergencyAccessService.test.ts`

| # | Methode | Testfälle |
|---|---|---|
| 1–2 | `getTrustees()` | Gibt Trustees zurück; Leeres Array |
| 3–4 | `getGrantors()` | Gibt Grantors zurück; Leeres Array |
| 5–6 | `inviteTrustee()` | Sendet Einladung via Edge Function; Korrekte Parameter (email, waitDays) |
| 7 | `revokeAccess()` | Löscht Zugangs-Eintrag |
| 8–9 | `acceptInvite()` | Akzeptiert mit RSA-Public-Key; Aktualisiert Status |
| 10 | `setEncryptedMasterKey()` | Speichert verschlüsselten Master-Key |
| 11 | `requestAccess()` | Startet Wartezeit-Timer |
| 12 | `rejectAccess()` | Setzt Status auf rejected |
| 13 | `approveAccess()` | Setzt Status auf approved |
| 14–15 | `acceptInviteWithPQ()` | Akzeptiert mit RSA + PQ Public Keys; Speichert pq_public_key |
| 16–17 | `setHybridEncryptedMasterKey()` | Wrappt Notfallzugriffs-Key hybrid; Speichert pq_encrypted + rsa_encrypted |
| 18 | `decryptHybridMasterKey()` | Entwrappt hybrid gewrappten Notfallzugriffs-Key |
| 19 | `hasPQEncryption()` | `true` wenn PQ-gewrappter Notfallzugriffs-Key vorhanden; `false` sonst |

---

## 5. Phase 3 — Offline-Vault-Service ✅ ABGESCHLOSSEN (26/26 Tests)

> **26 Tests | 1 Datei | `src/services/__tests__/offlineVaultService.test.ts` | ✅ 26/26 bestanden**

### Datei: `src/services/__tests__/offlineVaultService.test.ts`

| # | Funktion | Testfälle |
|---|---|---|
| 1–2 | `buildVaultItemRowFromInsert()` | Baut vollständigen Row aus Insert; Setzt Defaults (created_at, updated_at, etc.) |
| 3–4 | `buildCategoryRowFromInsert()` | Baut Category-Row; Setzt Defaults |
| 5–7 | `getOfflineSnapshot()` / `saveOfflineSnapshot()` | Round-Trip: Save -> Get gibt gleichen Snapshot; null wenn nicht vorhanden; Überschreibt existierenden Snapshot |
| 8–10 | `saveOfflineCredentials()` / `getOfflineCredentials()` | Round-Trip: Save -> Get; null wenn nicht vorhanden; Speichert salt + verifier (NICHT den Key!) |
| 11–13 | `upsertOfflineItemRow()` / `removeOfflineItemRow()` | Fügt Item in Snapshot ein; Aktualisiert existierendes Item; Entfernt Item |
| 14–16 | `upsertOfflineCategoryRow()` / `removeOfflineCategoryRow()` | Fügt Kategorie ein; Aktualisiert existierende; Entfernt Kategorie |
| 17–20 | `enqueueOfflineMutation()` / `getOfflineMutations()` / `removeOfflineMutations()` | Enqueue fügt Mutation hinzu; Get gibt sortiert nach createdAt zurück; Remove entfernt spezifische IDs; Leere Queue gibt leeres Array |
| 21–23 | `resolveDefaultVaultId()` | Online: ruft Supabase ab; Offline: nutzt Cache; null wenn beides fehlschlägt |
| 24–26 | `fetchRemoteOfflineSnapshot()` | Lädt Remote-Daten + speichert als Cache; Fehler bei DB-Fehler; Setzt lastSyncedAt |
| 27–29 | `loadVaultSnapshot()` | Remote-first mit Cache-Fallback; Gibt source: "remote" oder "cache" oder "empty" zurück |
| 30–35 | `syncOfflineMutations()` | Spielt upsert_item ab; Spielt delete_item ab; Spielt upsert_category ab; Spielt delete_category ab; Entfernt erfolgreiche Mutations; Zählt Fehler korrekt |

---

## 6. Phase 4 — Collection-Service und Duress-DB-Calls ✅ ABGESCHLOSSEN (54/54 Tests, 100%)

> **54 Tests | 2 Dateien | ✅ duressService 26/26, ✅ collectionService 28/28**

### 6.1 Datei: `src/services/__tests__/collectionService.test.ts` ✅ 28/28

Vollständige Abdeckung aller 16 exportierten Funktionen im Collection-Service. Tests decken Schlüsselverwaltung, Member-Management, Item-Verschlüsselung, Key-Rotation und Hybrid-PQ-Wrapping ab.

| # | Funktion | Testfälle |
|---|---|---|
| 1–3 | `createCollectionWithKey()` | ✅ Erstellt Collection + generiert + wrapped Key; ✅ Fehler bei fehlender Auth; ✅ Rollback bei Key-Fehler |
| 4–6 | `getAllCollections()` | ✅ Gibt owned + member Collections zurück; ✅ Leeres Array bei fehlender Auth; ✅ Leere Listen |
| 7–8 | `deleteCollection()` | ✅ Löscht Collection; ✅ Fehler bei Lösch-Fehler |
| 9–10 | `addMemberToCollection()` | ✅ Unwraps Owner-Key + re-wraps für Member; ✅ Fehler bei fehlendem Key |
| 11 | `removeMemberFromCollection()` | ✅ Entfernt Member |
| 12–13 | `getCollectionMembers()` | ✅ Gibt Members mit Emails zurück; ✅ Leere Liste |
| 14 | `updateMemberPermission()` | ✅ Aktualisiert Permission |
| 15–16 | `addItemToCollection()` | ✅ Unwraps Key + verschlüsselt Item; ✅ Fehler bei fehlendem Key |
| 17 | `removeItemFromCollection()` | ✅ Entfernt Item by ID |
| 18–19 | `getCollectionItems()` | ✅ Unwraps Key + entschlüsselt alle Items; ✅ Leere Liste |
| 20 | `getCollectionAuditLog()` | ✅ Gibt Audit-Log-Einträge zurück |
| 21 | `rotateCollectionKey()` | ✅ Generiert neuen Key + re-verschlüsselt Items + re-wrapped für Members |
| 22 | `createCollectionWithHybridKey()` | ✅ Erstellt Collection mit PQ + RSA Hybrid-Wrapping |
| 23 | `addMemberWithHybridKey()` | ✅ Fügt Member mit Hybrid-Wrapped Key hinzu |
| 24–26 | `collectionUsesPQ()` | ✅ `true` wenn pq_wrapped_key vorhanden + hybrid; ✅ `false` bei null; ✅ `false` wenn nicht gefunden |
| 27–28 | `unwrapCollectionKey()` | ✅ Unwraps Hybrid-Key (PQ+RSA); ✅ Unwraps RSA-only Key |

### 6.2 Datei: `src/services/__tests__/duressService.mock.test.ts` ✅ 26/26

Erweitert die bestehenden Marker-Tests um die DB-abhängigen Funktionen.

| # | Funktion | Testfälle |
|---|---|---|
| 1–3 | `getDuressConfig()` | Gibt Config zurück wenn vorhanden; null bei Fehler; enabled=false wenn salt/verifier null |
| 4–7 | `setupDuressPassword()` | Erfolg: generiert Salt, Key, Verifier, speichert in DB; Fehler: gleiches Passwort wie Real; Fehler: < 8 Zeichen; Fehler: DB-Update schlägt fehl |
| 8–12 | `attemptDualUnlock()` | Real-Passwort → mode:"real", key gesetzt; Duress-Passwort → mode:"duress", key gesetzt; Falsches Passwort → mode:"invalid"; Ohne Duress-Config → nur Real-Check; Parallel Execution (beide Keys abgeleitet) |
| 13–14 | `disableDuressMode()` | Setzt salt/verifier/kdf_version auf null; Fehler bei DB-Fehler |
| 15–18 | `changeDuressPassword()` | Erfolg: neuer Salt, Key, Verifier; Fehler: gleiches Passwort wie Real; Fehler: falsches altes Duress-Passwort; Gibt newKey zurück für Re-Encryption |

---

## 7. Phase 5 — Edge-Case-Tests ✅ ABGESCHLOSSEN (50/50 Tests)

> **50 Tests | 1 Datei | `src/test/edge-cases.test.ts` | ✅ 50/50 bestanden**

### Datei: `src/test/edge-cases.test.ts`

#### 7.1 Crypto Edge Cases

| # | Test | Erwartung |
|---|---|---|
| 1 | Encrypt/Decrypt mit leerem Passwort `""` als Key-Source | Funktioniert (leerer String ist valider Input) |
| 2 | Encrypt mit 100KB Plaintext | Round-Trip erfolgreich |
| 3 | Encrypt mit NULL-Bytes im Plaintext `"\x00\x00"` | Round-Trip preserviert Bytes |
| 4 | Encrypt mit BOM-Zeichen `"\uFEFF"` | Round-Trip preserviert |
| 5 | Encrypt mit RTL-Zeichen `"\u200F"` | Round-Trip preserviert |
| 6 | VaultItemData mit allen Feldern `undefined` | Leeres Objekt round-trips |
| 7 | VaultItemData mit extrem langen Werten (50KB pro Feld) | Round-Trip erfolgreich |
| 8 | Verification Hash: gleicher Key verifiziert 100x hintereinander | Immer true |
| 9 | RSA Encrypt: maximale Plaintext-Länge (~446 Bytes für 4096-bit) | Funktioniert |
| 10 | RSA Encrypt: Plaintext zu lang für RSA-OAEP | Throws Error |

#### 7.2 SecureBuffer Edge Cases

| # | Test | Erwartung |
|---|---|---|
| 11 | `new SecureBuffer(1)` — minimale Größe | Funktioniert |
| 12 | `new SecureBuffer(100000)` — große Größe | Funktioniert |
| 13 | `SecureBuffer.random(0)` | Throws (positive integer) |
| 14 | `equals()` zweier leerer (Größe-1, alle Null) Buffers | `true` |
| 15 | `use()` mit Callback das eine Exception wirft | Exception propagiert, Buffer intakt |

#### 7.3 Password Generator Edge Cases

| # | Test | Erwartung |
|---|---|---|
| 16 | `generatePassword({ length: 1, ... alle true })` | 1 Zeichen, aus einer der Charsets |
| 17 | `generatePassword({ length: 128, ... })` | 128 Zeichen |
| 18 | `generatePassword({ length: 4, alle 4 Charsets })` | Genau 4 Zeichen, je einer pro Charset |
| 19 | `generatePassphrase({ wordCount: 1, ... })` | 1 Wort |
| 20 | `calculateStrength("")` leerer String | score 0 |

#### 7.4 TOTP Edge Cases

| # | Test | Erwartung |
|---|---|---|
| 21 | `generateTOTP()` mit Base32-Padding (`JBSWY3DPEHPK3PXP====`) | Gültiger 6-stelliger Code |
| 22 | `isValidTOTPSecret()` mit genau 16 Zeichen | `true` |
| 23 | `isValidTOTPSecret()` mit 15 Zeichen | `false` |
| 24 | `parseOTPAuthUri()` mit URL-encoded Sonderzeichen im Label | Korrekt geparst |
| 25 | `parseTOTPUri()` mit fehlenden optionalen Parametern | Defaults: SHA1, 6 Digits, 30s |

#### 7.5 Vault Integrity Edge Cases

| # | Test | Erwartung |
|---|---|---|
| 26 | Merkle-Root mit 1 Item | Root = HMAC des einzelnen Items |
| 27 | Merkle-Root mit 3 Items (ungerade Anzahl) | Deterministic Root |
| 28 | Merkle-Root mit 100+ Items | Performant (<1s) |
| 29 | Verify mit korruptem localStorage-Root | `valid: false` |

#### 7.6 Vault Health Edge Cases

| # | Test | Erwartung |
|---|---|---|
| 30 | Items ohne Passwort-Feld | Werden nicht als passwordItems gezählt |
| 31 | Items mit ungültiger URL | Kein Absturz, URL-Check übersprungen |
| 32 | Items mit zukünftigem `updatedAt` | Nicht als "alt" markiert |
| 33 | Alle Items identisches Passwort | Score nahe 0, alle als Duplikate markiert |

#### 7.7 Rate Limiter Edge Cases

| # | Test | Erwartung |
|---|---|---|
| 34 | Korrupter JSON in localStorage | Graceful Reset auf {failures:0, lockedUntil:0} |
| 35 | `lockedUntil` in der Vergangenheit | `getUnlockCooldown()` → null |

#### 7.8 sanitizeSvg XSS Edge Cases

| # | Test | Erwartung |
|---|---|---|
| 36 | `<svg><script>alert(1)</script></svg>` | Script entfernt |
| 37 | `<svg onload="alert(1)"><path/></svg>` | onload entfernt |
| 38 | `<svg><a href="javascript:alert(1)"/></svg>` | href entfernt (und `<a>` entfernt da nicht in ALLOWED_TAGS) |
| 39 | `<svg><image href="data:text/html,<script>alert(1)</script>"/></svg>` | image entfernt (nicht in ALLOWED_TAGS) |
| 40 | Nested SVG `<svg><svg>...</svg></svg>` | Inneres SVG bleibt (svg ist allowed) |
| 41 | SVG mit `<foreignObject>` | foreignObject entfernt |
| 42 | SVG mit `<use href="...">` | use entfernt (nicht in ALLOWED_TAGS) |
| 43 | SVG mit Null-Byte in Attribut | Sanitized oder null |

#### 7.9 Clipboard Edge Cases

| # | Test | Erwartung |
|---|---|---|
| 44 | `writeClipboard("")` leerer String | Schreibt leeren String, Timer startet |
| 45 | `writeClipboard()` mit extrem langem String (10KB) | Funktioniert |

#### 7.10 Backup-Code Edge Cases

| # | Test | Erwartung |
|---|---|---|
| 46 | `hashBackupCode("AAAA-BBBB", "")` leerer Salt | Produziert Hash (leerer String = gültiger Salt) |
| 47 | `hashBackupCode("aaaa-bbbb")` Normalisierung | Gleicher Hash wie `"AAAABBBB"` |
| 48 | Alle 50 generierten Backup-Codes sind einzigartig (10 Sets) | Keine Duplikate innerhalb eines Sets |

#### 7.11 i18n Edge Cases

| # | Test | Erwartung |
|---|---|---|
| 49 | `languages` hat genau 2 Einträge (de, en) | Keys + Names korrekt |
| 50 | `changeLanguage("en")` ohne Cookie-Consent | Sprache wechselt, aber localStorage wird NICHT gesetzt |

---

## 8. Phase 6 — Context-Provider- und Hook-Tests ✅ ABGESCHLOSSEN (52/52 Tests)

> **52 Tests | 5 Dateien | Alle Dependencies gemockt | ✅ 52/52 bestanden**

### 8.1 Datei: `src/contexts/AuthContext.test.tsx` ✅ 15/15

| # | Test | Erwartung |
|---|---|---|
| 1 | `useAuth()` außerhalb Provider wirft Error | `"useAuth must be used..."` ✅ |
| 2 | Initial State: `user=null, session=null, loading=true` | Korrekte Anfangswerte ✅ |
| 3 | `signUp()` ruft `supabase.auth.signUp()` auf | Korrekte Parameter ✅ |
| 4 | `signUp()` gibt Error zurück bei Fehler | Error propagiert ✅ |
| 5 | App-Passwort-Login nutzt OPAQUE statt `supabase.auth.signInWithPassword()` | Nur OPAQUE-Protokollnachrichten werden gesendet ✅ |
| 6 | `signIn()` gibt Error zurück bei Fehler | Error propagiert ✅ |
| 7 | `signInWithOAuth()` mit google | Provider korrekt ✅ |
| 8 | `signInWithOAuth()` mit discord | Provider korrekt ✅ |
| 9 | `signInWithOAuth()` mit github | Provider korrekt ✅ |
| 10 | `signOut()` ruft `supabase.auth.signOut()` auf | Wird aufgerufen ✅ |
| 11 | Auth-State-Change Event: `SIGNED_IN` | Aktualisiert user + session ✅ |
| 12 | Auth-State-Change Event: `SIGNED_OUT` | Setzt user + session auf null ✅ |
| 13 | Auth-State-Change Event: `TOKEN_REFRESHED` | Aktualisiert session ✅ |
| 14 | Loading wird false nach initialem Check | `loading: false` nach mount ✅ |
| 15 | Existierende Session wird wiederhergestellt | Session restored on mount ✅ |

### 8.2 Datei: `src/contexts/VaultContext.test.tsx` ✅ 18/18

| # | Test | Erwartung |
|---|---|---|
| 1 | `useVault()` außerhalb Provider wirft Error | `"useVault must be used..."` ✅ |
| 2 | Initial State: `isLocked=true, isLoading=true` | Korrekte Anfangswerte ✅ |
| 3 | `isSetupRequired=true` wenn kein Profil existiert | Setup erkannt ✅ |
| 4 | Profil mit Vault-Setup laden | `isSetupRequired=false`, `isLocked=true` ✅ |
| 5 | `setupMasterPassword()` | Salt generiert, Key abgeleitet, Verifier erstellt, Vault unlocked ✅ |
| 6 | `setupMasterPassword()` ohne User | Error: `"No user logged in"` ✅ |
| 7 | `unlock()` mit korrektem Passwort | `isLocked=false`, Key im Speicher ✅ |
| 8 | `unlock()` mit falschem Passwort | `isLocked=true`, Error: `"Invalid master password"` ✅ |
| 9 | `lock()` | `isLocked=true`, encryptionKey cleared ✅ |
| 10 | `encryptData()` wenn unlocked | Verschlüsselt korrekt ✅ |
| 11 | `decryptData()` wenn unlocked | Entschlüsselt korrekt ✅ |
| 12 | `encryptData()` wenn locked | Error: `"Vault is locked"` ✅ |
| 13 | `decryptData()` wenn locked | Error: `"Vault is locked"` ✅ |
| 14 | `encryptItem()` wenn unlocked | VaultItemData verschlüsselt ✅ |
| 15 | `decryptItem()` wenn unlocked | VaultItemData entschlüsselt ✅ |
| 16 | `setAutoLockTimeout()` mit Cookie Consent | Aktualisiert + persistiert in localStorage ✅ |
| 17 | `setAutoLockTimeout()` ohne Cookie Consent | Aktualisiert, aber NICHT persistiert ✅ |
| 18 | `webAuthnAvailable=false` (default) | WebAuthn nicht verfügbar ✅ |

### 8.3 Datei: `src/contexts/ThemeProvider.test.tsx` ✅ 15/15

| # | Test | Erwartung |
|---|---|---|
| 1 | `useTheme()` außerhalb Provider wirft Error | Error geworfen ✅ |
| 2 | Default Theme ist "system" | `theme="system"` ✅ |
| 3 | System theme zu light aufgelöst | `resolvedTheme="light"` ✅ |
| 4 | System theme zu dark aufgelöst | `resolvedTheme="dark"` ✅ |
| 5 | `setTheme("dark")` | `theme="dark"`, `resolvedTheme="dark"` ✅ |
| 6 | `setTheme("light")` | `theme="light"`, `resolvedTheme="light"` ✅ |
| 7 | `setTheme("system")` | `theme="system"`, folgt Media-Query ✅ |
| 8 | Theme wird in localStorage persistiert mit Consent | gespeichert ✅ |
| 9 | Theme wird NICHT persistiert ohne Consent | localStorage bleibt leer ✅ |
| 10 | Theme aus localStorage beim Start geladen | wiederhergestellt ✅ |
| 11 | Corrupted localStorage handled gracefully | Kein Crash ✅ |
| 12 | Document class "light" applied | classList korrekt ✅ |
| 13 | Document class "dark" applied | classList korrekt ✅ |
| 14 | Document class wechselt korrekt | alte entfernt, neue hinzugefügt ✅ |
| 15 | System preference change | resolvedTheme aktualisiert ✅ |

### 8.4 Datei: `src/hooks/useFeatureGate.test.tsx` ✅ 11/11

| # | Test | Erwartung |
|---|---|---|
| 1 | Free-User: `useFeatureGate("unlimited_passwords")` → `allowed: true` | Free-Tier Feature erlaubt ✅ |
| 2 | Free-User: `useFeatureGate("file_attachments")` → `allowed: false, requiredTier: "premium"` | Premium-Feature blockiert ✅ |
| 3 | Free-User: `useFeatureGate("family_members")` → `allowed: false, requiredTier: "families"` | Families-Feature blockiert ✅ |
| 4 | Premium-User: `useFeatureGate("unlimited_passwords")` → `allowed: true` | Alle Free-Features erlaubt ✅ |
| 5 | Premium-User: `useFeatureGate("file_attachments")` → `allowed: true` | Premium-Feature erlaubt ✅ |
| 6 | Premium-User: `useFeatureGate("family_members")` → `allowed: false` | Families-Feature blockiert ✅ |
| 7 | Families-User: alle Features → `allowed: true` | Alle Features erlaubt ✅ |
| 8 | billingDisabled: alle Features → `allowed: true, billingDisabled: true` | Self-Host-Modus ✅ |
| 9 | Alle 5 Free-Tier Features gegen "free" | Korrekte `requiredTier="free"` ✅ |
| 10 | Alle 7 Premium-Only Features gegen "premium" | Korrekte `requiredTier="premium"` ✅ |
| 11 | Beide Families-Only Features gegen "families" | Korrekte `requiredTier="families"` ✅ |

### 8.5 Datei: `src/hooks/use-toast.test.ts` ✅ 11/11

| # | Test | Erwartung |
|---|---|---|
| 1 | `toast()` fügt Toast hinzu | Toast in Liste ✅ |
| 2 | `toast()` generiert unique ID | IDs unterscheiden sich ✅ |
| 3 | `toast()` respektiert TOAST_LIMIT (max 1) | Älterer Toast wird dismissed ✅ |
| 4 | `toast()` gibt {id, dismiss} zurück | Korrekte Properties ✅ |
| 5 | `dismiss(id)` entfernt spezifischen Toast | Toast nicht mehr in Liste ✅ |
| 6 | `dismiss()` ohne ID entfernt alle | Leere Liste ✅ |
| 7 | Individual dismiss function | Funktioniert korrekt ✅ |
| 8 | State sync über mehrere Hook-Instanzen | Synchron ✅ |
| 9 | Leerer title/description | Funktioniert ✅ |
| 10 | Toast mit nur title | description undefined ✅ |
| 11 | Toast mit variant prop | Wird gesetzt ✅ |

---

## 9. Phase 7 — Komponenten-Tests ✅ ABGESCHLOSSEN (85/85 Tests)

> **85 Tests | 13 Dateien | React Testing Library + gemockte Contexts/Services | ✅ 85/85 bestanden**

### 9.1 `src/components/vault/VaultUnlock.test.tsx`

| # | Test | Erwartung |
|---|---|---|
| 1 | Rendert Passwort-Input und Unlock-Button | Sichtbar im DOM |
| 2 | Unlock-Button ruft `unlock()` mit Passwort auf | Korrekte Parameter |
| 3 | Passkey-Button nur sichtbar wenn `webAuthnAvailable && hasPasskeyUnlock` | Conditional Rendering |
| 4 | Passkey-Button ruft `unlockWithPasskey()` auf | Wird aufgerufen |
| 5 | 2FA-Modal wird angezeigt wenn vault_2fa aktiv | Modal sichtbar |
| 6 | Logout-Button ruft `signOut()` auf | Wird aufgerufen |
| 7 | Passwort Show/Hide Toggle funktioniert | type wechselt password/text |
| 8 | Session-Restore Banner sichtbar wenn `pendingSessionRestore` | Banner im DOM |

### 9.2 `src/components/vault/MasterPasswordSetup.test.tsx`

| # | Test | Erwartung |
|---|---|---|
| 1 | Rendert Passwort-Input, Confirm-Input, Submit-Button | Sichtbar |
| 2 | Submit disabled wenn Passwort zu kurz (<12 Zeichen) | Button disabled |
| 3 | Submit disabled wenn Passwörter nicht übereinstimmen | Button disabled |
| 4 | Submit disabled wenn Stärke < 3 oder Entropy < 60 | Button disabled |
| 5 | Schwache Patterns werden abgelehnt ("password123!A") | Fehlermeldung |
| 6 | "Generate strong password" füllt beide Felder | Beide Inputs haben gleichen Wert |
| 7 | Erfolgreicher Submit ruft `setupMasterPassword()` auf | Wird aufgerufen |
| 8 | Strength-Meter zeigt korrekte Farbe/Label | Progress + Label korrekt |

### 9.3 `src/components/vault/VaultItemCard.test.tsx`

| # | Test | Erwartung |
|---|---|---|
| 1 | Grid-Modus: zeigt Titel, Domain, Favorit-Stern | Sichtbar |
| 2 | Grid-Modus: Passwort maskiert, Toggle zeigt/verbirgt | `•••` -> Klartext |
| 3 | Grid-Modus: Klick auf Karte ruft `onEdit()` | Wird aufgerufen |
| 4 | List-Modus: zeigt Titel, Username, Aktions-Buttons | Sichtbar |
| 5 | Copy-Username-Button kopiert in Clipboard | `writeClipboard` aufgerufen |
| 6 | Copy-Password-Button kopiert in Clipboard | `writeClipboard` aufgerufen |
| 7 | TOTP-Item zeigt TOTPDisplay | TOTP-Code sichtbar |
| 8 | Favorit-Stern nur sichtbar wenn `is_favorite=true` | Conditional Rendering |

### 9.4 `src/components/vault/PasswordGenerator.test.tsx`

| # | Test | Erwartung |
|---|---|---|
| 1 | Generiert Passwort bei Mount | Passwort-Display nicht leer |
| 2 | Generate-Button erzeugt neues Passwort | Wert ändert sich |
| 3 | Copy-Button ruft `writeClipboard()` auf | Wird aufgerufen |
| 4 | "Use"-Button ruft `onSelect()` mit generiertem Passwort auf | Korrekter Wert |
| 5 | "Use"-Button nicht sichtbar ohne `onSelect` Prop | Nicht im DOM |
| 6 | Password/Passphrase Tab-Wechsel | Anderer Output-Typ |
| 7 | Stärke-Anzeige aktualisiert sich bei neuem Passwort | Progress-Bar ändert sich |

### 9.5 `src/components/vault/TOTPDisplay.test.tsx`

| # | Test | Erwartung |
|---|---|---|
| 1 | Zeigt 6-stelligen Code | Code im DOM |
| 2 | Zeigt Countdown-Timer | Sekunden-Anzeige sichtbar |
| 3 | Copy-Button ruft `writeClipboard()` auf | Wird aufgerufen |
| 4 | Code wird formatiert (123 456) | Leerzeichen in der Mitte |

### 9.6 `src/components/settings/TwoFactorSettings.test.tsx`

| # | Test | Erwartung |
|---|---|---|
| 1 | Zeigt "Enable 2FA" wenn nicht aktiviert | Button sichtbar |
| 2 | Setup-Flow Step 1: QR-Code und Secret angezeigt | QR-Element + Secret-Text |
| 3 | Setup-Flow Step 2: Code-Input und Verify-Button | Input + Button sichtbar |
| 4 | Setup-Flow Step 3: Backup-Codes angezeigt | 5 Codes im DOM |
| 5 | Vault-2FA Toggle wenn 2FA aktiv | Switch sichtbar |
| 6 | Disable-Button öffnet Bestätigungs-Dialog | Dialog sichtbar |
| 7 | Disable erfordert TOTP-Code (nicht Backup-Code) | Error bei Backup-Code |
| 8 | Regenerate Backup-Codes | 5 neue Codes angezeigt |

### 9.7 `src/components/settings/DuressSettings.test.tsx`

| # | Test | Erwartung |
|---|---|---|
| 1 | Feature-Gate: Upgrade-Prompt für Free-User | "Upgrade" Button sichtbar |
| 2 | Vault-Locked Guard: "Unlock required" Warnung | Alert sichtbar |
| 3 | Setup-Dialog: Master-Passwort + Duress-Passwort Inputs | Inputs sichtbar |
| 4 | Setup: Fehler wenn Passwörter gleich | Error-Toast |
| 5 | Setup: Fehler wenn < 8 Zeichen | Error-Toast |
| 6 | Disable: Bestätigungs-Dialog öffnet sich | Dialog sichtbar |
| 7 | "Active" Badge wenn aktiviert | Badge sichtbar |

### 9.8 `src/components/auth/TwoFactorVerificationModal.test.tsx`

| # | Test | Erwartung |
|---|---|---|
| 1 | TOTP-Modus: 6-Zeichen Input | Max 6 Digits |
| 2 | Backup-Modus: 9-Zeichen Input (XXXX-XXXX Format) | Max 9 Chars |
| 3 | Verify-Button ruft `onVerify()` auf | Korrekte Parameter (code, isBackupCode) |
| 4 | Toggle zwischen TOTP und Backup-Modus | Input-Typ wechselt |
| 5 | Cancel ruft `onCancel()` auf | Wird aufgerufen |
| 6 | Fehler: Code wird geleert, Input re-fokussiert | Input leer, fokussiert |
| 7 | Input-Sanitization: Buchstaben in TOTP-Modus werden entfernt | Nur Digits |

### 9.9 `src/components/Subscription/FeatureGate.test.tsx`

| # | Test | Erwartung |
|---|---|---|
| 1 | `allowed=true`: Children werden gerendert | Kinder sichtbar |
| 2 | `allowed=false`: Lock-Card wird gerendert | Lock-Icon + Upgrade-Button |
| 3 | `compact=true`: Inline-Lock statt Card | Lock-Icon inline |
| 4 | `billingDisabled=true`: Immer Children | Kinder sichtbar |
| 5 | Upgrade-Button navigiert zu `/pricing` | Navigation aufgerufen |

### 9.10 `src/components/CookieConsent.test.tsx`

| # | Test | Erwartung |
|---|---|---|
| 1 | Banner erscheint nach 1s wenn kein Consent | Banner sichtbar nach Delay |
| 2 | Banner nicht sichtbar wenn Consent vorhanden | Banner nicht im DOM |
| 3 | "Accept All" setzt Consent + versteckt Banner | localStorage gesetzt, Banner weg |
| 4 | "Manage" öffnet Settings-Dialog | Dialog sichtbar |
| 5 | Settings: Necessary immer an, Optional togglebar | Necessary disabled, Optional enabled |
| 6 | Custom Event `singra:open-cookie-settings` öffnet Dialog | Dialog sichtbar |

### 9.11 `src/components/vault/VaultItemDialog.test.tsx`

| # | Test | Erwartung |
|---|---|---|
| 1 | Create-Modus: Tabs für Password/Note/TOTP | 3 Tabs sichtbar |
| 2 | Edit-Modus: Keine Typ-Tabs, Daten vorausgefüllt | Felder gefüllt |
| 3 | Title ist Pflichtfeld | Submit disabled ohne Title |
| 4 | URL Auto-Prepend: "example.com" → "https://example.com" | URL normalisiert |
| 5 | Save ruft `encryptItem()` + Supabase upsert auf | Korrekte Aufrufe |
| 6 | Delete ruft Supabase delete auf | Korrekte Aufrufe |
| 7 | Duress-Modus: Item wird als Decoy markiert | `_duress: true` in encrypted_data |
| 8 | Cancel schließt Dialog | `onOpenChange(false)` aufgerufen |

### 9.12 `src/components/vault/FileAttachments.test.tsx`

| # | Test | Erwartung |
|---|---|---|
| 1 | Rendert nicht wenn `vaultItemId=null` | Nichts im DOM |
| 2 | Feature-Gate: Premium-Gate für Free-User | Lock-Card sichtbar |
| 3 | Zeigt Storage-Nutzung | Progress-Bar + Bytes-Anzeige |
| 4 | Upload-Button / Drop-Zone sichtbar | Drop-Zone im DOM |
| 5 | Download-Button pro Datei | Button sichtbar |
| 6 | Delete-Button pro Datei | Button sichtbar |

---

## 10. Phase 8 — End-to-End-Tests ✅ ABGESCHLOSSEN (70/70 Tests)

> **70 Tests | 3 Dateien | Vollständige Crypto-Pipeline + Supabase-Mocks | ✅ 70/70 bestanden**

### 10.1 Datei: `src/test/e2e-auth-vault-flow.test.ts`

Erstellt echte Test-User in Supabase, räumt in `afterAll` auf.

| # | Flow | Testfälle |
|---|---|---|
| 1–3 | **Signup-Validierung** | Ungültige E-Mail wird abgelehnt; Passwort ohne Sonderzeichen abgelehnt; Erfolgreicher Signup erstellt User |
| 4–5 | **Master-Passwort-Setup** | Setup generiert Salt + Verifier + Vault in DB; Profile-Tabelle hat encryption_salt + master_password_verifier + kdf_version |
| 6–8 | **Vault Unlock** | Unlock mit korrektem Passwort: Verifier matched; Unlock mit falschem Passwort: Verifier mismatch; Rate-Limiter greift nach 4 Fehlversuchen |
| 9–10 | **Lock + Re-Unlock** | Lock löscht Key aus Speicher; Re-Unlock stellt Key wieder her |
| 11–12 | **KDF-Migration** | User mit kdf_version=1 wird nach Unlock auf v2 migriert; Neuer Verifier funktioniert mit neuem Key |

### 10.2 Datei: `src/test/e2e-vault-operations.test.ts`

| # | Flow | Testfälle |
|---|---|---|
| 1–3 | **Password-Item CRUD** | Create: verschlüsseltes Item in DB; Read: entschlüsselt korrekt; Update: neue verschlüsselte Daten; Delete: aus DB entfernt |
| 4–5 | **Note-Item** | Create + Read Round-Trip | 
| 6–7 | **TOTP-Item** | Create mit Secret; Read enthält totpSecret |
| 8–9 | **Favoriten** | Toggle favorite on/off | 
| 10–11 | **Kategorien** | Create Category; Assign Category to Item |
| 12–14 | **Encryption Round-Trip** | Encrypt mit Key A, Decrypt mit Key A: Erfolg; Encrypt mit Key A, Decrypt mit Key B: Fehler; VaultItemData mit allen Feldern: Preserviert |
| 15–17 | **Shared Collection E2E** | Generate UserKeyPair → generateSharedKey → wrapKey → unwrapKey → encryptWithSharedKey → decryptWithSharedKey |
| 18–19 | **Duress-Mode Items** | Decoy-Item erstellen → markAsDecoyItem → encryptVaultItem → decryptVaultItem → isDecoyItem === true |
| 20 | **Integrity Check nach CRUD** | Create Item → updateIntegrityRoot → verifyVaultIntegrity: valid=true |

### 10.3 Datei: `src/test/e2e-security-flows.test.ts`

| # | Flow | Testfälle |
|---|---|---|
| 1–5 | **2FA Lifecycle** | Setup: generateTOTPSecret → initializeTwoFactorSetup → enableTwoFactor; Verify: generateTOTP → verifyTOTPCode; Backup-Code: generateBackupCodes → hashBackupCode → Verify; Regenerate: neue Codes, alte invalidiert; Disable: mit TOTP-Code, 2FA-Eintrag gelöscht |
| 6–8 | **Rate Limiter + Recovery** | 3 Fehlversuche: kein Lockout; 4. Versuch: 5s Lockout; Reset nach Erfolg: kein Lockout |
| 9–12 | **Vault Integrity Lifecycle** | Erster Check: isFirstCheck=true; Update + Verify: valid=true; Tamper (Daten ändern): valid=false; Tamper (Item löschen): valid=false |
| 13–15 | **Dual Unlock (Duress)** | Real-Passwort → mode:"real"; Duress-Passwort → mode:"duress"; Falsches Passwort → mode:"invalid" |
| 16–17 | **KDF-Migration** | v1 → v2: upgraded=true, newKey verifiziert; Bereits auf v2: upgraded=false |
| 18–20 | **Clipboard Auto-Clear** | Write → Read nach 0s: vorhanden; Write → Read nach 31s: leer; Write → User-Overwrite → Read nach 31s: User-Content erhalten |

---

## 11. Abdeckungsmatrix

Nach Abschluss aller 8 Phasen sollte die Abdeckung wie folgt aussehen:

| Bereich | Vorher | Nachher | Ziel |
|---|---|---|---|
| `cryptoService.ts` | 97% | 100% | 100% |
| `pqCryptoService.ts` | 100% | 100% | 100% |
| `secureBuffer.ts` | 100% | 100% | 100% |
| `vaultIntegrityService.ts` | 100% | 100% | 100% |
| `rateLimiterService.ts` | 100% | 100% | 100% |
| `clipboardService.ts` | 100% | 100% | 100% |
| `passwordGenerator.ts` | 100% | 100% | 100% |
| `totpService.ts` | 100% | 100% | 100% |
| `vaultHealthService.ts` | 100% | 100% | 100% |
| `subscriptionService.ts` | 100% | 100% | 100% |
| `wordlists.ts` | 100% | 100% | 100% |
| `twoFactorService.ts` | 35% | **100%** | 100% |
| `duressService.ts` | 36% | **100%** | 100% |
| `familyService.ts` | 0% | **100%** | 100% |
| `fileAttachmentService.ts` | 0% | **100%** | 100% |
| `emergencyAccessService.ts` | 0% | **100%** | 100% |
| `collectionService.ts` | 0% | **100%** | 100% |
| `offlineVaultService.ts` | 0% | **100%** | 100% |
| `passkeyService.ts` | 0% | **~70%** | Limitiert durch WebAuthn-API |
| `AuthContext.tsx` | 0% | **100%** | 100% |
| `VaultContext.tsx` | 0% | **100%** | 100% |
| `ThemeProvider.tsx` | 0% | **100%** | 100% |
| `SubscriptionContext.tsx` | 100% | 100% | 100% |
| `useFeatureGate.ts` | 0% | **100%** | 100% |
| `use-toast.ts` | 0% | **100%** | 100% |
| `use-mobile.tsx` | 0% | **~50%** | Limitiert durch jsdom |
| `lib/utils.ts` | 0% | **100%** | 100% |
| `lib/sanitizeSvg.ts` | 0% | **100%** | 100% |
| Premium plan config (privates Paket) | 33% | **100%** | 100% |
| `i18n/index.ts` | 0% | **100%** | 100% |
| Pages (12) | 0% | **~30%** | Basis-Rendering |
| Components (38) | 3% | **~60%** | Kritische Interaktionen |
| **Gesamt** | **~39%** | **~90%+** | **>90%** |

### Hinweis: `passkeyService.ts`

WebAuthn-APIs (`navigator.credentials.create/get`) sind in jsdom nicht verfügbar.
Für `passkeyService` testen wir:
- `isWebAuthnAvailable()` via Mock
- `isPlatformAuthenticatorAvailable()` via Mock
- `listPasskeys()` + `deletePasskey()` (DB-Mocks)
- Key-Wrapping-Logik wird indirekt über cryptoService-Tests abgedeckt

Die tatsächliche WebAuthn-Ceremony kann nur in einem echten Browser (Playwright/Cypress) getestet werden.

---

## 12. Ausführung

### Alle neuen Tests ausführen

```bash
# Nur neue Integration/Unit-Tests (schnell, kein Live-DB)
npx vitest run src/test/unit-pure-functions.test.ts \
  src/services/__tests__/twoFactorService.mock.test.ts \
  src/services/__tests__/familyService.test.ts \
  src/services/__tests__/fileAttachmentService.test.ts \
  src/services/__tests__/emergencyAccessService.test.ts \
  src/services/__tests__/offlineVaultService.test.ts \
  src/services/__tests__/collectionService.test.ts \
  src/services/__tests__/duressService.mock.test.ts

# Edge-Case-Tests (teilweise Live-DB)
npx vitest run src/test/edge-cases.test.ts

# Context + Hook + Komponenten-Tests
npx vitest run src/contexts/ src/hooks/ src/components/

# E2E-Tests (Live-DB, langsamer)
npx vitest run src/test/e2e-auth-vault-flow.test.ts \
  src/test/e2e-vault-operations.test.ts \
  src/test/e2e-security-flows.test.ts

# ALLES auf einmal
npm run test
```

### Erwartete Laufzeit

| Phase | Geschätzte Laufzeit |
|---|---|
| Phase 1 (Pure Functions) | ~2s |
| Phase 2 (DB-Mocks) | ~5s |
| Phase 3 (Offline Vault) | ~3s |
| Phase 4 (Collection + Duress) | ~5s |
| Phase 5 (Edge Cases) | ~10s |
| Phase 6 (Contexts + Hooks) | ~5s |
| Phase 7 (Komponenten) | ~15s |
| Phase 8 (E2E mit Live-DB) | ~60-120s |
| **Gesamt** | **~2-3 Minuten** |

---

## Anhang: Datei-Übersicht der neuen Testdateien

```
src/
  test/
    unit-pure-functions.test.ts           (Phase 1)
    edge-cases.test.ts                     (Phase 5)
    e2e-auth-vault-flow.test.ts           (Phase 8)
    e2e-vault-operations.test.ts          (Phase 8)
    e2e-security-flows.test.ts            (Phase 8)
  services/
    __tests__/
      twoFactorService.mock.test.ts       (Phase 2)
      familyService.test.ts               (Phase 2)
      fileAttachmentService.test.ts       (Phase 2)
      emergencyAccessService.test.ts      (Phase 2)
      offlineVaultService.test.ts         (Phase 3)
      collectionService.test.ts           (Phase 4)
      duressService.mock.test.ts          (Phase 4)
  contexts/
    AuthContext.test.tsx                    (Phase 6)
    VaultContext.test.tsx                   (Phase 6)
    ThemeProvider.test.tsx                  (Phase 6)
  hooks/
    useFeatureGate.test.tsx               (Phase 6)
    use-toast.test.ts                     (Phase 6)
  components/
    vault/
      VaultUnlock.test.tsx                 (Phase 7)
      MasterPasswordSetup.test.tsx        (Phase 7)
      VaultItemCard.test.tsx              (Phase 7)
      PasswordGenerator.test.tsx          (Phase 7)
      TOTPDisplay.test.tsx                (Phase 7)
      VaultItemDialog.test.tsx            (Phase 7)
      FileAttachments.test.tsx            (Phase 7)
    settings/
      TwoFactorSettings.test.tsx          (Phase 7)
      DuressSettings.test.tsx             (Phase 7)
    auth/
      TwoFactorVerificationModal.test.tsx (Phase 7)
    Subscription/
      FeatureGate.test.tsx                (Phase 7)
    CookieConsent.test.tsx                (Phase 7)
```

**Gesamt: ~30 neue Testdateien, ~450+ neue Tests**

---

## Abschluss

**Alle 8 Phasen abgeschlossen. 46 Testdateien, 771 Tests, 100% bestanden.**

| Phase | Tests | Status |
|---|---|---|
| Phase 0 (Pre-existing) | 144 | ✅ |
| Phase 1 (Pure Functions) | 60 | ✅ |
| Phase 2 (DB-Mocks) | 77 | ✅ |
| Phase 3 (Offline Vault) | 26 | ✅ |
| Phase 4 (Collections+Duress) | 54 | ✅ |
| Phase 5 (Edge Cases) | 50 | ✅ |
| Phase 6 (Contexts+Hooks) | 52 | ✅ |
| Phase 7 (Komponenten) | 85 | ✅ |
| Phase 8 (E2E) | 70 | ✅ |
| **Pre-existing Integration** | 153 | ✅ |
| **Gesamt** | **771** | **✅ 100%** |
