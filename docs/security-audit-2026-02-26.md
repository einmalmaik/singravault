# Singra Vault — Security Audit Report

**Datum:** 2026-02-26  
**Durchgeführt von:** Lovable AI Agent  
**Scope:** Vollständiges Repository (Frontend, Services, Edge Functions, DB)

> Historischer Audit-Stand. Die beschriebenen App-Passwort-Login-Findings zu `auth-session`, serverseitigem Argon2id und Passwort-über-TLS sind durch den OPAQUE-Cutover vom 2026-04-24 ersetzt: App-eigene Passwort-Logins laufen nur noch über OPAQUE; `auth-session` blockiert Passwort-POSTs.

---

## Bereich 1 — Kryptographie

### [KRITISCH] auth-session Edge Function liest TOTP-Secret im Plaintext statt verschlüsselt

**Datei:** `supabase/functions/auth-session/index.ts`  
**Zeile:** ca. 161–184  
**Problem:** Die Edge Function liest `totp_secret` (Plaintext-Spalte) statt `totp_secret_enc` (verschlüsselte Spalte) für die TOTP-Verifizierung. Die DB-Funktion `get_user_2fa_secret` existiert genau dafür — sie entschlüsselt serverseitig und migriert Legacy-Plaintext automatisch. Die Edge Function umgeht diese Logik komplett.  
**Risiko:** Wenn die Plaintext-Migration (`totp_secret → NULL`) bereits stattgefunden hat, schlägt die 2FA-Verifizierung fehl (`null`). Wenn nicht, werden Secrets unnötig im Klartext gelesen statt über die sichere DB-Funktion.  
**Empfehlung:** `totp_secret` durch RPC-Aufruf `get_user_2fa_secret(user.id, true)` ersetzen.

### [KRITISCH] auth-register Argon2id Parameter deutlich schwächer als Client-seitig

**Datei:** `supabase/functions/auth-register/index.ts`  
**Zeile:** ca. 51–59  
**Problem:** Server-seitige Argon2id-Parameter sind `memorySize: 19456` (19 MiB), `parallelism: 1`, `iterations: 2`. Der Client nutzt `memory: 131072` (128 MiB), `parallelism: 4`, `iterations: 3` (KDF v2). Der Server-Hash ist ca. 25x schwächer als der Client-Hash.  
**Risiko:** Bei einem DB-Leak wäre der serverseitige Argon2-Hash deutlich schneller zu bruteforcen als der Client-Hash. Da `user_security.argon2_hash` für den Login-Verifikationspfad genutzt wird, ist dies der primäre Angriffspunkt.  
**Empfehlung:** Server-Parameter auf mindestens `memorySize: 65536` (64 MiB), `parallelism: 4`, `iterations: 3` anheben, sofern Edge Function Memory Limits dies erlauben. Gleiches gilt für `auth-reset-password/index.ts` (Zeile 54–59).

### [MITTEL] generateUserKeyPair() Default ist RSA-only (version=1)

**Datei:** `src/services/cryptoService.ts`  
**Zeile:** ca. 815–821  
**Problem:** Der TODO-Kommentar dokumentiert, dass der Default auf `version: 2` (hybrid PQ+RSA) umgestellt werden soll. Aktuell werden neue Shared-Collection-Keys ohne Post-Quantum-Key-Wrapping generiert.  
**Risiko:** Neu gewrappte Sharing-Schlüssel sind anfällig für "harvest now, decrypt later"-Angriffe durch zukünftige Quantencomputer.  
**Empfehlung:** Default auf `version: 2` umstellen, sobald die PQ-Validierung abgeschlossen ist.

### [MITTEL] RSA-4096 Key Generation mit extractable: true

**Datei:** `src/services/cryptoService.ts`  
**Zeile:** ca. 731, 836, 865  
**Problem:** RSA-Key-Generierung verwendet `extractable: true` (notwendig für JWK-Export), aber `importPublicKey()` (Zeile 748) importiert ebenfalls mit `extractable: true`. Public Keys müssen nicht exportierbar sein nach Import.  
**Risiko:** Gering — Public Keys sind per Definition öffentlich. Aber Best Practice ist `false` wo nicht benötigt.  
**Empfehlung:** `importPublicKey()` auf `extractable: false` umstellen.

### [MINOR] Legacy-AAD-Fallback ohne aktive Migration

**Datei:** `src/services/cryptoService.ts`  
**Zeile:** ca. 319–330, 1066–1075  
**Problem:** Der AAD-Fallback (`decryptVaultItem`, `decryptWithSharedKey`) loggt eine Warnung und zählt `_legacyDecryptCount`, aber es findet keine automatische Re-Encryption der Legacy-Einträge auf das AAD-Format statt (außer bei KDF-Upgrade).  
**Risiko:** Legacy-Einträge bleiben unbegrenzt anfällig für Ciphertext-Swap-Angriffe, solange der Nutzer kein KDF-Upgrade durchführt.  
**Empfehlung:** Einen separaten Migration-Path implementieren, der Legacy-Einträge proaktiv auf AAD umstellt.

### [MINOR] `as any` Casts in Crypto-Code

**Datei:** `src/services/pqCryptoService.ts`  
**Zeilen:** 160, 175, 258, 445, 457, 488, 500, 577, 600, 608, 615  
**Problem:** Viele `as any` Casts bei `crypto.subtle.importKey()`, `crypto.subtle.encrypt()` etc. Diese umgehen TypeScript-Typchecks.  
**Risiko:** Gering — die Werte sind korrekt typisiert (Uint8Array → BufferSource). Es handelt sich um TypeScript-Inkompatibilitäten, nicht um Sicherheitsprobleme.  
**Empfehlung:** `as BufferSource` statt `as any` verwenden.

---

## Bereich 2 — Zero-Knowledge Prinzip

### [MITTEL] auth-session sendet Plaintext-Passwort an Edge Function

**Datei:** `supabase/functions/auth-session/index.ts`  
**Zeile:** 86  
**Problem:** Das Login-Passwort wird im Request-Body (`{ email, password }`) an die Edge Function gesendet. Dies ist **architektonisch beabsichtigt** (BFF-Pattern mit serverseitigem Argon2id-Vergleich), aber das Passwort ist damit kurzzeitig im Server-Kontext vorhanden.  
**Risiko:** Bei kompromittiertem Edge Function Log oder Memory-Dump könnte das Login-Passwort exponiert werden. Das Login-Passwort ≠ Master-Passwort (Master-Passwort wird nur client-seitig verwendet), daher ist das Zero-Knowledge-Prinzip für Vault-Daten nicht verletzt.  
**Empfehlung:** Zur Überprüfung — Sicherstellen, dass `console.error("Auth Session Error:", err)` niemals den Request-Body loggt (aktuell korrekt: nur `err` wird geloggt).

### [MINOR] auth-register sendet ebenfalls Plaintext-Passwort

**Datei:** `supabase/functions/auth-register/index.ts`  
**Zeile:** 21  
**Problem:** Gleich wie auth-session — architektonisch beabsichtigt (Server-seitige HIBP-Prüfung + Argon2id-Hash).  
**Risiko:** Akzeptabel, da das Login-Passwort nicht das Master-Passwort ist.  
**Empfehlung:** Dokumentieren, warum dies akzeptabel ist und dass Master-Passwort strikt client-seitig bleibt.

---

## Bereich 3 — Authentifizierung & Sessions

### [MITTEL] Backup Code Verification in auth-session referenziert falsche Spalte `used`

**Datei:** `supabase/functions/auth-session/index.ts`  
**Zeile:** ca. 203  
**Problem:** Die Query filtert `.eq('used', false)`, aber die Tabelle `backup_codes` hat die Spalte `is_used` (nicht `used`). Ebenso wird in Zeile 229 `.update({ used: true, used_at: ... })` geschrieben, was auf `is_used` heißen müsste.  
**Risiko:** Backup-Code-Login funktioniert nicht — die Query gibt keine Ergebnisse zurück (falscher Spaltenname). Nutzer mit 2FA können sich nicht mit Backup-Codes einloggen.  
**Empfehlung:** `used` → `is_used` umbenennen.

### [MINOR] VaultUnlock speichert Passwort kurzzeitig in State

**Datei:** `src/components/vault/VaultUnlock.tsx`  
**Zeile:** 33, 40  
**Problem:** `password` und `pendingPassword` werden als React State (`useState`) gespeichert. Nach dem Unlock wird `password` nicht explizit gelöscht.  
**Risiko:** In JavaScript-Strings ist keine sichere Löschung möglich. Die Dauer im State ist kurz (nur während der Eingabe), aber der GC bestimmt, wann der Wert aus dem Heap verschwindet.  
**Empfehlung:** Nach erfolgreichem Unlock `setPassword('')` und `setPendingPassword('')` aufrufen (bereits in manchen Pfaden der Fall — konsistent machen).

### [MINOR] Fehlende autocomplete-Attribute auf Passwort-Feldern

**Datei:** `src/pages/Auth.tsx` (Zeile 523, 685), `src/components/vault/MasterPasswordSetup.tsx` (Zeile 245), `src/components/settings/*.tsx` (diverse)  
**Problem:** Viele `<Input type="password">` Felder haben kein `autocomplete`-Attribut. Nur das 2FA-Modal hat `autoComplete="one-time-code"`.  
**Risiko:** Browser-Autofill könnte das Master-Passwort oder Login-Passwort in unsichere Kontexte füllen. Ohne `autocomplete="new-password"` oder `autocomplete="current-password"` ist das Verhalten browser-abhängig.  
**Empfehlung:** `autocomplete="current-password"` für Login-Felder, `autocomplete="new-password"` für Setup-Felder, `autocomplete="off"` für Vault-Master-Passwort-Felder.

---

## Bereich 4 — Supabase RLS

### [KRITISCH] Tabellen `recovery_tokens` und `user_security` haben RLS aktiviert aber keine Policies

**Datei:** Supabase Linter  
**Problem:** Die Tabellen `recovery_tokens` und `user_security` haben `ENABLE ROW LEVEL SECURITY` aber keine einzige Policy. Das bedeutet: **Kein Nutzer (auch nicht anon) kann lesen oder schreiben** — aber Service-Role-Zugriff funktioniert.  
**Risiko:** Aktuell funktional korrekt, da beide Tabellen nur über Edge Functions (Service Role) angesprochen werden. Aber es fehlt eine explizite "Service Role Only"-Policy für Klarheit. Falls versehentlich ein Client-Query auf diese Tabellen ausgeführt wird, gibt es leise leere Ergebnisse statt einer klaren Fehlermeldung.  
**Empfehlung:** Explizite `service_role`-only Policies hinzufügen (wie bei `rate_limit_attempts`).

### [MITTEL] 4 DB-Funktionen ohne `SET search_path`

**Datei:** Supabase Linter  
**Problem:** Die Funktionen `update_profile_pq_keys_timestamp()`, `update_collection_member_count()`, `update_collection_item_count()`, `update_updated_at_column()` haben kein `SET search_path`.  
**Risiko:** Bei kompromittiertem Schema-Suchreihenfolge könnten bösartige Funktionen gleichen Namens in einem anderen Schema ausgeführt werden.  
**Empfehlung:** `SET search_path TO 'public'` zu diesen Funktionen hinzufügen.

### [MITTEL] Supabase Leaked Password Protection deaktiviert

**Datei:** Supabase Auth Konfiguration  
**Problem:** Die eingebaute GoTrue Leaked-Password-Protection ist deaktiviert.  
**Risiko:** Da Singra eigene HIBP-Checks durchführt (client-seitig + Edge Functions), ist dies architektonisch akzeptabel. Aber ein Defense-in-Depth Ansatz würde es aktivieren.  
**Empfehlung:** In Supabase Dashboard unter Auth > Settings aktivieren.

---

## Bereich 5 — Input Validation & Injection

### [MITTEL] JSON.parse() ohne try/catch in pqCryptoService

**Datei:** `src/services/pqCryptoService.ts`  
**Zeile:** 148, 246, 565  
**Problem:** `JSON.parse(rsaPublicKey)` und `JSON.parse(rsaPrivateKey)` werden ohne try/catch aufgerufen. Wenn ein korrupter JWK-String übergeben wird, fliegt ein ungefangener Fehler.  
**Risiko:** Kein Injection-Risiko (Werte stammen aus kontrollierter Quelle), aber ein unerwarteter Crash bei korrupten Key-Daten.  
**Empfehlung:** try/catch mit aussagekräftiger Fehlermeldung wrappen.

### [MINOR] JSON.parse() ohne try/catch in cryptoService

**Datei:** `src/services/cryptoService.ts`  
**Zeile:** 334, 945, 1022, 1055, 1080  
**Problem:** Ähnlich wie pqCryptoService — JSON.parse auf entschlüsselte Vault-Daten ohne explizites try/catch.  
**Risiko:** Wenn eine Entschlüsselung zwar "erfolgreich" ist (z.B. falscher Key produziert gültiges Ciphertext aber ungültiges JSON), wird ein Parse-Error geworfen. Dies ist erwartetes Verhalten, aber nicht explizit dokumentiert.  
**Empfehlung:** Zur Überprüfung — prüfen ob callers den Error korrekt fangen.

### [OK] Kein dangerouslySetInnerHTML im Code

Keine Treffer gefunden — ✅ Best Practice eingehalten.

---

## Bereich 6 — Passwort-Handling

### [OK] usePasswordCheck korrekt verwendet

`usePasswordCheck` wird in allen drei Stellen genutzt: `Auth.tsx`, `MasterPasswordSetup.tsx`, `VaultItemDialog.tsx` — ✅

### [OK] Kein statischer @zxcvbn-ts Import

Keine statischen Imports von `@zxcvbn-ts/*` gefunden — ✅ Alle Imports sind dynamisch.

### [MINOR] Passwörter in Einstellungs-Dialogen nicht über usePasswordCheck validiert

**Datei:** `src/components/settings/SharedCollectionsSettings.tsx`, `PasskeySettings.tsx`, `EmergencyAccessSettings.tsx`, `DuressSettings.tsx`  
**Problem:** Diese Settings-Dialoge fragen das Master-Passwort zur Bestätigung ab, verwenden aber nicht `usePasswordCheck`. Das ist architektonisch korrekt (es handelt sich um **bestehende** Passwörter, nicht neue), aber es fehlt eine konsistente Dokumentation darüber.  
**Risiko:** Kein direktes Risiko — die Stellen bestätigen nur ein bestehendes Passwort.  
**Empfehlung:** Kommentar in jede Datei, warum `usePasswordCheck` hier nicht nötig ist.

---

## Bereich 7 — Dependencies & Supply Chain

### [MITTEL] @noble/post-quantum nicht auditiert

**Datei:** `package.json` (Version 0.5.4)  
**Problem:** Die Library hat laut eigener Dokumentation kein unabhängiges Security-Audit und bietet keinen Schutz gegen Side-Channel-Angriffe. Die NPM-Version ist 0.5.4, die neueste verfügbare ist 0.4.x auf NPM — Version 0.5.4 könnte ein Pre-Release oder Fork sein.  
**Risiko:** Potentielle Timing-Side-Channels bei ML-KEM-768 Key-Operationen. In einem Browser-Kontext ist das Risiko geringer als server-seitig, aber nicht null.  
**Empfehlung:** Version verifizieren; regelmäßig auf Audit-Status prüfen; in Produktion nur als "Defense in Depth" neben klassischer RSA-4096 verwenden (was bereits der Fall ist — Hybrid-Modus).

### [MINOR] Supabase SDK Versionsinkonsistenz in Edge Functions

**Datei:** `supabase/functions/auth-register/index.ts` und `auth-reset-password/index.ts`  
**Problem:** Diese Edge Functions importieren `@supabase/supabase-js@2.49.1` via ESM, während `auth-session/index.ts` `npm:@supabase/supabase-js@2` (latest) importiert. Unterschiedliche Versionen können zu unterschiedlichem Verhalten führen.  
**Empfehlung:** Alle Edge Functions auf die gleiche Version pinnen.

---

## Bereich 8 — Secrets & Konfiguration

### [OK] Keine hardcodierten Secrets im Code

- `.env` enthält nur publishable Keys (Supabase Anon Key, Project URL) — ✅
- Service Role Key nur in Edge Functions via `Deno.env.get()` — ✅
- Stripe, Resend Keys nur als Supabase Secrets — ✅

### [MINOR] CORS erlaubt alle *.lovable.app Subdomains

**Datei:** `supabase/functions/_shared/cors.ts`  
**Zeile:** 32  
**Problem:** Jede Subdomain von `lovable.app` und `lovableproject.com` wird als erlaubte Origin akzeptiert. Während der Entwicklung akzeptabel, aber in Produktion könnte ein anderes Lovable-Projekt Cross-Origin-Requests senden.  
**Risiko:** Gering — CORS ist kein Sicherheitsmechanismus für Server-seitige Daten, und Auth-Tokens sind weiterhin erforderlich.  
**Empfehlung:** Für Produktion die Lovable-Wildcard entfernen und nur die spezifische Preview-URL whitelisten.

---

## Bereich 9 — Fehlerbehandlung & Information Disclosure

### [MITTEL] Error-Stack in Edge Function Logs

**Datei:** `supabase/functions/auth-session/index.ts` (Zeile 289), `auth-register/index.ts` (Zeile 127), `auth-reset-password/index.ts` (Zeile 84)  
**Problem:** `console.error("Auth ... Error:", err)` loggt den vollständigen Error mit Stack-Trace in die Supabase Logs. Die Response an den Client ist korrekt generisch ("Internal Server Error").  
**Risiko:** Gering — Server-Logs sind nicht client-seitig sichtbar. Aber bei versehentlicher Log-Exposition könnten interne Details sichtbar werden.  
**Empfehlung:** Nur `err.message` loggen, nicht das vollständige Error-Objekt.

### [OK] Generische Fehlermeldungen an Client

Alle Edge Functions geben generische Fehlermeldungen zurück — ✅

---

## Bereich 10 — Allgemeine Code-Qualität & Bugs

### [MITTEL] Backup Code Spaltenname-Bug in auth-session

**Datei:** `supabase/functions/auth-session/index.ts`  
**Zeile:** 203, 229  
**Problem:** Bereits unter Bereich 3 dokumentiert — `used` statt `is_used`. Dies ist sowohl ein Bug als auch ein Sicherheitsproblem (2FA-Backup-Login funktioniert nicht).  
**Risiko:** 2FA-Backup-Codes können nicht eingelöst werden.  
**Empfehlung:** Sofort beheben.

### [MINOR] Potentielles Memory Leak bei edgeFunctionService Debug Logs

**Datei:** `src/services/edgeFunctionService.ts`  
**Zeile:** 33, 35, 45, 53  
**Problem:** `console.debug` Aufrufe mit Timing-Informationen in Production-Code. Nicht sicherheitskritisch, aber unnötiger Performance-Overhead.  
**Empfehlung:** Hinter einem Debug-Flag verstecken oder in Produktion entfernen.

### [MINOR] TODO-Kommentar zu PQ-Default

**Datei:** `src/services/cryptoService.ts`  
**Zeile:** 815–817  
**Problem:** `TODO(security): Set default to 2 (hybrid PQ+RSA)` — offener Tracking-Punkt.  
**Empfehlung:** Issue erstellen und verfolgen.

### [OK] Kein offensichtliches Memory Leak

Event Listener werden korrekt in Cleanup-Funktionen entfernt — ✅

### [OK] sessionStorage für Session-Daten (nicht localStorage)

Vault-Session-Daten werden in `sessionStorage` gespeichert (tab-gebunden, verschwindet bei Tab-Close) — ✅

---

## Zusammenfassung

| Priorität | Anzahl |
|-----------|--------|
| KRITISCH  | 3      |
| MITTEL    | 8      |
| MINOR     | 9      |
| OK        | 6      |

### Die 3 dringendsten Punkte

1. **🔴 Backup Code Spaltenname-Bug** (`used` → `is_used` in `auth-session`) — 2FA-Backup-Login ist komplett kaputt.
2. **🔴 TOTP Secret Plaintext-Lesen** in `auth-session` — sollte verschlüsselte Spalte via DB-Funktion nutzen.
3. **🔴 Schwache Server-Argon2id-Parameter** in `auth-register` und `auth-reset-password` — 25x schwächer als Client-seitig.

### Gesamteinschätzung

Die Sicherheitsarchitektur von Singra Vault ist **insgesamt solide**:

- ✅ Zero-Knowledge-Prinzip korrekt implementiert (Master-Passwort bleibt client-seitig)
- ✅ AES-256-GCM mit AAD-Bindung gegen Ciphertext-Swap
- ✅ Key-Zeroing nach Verwendung konsequent umgesetzt
- ✅ Keine extractable CryptoKeys wo nicht nötig
- ✅ RLS auf allen relevanten Tabellen aktiv
- ✅ CORS-Konfiguration mit explizitem Origin-Matching
- ✅ Dynamisches zxcvbn-ts Loading
- ✅ Keine hardcodierten Secrets

Die kritischen Findings betreffen primär die **Edge Functions** (auth-session), nicht den Kern-Krypto-Code. Der pqCryptoService und cryptoService sind handwerklich sauber implementiert. Die Server-seitigen Argon2id-Parameter sollten zeitnah angehoben werden, und der Backup-Code-Bug muss sofort behoben werden.
