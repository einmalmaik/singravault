# Runtime Refactor, Quarantine and Dev Test Account - 2026-04-29

## Verstanden und Annahmen

Ziel ist ein sicherer Runtime-Fix für Auth-State, Vault-State, Device Key, Passkey/WebAuthn, Quarantäne/Integrität und Dev-Testbetrieb. Annahme: lokale Runtime-Reproduktion mit echten Supabase-Daten ist ohne bereitgestellte `.env.local` nur begrenzt möglich; reproduzierbare Befunde werden daher über Codepfad, Unit-Tests und lokale Browser-/Build-Checks dokumentiert.

## Reproduktionsmatrix

| ID | Bereich | Plattform | Schritte | Erwartet | Ist | Ursache | Fix | Status |
|---|---|---|---|---|---|---|---|---|
| AUTH-01 | Auto-Login | Web/PWA | App online ohne BFF-Session, alte Offline-Identity vorhanden | anonymous | tokenfreie Offline-Identity konnte User setzen | `hydrateAuthSession()` fiel online auf Offline-Identity zurück | Web online ohne BFF-Session wird unauthenticated | behoben |
| AUTH-02 | Dev-Bypass | Tauri Dev | `?tauriDevAuth=1` oder localStorage-Marker | kein Login | synthetische Session mit hardcoded User | URL/localStorage-Bypass in `AuthContext` | Bypass entfernt, Legacy-Marker wird bereinigt | behoben |
| AUTH-03 | Logout/Refresh | Web/Tauri | Logout, Refresh | Account- und Vault-State leer | VaultContext räumt Userwechsel bereits ab, Auth-Offline-Identity blieb möglich | Auth-Hydration | Auth-Fix plus bestehendes Vault-State-Reset | behoben |
| VAULT-01 | Account vs Vault | Web/Tauri | Account Settings ohne Unlock | Account-Session reicht | ProtectedRoute braucht nur Account; VaultContext nicht erforderlich | Architektur ok | keine Vault-Unlock-Pflicht für `/settings` ergänzt | geprüft |
| INT-01 | Einzelnes Item manipuliert | Web/PWA/Tauri | V2-Baseline, Item-Ciphertext driftet | Item quarantined, Vault nutzbar | Service quarantined, aber Remote-Drift konnte automatisch rebaselined werden | decryptable remote rebaseline | automatische Remote-Rebaseline entfernt; quarantined Items werden nicht entschlüsselt | behoben |
| INT-02 | Kategorie manipuliert | Web/PWA/Tauri | Kategorie-Digest driftet | Vault blockiert | blockiert | Kategorie-Digest ist blockierend | beibehalten, canonicalization stabilisiert | behoben |
| INT-03 | Baseline malformed | Web/PWA/Tauri | Baseline nicht entschlüsselbar | Vault blockiert | Fehler wurde auf baseline_unreadable gemappt | ok | Reason-Typ ergänzt | behoben |
| DK-01 | Device Key required | Web/PWA/Tauri | neuer Client ohne Key | Login erlaubt, Unlock blockiert | Policy trennt Account/Vault; Device-Key-Missing eigener Fehler | ok | keine Master-only-Fallbacks ergänzt | geprüft |
| 2FA-01 | falsche 2FA | Web/PWA/Tauri | Account ohne Vault-2FA unlocken | keine 2FA | Service fragt `vault_unlock` explizit ab | ok | AuthRuntimeState trennt 2FA/DeviceKey/Integrity | verbessert |
| PK-01 | Passkey unsupported/abort | Web/PWA/Tauri | Unsupported/Cancel | klarer Fehler, keine kaputte Session | Service mappt Cancel/No PRF getrennt | ok | keine Session-Handoff-Änderung nötig | geprüft |

## Aktuelle Architektur

- `AuthContext` verwaltet nur Account-Session und nutzt `authSessionManager`.
- `VaultContext` orchestriert Vault-Setup, Unlock, Device Key, 2FA, Passkey und Integrity. Er bleibt ein Hotspot, wurde aber durch State-Machine, Decision Engine und Quarantine Orchestrator weiter entlastet.
- Integrity-Baselines liegen verschlüsselt in IndexedDB, Legacy-Secret-Store wird migriert.
- Device-Key-Policy liegt in `deviceKeyProtectionPolicy`; Account-Login ist getrennt vom Vault-Unlock.

## Erkannte Ursachen

- Hardcoded Tauri-Dev-Session per URL/localStorage war ein echter Auth-Bypass.
- Web-Hydration konnte online eine tokenfreie Offline-Identity als Account-State verwenden.
- Remote Item-Drift wurde automatisch re-baselined, wenn sie entschlüsselbar war. Das war zu permissiv.
- Baseline-Provenance war zu dünn; V2-Baseline enthält jetzt User-/Schema-/Source-Metadaten.

## Fix-Plan und Refactor-Plan

- Auth-Bypass entfernen und Legacy-Marker bereinigen.
- Dev-Testaccount nur per Node-Script und nicht per Client-Secret bereitstellen.
- AuthRuntimeState auf fachliche Zustände erweitern.
- Quarantäne-Entscheidung zentraler typisieren.
- Automatische Remote-Rebaseline entfernen; Rebaseline nur bei trusted local mutation scope.
- Canonicalization für Kategorie-Digests stabilisieren.

## Sicherheitsinvarianten

- Account Login ist nicht Vault Unlock.
- Device-Key-required erlaubt Account-Session, aber keinen Vault-Unlock ohne passenden lokalen Device Key.
- Einzelne Item-Drift wird quarantined und nicht entschlüsselt.
- Kategorie-Drift, malformed Snapshot, unreadable Baseline und Legacy-Mismatch blockieren den Vault.
- Dev-Testaccount ist ein normaler Supabase-User; kein URL/localStorage/Auth-Bypass.
- Keine Testaccount-Passwörter oder Service-Role-Keys im Client-Bundle.
