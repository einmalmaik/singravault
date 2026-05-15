# Changelog

Alle nennenswerten Änderungen an diesem Projekt werden hier dokumentiert.

## 0.4.8 - 2026-05-15

### Verbesserungen

- Neues Designsystem nach Maunting Design-DNA: dunkles Premium-Vault-UI, Glassmorphism und eine durchgaengig responsive App-Shell. Login, Landing, rechtliche Unterseiten und die Vault-Oberflaeche sind visuell an das neue Premium-Dark-Design angeglichen.
- Vault-Liste komplett ueberarbeitet: neuer Item-Vorschau-Bereich mit Schnellaktionen (Benutzername/Passwort kopieren, Favorit umschalten, bearbeiten, loeschen) sowie sichtbare Metadaten zum Eintrag.
- Eintraege koennen jetzt per Drag-and-Drop zwischen Kategorien verschoben werden, sowohl mit Maus als auch per Touch (langes Druecken zum Aktivieren). Auch Kategorien lassen sich per Drag-and-Drop neu sortieren.
- Neue Tabellenansicht fuer Vault-Eintraege mit zeilenweisem Kopieren, Favoriten-Toggle und Bearbeiten direkt aus der Liste; gruppierte Kategorie-Abschnitte sind klappbar.
- Beim Springen zu einem bestimmten Eintrag (z. B. ueber Suche/Hinweise) wird der Eintrag jetzt scrolled-into-view und kurzzeitig hervorgehoben, damit klar ist, welcher Eintrag gemeint ist.
- Sidebar zeigt eine Tresor-Gesundheitszusammenfassung an: schwache, pwned, doppelt verwendete, alte, wiederverwendete und starke Passwoerter werden lokal ausgewertet und je nach Status (gesund / Pruefen / kritisch) angezeigt.
- "Have I Been Pwned"-Pruefung erfolgt mit k-Anonymity ueber den SHA-1-Praefix; vollstaendige Passwoerter verlassen das Geraet nicht. Ergebnisse werden waehrend der Sitzung zwischengespeichert, damit dieselben Hashes nicht wiederholt nachgefragt werden.
- Passwort-Staerke-Bewertung beruecksichtigt jetzt zusaetzlichen Nutzerkontext (z. B. Titel, Benutzername, URL), damit naheliegende Varianten wie "github-meinname" korrekt schwaecher bewertet werden.
- Toast-Benachrichtigungen lassen sich per Klick in die Zwischenablage kopieren, was das Teilen von Fehlerdetails vereinfacht.
- Mobile- und Touch-Verbesserungen: groessere Tap-Ziele fuer Icon-Buttons, kompakte Bottom-Navigation mit Safe-Area-Abstand, dialoge nutzen die volle dynamische Viewport-Hoehe, Tabs mit horizontalem Scroll erhalten einen Fade-Hinweis, Favoriten erscheinen auf Mobil/Tablet als vertikales Grid und auf Desktop als horizontaler Karussell.
- Provider-Icons fuer viele bekannte Anbieter (z. B. Gmail, Google, GitHub, AWS, Stripe, Proton, Binance) werden zentral auf interne Icon-IDs gemappt; Kategorie-Icons verwenden kontrollierte Registry-IDs statt sichtbarer Emoji-Icons.
- Kategorie-Dialog: aufgeraeumtere Icon-Auswahl und sauberer geleiteter Loeschvorgang.
- Item-Dialog: polishierte Layouts und Detail-Korrekturen.

### Fehlerbehebungen

- Leere Tresore zeigen beim ersten Laden nicht mehr faelschlich "Entschluessele Eintraege..." an, wenn keine Eintraege vorhanden sind.
- Frisch erstellte Social-Login-Accounts erhalten beim Masterpasswort-Setup direkt einen initialen OpLog-Trust-State mit lokalem Device-Signing-Key, sodass neue Eintraege nicht mehr wegen fehlender OpLog-Device-Identitaet blockieren.
- Frische, leere OpLog-Tresore werden nach lokaler Working-Set-Verifikation als verifiziert behandelt, statt faelschlich in alte Manifest-/Safe-Mode-Pfade zu fallen.
- Der Sicherheitsstatus in der Sidebar flackert nicht mehr bei jedem Hintergrund-Refresh als Ladezustand; Realtime bleibt der Hauptpfad, Polling ist nur noch Fallback.
- Routine-Pruefungen im gesunden Zustand schreiben keine dauerhaften `VaultRuntime`-Info-Logs mehr in die Konsole.
- Passkey-Einstellungen: ein harmloser 401 waehrend des Session-Warmups zeigt keinen Fehler-Toast mehr.
- Kategorie-Dialog: ein direkter Loeschwunsch oeffnet nicht mehr versehentlich erst den Bearbeiten-Dialog, und ein abgebrochener Bestaetigungsdialog schliesst auch den umgebenden Dialog sauber.

### Stabilitaet & Sicherheit

- Vault-CRUD-Aktionen werden ueber eine interne Aktions-Warteschlange serialisiert: signierte Operationen laufen sequenziell ab, sodass schnelle Folge-Aktionen auf langsamen Verbindungen nicht mehr in OpLog-Konflikte laufen.
- Die Tresor-Gesundheits-Eingaben werden vor Uebergabe an Erweiterungs-Hooks bereinigt; Klartext-Passwoerter verlassen den lokalen Auswerter nicht.
- HIBP-Cache vermeidet wiederholte Anfragen fuer denselben Passwort-Hash innerhalb einer Sitzung; bei Netzwerkfehlern werden Eintraege nicht zwischengespeichert.
- Erweiterte Tests fuer die zentrale Crypto-Grenze (`cryptoService`): AES-GCM-Roundtrip fuer Text und binaere Payloads, IV-Eindeutigkeit, Manipulationsablehnung, AAD-Bindung, Envelope-Versionierung, KDF-Parameter-Stabilitaet und UserKey-/Private-Key-Wrapping. Sicherheitsversprechen aendern sich dadurch nicht; bestehende Eigenschaften sind jetzt vertraglich abgesichert.

### Hinweise

- Singra Vault bleibt ein experimenteller Prototyp. Bitte keine echten Passwoerter, produktiven Secrets oder Recovery-Daten speichern.
- Die Tresor-Gesundheits-Auswertung ist ein Premium-Feature; ohne aktive Premium-Lizenz wird in der Sidebar ein Feature-Hinweis angezeigt.
- Wenn alle vertrauenswuerdigen Geraete und alle Recovery-Codes verloren sind, gibt es weiterhin keinen Support-Bypass fuer den Tresorzugriff.
- Externe Hinweise: Die `webauthn` Edge Function muss deployt sein, damit Passkey-Registrierung in der gehosteten Singra-Instanz weiterhin zuverlaessig funktioniert. Diese externe Komponente ist nicht Teil des Desktop-Builds.

## 0.4.7 - 2026-05-13

### Highlights

- Neues Vault Operation Log: Tresor-Aenderungen laufen jetzt ueber signierte Operationen statt ueber das alte Integritaets-/Snapshot-System als primaere Vertrauensbasis.
- OpLog Verification prueft Operation-Chain, Record-Kontext, Device-Trust, Trust-Epoch und Vault-Head, bevor Eintraege normal angezeigt oder fuer Export/Suche/Zwischenablage freigegeben werden.
- Geraetevertrauen ist sichtbarer und strenger getrennt: Device Key entsperrt lokal, Device-Signing-Key und verifizierter Trust-State autorisieren Operationen.
- Offline-Modus baut auf dem neuen OpLog-Modell auf: Offline erstellte, bearbeitete und geloeschte Eintraege werden als signierte Operationen nach dem Reconnect verifiziert synchronisiert.
- Neue Sicherheitsanzeigen machen klarer, ob der Tresor verifiziert, eingeschraenkt, in Quarantaene, im Sicherheitsmodus oder wegen Geraetevertrauen gesperrt ist.
- Singra Vault wird in App, README und Release-Kontext klarer als experimenteller Prototyp markiert: keine echten Passwoerter, produktiven Secrets oder Recovery-Daten speichern.

### Verbesserungen

- Item-, Kategorie- und Delete-Flows sind an den OpLog-CRUD-Pfad angebunden und vermeiden direkte Legacy-Writes als normale Vertrauensbasis.
- Quarantaene, Konflikte und geloeschte Eintraege werden aus dem verifizierten OpLog-UI-State abgeleitet statt aus einem ungeprueften Serverstand.
- Restore-/Resolve-Pfade erzeugen neue signierte Operationen oder blockieren fail-closed, wenn kein verifizierter Kontext vorhanden ist.
- Offline-Aenderungen werden als wartende Aenderungen behandelt und erst nach erfolgreicher Verifikation als synchronisiert markiert.
- Ein widerrufenes Geraet kann wartende Offline-Aenderungen nicht mehr automatisch in die Cloud senden.
- Eintraege, Kategorien und geloeschte Eintraege bleiben nach Offline-Nutzung und erneutem Online-Gehen konsistenter zwischen mehreren Geraeten.
- Export, Suche und Zwischenablage verwenden nur verifizierte Tresor-Eintraege.

### Behoben

- Frische, leere Tresore nach Social-Login/Neuregistrierung werden nicht mehr faelschlich wegen fehlendem Manifest V2 blockiert.
- Leere, verifizierte OpLog-Tresore zeigen beim Aktualisieren nicht mehr faelschlich "Entschluessele Eintraege..." an.
- Offline erstellte oder geloeschte Eintraege wurden in manchen Situationen nicht zuverlaessig synchronisiert.
- Kurzzeitige Quarantaene-Anzeigen beim Laden des Sicherheitsstatus verschwinden nun sauberer nach erfolgreicher Verifikation.
- Geraete-Recovery und erneutes Vertrauen eines Geraets funktionieren nach Widerruf stabiler.
- Add-Device-Anfragen bleiben erneut versuchbar, wenn der spaetere Speichervorgang fehlschlaegt.
- Deutsche Texte in Recovery-Code-Downloads und Sicherheitsmeldungen wurden verbessert.

### Hinweise

- Wenn alle vertrauenswuerdigen Geraete und alle Recovery-Codes verloren sind, gibt es weiterhin keinen Support-Bypass fuer den Tresorzugriff.

## 0.4.3 - 2026-04-28

### Security Hardening

- Server-sichtbare Vault-Item-Metadaten werden bei neuen Core-Writes zentral neutralisiert: Titel, URL, Icon, Typ, Favorit, Kategorie, Sortierung und `last_used_at` bleiben nicht mehr als fachliche Klartext-Metadaten in den `vault_items`-Spalten stehen.
- Legacy-Vault-Item-Metadaten werden nach erfolgreichem Unlock lokal in den verschlüsselten Payload übernommen und anschließend serverseitig neutralisiert; bei fehlender Remote-Persistenz bleibt das entschlüsselte Item nutzbar, ohne Daten aus dem Payload zu verwerfen.
- Kategorien werden stärker auf verschlüsselte `enc:cat:v1:`-Metadaten ausgerichtet; direkte Kategorie- und Sync-RPC-Writes neutralisieren Parent-/Sortier-Metadaten und erzwingen verschlüsselte Kategorie-Namen.
- Device-Key-Aktivierung schlägt geschlossen fehl, wenn die UserKey-Migration noch nicht persistiert ist, damit keine Device-Key-Pflicht ohne rettbaren Unlock-Zustand entsteht.
- Device-Key-Transfer und Import wurden von einfachem PIN-Wrapping auf versionierte `sv-dk-transfer-v2`-Envelopes mit Argon2id-Parametern, Längenlimits und Downgrade-/DoS-Prüfungen gehärtet.
- WebAuthn-Challenges werden an konkrete Challenge-IDs, RP-ID, Origin und optional Credential-ID gebunden; die Funktion nutzt zusätzlich serverseitige Rate-Limits für Challenge-, Verify- und Verwaltungsaktionen.
- Account-Löschung läuft über eine Edge Function mit Rate-Limit, enger CORS-Methodenliste und Storage-API-Cleanup statt direkter Storage-Tabellenlöschung.
- Sensitive Supabase-RPCs für OPAQUE-Reset, Session-Revocation und 2FA-Secret-Helfer wurden von `anon`/`authenticated` entzogen und auf `service_role` beziehungsweise SECURITY-DEFINER-Wrapper eingegrenzt.
- Edge-CORS gibt bei abgelehnten Origins keinen `null`- oder Wildcard-Origin mehr aus und behandelt hyphen-delimitierte Preview-Origin-Suffixe nur für ausreichend spezifische, kontrollierte Host-Suffixe.
- Ein versehentlich generiertes Loadtest-Token-Artefakt wurde entfernt; die Repository-Guardrails erkennen nun auch `.failed.txt`-Varianten dieser Artefakte.

### Zero-Knowledge & Metadata

- Neue Vault-Item-Writes in Dialogen, Offline-Mutations und Quarantine-Recovery verwenden eine gemeinsame Metadata-Policy, damit fachliche Item-Metadaten im verschlüsselten Payload bleiben.
- Legacy-Migrationen führen serverseitige Altdaten zuerst in die lokal entschlüsselten Item-Daten zusammen, verschlüsseln danach neu und schreiben nur neutrale Serverfelder zurück.
- Offline-Snapshots speichern zusätzlich einen monotonen Sync-Head und queued Mutations laufen über eine Compare-and-Set-RPC, um Rollback- oder stale-write-Situationen besser zu erkennen.
- Die Security-Dokumentation wurde präzisiert: Vault-Inhalte und fachliche Vault-Metadaten werden stärker minimiert, aber Account-, Auth-, Sync-, Recovery-, Billing-/Support-, Storagegrößen-, Zeitstempel- und Laufzeit-Metadaten liegen weiterhin außerhalb der strikten Vault-Content-Zero-Knowledge-Grenze.

### Device Key

- `vault_protection_mode`, `device_key_version`, `device_key_enabled_at` und `device_key_backup_acknowledged_at` wurden als nicht-geheime Profilmetadaten ergänzt, um `master_only` und `device_key_required` sauber zu unterscheiden.
- Device Keys werden konsequent als 32-Byte-Schlüssel validiert; ungültige lokale oder Legacy-Keys werden nicht als verwendbare Device Keys akzeptiert.
- Tauri/Desktop hält rohe Device-Key-Bytes in Rust/OS-Keychain-Pfaden und stellt dem Renderer nur eng begrenzte native Operationen bereit: Verfügbarkeit prüfen, erzeugen, ableiten, exportieren und importieren.
- Lokale Secret-Keychain-Namen wurden auf erlaubte, nutzergebundene Namespaces eingegrenzt; generische Renderer-Lese-/Schreibzugriffe auf den Device-Key-Namespace sind blockiert.
- Die Device-Key-Settings und Dokumentation beschreiben Import, Backup-Risiko und Web/PWA- versus Tauri/Desktop-Grenzen expliziter.

### Supabase / Edge Functions

- Neue Migrationen erweitern die Rate-Limit-Aktionsliste für Account Delete und WebAuthn, härten WebAuthn-Challenge-Scope, erzwingen opaque Vault-Item- und verschlüsselte Category-Metadaten, ergänzen Sync-Head/CAS-Mutationslogik und fügen Device-Key-Schutzmodus-Metadaten hinzu.
- Linked-DB-Lint-Fixes qualifizieren Extension-Funktionen, korrigieren OPAQUE-Reset-Konfliktziele und räumen problematische Grants auf.
- `account-delete` ist im Open-Core-Edge-Function-Set enthalten; Premium-, Admin-, Billing-, Support- und Family-Funktionen bleiben getrennt dokumentiert und werden nicht in den öffentlichen Core gezogen.

### Tauri / Desktop

- Device-Key-Derivation, Export und Import wurden in native Tauri-Kommandos verschoben, damit langfristiges Device-Key-Material nicht über generische JS-Secret-Reads läuft.
- Die Tauri-Capabilities erlauben weiterhin den nötigen Save-Dialog und app-spezifische Log-Verzeichnisse, geben aber keine breiten Opener- oder Lese-Permissions frei.
- CSP-, Session- und Renderer-Risiken wurden dokumentiert; verbleibende Web/PWA- und Desktop-Renderer-Grenzen werden nicht als vollständig gelöst dargestellt.

### Tests

- Neue und erweiterte Regressionstests decken Vault-Metadata-Policy, Legacy-Metadata-Migration, Device-Key-Service und Native Bridge, Device-Key-Protection-Policy, Account-Delete-Runtime-Hardening, Edge-CORS, WebAuthn/Rate-Limit-Kontrakte, Tauri-Capabilities und Repository-Guardrails ab.
- Security-Whitepaper-, Footer-/Version-, Offline-Vault-, Auth-Session-, Export- und Crypto-Pipeline-Tests wurden an die gehärteten Flows angepasst.

### Notes

- Dieses Release verbessert die Sicherheitslage und reduziert fachliche Vault-Metadaten auf dem Server, behauptet aber nicht „100 % Zero Knowledge für alle Metadaten“.
- Premium, Admin, Billing, Support und Family bleiben außerhalb des öffentlichen Core-Repositories.
- Der manuelle Runtime-Check für `/vault/settings` wurde mit echtem Account durchgeführt: Settings laden sauber, Device-Key-Schutz wird angezeigt, keine doppelten Provider, keine Hook-/Context-/`@fs`-Fehler und keine Browser-Konsolenfehler.

## 0.4.0 - 2026-04-27

### Highlights

- Sicherheitsrelease mit bereinigter Git-Historie für den versehentlich committeden Klartext-Vault-Export
- OPAQUE-only Passwort-Authentifizierung, Reset- und Change-Flows wurden konsolidiert und gehärtet
- Vault-Recovery, Quarantäne, Integrity-Rebaseline und destruktive Reset-Pfade wurden gegen Datenverlust und schwache Reauthentifizierung gehärtet
- Post-Quantum-Kryptografie ist klarer auf Key-Wrapping-/Sharing-/Emergency-Flows ausgerichtet
- Desktop-Dateirechte und Release-Guardrails wurden enger gefasst

### Added

- Vault-Quarantäne- und Recovery-Oberflächen für Integritätsprobleme
- Trusted-Rebaseline-Flow für Vault-Integrity-Recovery
- Server-seitig abgesicherte Vault-Reset-Recovery-Challenge mit frischer Reauthentifizierung
- Konfigurierbare TOTP-Parameter und persistente TOTP-Speicherpfade
- Pending-Premium-Attachment-Flow und Dialog-Reset-Verhalten
- Repository-Secret-Guardrail für CI und Release-Builds
- Release-Artefakt-Guardrail gegen versehentliche Secret-/Export-Artefakte
- Tests für AAD-gebundene Shared-Key- und Hybrid/PQ-Key-Wrapping-Pfade

### Changed

- Neue Sharing-/Emergency-/Family-Keypairs verwenden standardmäßig Hybrid/PQ-Key-Wrapping statt still auf RSA-only zu fallen
- Shared-Key-Entschlüsselung ist im normalen Runtime-Pfad fail-closed und erlaubt Legacy-No-AAD-Fallback nur noch explizit für Migrationspfade
- Hybrid/PQ-Key-Wrapping verlangt Kontextbindung per AAD für sicherheitskritische Wrapped Keys
- Vault-Reset-RPCs erzwingen serverseitig Challenge-, Reauth- und 2FA/VaultFA-Schutz statt nur Client-seitiger Bestätigung
- Tauri-Capabilities erlauben keine breiten rekursiven Schreib-, Rename- oder Löschrechte mehr auf Nutzerordnern
- Vault-Notes bleiben in Payloads und Snapshots verschlüsselt
- Snapshot-Quelle wird bei Integrity-Checks explizit berücksichtigt
- Support-Widget erhält Host-Auth sauberer
- Landing- und Auth-Branding wurden mit neuen Bildassets und Cover-Verhalten überarbeitet
- Post-Quantum-Dokumentation beschreibt PQ als Key-Wrapping-Schicht, nicht als Primär-Vault-Verschlüsselung

### Fixed

- Vault-Unlock zeigt Fehler zuverlässiger an und Reset-Logik wurde entkoppelt
- Legacy-Device-Keys werden toleranter migriert; defekte Secrets führen nicht mehr unkontrolliert in Folgefehler
- Kategorie-Integrity-Flows wurden stabilisiert
- OTP-Sendefehler bei OPAQUE-Signup rollen sauber zurück
- Passkey-Status wird auch dann geladen, wenn eine WebAuthn-Probe fehlschlägt
- Account-Deletion-, Auth-Fehler- und OAuth-Flows wurden robuster
- Legacy-Desktop-Tokens werden konsequenter bereinigt
- Lokales Secret-Handling und Core-Unlock-Pfade wurden gehärtet

### Security

- Der versehentlich committede Klartext-Vault-Export wurde aus der Branch-Historie entfernt und der Branch neu auf `origin/main` basiert
- CI prüft jetzt auf Klartext-Vault-Exports, `.env`-Leaks, TOTP-Seeds, private Keys und andere Secret-Muster
- Release-Builds prüfen zusätzlich, dass keine blockierten Export-/Secret-Artefakte ausgeliefert werden
- Die alte unsichere destruktive Reset-RPC-Zwischenversion wurde durch einen nicht gegranteten Fail-Closed-Placeholder ersetzt
- SECURITY DEFINER-RPCs für Vault-Reset laufen mit engerem Suchpfad und serverseitigen Schutzbedingungen
- AAD-Kontextbindung verhindert Runtime-No-AAD-Fallbacks und Wrapped-Key-Kontextvertauschung in den gehärteten Pfaden

### Operational Notes

- Passwörter und TOTP-Seeds aus dem exponierten Vault-Export müssen operativ rotiert werden; der Code-Release kann diese externen Konten nicht automatisch absichern
- Bestehende lokale Klone, Forks, CI-Caches und Artefakte können alte Git-Objekte weiter enthalten und müssen bei Bedarf separat bereinigt werden
- OPAQUE-Server-Setup wurde nicht rotiert, weil im Export kein Projekt-OPAQUE-Secret nachgewiesen wurde

## 0.3.0 - 2026-04-21

### Added

- Premium-only Desktop-Downloads können jetzt über einen Erweiterungsslot in die gehostete Oberfläche eingebunden werden, ohne den öffentlichen Core aufzublähen

### Changed

- `0.3.0` ist die erste Version, die wir als stabil markieren
- deutsche UI-Texte in Einstellungen, Abo-Hinweisen und Rechtstexten wurden vereinheitlicht
- Release-Dokumentation und Versionsmetadaten wurden auf den stabilen Desktop- und Web-Stand angehoben

### Fixed

- Desktop-Sitzungen bleiben über App-Neustarts hinweg stabil erhalten
- manuell verwaltete Abos zeigen saubere Hinweise ohne fehlerhafte deutsche Zeichen
- Premium/Core-Grenzen bleiben im Core-only-Build und in der gehosteten Premium-Integration konsistent

## 0.2.3 Beta - 2026-04-21

### Added

- Desktop-Anmeldung bietet jetzt einen eingebauten Dialog für den manuellen Callback-Link statt eines Browser-Prompts

### Changed

- manueller Social-Login-Fallback ist jetzt direkt in die Auth-Oberfläche integriert und passt zum restlichen App-Design

### Fixed

- Tauri leitet OAuth-Callbacks bei bereits laufender App jetzt sauber an die bestehende Instanz weiter
- nativer PKCE-Speicher unterstützt jetzt mehrere Schlüssel parallel, damit Desktop-Social-Login nicht an kollidierenden Flow-Zuständen scheitert

## 0.2.2 Beta - 2026-04-21

### Fixed

- Tauri-Desktop-Build injiziert keine PWA-Service-Worker-Registrierung mehr in `index.html`
- Windows-Desktop-Build bereinigt alte WebView-Service-Worker-Caches vor dem Start, damit offizielle Releases nicht an einer veralteten App-Shell hängen bleiben
- Tauri-Laufzeiterkennung berücksichtigt jetzt auch `tauri.localhost`, `asset.localhost` und `ipc.localhost`, damit Desktop-spezifische Pfade zuverlässig greifen

## 0.2.1 Beta - 2026-04-21

### Added

- offizieller Desktop-Release-Build prüft jetzt die gehostete Singra-Supabase-Konfiguration vor dem Tag-Build
- Windows-Installer-Ressourcen für NSIS und WiX mit eigenem Branding und Lizenzseite

### Changed

- öffentliche Desktop-Releases injizieren die offizielle Singra-Cloud-Konfiguration nur noch im GitHub-Action-Build
- Windows-Installer bindet den WebView2-Bootstrapper ein, damit Erstinstallationen robuster funktionieren
- Release-Notizen für Desktop-Tags wurden auf nutzerrelevante Hinweise reduziert

## 0.2.0 Beta - 2026-04-21

### Added

- Tauri-v2-Desktop-App auf Basis des bestehenden React/Vite-Bundles
- persistente Desktop-Anmeldung mit Keychain-gestütztem Refresh-Token-Speicher
- Deep-Link-basierter Social-Login für Desktop
- Update-Overlay für Desktop-Starts und eine Dev-Vorschau für den Updater-Screen
- Core-only-Start- und Build-Skripte für lokale Entwicklung und Self-Hosting
- GitHub-Actions-Workflows für Core-CI und signierte Desktop-Releases

### Changed

- zentrales Premium/Core-Boundary: öffentliches Repo bleibt buildbar ohne privates Paket
- Einstellungen, Navigation und Desktop-Pfade wurden auf gemeinsame Shell-Logik umgestellt
- deutsche Updater-Texte und Release-Hinweise wurden vereinheitlicht
- Dokumentation für Self-Hosting, Premium-Ladung und Desktop-Releases aktualisiert

### Fixed

- Social-Login-Weiterleitung zwischen Browser und Tauri-App
- mehrere Premium/Core-Auflösungsfehler im Desktop- und Settings-Bereich
- Update-Overlay-Rendering im Detailbereich

### Notes

- Diese Version ist weiterhin **Beta**.
- Das öffentliche Repository enthält nur den Core. Premium wird ausschließlich während privater Builds injiziert.
