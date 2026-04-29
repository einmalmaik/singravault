# Web/PWA Threat Model

## Zweck

Dieses Dokument beschreibt bewusst nur den tatsächlichen Sicherheitsrahmen für Web und PWA. Es ist kein Marketingtext.

## Schutzgüter

- Masterpasswort
- Vault-Key / User-Key
- verschlüsselte Vault-Daten
- Passkey-Wrapping-Material
- lokale Offline-Snapshots
- lokale Integritäts-Baseline
- Device-Key, falls aktiviert

## Angreifermodelle

### A1: kompromittierter oder manipulierte Serverantworten

Ziel:

- verschlüsselte Daten manipulieren
- alte oder fehlerhafte Zustände ausliefern

Abwehr in diesem Branch:

- lokale Integritäts-Baseline für Vault-Snapshot
- kein Passkey-Unlock ohne denselben Finalisierungspfad wie Passwort-Unlock

Grenze:

- ohne signierte Mutationen gibt es noch keine vollständige Ende-zu-Ende-verifizierte Ereigniskette

### A2: Browser-/Origin-Angreifer im gleichen Client-Kontext

Ziel:

- Scripts im selben Origin-Kontext ausführen
- lokale Daten oder Laufzeitzustände auslesen

Grenze:

- Ein kompromittierter Browser-Kontext ist für Web/PWA ein starker Angreifer.
- Nicht extrahierbare Keys reduzieren Exfiltration, heilen aber keinen kompromittierten Runtime-Kontext.

### A3: lokaler Zugriff auf Browser-Speicher

Ziel:

- IndexedDB oder andere persistent gespeicherte Daten auslesen

Abwehr:

- Local Secrets werden nicht in `localStorage` abgelegt
- lokale Secret-Nutzdaten werden über den Local-Secret-Store gekapselt

Grenze:

- Browser-Persistenz hat keine Desktop-Keyring-Stärke

## Vertrauensgrenzen

### Vertrauenswürdig innerhalb des Modells

- WebCrypto-Primitiven des Browsers
- nicht extrahierbare `CryptoKey`-Objekte, sofern korrekt unterstützt
- lokaler Speicher nur in Kombination mit dem Wrapping-Key-Modell

### Nicht automatisch vertrauenswürdig

- der Browser-Prozess insgesamt
- Erweiterungen, kompromittierte Render-Prozesse oder XSS im gleichen Kontext
- serverseitig gespeicherte verschlüsselte Daten als solche

## Offline-Verhalten

### Unterstützt

- Offline-Passwort-Unlock mit vorhandenem Snapshot
- Offline-Lesen bereits synchronisierter Daten

### Nicht unterstützt

- frischer Passkey-Login offline
- implizite Wiederherstellung fehlender lokaler Geheimnisse durch unsichere Fallbacks

## PWA-spezifische Hinweise

- Service Worker und Offline-Caches dürfen keine Entschlüsselungslogik ersetzen
- App-Shell-Caching ist nicht gleich sichere lokale Vault-Speicherung
- lokale Geheimnisse und Offline-Snapshots bleiben getrennte Schichten

## Unterschiede zwischen Web/PWA und Tauri

### Tauri

- OS-Keyring
- native lokale Secret-Speicherung
- stärkere Gerätebindung

### Web/PWA

- Browser-API-Grenzen
- Origin-gebundene lokale Speicherung
- weniger robuste lokale Geheimnishärtung

## Restrisiko

Folgende Punkte bleiben nach diesem Branch bewusst dokumentierte Restrisiken:

1. Ohne signierte Mutationen gibt es keine vollständige, clientverifizierte Mutationshistorie.
2. Ein kompromittierter Browser-Kontext bleibt im Web/PWA-Modell ein ernster Angreifer.
3. Browser, die den nicht extrahierbaren lokalen Wrapping-Key nicht sauber tragen, sind für stärkere lokale Schutzpfade ungeeignet.

## Operative Empfehlung

- Für den stärksten lokalen Schutz: Tauri/Desktop bevorzugen
- Für Web/PWA: realistische Erwartungshaltung beibehalten und Plattformgrenzen nicht verschweigen
