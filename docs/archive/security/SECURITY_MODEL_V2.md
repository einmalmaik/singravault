# Security Model V2

## Kurzfassung

Der Core trennt nach diesem Branch klarer zwischen:

- Authentifizierung
- Vault-Unlock
- Synchronisation

Supabase bleibt für Identität, Blind-Sync, Policies und notwendige Metadaten zuständig. Die Entschlüsselung des Vaults bleibt clientseitig.

## Systemgrenzen

### Authentifizierung

Authentifizierung bedeutet nur:

- Identität des Users feststellen
- Session aufbauen
- Zugriff auf serverseitig geschützte Metadaten und verschlüsselte Daten erlauben

Authentifizierung entsperrt den Vault nicht automatisch.

### Vault-Unlock

Vault-Unlock bedeutet:

- aktiven Vault-Key bereitstellen
- verschlüsselte Vault-Daten lokal entschlüsseln können
- lokale Integritäts-Baseline prüfen oder vertrauenswürdig initialisieren

Unlock geschieht entweder:

- per Passwort
- oder per Passkey mit PRF, sofern ein passender Passkey registriert wurde

Wenn VaultFA aktiviert ist, muss der offizielle Client vor Freigabe des aktiven Vault-Keys eine serverseitige 2FA-Challenge über `auth-2fa` bestehen. Passkey und Masterpasswort sind Unlock-Methoden, aber kein Ersatz für VaultFA.

### Sync

Sync bedeutet:

- verschlüsselte Items und Kategorien laden oder schreiben
- Offline-Snapshots und Re-Sync verarbeiten

Sync ist nicht gleich Unlock. Der Server sieht nur verschlüsselte Nutzdaten und notwendige Metadaten.

## Schlüsselmodell

### Passwortpfad

1. Argon2id leitet KDF-Material aus Masterpasswort und Salt ab
2. bei USK-Konten wird damit `encrypted_user_key` entpackt
3. der resultierende User-/Vault-Key ist der aktive Schlüssel für den Vault
4. die lokale Integritäts-Baseline wird mit diesem aktiven Schlüssel geprüft

### Passkey-Pfad

1. WebAuthn PRF liefert gerätegebundenes PRF-Material
2. daraus wird ein Wrapping-Key abgeleitet
3. dieser Wrapping-Key entschlüsselt eine serverseitig gespeicherte Passkey-Envelope
4. die Envelope liefert das relevante Vault-Key-Material
5. der aktive Vault-Key durchläuft dieselbe lokale Integritätsprüfung wie der Passwortpfad

Wichtig:

- der Passkey-Pfad darf den Vault nicht entsperren, wenn Integrität oder Tamper-Prüfung fehlschlägt
- Legacy-Envelopes werden nur als Migrationspfad unterstützt und nach erfolgreichem Unlock auf das neue Format rotiert

## Integritätsmodell

Der Core führt eine minimale lokale Vault-Integritätsprüfung selbst aus:

- kanonischer Digest über verschlüsselte Items und Kategorien
- Digest-Baseline lokal verschlüsselt gespeichert
- Baseline ist an den aktiven Vault-Key gebunden

Das Ziel ist keine globale, serververifizierte Historie, sondern:

- lokale Erkennung offensichtlicher Tamper-Zustände
- gleiche Sicherheitsanforderungen für Passwort- und Passkey-Unlock

Nicht Teil dieses Branches:

- signierte Mutationen
- append-only Ereignislog
- serverseitige Verifikation von Mutationssignaturen

## Local Secret Store

### Tauri

Tauri nutzt native Secret-Speicherung über Core-Commands und das Betriebssystem-Keyring. Das ist die stärkere lokale Absicherung.

### Web/PWA

Web/PWA nutzt:

- IndexedDB für persistente Daten
- einen nicht extrahierbaren Wrapping-Key, sofern der Browser das sauber unterstützt

Der Browser bleibt trotzdem die schwächere Plattform:

- der Client-Code läuft im Angriffsraum des Browsers
- lokale Geheimnisse sind dort nur begrenzt härtbar
- Device-Key- und Integritätsmaterial dürfen deshalb nicht mit Desktop-Härte verwechselt werden

## Offline-Modell

Unterstützt:

- Offline-Passwort-Unlock mit bereits vorhandenem Snapshot und Offline-Credentials
- Re-Sync nach Wiederverbindung

Nicht unterstützt:

- frischer Passkey-Login offline ohne vorhandenen lokal vertrauenswürdigen Zustand

Bei inkonsistentem lokalem Zustand gilt:

- kein stiller Soft-Fallback
- sicherer Fehlerzustand statt Teil-Entsperrung

## Was dieser Branch nicht löst

- Emergency Access bleibt fachlich/kryptografisch ein separater Workstream
- Shared Collections und Membership-Rotation bleiben separat
- Mutation Signing bleibt separat

## Sicherheitsversprechen

Der ehrliche Stand nach diesem Branch lautet:

- Der Core ist bei Unlock, Passkeys und lokalem Secret-Handling konsistenter und defensiver als zuvor.
- Tauri/Desktop bietet stärkere lokale Absicherung als Web/PWA.
- Web/PWA bleibt nutzbar, aber mit klar dokumentierten Plattformgrenzen.
