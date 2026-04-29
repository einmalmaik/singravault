# ADR-001: Core Vault Integrity aus Premium-Hooks lösen

## Status

Angenommen

## Kontext

Der bisherige Core-Pfad hing für Vault-Integrität teilweise an optionalen Hook-Strukturen. Zusätzlich war die Integritätsableitung strukturell näher am Passwortpfad als am eigentlichen aktiven Vault-Key. Dadurch war der Passkey-Pfad schlechter gestellt.

Für CORE-P0 war das nicht haltbar:

- Integrität durfte nicht von optionaler Premium-Laufzeitlogik abhängen
- Passwort- und Passkey-Unlock mussten denselben Sicherheitsabschluss haben
- kryptografisch relevante Zustände durften nicht im `localStorage` liegen

## Entscheidung

Der Core führt eine minimale lokale Vault-Integritätsprüfung selbst aus:

- kanonischer Digest über verschlüsselte Vault-Daten
- lokale Digest-Baseline verschlüsselt gespeichert
- Baseline an den aktiven Vault-Key gebunden

Der Unlock gilt erst dann als erfolgreich, wenn:

- der aktive Vault-Key hergestellt ist
- die Integritätsprüfung erfolgreich war
- oder ein sauberer Erstaufbau der Baseline erfolgt ist

## Nicht entschieden

Dieses ADR führt ausdrücklich nicht ein:

- signierte Mutationen
- serverseitig überprüfbare Mutationshistorie
- globale Mehrgeräte-Konsenslogik

Diese Themen gehören in einen späteren Workstream.

## Konsequenzen

### Positiv

- Core ist in sich konsistenter
- Passkey- und Passwortpfad sind gleichwertiger
- Premium bleibt optionale Erweiterung statt Laufzeitvoraussetzung für minimale Integrität

### Negativ

- Die lokale Integritäts-Baseline ist kein Ersatz für signierte Mutationen
- Mehrgeräte-Szenarien bleiben ohne zusätzliche Signaturschicht begrenzt

## Verwerfungen verworfener Alternativen

### Alles im Premium-Hook belassen

Verworfen, weil der Core dann seine eigenen Mindestgarantien nicht selbst tragen würde.

### Integritätsdaten weiter aus Passwortmaterial ableiten

Verworfen, weil das den Passkey-Pfad strukturell schlechter stellt und unnötig am Passwort hängt.
