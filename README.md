# Singra Password Manager

Wilkommen bei **Singra Vault**, deinem sicheren, Open-Source Passwort-Manager.

**Live-URL**: [singravault.mauntingstudios.de](https://singravault.mauntingstudios.de)

## Was ist Singra?

Singra (abgeleitet von "Singularity") ist ein moderner, webbasierter Passwort-Manager, der deine Datensicherheit in den Mittelpunkt stellt. Er ermöglicht es dir, deine Passwörter sicher zu speichern, zu verwalten und von überall darauf zuzugreifen, ohne die Kontrolle über deine Daten aufzugeben.

### Sicherheitsarchitektur

Singra verfolgt einen **Zero-Knowledge** Ansatz. Das bedeutet, dass deine Passwörter **ausschließlich auf deinem Gerät** ("Client-Side") verschlüsselt und entschlüsselt werden. Niemand – nicht einmal der Server-Administrator – kann deine Daten lesen.

Technische Details:
- **Verschlüsselung**: AES-GCM (Advanced Encryption Standard im Galois/Counter Mode) für die sichere Verschlüsselung deiner Daten.
- **Schlüsselableitung**: Argon2id Hash-Algorithmus, um dein Master-Passwort in einen kryptografisch sicheren Schlüssel zu verwandeln. Dies macht Brute-Force-Angriffe extrem schwierig.

## Installation & Lokale Entwicklung

Du kannst Singra ganz einfach auf deinem eigenen PC laufen lassen.

### Voraussetzungen
- [Node.js](https://nodejs.org/) & npm müssen installiert sein.

### Schritte

1. **Repository klonen**
   ```sh
   git clone https://github.com/einmalmaik/singravault.git
   cd singra-secure-vault
   ```

2. **Abhängigkeiten installieren**
   ```sh
   npm install
   ```

3. **Umgebungsvariablen konfigurieren**
   Erstelle eine `.env` Datei im Hauptverzeichnis (basiert auf `.env.example`) und trage deine Supabase-Zugangsdaten ein.

4. **Anwendung starten**
   ```sh
   npm run dev
   ```
   Die Anwendung ist nun unter `http://localhost:8080` (oder einem ähnlichen Port) erreichbar.

## Technologien

Dieses Projekt basiert auf modernen Web-Technologien:
- **Frontend**: React, TypeScript, Vite
- **UI**: Tailwind CSS, shadcn/ui
- **Backend/Datenbank**: Supabase
- **Kryptografie**: Web Crypto API, Argon2id

## Lizenz

Dieses Projekt ist unter der **Business Source License 1.1 (BSL 1.1)** lizenziert.

- **Code einsehen**: Ja — der gesamte Quellcode ist öffentlich einsehbar
- **Self-Hosting (privat)**: Ja — für persönliche, nicht-kommerzielle Nutzung
- **Kommerzieller Verkauf/Hosting**: Nein — ohne schriftliche Genehmigung von Maunting Studios
- **Change Date**: 4 Jahre nach Release wird der Code automatisch Apache 2.0

Siehe [LICENSE](./LICENSE) für den vollständigen Lizenztext.
