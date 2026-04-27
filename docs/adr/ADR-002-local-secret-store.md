# ADR-002: Gemeinsamer Local Secret Store für Core

## Status

Angenommen

## Kontext

Vor diesem Branch lagen lokale kryptografisch relevante Hilfsdaten in uneinheitlichen Pfaden. Für CORE-P0 mussten drei Dinge sauberer werden:

- keine kryptografisch relevanten Fallbacks über `localStorage`
- gemeinsame Abstraktion für Tauri und Web/PWA
- Device-Key-Pfad auf ein belastbareres lokales Secret-Modell umstellen

## Entscheidung

Der Core führt `src/platform/localSecretStore.ts` als gemeinsame Abstraktion ein.

### Tauri

- native Speicherung über Core-Commands mit Rust-seitiger Key-Allowlist
- OS-Keyring als lokaler Secret-Store
- erlaubte Secret-Domänen sind eng begrenzt (`device-key:<user-uuid>`, `vault-integrity:<user-uuid>`)

### Web/PWA

- persistente Secret-Nutzdaten in IndexedDB
- Wrapping-Key als nicht extrahierbarer `CryptoKey`, sofern vom Browser sauber unterstützt

## Designgrenzen

- `localStorage` ist keine kryptografische Quelle
- Browser-Secret-Handling wird nicht auf Desktop-Stärke hochdefiniert
- wenn ein Schutzpfad auf sicheren lokalen Secrets beruht, muss er an die tatsächlichen Plattformfähigkeiten gekoppelt bleiben

## Konsequenzen

### Positiv

- gemeinsame Schnittstelle statt verstreuter Speziallogik
- Tauri kann stärkere lokale Schutzpfade sauber nutzen
- Device-Key-Service ist nicht mehr an einen pseudo-geheimen, aus `userId` abgeleiteten Wrapper gebunden

### Negativ

- Browser-Persistenz bleibt plattformbedingt begrenzt
- Offline- und Local-Secret-Verhalten muss dokumentiert und getestet werden, statt implizit angenommen zu werden

## Verworfene Alternativen

### lokale Geheimnisse weiter in Web Storage halten

Verworfen, weil das dem Sicherheitsziel direkt widerspricht.

### getrennte Implementierungen pro Plattform ohne gemeinsame Abstraktion

Verworfen, weil das Wartbarkeit, Testbarkeit und spätere Erweiterbarkeit unnötig verschlechtert.
