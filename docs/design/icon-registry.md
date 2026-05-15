# Icon Registry

Stand: 2026-05-14

Singra Vault rendert Provider- und Kategorie-Icons nur aus kontrollierten internen Registries:

- `src/lib/icons/providerMatcher.ts`
- `src/lib/icons/brandIconRegistry.tsx`
- `src/lib/icons/categoryIconRegistry.tsx`
- `src/components/icons/VaultIcon.tsx`
- `src/components/vault/CategoryIcon.tsx`

## Sicherheitsregeln

- Keine Runtime-Downloads von Icons.
- Keine dynamischen Dateipfade aus Nutzerwerten.
- Keine gerenderten User-SVGs, kein HTML und keine Icon-URLs aus Vault-Daten.
- Provider-Matching liefert nur Registry-IDs wie `github`, `gmail` oder `generic`.
- Kategorie-Icons werden als Registry-IDs gespeichert; alte Emoji-Werte werden nur auf kontrollierte IDs gemappt.

## Lizenz- und Trademark-Hinweis

Kategorie-Icons nutzen die bereits vorhandene Dependency `lucide-react` als generische, kontrollierte SVG-Iconbasis.

Brand-SVGs werden als statische Teilmenge aus `simple-icons@16.19.0` unter `public/icons/brands/` ausgeliefert. Die Simple-Icons-Dateien stehen unter CC0; Markenrechte, Namen und Logos bleiben trotzdem bei den jeweiligen Rechteinhabern. Die Icons duerfen in Singra Vault nur zur identifizierenden Darstellung gespeicherter Anbieter genutzt werden. Sie duerfen nicht als eigene Marke, Werbeaussage, Partnerschaftsbehauptung oder Endorsement verwendet werden.

Die ausgelieferte Brand-Teilmenge umfasst derzeit 125 kontrollierte SVGs. Simple Icons liefert ueberwiegend einfarbige Marken-Glyphen; Singra Vault faerbt diese deshalb ausschliesslich ueber die entwicklergepflegte Registry-Farbe und nicht ueber Nutzerwerte. Google und Gmail nutzen statische, mehrfarbige Sonderdateien aus der internen Registry, weil ihre Wiedererkennbarkeit stark von der Originalfarbgebung abhaengt. Weitere mehrfarbige offizielle Logos werden erst aufgenommen, wenn Quelle, Lizenz und Trademark-Guidelines separat geprueft wurden. `Hytale` ist aktuell nicht enthalten, weil in der verwendeten Simple-Icons-Version kein passendes SVG vorhanden ist.

Lokale Lizenzkopien:

- `docs/design/third-party-icons/simple-icons-LICENSE.md`
- `docs/design/third-party-icons/simple-icons-DISCLAIMER.md`

Nicht enthaltene Markenlogos fallen automatisch auf kontrollierte Lucide-Fallbacks zurueck, wenn Simple Icons kein Logo bereitstellt oder die Nutzung nicht eindeutig genug ist.
