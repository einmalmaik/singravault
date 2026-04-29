# Security Architecture

Stand: 2026-04-29

## Zero-Knowledge-Grenzen

Der Refactor ändert die Zero-Knowledge-Grenzen nicht. Der Server erhält kein Masterpasswort, keinen Vault-Decryption-Key und keinen Device Key. Serverseitig sichtbare Device-Key-Metadaten beschreiben nur den Protection Mode und enthalten kein Device-Key-Material, keinen Hash und keinen Fingerprint.

## Auth-State vs Vault-State

Account-Session und Vault-Unlock sind getrennt. Account Settings benötigen eine Account-Session, aber keinen Vault-Key. Vault-Inhalte, Device-Key-Rewrap, Export und Quarantäne-Recovery benötigen Vault-Unlock. Device-Key-Missing, 2FA, Passkey-Fehler und Integrity-Block sind getrennte Runtime-Zustände.

## Device-Key-required

Wenn `vault_protection_mode = device_key_required` gilt, ist Account-Login auf einem neuen Gerät erlaubt, Vault-Unlock ohne passenden lokalen Device Key aber verboten. Es gibt keinen Master-only-Fallback. Tauri nutzt den OS-Secret-Store über die Native Bridge; Web/PWA nutzt lokalen Browser-Storage als schwächere Defense-in-Depth-Grenze.

## Quarantäne und Integrity

Item-Manipulation quarantined nur betroffene Items. Diese Items werden nicht entschlüsselt. Kategorie-Struktur-Drift blockiert den Vault, weil Kategorien Teil der Vault-Integritätsstruktur sind. Baseline-Fehler, Legacy-Baseline-Mismatch und malformed Snapshots blockieren ebenfalls. Automatische Rebaseline bei untrusted Drift ist verboten.

## Web/PWA vs Tauri

Die Integrity-Entscheidung ist in einem plattformneutralen Service gebündelt. Plattformunterschiede liegen in Storage und Device-Key-Bridge, nicht in unterschiedlichen Quarantäne-Regeln. Bei gleichem Snapshot und gleicher Baseline soll die gleiche Decision entstehen.

## Dev- und Testmodus

URL- und localStorage-basierte Auth-Bypässe sind entfernt. Dev-Testaccount-Secrets sind server-only und dürfen nicht mit `VITE_` in den Client gelangen. Production-Builds schlagen fehl, wenn Dev-Testaccount-UI oder serverseitige Dev-Testaccount-Aktivierung aktiv gesetzt sind.

## Restrisiken

Legacy-KDF-Reparatur und Device-Key-Aktivierung enthalten noch viel Orchestrierung in `VaultContext.tsx`. Diese Pfade sind durch bestehende Tests charakterisiert, aber noch nicht vollständig in Data-Access-/Migration-Services zerlegt. Echte PWA-, Tauri-dev- und Plattform-WebAuthn-Abnahmen bleiben Release-Prüfungen.
