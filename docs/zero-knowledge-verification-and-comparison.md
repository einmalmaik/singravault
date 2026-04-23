# Zero-Knowledge Verifikation & Vergleich mit Bitwarden, 1Password, Proton Pass

**Datum:** 2026-02-26  
**Scope:** Vollständige Prüfung der Zero-Knowledge-Architektur + Branchenvergleich

---

## Teil 1: Zero-Knowledge Verifikation — Singra Vault

### Was der Server sieht

| Datenpunkt | Gespeichert auf Server | Plaintext? |
|---|---|---|
| Master-Passwort | ❌ Nie | — |
| Vault-Einträge (`encrypted_data`) | ✅ | ❌ AES-256-GCM verschlüsselt |
| Encryption Salt | ✅ | Ja (ist öffentlich, ohne Passwort nutzlos) |
| Master-Password-Verifier (V3) | ✅ | Nein (verschlüsselte Konstante, kein Hash des Passworts) |
| TOTP Secrets (2FA) | ✅ | ❌ PGP-AES-256 verschlüsselt (server-seitig) |
| Dateianhänge | ✅ | ❌ Client-seitig AES-256-GCM verschlüsselt |
| Argon2id Hash (Login) | ✅ | Nein (irreversibel, nicht zum Vault-Entschlüsseln nutzbar) |

### Prüfungsergebnisse

#### ✅ Edge Functions berühren KEINE Vault-Daten

Geprüfte Edge Functions:
- `auth-session` — Nur Auth-Logik, kein Zugriff auf `encrypted_data`
- `auth-register` — Erstellt User + Argon2id-Hash, keine Vault-Daten
- `auth-reset-password` — Setzt nur den Argon2id-Hash neu
- `auth-recovery` — Sendet Recovery-Code per E-Mail
- `stripe-webhook` — Nur Subscription-Management
- `invite-family-member` / `accept-family-invitation` — Nur Mitgliedschaft
- `invite-emergency-access` — Nur Einladungslogik
- `admin-support` / `support-*` — Nur Ticketsystem
- `webauthn` — Challenge/Response, keine Vault-Daten

**Ergebnis:** Keine einzige Edge Function liest, schreibt oder verarbeitet `encrypted_data`.

#### ✅ Entschlüsselung ausschließlich im Browser

- `cryptoService.ts` → `decryptData()` läuft nur im Browser (Web Crypto API)
- `pqCryptoService.ts` → Hybrid-Entschlüsselung von Sharing-/Notfall-Schlüsseln nur im Browser
- `VaultContext.tsx` → CryptoKey wird nur im Memory gehalten, nie persistiert
- `collectionService.ts` → Shared-Collection-Entschlüsselung client-seitig

#### ✅ Kein Passwort-Leak in Logs/Requests

- Keine `console.log` mit Passwörtern, Keys oder Hashes gefunden
- Edge Functions loggen nur generische Fehlermeldungen ("Internal Server Error")
- Auth-Requests senden Passwort nur an `auth-session` (für Argon2id-Verifikation), danach wird es verworfen

#### ✅ Admin-Zugriff unmöglich

Selbst mit vollem Datenbankzugriff (Service Role Key) kann ein Admin:
- `encrypted_data` lesen → nur Ciphertext, ohne Master-Passwort nicht entschlüsselbar
- `encryption_salt` lesen → nutzlos ohne Master-Passwort
- `master_password_verifier` lesen → V3-Format ist eine verschlüsselte Konstante, nicht umkehrbar
- `argon2_hash` lesen → irreversibel, und selbst wenn gebrochen: der Argon2-Hash ist **nicht** der Vault-Schlüssel

**Kritischer Punkt:** Der Argon2id-Hash in `user_security` dient **nur** der Server-Authentifizierung. Der Vault-Schlüssel wird separat via `deriveKey()` im Client abgeleitet. Selbst wenn ein Admin den Argon2-Hash bricht, hat er **nicht** den AES-256-GCM Key.

#### ⚠️ Einzige Einschränkung: TOTP Secrets

Die TOTP-Secrets für 2FA sind server-seitig verschlüsselt (PGP-AES-256 via `pgp_sym_encrypt`). Ein Admin mit Zugriff auf den `totp_encryption_key` in `private.app_secrets` könnte theoretisch TOTP-Secrets entschlüsseln. Dies betrifft aber **nicht** die Vault-Daten — nur die 2FA-Codes. Dies ist eine bewusste Architekturentscheidung, da TOTP-Verifikation server-seitig erfolgen muss.

---

## Teil 2: Vergleich mit der Branche

### Verschlüsselungsarchitektur

| Feature | **Singra Vault** | **Bitwarden** | **1Password** | **Proton Pass** |
|---|---|---|---|---|
| **Verschlüsselung** | AES-256-GCM | AES-256-CBC | AES-256-GCM | AES-256-GCM |
| **KDF** | Argon2id (64 MiB, 3 iter) | Argon2id (64 MiB, 3 iter) oder PBKDF2 (600k iter) | Argon2id | bcrypt + HKDF |
| **Zero-Knowledge** | ✅ | ✅ | ✅ | ✅ |
| **Open Source** | ✅ Client + Server | ✅ Client + Server | ❌ Server proprietär | ✅ Client + Server |
| **Post-Quantum für Sharing-Keys** | ✅ ML-KEM-768 + RSA-4096 Key-Wrapping | ❌ Nicht verfügbar | ❌ Nicht verfügbar | ❌ Nicht verfügbar |
| **AAD (Authenticated Associated Data)** | ✅ Item-ID gebunden | ❌ | ✅ | Unklar |
| **Duress/Panik-Modus** | ✅ Fake-Vault bei Zwang | ❌ | ❌ | ❌ |
| **Emergency Access** | ✅ Mit Cooldown + PQ-Key-Wrapping | ✅ (einfacher) | ❌ | ❌ |
| **Vault-Integrität (Merkle)** | ✅ Client-seitig | ❌ | ❌ | ❌ |

### KDF-Parameter im Detail

| Manager | KDF | Memory | Iterations | Parallelism |
|---|---|---|---|---|
| **Singra Vault** (Client) | Argon2id | 128 MiB | 3 | 1 |
| **Singra Vault** (Server) | Argon2id | 64 MiB | 3 | 1 |
| **Bitwarden** (Default) | Argon2id | 64 MiB | 3 | 4 |
| **Bitwarden** (Legacy) | PBKDF2-SHA256 | — | 600.000 | — |
| **1Password** | Argon2id | Nicht öffentlich dokumentiert | — | — |

**Bewertung:** Die Client-seitige KDF von Singra (128 MiB) ist stärker als Bitwardens Default (64 MiB). Server-seitig sind wir gleichauf (64 MiB). Bitwarden hat `parallelism: 4`, wir `parallelism: 1` — in der Praxis ist der Unterschied marginal.

### Wo Singra Vault **stärker** ist

1. **Post-Quantum-Key-Wrapping (PQ):** Singra nutzt hybride ML-KEM-768 + RSA-4096 Kryptografie für Sharing- und Notfallzugriffs-Schlüssel. Das ist kein Claim, dass jeder Vault-Item-Ciphertext post-quantum verschlüsselt ist; Vault Items bleiben AES-256-GCM-verschlüsselt.

2. **AES-256-GCM statt CBC:** Bitwarden nutzt AES-CBC (Cipher Block Chaining), was anfälliger für Padding-Oracle-Angriffe ist. Singra nutzt AES-GCM (Galois/Counter Mode) mit integrierter Authentifizierung.

3. **AAD (Additional Authenticated Data):** Singra bindet die Item-ID als AAD in die Verschlüsselung ein. Das verhindert, dass ein Angreifer verschlüsselte Blöcke zwischen Items vertauschen kann (Ciphertext-Substitution).

4. **Duress-Modus:** Einzigartig — ein Fake-Vault wird bei Eingabe des Duress-Passworts angezeigt. Kein anderer Major-Passwortmanager bietet dieses Feature.

5. **Vault-Integritätsprüfung:** Client-seitiger Merkle-Tree über alle Vault-Items erkennt Manipulation, Löschung oder Hinzufügung durch den Server.

6. **Stärkere Client-KDF:** 128 MiB vs. Bitwarden's 64 MiB Default.

### Wo Singra Vault **gleichauf** ist

- Zero-Knowledge Architektur (alle vier Manager)
- Open-Source (Client + Server, wie Bitwarden und Proton Pass)
- TOTP/2FA-Support
- File Attachments (verschlüsselt)

### Wo die Konkurrenz **stärker** ist

1. **Audit-Historie:** Bitwarden und 1Password haben jahrelange unabhängige Security-Audits (Cure53, NCC Group). Singra hat noch keinen externen Audit.

2. **Parallelism in KDF:** Bitwarden nutzt `parallelism: 4`, was auf Multi-Core-CPUs die Brute-Force-Kosten erhöht.

3. **Secret Key (1Password):** 1Password verwendet einen zusätzlichen 128-bit Secret Key, der zusammen mit dem Master-Passwort die Verschlüsselung ableitet. Dieser wird nie an den Server gesendet. Das schützt selbst bei einem kompromittierten Server + schwachem Passwort.

4. **SRP (1Password):** 1Password nutzt Secure Remote Password (SRP) für die Authentifizierung, bei der das Passwort nie den Client verlässt — nicht einmal als Hash. Singra sendet das Passwort an die `auth-session` Edge Function für die Argon2id-Verifikation.

---

## Teil 3: Empfehlungen

### Kurzfristig (kein Code-Change nötig)

- ✅ Zero-Knowledge ist bestätigt und intakt
- ✅ Kein Admin-Zugriff auf Vault-Daten möglich

### Mittelfristig (Verbesserungspotential)

| Priorität | Maßnahme | Vorbild |
|---|---|---|
| MITTEL | SRP-Protokoll statt Passwort-über-TLS für Login | 1Password |
| MITTEL | Secret Key zusätzlich zum Master-Passwort | 1Password |
| MITTEL | `parallelism: 4` für Argon2id | Bitwarden |
| NIEDRIG | Unabhängiger Security-Audit beauftragen | Bitwarden (Cure53) |

---

## Fazit

**Singra Vault ist kryptographisch mindestens auf dem Niveau von Bitwarden und in mehreren Bereichen darüber hinaus** (PQ-Key-Wrapping für Sharing/Notfallzugriff, AES-GCM, AAD, Duress-Modus, Vault-Integrität). Die Zero-Knowledge-Architektur ist sauber implementiert — weder Admins noch der Server können Vault-Daten entschlüsseln.

Die größte Lücke gegenüber 1Password ist das Fehlen eines Secret Keys und SRP. Gegenüber Bitwarden ist Singra in mehreren Kryptografie-Bausteinen stärker (GCM > CBC, PQ-Key-Wrapping für Sharing/Notfallzugriff, stärkere KDF), aber Bitwarden hat den Vorteil jahrelanger externer Audits.

**Quellen:**
- [Bitwarden KDF Algorithms](https://bitwarden.com/help/kdf-algorithms/)
- [Bitwarden Zero-Knowledge Whitepaper](https://bitwarden.com/resources/zero-knowledge-encryption-white-paper/)
- [Bitwarden Encryption Protocols](https://bitwarden.com/pdf/help-what-encryption-is-used.pdf)
- [IACR 2026/058 — Comparative Security Analysis of Password Managers](https://eprint.iacr.org/2026/058)
- [Proton Pass vs Bitwarden — Security.org](https://www.security.org/password-manager/proton-pass-vs-bitwarden/)
