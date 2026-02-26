# OPAQUE Protocol Integration

## Datum: 2026-02-26

## Zusammenfassung

Singra Vault nutzt das OPAQUE-Protokoll (IETF draft-irtf-cfrg-opaque) als modernes Password-Authenticated Key Exchange (PAKE). Das Passwort verlässt den Client **niemals** — nicht einmal als Hash.

## Architektur

```
Registration:
  Client                          Server
    |-- startRegistration(pw) -->   |
    |   registrationRequest         |
    |                               |-- createRegistrationResponse(req, setup)
    |   <-- registrationResponse -- |
    |-- finishRegistration() -->    |
    |   registrationRecord          |
    |                               |-- store(registrationRecord)

Login:
  Client                          Server
    |-- startLogin(pw) ----------> |
    |   startLoginRequest           |
    |                               |-- startLogin(req, record, setup)
    |   <-- loginResponse --------- |
    |   (+ serverLoginState)        |
    |-- finishLogin() -----------> |
    |   finishLoginRequest          |
    |                               |-- finishLogin(req, state)
    |   <-- session ---------------- |   → sessionKey match = authenticated
```

## Dateien

| Datei | Zweck |
|-------|-------|
| `src/services/opaqueService.ts` | Client-seitige OPAQUE-Logik |
| `supabase/functions/auth-opaque/index.ts` | Server-seitige OPAQUE-Logik |
| `user_opaque_records` Tabelle | Speichert Registration Records (service-role only) |
| `opaque_login_states` Tabelle | Ephemere Login-States (server-side, 5 min TTL, service-role only) |

## Library

- `@serenity-kit/opaque` v1.1.0 — Security Audit durch 7ASecurity
- Inlined WebAssembly, kein externer WASM-Load
- Unterstützt Browser (ESM) und Deno (npm: specifier)

## Secrets

- `OPAQUE_SERVER_SETUP`: Langlebiger Server-Setup-String, generiert via `opaque.server.createSetup()`

## Migration

- Bestehende Nutzer: Legacy-Login über `auth-session` (Argon2id über TLS)
- Nach erfolgreichem Legacy-Login: automatische OPAQUE-Registration
- `profiles.auth_protocol`: `'legacy'` → `'opaque'` nach Migration
- Legacy-Pfad bleibt permanent als Fallback

## Sicherheitseigenschaften

1. **Zero-Knowledge**: Server sieht niemals das Passwort
2. **Offline-Angriff-Schutz**: Selbst bei Server-Kompromittierung kann der Angreifer keinen Offline-Dictionary-Angriff starten
3. **Forward Secrecy**: Jede Login-Session hat einen einzigartigen Session-Key
4. **Formal bewiesen**: OPAQUE hat formale Sicherheitsbeweise (im Gegensatz zu SRP)

## 2FA-Integration

Wenn 2FA aktiviert ist, gibt `login-finish` `requires2FA: true` zurück. Der Client muss dann den TOTP-Code über den bestehenden `auth-session`-Endpunkt verifizieren (mit dem `opaqueVerified`-Flag).
