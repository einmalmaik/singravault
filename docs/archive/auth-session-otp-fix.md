# Auth Session OTP Fix (2026-02-25)

> Historisches Dokument. `auth-session` ist seit dem OPAQUE-Cutover kein App-Passwort-Login-Endpunkt mehr. Es bleibt nur für Session-Hydration, Logout und OAuth-Sync zuständig; direkte Passwort-POSTs werden mit `LEGACY_PASSWORD_LOGIN_DISABLED` blockiert.

## Problem

Login über die `auth-session` Edge Function schlug fehl mit `otp_expired` / `token has expired or is invalid`. Nutzer konnten sich trotz existierendem Account nicht anmelden.

Zusätzlich kam die Passwort-Reset-E-Mail nicht korrekt an bzw. der Redirect nach dem Klick führte auf `/vault` statt auf `/auth`.

## Ursache

### Bug 1: `verifyOtp` mit falschem Parameter

Die `auth-session` Edge Function nutzte das BFF-Pattern:
1. `admin.generateLink({ type: 'magiclink' })` → generiert einen Link mit Token
2. Token aus der URL extrahieren
3. `verifyOtp({ token, type: 'magiclink' })` → Session erstellen

Seit Supabase PKCE-Kompatibilität liefert `generateLink` einen **gehashten Token** (`hashed_token` in `properties`). Der alte Code extrahierte den Token aus der URL und übergab ihn als `token`-Parameter — aber `verifyOtp` erwartet `token_hash` für gehashte Tokens.

**Ergebnis:** Jeder Login-Versuch schlug sofort mit `otp_expired` fehl.

### Bug 2: Falscher `redirectTo` bei Passwort-Reset

Die `auth-recovery` Edge Function setzte `redirectTo: ${siteUrl}/vault`. Der Nutzer wurde nach dem Klick auf den Reset-Link zum Vault weitergeleitet, nicht zum Auth-Formular wo das neue Passwort eingegeben werden kann.

## Fix

### auth-session/index.ts
```diff
- const url = new URL(linkData.properties.action_link);
- const token = url.searchParams.get('token');
- if (!token) throw new Error("No token in magic link");
- const { data: sessionData, error: verifyError } = await supabaseAdmin.auth.verifyOtp({
-     email,
-     token,
-     type: 'magiclink'
- });
+ const tokenHash = linkData.properties.hashed_token;
+ if (!tokenHash) throw new Error("No hashed_token in generateLink response");
+ const { data: sessionData, error: verifyError } = await supabaseAdmin.auth.verifyOtp({
+     token_hash: tokenHash,
+     type: 'magiclink'
+ });
```

### auth-recovery/index.ts
```diff
- redirectTo: `${siteUrl}/vault`,
+ redirectTo: `${siteUrl}/auth`,
```

## Betroffene Dateien
- `supabase/functions/auth-session/index.ts`
- `supabase/functions/auth-recovery/index.ts`

## Verifizierung
- Edge Functions deployed am 2026-02-25
- Login-Flow muss getestet werden: E-Mail + Passwort → Session wird korrekt erstellt
- Passwort-Reset muss getestet werden: E-Mail eingeben → Link in E-Mail → Redirect auf `/auth`
