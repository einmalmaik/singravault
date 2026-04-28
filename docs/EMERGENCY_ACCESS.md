# Emergency Access - Architektur, Key-Pfad und Sicherheitsgrenzen

> **Komponenten:** `@singra/premium/src/services/emergencyAccessService.ts`, `@singra/premium/src/components/settings/EmergencyAccessSettings.tsx`, `supabase/migrations/20260427212000_harden_emergency_access_and_sync_heads.sql`

## Zweck

Emergency Access erlaubt Premium-Nutzern, einem Trustee nach Einladung, Annahme und Wartezeit Zugriff auf den Vault-Key-Pfad zu geben. Das ist bewusst kein Zero-Knowledge-Nebenfeature ohne Zusatzrisiko: Es ist ein alternativer Vault-Key-Zugriffspfad und erweitert die Trusted Computing Base um Trustee-Account, Trustee-Private-Key, Serverstatus, Wartezeit, Benachrichtigung und Widerruf.

## Zielregel

- Der Server darf keinen entschlüsselten Vault-Key sehen.
- Legacy-Spalten wie `encrypted_master_key` dürfen nicht mehr für neue Key-Flows genutzt werden.
- Trustees dürfen Grantor-Vault-Items nur sehen, wenn der Grant ausdrücklich `granted` ist und `pq_encrypted_master_key` gesetzt ist.
- Der Trustee-Zugriff bleibt an `trusted_user_id`, Grantor, Status und Grant-Zeit gebunden.
- E-Mail-Vergleiche für noch nicht verknüpfte Einladungen sind case-insensitive.

## Aktueller Key-Flow

1. Grantor erstellt eine Einladung mit `trusted_email`, `wait_days` und Status `pending`.
2. Trustee nimmt die Einladung an. Dabei wird der Trustee-Account über `trusted_user_id` gebunden.
3. Der Trustee-Private-Key wird als verschlüsselter Vault-Eintrag im eigenen Trustee-Vault abgelegt. Die Zuordnung erfolgt über ein Custom Field mit `emergency_access_id`.
4. Nach Ablauf der Wartezeit kann der Trustee den Zugriff claimen. Der Status wird auf `granted` gesetzt und `granted_at` gespeichert.
5. Der Grantor-Key-Pfad wird über `pq_encrypted_master_key` bereitgestellt. Die alte `encrypted_master_key`-Spalte ist per Check Constraint und Trigger für neue Writes blockiert.
6. Die Premium-Grantor-Ansicht importiert den entschlüsselten Key nur in einen `CryptoKey`; temporäre Byte-Arrays werden nach Import überschrieben.

## Datenbank-Härtung

Migration `20260427212000_harden_emergency_access_and_sync_heads.sql` setzt folgende Regeln:

- `emergency_access_no_legacy_master_key_check` blockiert neue Werte in `encrypted_master_key`.
- `validate_emergency_access_transition()` verhindert neue oder aktualisierte Rows mit Legacy-Master-Key-Material.
- Alte breite/duplizierte Policies werden entfernt.
- Grantor-Updates sind auf den eigenen Grantor-Datensatz beschränkt.
- Trustee-Updates sind auf zulässige Statusübergänge am verknüpften Trustee-Datensatz beschränkt.
- Die Vault-Items-Policy für Trustees verlangt `status='granted'`, `granted_at IS NOT NULL` und `pq_encrypted_master_key IS NOT NULL`.

## UI- und Service-Regeln

- `getGrantors()` nutzt getrennte Queries statt interpolierter PostgREST-OR-Ausdrücke. Das reduziert Fehler durch E-Mail-Sonderzeichen und hält die RLS-Absicht sichtbar.
- Die UI bietet keine `0 days`-Wartezeit mehr an, weil Datenbank/Edge-Pfade `1..90` Tage erzwingen.
- Der Trustee kann einen wartenden Grant erst nach Ablauf von `requested_at + wait_days` claimen.
- Beim Suchen des Trustee-Private-Key-Items verlässt sich die UI nicht mehr auf die Klartextspalte `item_type`, weil Vault-Metadaten neutralisiert werden. Stattdessen wird der eigene Vault entschlüsselt und das Emergency-Custom-Field geprüft.

## Sicherheitsgrenzen

- Ein kompromittierter Trustee-Account plus Zugriff auf dessen entschlüsselten Vault kann nach Ablauf/Freigabe den Grantor-Key-Pfad nutzen.
- Emergency Access ist daher schwächer als ein Modell ohne alternativen Key-Pfad. Das ist eine bewusste Produktfunktion, kein Bestandteil des strikten Zero-Knowledge-Kerns.
- Hybrides/PQ-Key-Wrapping über `pq_encrypted_master_key` und Trustee-PQ-Key-Material härtet den Key-Wrapping-Pfad gegen spätere kryptografische Angriffe. Es adressiert nicht die Account-, Geräte-, RLS-, Benachrichtigungs- oder entsperrter-Client-Trust-Boundary.
- Wenn Trustee-Account, Trustee-Gerät oder ein entsperrter Trustee-Vault kompromittiert sind, hilft PQ nicht gegen diesen lokalen oder Account-Kompromiss.
- Server- oder Admin-Manipulationen müssen durch Statusregeln, RLS, Benachrichtigungen und Auditierbarkeit begrenzt werden. Sie sind nicht vollständig kryptografisch unmöglich gemacht.
- Widerruf vor Grant muss den Pfad effektiv schließen; bereits gewährter Zugriff kann nach Kenntnisnahme durch den Trustee nicht rückwirkend kryptografisch ungeschehen gemacht werden.

## Verifikationspunkte

- Neue Rows dürfen `encrypted_master_key` nicht setzen.
- Trustees dürfen keine Grantor-Vault-Items sehen, solange Status nicht `granted` ist.
- Case-insensitive Einladungen müssen für `Trusted@Example.com` und `trusted@example.com` gleich funktionieren.
- Pending-Zugriff vor Ablauf der Wartezeit darf nicht claimbar sein.
- Premium-Build muss die Emergency-Settings-Seite und Grantor-Vault-Seite ohne doppelte Core-Modulidentitäten laden.
