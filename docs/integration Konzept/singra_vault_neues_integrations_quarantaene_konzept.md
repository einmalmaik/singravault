# Singra Vault — Neues Integrations-, Quarantäne- und Manipulationsschutzsystem

## Verbindlicher Architekturentwurf für den Neuaufbau

Dieses Dokument beschreibt das neue Integrations-, Synchronisations-, Quarantäne- und Manipulationsschutzsystem von Singra Vault. Es ersetzt das bisherige Modell aus lokalem Snapshot-Digest, heuristischer Rebaseline-Logik, Kategorie-Blockierung und zeitbasierten Recent-Local-Mutation-Fenstern.

Das Ziel ist ein robustes, offline-first, Ende-zu-Ende-verschlüsseltes Vault-System, bei dem legitime Änderungen zwischen Web, Tauri und später weiteren Clients zuverlässig synchronisiert werden, manipulierte Daten aber nicht entschlüsselt, nicht angezeigt, nicht autofilled und nicht stillschweigend akzeptiert werden.

Dieses Dokument ist als verbindlicher Plan zu verstehen. Es soll verhindern, dass dieselbe Sicherheitsfrage später mehrfach unterschiedlich interpretiert wird.

---

# 1. Grundentscheidung

Das neue System basiert nicht mehr auf der Idee:

> „Ein Remote-Snapshot wird mit einer lokalen Baseline verglichen. Wenn er abweicht, ist er verdächtig.“

Stattdessen gilt verbindlich:

> „Jede legitime Änderung am Vault ist eine kryptografisch signierte Operation eines vertrauenswürdigen Geräts. Der Client integriert nur Operationen, die signiert, versioniert, kausal nachvollziehbar, entschlüsselbar und schema-valide sind.“

Daraus folgt:

- Der Server ist niemals Vertrauensanker.
- Der Server ist nur Transport-, Speicher- und Ordnungsdienst.
- Der lokale Snapshot ist nicht die globale Wahrheit.
- Der lokale Snapshot ist ein Recovery-Punkt.
- Die eigentliche Wahrheit entsteht aus verifizierten Operationen vertrauenswürdiger Geräte.
- Quarantäne betrifft grundsätzlich einzelne Records, Kategorien, Container oder Sync-Zweige, nicht automatisch den ganzen Tresor.
- Der gesamte Tresor wird nur dann blockiert, wenn die Root-Vertrauensstruktur beschädigt ist.

---

# 2. Sicherheitsziele

## 2.1 Primäre Ziele

Das neue System muss folgende Ziele erfüllen:

1. Manipulierte Datenbankeinträge dürfen nicht entschlüsselt werden.
2. Manipulierte Datenbankeinträge dürfen nicht in der normalen UI erscheinen.
3. Manipulierte Datenbankeinträge dürfen nicht im Autofill verwendet werden.
4. Manipulierte Datenbankeinträge dürfen nicht exportiert werden.
5. Manipulierte Datenbankeinträge dürfen nicht in Suchindizes, Clipboard-Flows oder Vorschauen gelangen.
6. Legitimes Multi-Client-Sync zwischen Web, Tauri und später Mobile darf nicht ständig Quarantäne oder Vault-Sperren auslösen.
7. Kategorieänderungen dürfen den Tresor nicht mehr global blockieren.
8. Kategorien müssen einzeln quarantänisierbar sein.
9. Items innerhalb beschädigter Kategorien müssen weiterhin einzeln prüfbar bleiben.
10. Lokale Snapshots müssen als Recovery-Quelle nutzbar sein.
11. Recovery aus Snapshots muss selbst wieder als legitime signierte Operation synchronisiert werden.
12. Offline-Arbeiten muss möglich bleiben.
13. Spätere Online-Synchronisation muss deterministisch und idempotent sein.
14. Konflikte zwischen legitimen Geräten müssen als Konflikte behandelt werden, nicht als Manipulation.
15. Löschungen müssen beweisbar sein und dürfen nicht durch bloßes Fehlen eines Records entstehen.
16. Rollbacks und Replay-Angriffe müssen erkannt oder zumindest isoliert werden.
17. Der Server darf keine geheimen Schlüssel kennen.
18. Der Server darf keine Vault-Inhalte entschlüsseln können.
19. Der Server darf legitime Clients nicht dazu bringen, manipulierte Daten stillschweigend zu akzeptieren.
20. Das System muss für den Nutzer verständlich bleiben: normale Zustände, Konflikte, Quarantäne, Safe Mode und echte Blockade müssen klar unterscheidbar sein.

## 2.2 Nicht-Ziele

Dieses System garantiert nicht:

1. Schutz, wenn das aktuell entsperrte Endgerät vollständig kompromittiert ist.
2. Schutz, wenn Malware im entsperrten Prozess Klartextdaten ausliest.
3. Schutz, wenn ein Nutzer bewusst ein kompromittiertes Gerät als vertrauenswürdig bestätigt.
4. Vollständige Verfügbarkeit bei bösartigem Server, der alle Daten löscht oder keine Daten mehr ausliefert.
5. Vollständige Wiederherstellung, wenn kein lokaler Snapshot, kein anderer Client und kein Backup mehr existiert.
6. Automatische semantische Konfliktlösung bei zwei legitimen, konkurrierenden Änderungen desselben Passwort-Eintrags.

Das System soll Integrität und Recovery verbessern. Es ersetzt nicht Gerätesicherheit, sichere Updates, Backup-Strategien oder gute UX-Warnungen.

---

# 3. Bedrohungsmodell

## 3.1 Angreifer: manipulierter oder kompromittierter Server

Der Server kann versuchen:

- Ciphertexte zu verändern.
- alte Ciphertexte wieder einzuspielen.
- Records zu löschen.
- Records anderer IDs zu vertauschen.
- Kategorien zu verändern.
- Operationen zu unterschlagen.
- alte Operationen erneut auszuliefern.
- neue Records ohne legitime Operation einzufügen.
- eine alte Vault-Version als aktuelle auszugeben.
- Operationen in falscher Reihenfolge auszuliefern.
- einen Client durch inkonsistente Daten in Quarantäne oder Safe Mode zu zwingen.

Der Server kann nicht:

- Vault-Inhalte entschlüsseln, wenn die Kryptografie korrekt ist.
- gültige Operationen vertrauenswürdiger Geräte fälschen, wenn er keine privaten Signaturschlüssel besitzt.
- AEAD-geschützte Ciphertexte unbemerkt in andere Record-Kontexte verschieben, wenn AAD korrekt gebunden ist.

## 3.2 Angreifer: anderer Client ohne Gerätevertrauen

Ein nicht vertrauenswürdiger Client kann versuchen:

- neue Records hochzuladen.
- signaturlose Änderungen einzuschleusen.
- mit gestohlenen Account-Credentials auf den Server zuzugreifen.
- Items zu löschen.
- Snapshot-Zustände zu beeinflussen.

Er darf nicht erreichen:

- dass seine Daten als normaler Vault-Inhalt erscheinen.
- dass seine Daten entschlüsselt oder autofilled werden.
- dass seine Löschungen als legitime Löschungen akzeptiert werden.

## 3.3 Angreifer: kompromittiertes vertrauenswürdiges Gerät

Ein kompromittiertes, bereits vertrauenswürdiges Gerät ist ein schwerer Fall.

Dieses Gerät kann:

- gültige Operationen signieren.
- legitime Updates erzeugen.
- Daten löschen.
- falsche Daten einfügen.

Das System kann solche Operationen kryptografisch nicht von Nutzeraktionen unterscheiden, weil das Gerät vertrauenswürdig ist.

Deshalb braucht das System:

- Gerätewiderruf.
- Audit-Anzeige für Operationen.
- lokale Snapshots.
- Papierkorb/Tombstones.
- Warnungen bei ungewöhnlich vielen Änderungen.
- optional manuelle Bestätigung bei Massenänderungen.

## 3.4 Angreifer: lokaler Speicher manipuliert

Ein Angreifer kann versuchen:

- IndexedDB-Daten zu verändern.
- lokale Snapshots zu verändern.
- Mutation-Queues zu manipulieren.
- lokale Device-Trust-Daten zu verändern.

Gegenmaßnahmen:

- lokale Snapshots werden verschlüsselt und signiert.
- lokale Operationen werden vor Anwendung geprüft.
- lokale Queues enthalten signierte Operationen.
- nach Unlock wird lokale Integrität geprüft.
- beschädigte lokale Daten führen zu Safe Mode oder eingeschränkter Recovery, nicht zu blindem Vertrauen.

---

# 4. Architekturprinzipien

Diese Prinzipien sind verbindlich.

## P1: Server ist untrusted

Der Server speichert Daten, verteilt Daten und erzwingt grobe Konsistenz. Er ist aber keine Sicherheitsautorität.

Ein Client darf niemals sagen:

> „Der Server hat es geliefert, also ist es gültig.“

Ein Client darf nur sagen:

> „Der Server hat es geliefert, und ich habe lokal kryptografisch verifiziert, dass es gültig ist.“

## P2: Signierte Operationen sind die Integrationsquelle

Nicht der Snapshot ist die Vertrauensquelle. Nicht `remoteRevision` ist die Vertrauensquelle. Nicht die Entschlüsselbarkeit allein ist die Vertrauensquelle.

Die Vertrauensquelle ist:

1. eine gültige Signatur,
2. eines vertrauenswürdigen Geräts,
3. über eine kanonische Operation,
4. die zu einer bekannten Record-Historie passt,
5. deren Zielrecord entschlüsselbar und schema-valide ist.

## P3: Records sind einzeln geschützt

Jedes Item, jede Kategorie und jede andere Vault-Entität ist ein separater verschlüsselter Record.

Ein Fehler an einem Record darf nicht automatisch den gesamten Vault blockieren.

## P4: Quarantäne ist granular

Quarantäne betrifft:

- einzelne Items,
- einzelne Kategorien,
- einzelne Attachments,
- einzelne Container-Zuordnungen,
- einzelne unbekannte Operationen,
- einzelne Konflikte.

Der Vault wird nur global blockiert, wenn Root-Vertrauen beschädigt ist.

## P5: Konflikt ist nicht Manipulation

Zwei gültige Geräte können denselben Record parallel ändern. Das ist kein Angriff.

Solche Fälle werden als `conflict` markiert und vom Nutzer oder durch definierte Merge-Regeln aufgelöst.

## P6: Löschung ist eine Operation, kein Fehlen

Ein Record gilt nur dann als legitim gelöscht, wenn es eine gültige signierte Delete- oder Tombstone-Operation gibt.

Wenn ein Record auf dem Server fehlt, aber keine gültige Löschoperation existiert, ist das ein verdächtiges Fehlen.

## P7: Entschlüsselung ist ein Gate

Ein Record darf nur entschlüsselt werden, wenn seine Operation und sein Kontext vorher verifiziert wurden.

Quarantäne-Records werden nicht entschlüsselt.

## P8: Snapshot ist Recovery, nicht Wahrheit

Trusted Snapshots sind lokale Wiederherstellungspunkte.

Sie entscheiden nicht automatisch, was global richtig ist.

## P9: Safe Mode ist Betriebsmodus, keine Reparatur

Safe Mode bedeutet:

> „Ich traue dem aktuellen Remote-Zustand nicht. Ich arbeite aus einem lokal zuletzt geprüften Zustand.“

Safe Mode darf nicht automatisch Remote-Daten überschreiben. Recovery muss explizit über signierte Restore-Operationen erfolgen.

## P10: Keine automatische Rebaseline bei unbekannter Remote-Änderung

Das alte Muster „Remote-Änderung ist entschlüsselbar, also Baseline neu setzen“ wird abgeschafft.

Eine Remote-Änderung wird nur automatisch akzeptiert, wenn sie als legitime Operation eines vertrauenswürdigen Geräts verifizierbar ist.

---

# 5. Begriffsklärung

## 5.1 Vault

Der Vault ist die logische Sammlung aller verschlüsselten Daten eines Nutzers oder einer Organisation.

Ein Vault besitzt:

- `vaultId`,
- Vault-Manifest,
- Vault-Key oder Key-Hierarchie,
- vertrauenswürdige Geräte,
- Records,
- Operation-Log,
- lokale Snapshots.

## 5.2 Record

Ein Record ist eine einzelne verschlüsselte Vault-Entität.

Beispiele:

- Passwort-Item,
- Kategorie,
- Attachment-Metadaten,
- Attachment-Chunk,
- Notiz,
- Passkey-Credential,
- Tombstone,
- Vault-Manifest.

## 5.3 Operation

Eine Operation beschreibt eine Änderung an einem Record.

Beispiele:

- Create Item,
- Update Item,
- Delete Item,
- Restore Item,
- Create Category,
- Update Category,
- Delete Category,
- Move Item,
- Rekey,
- Add Device,
- Revoke Device.

Jede Operation wird vom erzeugenden Gerät signiert.

## 5.4 Trusted Device

Ein Trusted Device ist ein Gerät, dessen Signaturschlüssel für diesen Vault akzeptiert wird.

Ein Gerät ist nicht deshalb vertrauenswürdig, weil es eingeloggt ist.

Ein Gerät ist nur vertrauenswürdig, wenn es im Vault-Device-Trust verankert wurde.

## 5.5 Tombstone

Ein Tombstone ist ein signierter Löschmarker.

Ein gelöschter Record verschwindet nicht einfach aus der Historie. Es gibt eine signierte Operation, die erklärt, dass er gelöscht wurde.

## 5.6 Quarantäne

Quarantäne ist ein isolierter Zustand für Daten, deren Integrität, Herkunft, Version oder Entschlüsselbarkeit nicht vertrauenswürdig ist.

Quarantäne bedeutet:

- nicht entschlüsseln,
- nicht anzeigen,
- nicht autofillen,
- nicht exportieren,
- nicht in normalen Listen verwenden,
- Recovery-Aktion anbieten.

## 5.7 Safe Mode

Safe Mode ist ein Vault-weiter eingeschränkter Betriebsmodus, in dem der Client auf einem lokal signierten, zuletzt verifizierten Snapshot arbeitet, weil der aktuelle Remote-Zustand nicht ausreichend vertrauenswürdig ist.

Safe Mode ist nicht dasselbe wie `locked`.

## 5.8 Locked Critical

Locked Critical ist eine echte Sperre des Tresors.

Sie tritt nur ein, wenn der Client keine sichere Grundlage mehr hat, um überhaupt zwischen vertrauenswürdigen und nicht vertrauenswürdigen Daten zu unterscheiden.

---

# 6. Kryptografisches Modell

## 6.1 Schlüsseltypen

Das System verwendet logisch getrennte Schlüssel.

### 6.1.1 Master-Passwort-Ableitung

Das Master-Passwort wird nicht direkt als Verschlüsselungsschlüssel verwendet.

Es wird mit einer KDF verarbeitet.

Konzeptionell:

```text
masterPassword + salt + kdfParams -> masterUnlockKey
```

Der `masterUnlockKey` dient dazu, einen verschlüsselten Vault-Key oder User-Key zu entsperren.

Er wird nicht direkt für jedes Item verwendet.

### 6.1.2 Vault Encryption Key

Der Vault Encryption Key verschlüsselt Records oder leitet Record-Keys ab.

```text
vaultEncryptionKey -> recordKey(recordId, recordType, keyVersion)
```

Der Vault Encryption Key verlässt das Client-Gerät niemals im Klartext.

### 6.1.3 Record Key

Jeder Record kann über einen abgeleiteten Schlüssel verschlüsselt werden.

Beispiel:

```text
recordKey = HKDF(vaultEncryptionKey, "singra:record", vaultId | recordId | recordType | keyVersion)
```

Ziel:

- klare Kontextbindung,
- saubere spätere Key-Rotation,
- Trennung zwischen Records.

### 6.1.4 Device Signing Key

Jedes vertrauenswürdige Gerät besitzt ein eigenes Signaturschlüsselpaar.

```text
privateDeviceSigningKey -> bleibt lokal
publicDeviceSigningKey -> im Vault-Trust gespeichert
```

Der private Device Signing Key signiert Operationen.

Der öffentliche Schlüssel wird verwendet, um Operationen anderer Geräte zu prüfen.

### 6.1.5 Snapshot Signing Key

Der Device Signing Key kann auch lokale Snapshots signieren. Alternativ kann ein eigener Snapshot-Signaturschlüssel verwendet werden.

Für den ersten Neuaufbau reicht:

```text
Device Signing Key signiert lokale Snapshots.
```

## 6.2 Verschlüsselung pro Record

Jeder Record wird mit AEAD verschlüsselt.

Verbindliche Eigenschaften:

- zufällige Nonce pro Verschlüsselung,
- kein Nonce-Reuse mit gleichem Schlüssel,
- AAD bindet den Ciphertext an seinen Kontext,
- Entschlüsselung schlägt fehl, wenn Record in falschen Kontext verschoben wird.

## 6.3 AAD-Struktur

AAD steht für Additional Authenticated Data.

AAD wird nicht verschlüsselt, aber kryptografisch authentifiziert.

Verbindliche AAD-Felder:

```ts
type RecordAAD = {
  app: 'singra-vault';
  aadSchema: 'record-aad-v1';
  vaultId: string;
  recordId: string;
  recordType: 'item' | 'category' | 'attachment_metadata' | 'attachment_chunk' | 'manifest' | 'tombstone';
  recordVersion: number;
  keyVersion: number;
  encryptionSchema: 'record-aead-v1';
};
```

Diese Felder müssen exakt kanonisiert werden.

AAD verhindert unter anderem:

- Verschieben eines Item-Ciphertexts auf eine andere Item-ID,
- Verschieben eines Kategorie-Ciphertexts auf ein Item,
- Wiedereinspielen einer Version in falschem Kontext,
- Vertauschen zwischen Vaults,
- falsche Key-Versionen.

## 6.4 Hashes

Für Records und Operationen werden Hashes verwendet.

### 6.4.1 Ciphertext Hash

```text
ciphertextHash = Hash(canonical(record metadata relevant to encryption) | nonce | ciphertext | aad)
```

Der Hash muss stabil und eindeutig sein.

Er dient nicht als Geheimnis, sondern als Integritäts- und Referenzwert.

### 6.4.2 Operation Hash

```text
opHash = Hash(canonical(operationWithoutSignature) | signature)
```

Der Operation Hash identifiziert eine Operation eindeutig.

### 6.4.3 Previous Record Hash

Jede Update-, Delete- oder Restore-Operation referenziert den vorherigen erwarteten Record-Hash.

Dadurch erkennt der Client:

- ob eine Operation auf der erwarteten Version basiert,
- ob eine konkurrierende Änderung existiert,
- ob ein Rollback oder Fork vorliegt.

## 6.5 Signaturinhalt

Signiert wird die kanonische Operation ohne Signaturfeld.

```text
signature = Sign(privateDeviceSigningKey, Hash(canonicalOperationWithoutSignature))
```

Die Signatur muss alle sicherheitsrelevanten Felder umfassen:

- `opId`,
- `vaultId`,
- `authorDeviceId`,
- `opType`,
- `recordId`,
- `recordType`,
- `baseRecordVersion`,
- `previousRecordHash`,
- `newRecordHash`,
- `baseVaultHead`,
- `createdAtClient`,
- `payloadRef`,
- bei Device-Operationen auch Trust-Epoch und Zielgerät.

Nicht signierte Felder dürfen nicht sicherheitsrelevant sein.

---

# 7. Datenmodell

## 7.1 Vault Manifest

Das Vault Manifest beschreibt Root-Eigenschaften des Vaults.

```ts
type VaultManifestPlaintext = {
  vaultId: string;
  manifestVersion: number;
  createdAt: string;
  createdByDeviceId: string;
  currentKeyVersion: number;
  cryptoPolicy: {
    recordEncryption: 'record-aead-v1';
    kdfVersion: number;
    operationSignature: 'device-signature-v1';
  };
  features: {
    categories: boolean;
    attachments: boolean;
    sharing: boolean;
    passkeys: boolean;
  };
};
```

Das Manifest ist besonders sicherheitskritisch.

Wenn das Manifest nicht verifizierbar ist, ist der Vault nicht sicher interpretierbar.

Manifest-Probleme können `lockedCritical` auslösen.

## 7.2 Vault Record

```ts
type VaultRecordRow = {
  vault_id: string;
  record_id: string;
  record_type: string;
  record_version: number;
  key_version: number;
  encryption_schema: string;
  nonce: string;
  ciphertext: string;
  aad_hash: string;
  ciphertext_hash: string;
  last_op_id: string;
  author_device_id: string;
  deleted: boolean;
  server_created_at: string;
  server_updated_at: string;
};
```

Regeln:

- `record_id` ist stabil.
- `record_version` steigt pro Record monoton.
- `ciphertext_hash` ist aus Ciphertext, Nonce, AAD und relevanten Metadaten abgeleitet.
- `last_op_id` verweist auf die Operation, die diesen Zustand erzeugt hat.
- `deleted = true` darf nur durch gültige Tombstone-Operation entstehen.

## 7.3 Vault Operation

```ts
type VaultOperationRow = {
  op_id: string;
  vault_id: string;
  author_device_id: string;
  op_type: 'create' | 'update' | 'delete' | 'restore' | 'move' | 'rekey' | 'add_device' | 'revoke_device';
  record_id: string;
  record_type: string;
  base_record_version: number | null;
  previous_record_hash: string | null;
  new_record_hash: string | null;
  base_vault_head: string | null;
  payload_ciphertext_hash: string | null;
  payload_aad_hash: string | null;
  created_at_client: string;
  received_at_server: string;
  trust_epoch: number;
  op_hash: string;
  signature: string;
};
```

Regeln:

- `op_id` ist global eindeutig.
- Operationen sind idempotent.
- dieselbe `op_id` darf mehrfach eingereicht werden, muss aber zum exakt selben Inhalt führen.
- unterschiedliche Inhalte mit gleicher `op_id` sind ein Fehler und werden verworfen.
- `base_record_version` und `previous_record_hash` sind bei Updates, Deletes und Restores Pflicht.
- bei Create muss `base_record_version = null` und `previous_record_hash = null` sein.
- bei Delete ist `new_record_hash` der Hash des Tombstone-Records oder null, je nach Implementierung; empfohlen ist ein echter Tombstone-Record mit Hash.

## 7.4 Trusted Device Record

```ts
type TrustedDeviceRecord = {
  vaultId: string;
  deviceId: string;
  publicSigningKey: string;
  deviceNameEncrypted: string;
  addedByDeviceId: string | null;
  addedAt: string;
  trustEpoch: number;
  status: 'trusted' | 'revoked';
  revokedAt: string | null;
  revokedByDeviceId: string | null;
};
```

Gerätevertrauen ist selbst Teil des verifizierten Vault-Zustands.

Geräteoperationen müssen besonders streng geprüft werden.

## 7.5 Lokaler Client State

Lokal speichert der Client:

```ts
type LocalVaultState = {
  vaultId: string;
  userId: string;
  verifiedRecordsById: Record<string, LocalVerifiedRecord>;
  quarantinedRecordsById: Record<string, LocalQuarantinedRecord>;
  conflictsByRecordId: Record<string, LocalRecordConflict>;
  trustedDevicesById: Record<string, TrustedDeviceRecord>;
  lastVerifiedVaultHead: string | null;
  lastSyncedServerRevision: number | null;
  pendingOperations: VaultOperationRow[];
  trustedSnapshots: TrustedSnapshot[];
};
```

Lokaler State ist Cache und Arbeitszustand, aber nicht alleiniger globaler Vertrauensanker.

---

# 8. Operationstypen

## 8.1 Create Record

Create erzeugt einen neuen Record.

Bedingungen:

- `recordId` existiert lokal noch nicht als aktiver Record.
- `baseRecordVersion = null`.
- `previousRecordHash = null`.
- Operation ist von vertrauenswürdigem Gerät signiert.
- Ciphertext ist entschlüsselbar.
- Plaintext-Schema ist gültig.

Ergebnis:

- Record wird `verified`.
- Operation wird ins lokale Operation-Log übernommen.

## 8.2 Update Record

Update verändert einen bestehenden Record.

Bedingungen:

- `baseRecordVersion` entspricht der bekannten Version oder erzeugt einen Konflikt.
- `previousRecordHash` entspricht dem bekannten Record-Hash oder erzeugt einen Konflikt/Verdacht.
- Operation ist gültig signiert.
- neuer Ciphertext ist entschlüsselbar.
- neues Plaintext-Schema ist gültig.

Ergebnis:

- bei sauberer Kette: Record wird aktualisiert.
- bei konkurrierender gültiger Kette: Conflict.
- bei ungültiger Signatur: Quarantäne.

## 8.3 Delete Record

Delete löscht einen Record logisch.

Delete ist niemals bloßes Entfernen einer Zeile.

Bedingungen:

- Operation ist gültig signiert.
- `previousRecordHash` passt.
- `baseRecordVersion` passt oder erzeugt Konflikt.

Ergebnis:

- Record wird als `deletedByTrustedDevice` markiert.
- Tombstone bleibt lokal und serverseitig erhalten.
- UI kann Papierkorb oder Undo anbieten.

## 8.4 Restore Record

Restore erzeugt aus einem Snapshot oder Tombstone einen neuen aktuellen Record.

Bedingungen:

- Restore-Operation ist gültig signiert.
- wiederherzustellender Record stammt aus einem lokal verifizierten Snapshot oder einer gültigen älteren Version.
- neuer Record-Ciphertext ist entschlüsselbar.
- Schema ist gültig.

Ergebnis:

- Record wird neue aktive Version.
- andere Clients akzeptieren Restore, weil es eine normale signierte Operation ist.

## 8.5 Move Record

Move ist nur erforderlich, wenn Kategorien oder Container-Zuordnung separat modelliert werden.

Empfehlung:

- Kategorie-ID liegt im verschlüsselten Item-Plaintext.
- Ein Verschieben eines Items ist dann ein normales Item-Update.

Separate Move-Operationen sind nur nötig, wenn man Container-Zuordnung außerhalb des Item-Plaintexts speichern will. Das sollte vermieden werden, weil es die Sicherheitslogik verkompliziert.

## 8.6 Rekey

Rekey ändert Schlüsselversionen.

Rekey ist root-sicherheitskritisch.

Regeln:

- Rekey darf nicht wie normale Item-Updates behandelt werden.
- Rekey muss eigene Operationen haben.
- Rekey muss atomar oder transaktional wiederaufnehmbar sein.
- Clients, die Rekey nicht verstehen, müssen sicher stoppen.

Für den ersten Neuaufbau sollte Rekey möglichst minimal gehalten werden.

## 8.7 Add Device

Add Device fügt ein neues vertrauenswürdiges Gerät hinzu.

Regeln:

- Ein neues Gerät ist nicht automatisch vertrauenswürdig, nur weil der Nutzer sich einloggen kann.
- Ein bestehendes vertrauenswürdiges Gerät sollte das neue Gerät bestätigen.
- Die Add-Device-Operation wird signiert.
- Der öffentliche Signaturschlüssel des neuen Geräts wird Teil der Trust-Struktur.

## 8.8 Revoke Device

Revoke Device widerruft ein Gerät.

Regeln:

- neue Operationen dieses Geräts nach dem Widerruf werden nicht akzeptiert.
- alte Operationen vor dem Widerruf bleiben historisch gültig, sofern sie damals gültig waren.
- der Widerruf erhöht die Trust-Epoch.

---

# 9. Verifikationspipeline

Jede Remote-Operation und jeder Remote-Record durchlaufen eine feste Pipeline.

## 9.1 Operation prüfen

```text
1. Operation kanonisieren.
2. opHash berechnen.
3. authorDeviceId im lokalen Trust finden.
4. Prüfen, ob Gerät zum Operationszeitpunkt trusted war.
5. Signatur prüfen.
6. Operationstyp gegen Record-Typ prüfen.
7. baseRecordVersion und previousRecordHash prüfen.
8. payload hashes prüfen.
9. Ergebnis klassifizieren.
```

## 9.2 Record prüfen

```text
1. Record-Metadaten lesen.
2. AAD aus Metadaten deterministisch bauen.
3. aadHash prüfen.
4. ciphertextHash prüfen.
5. Prüfen, ob lastOpId zur Operation passt.
6. Erst jetzt AEAD-Decrypt versuchen.
7. Plaintext-Schema prüfen.
8. Semantische Validierung durchführen.
9. Record-State setzen.
```

## 9.3 Wichtigste Regel

Ein Record wird erst entschlüsselt, nachdem seine Herkunft und Kontextbindung geprüft wurden.

Falls Operation oder Kontext ungültig sind:

```text
Nicht entschlüsseln.
Record in Quarantäne.
```

---

# 10. Record Security States

Jeder Record hat lokal genau einen Sicherheitszustand.

```ts
type RecordSecurityState =
  | 'verified'
  | 'pendingVerification'
  | 'conflict'
  | 'quarantinedTampered'
  | 'quarantinedUnknownAuthor'
  | 'quarantinedMissingWithoutDelete'
  | 'quarantinedUnreadable'
  | 'quarantinedInvalidSchema'
  | 'containerQuarantined'
  | 'deletedByTrustedDevice'
  | 'restoredFromSnapshot';
```

## 10.1 verified

Der Record ist vollständig geprüft:

- Operation gültig,
- Autorgerät trusted,
- Version konsistent,
- Hashes korrekt,
- AEAD-Decrypt erfolgreich,
- Schema gültig.

Nur `verified` Records dürfen normal verwendet werden.

## 10.2 pendingVerification

Der Record wurde geladen, aber noch nicht vollständig geprüft.

Regel:

- Nicht anzeigen.
- Nicht entschlüsseln.
- Nicht autofillen.

Dieser Zustand sollte kurzlebig sein.

## 10.3 conflict

Es gibt mindestens zwei gültige, aber konkurrierende Versionen.

Regel:

- Beide Versionen stammen aus gültigen Operationen.
- Beide dürfen entschlüsselt werden, wenn sie jeweils verifiziert sind.
- Nicht automatisch überschreiben.
- Nutzer muss auflösen oder eine definierte Merge-Regel greift.

## 10.4 quarantinedTampered

Der Record wurde wahrscheinlich manipuliert.

Beispiele:

- CiphertextHash passt nicht.
- AAD passt nicht.
- Record verweist auf falsche Operation.
- previousRecordHash ist unmöglich.

Regel:

- Nicht entschlüsseln.
- Recovery anbieten.

## 10.5 quarantinedUnknownAuthor

Die Operation stammt von einem unbekannten oder nicht vertrauenswürdigen Gerät.

Regel:

- Nicht entschlüsseln.
- Nicht integrieren.
- Nutzer kann Gerät prüfen, Record löschen oder Safe Mode nutzen.

## 10.6 quarantinedMissingWithoutDelete

Ein lokal bekannter Record fehlt remote, aber es gibt keine gültige Delete-Operation.

Regel:

- lokale geprüfte Kopie behalten.
- nicht als legitime Löschung akzeptieren.
- Restore aus lokalem Snapshot oder lokalem State anbieten.

## 10.7 quarantinedUnreadable

Operation und Kontext können gültig sein, aber Entschlüsselung schlägt fehl.

Mögliche Ursachen:

- korrupter Ciphertext,
- falsche Key-Version,
- lokaler Key beschädigt,
- Implementierungsfehler,
- fehlerhafte Migration.

Regel:

- nicht anzeigen,
- Recovery anbieten,
- falls viele Records betroffen sind: Safe Mode oder Key-Diagnose.

## 10.8 quarantinedInvalidSchema

Entschlüsselung erfolgreich, aber Plaintext entspricht nicht dem erwarteten Schema.

Regel:

- nicht normal anzeigen,
- keine Autofill-Freigabe,
- Diagnose und Recovery anbieten.

## 10.9 containerQuarantined

Der Record selbst kann gültig sein, aber sein Container ist beschädigt.

Beispiel:

- Item ist gültig.
- referenzierte Kategorie ist manipuliert oder fehlt ohne gültige Delete-Operation.

Regel:

- Item-Plaintext darf nur nach eigener Prüfung verwendet werden.
- UI zeigt es in „Kategorie ungeprüft“ oder „Container beschädigt“.
- Autofill kann erlaubt bleiben, wenn Item selbst `verified` ist und keine sicherheitskritische Container-Abhängigkeit besteht.

## 10.10 deletedByTrustedDevice

Der Record wurde durch gültige Delete-Operation gelöscht.

Regel:

- nicht in normaler Vault-Liste anzeigen,
- optional Papierkorb/Undo,
- Tombstone behalten.

## 10.11 restoredFromSnapshot

Der Record wurde aus einem lokalen Snapshot wiederhergestellt und als neue signierte Operation synchronisiert.

Regel:

- nach erfolgreicher Verifikation wird er wie `verified` behandelt,
- UI kann Wiederherstellung protokollieren.

---

# 11. Vault Security Modes

Der Vault selbst hat einen separaten Modus.

```ts
type VaultSecurityMode =
  | 'normal'
  | 'restricted'
  | 'safeMode'
  | 'lockedCritical';
```

## 11.1 normal

Alle geladenen aktiven Records sind geprüft oder sauber als gelöscht markiert.

Es gibt keine aktive Quarantäne und keine ungelösten Konflikte.

## 11.2 restricted

Der Vault ist grundsätzlich nutzbar, aber einzelne Records, Kategorien oder Container sind isoliert.

Typische Ursachen:

- einzelnes manipuliertes Item,
- einzelne manipulierte Kategorie,
- fehlender Record ohne Delete,
- unbekannter Autor,
- einzelner Konflikt.

Regel:

- gesunde Items bleiben nutzbar,
- quarantänisierte Items bleiben gesperrt,
- UI zeigt klaren Sicherheitsstatus.

## 11.3 safeMode

Der aktuelle Remote-Zustand ist nicht ausreichend vertrauenswürdig oder zu inkonsistent.

Der Client arbeitet mit einem lokalen Trusted Snapshot.

Regeln:

- keine automatische Remote-Reparatur,
- keine automatische Rebaseline,
- Recovery-Aktionen erzeugen signierte Restore-Operationen,
- Nutzer wird klar informiert.

Safe Mode ist sinnvoll bei:

- vielen fehlenden Records ohne Delete,
- vielen manipulierten Records,
- serverseitigem Rollback-Verdacht,
- Operation-Log-Lücken,
- widersprüchlichen Serverdaten.

## 11.4 lockedCritical

Der Vault wird wirklich blockiert.

Nur diese Fälle dürfen `lockedCritical` auslösen:

1. Vault Manifest nicht verifizierbar.
2. Vault-Key kann nicht entschlüsselt werden.
3. Device-Trust-Struktur ist beschädigt oder widersprüchlich.
4. Rekey-Zustand ist unverständlich oder unsicher.
5. Client versteht die benötigte Sicherheits-/Schema-Version nicht.
6. Lokaler Zustand ist so beschädigt, dass keine sichere Trennung zwischen validen und invaliden Records möglich ist.

Nicht erlaubt als `lockedCritical`-Auslöser:

- einzelne Kategorie kaputt,
- einzelnes Item kaputt,
- einzelnes Item fehlt remote,
- Konflikt zwischen zwei gültigen Geräten,
- unbekannter neuer Record,
- kaputtes Attachment.

---

# 12. Kategorien im neuen Modell

## 12.1 Grundsatz

Kategorien sind normale verschlüsselte Records.

Eine Kategorie ist kein Grund, den gesamten Vault zu sperren.

## 12.2 Kategorie-Plaintext

```ts
type CategoryPlaintext = {
  categoryId: string;
  name: string;
  icon: string | null;
  color: string | null;
  parentCategoryId: string | null;
  sortOrder: number;
  createdAt: string;
  updatedAt: string;
};
```

## 12.3 Item-Plaintext mit Kategoriebezug

```ts
type VaultItemPlaintext = {
  itemId: string;
  title: string;
  username: string | null;
  password: string | null;
  uris: string[];
  notes: string | null;
  categoryId: string | null;
  createdAt: string;
  updatedAt: string;
};
```

Die Kategoriezuordnung liegt im verschlüsselten Item-Plaintext.

Dadurch kann der Server nicht unbemerkt Items anderen Kategorien zuordnen.

## 12.4 Kategorie manipuliert

Wenn eine Kategorie manipuliert ist:

```text
Kategorie -> quarantinedTampered oder quarantinedUnreadable
Items mit categoryId dieser Kategorie -> containerQuarantined
```

Wichtig:

- Items werden nicht automatisch selbst als manipuliert markiert.
- Jedes Item wird separat verifiziert.
- Ein gültiges Item bleibt kryptografisch gültig.
- Die UI darf aber nicht so tun, als sei die Kategorie normal.

## 12.5 UI-Verhalten bei Kategoriequarantäne

Anzeige:

```text
Quarantäne
└── Kategorie beschädigt: ehemals „Arbeit“ oder unbekannte Kategorie-ID
    ├── Item A: Inhalt gültig, Kategoriezuordnung ungeprüft
    ├── Item B: Inhalt gültig, Kategoriezuordnung ungeprüft
    └── Item C: Item selbst manipuliert, gesperrt
```

Regeln:

- Item A und B dürfen nur angezeigt werden, wenn sie selbst `verified` sind.
- Item C darf nicht entschlüsselt oder angezeigt werden.
- Die beschädigte Kategorie kann aus Snapshot wiederhergestellt werden.
- Alternativ kann der Nutzer Items in eine andere verifizierte Kategorie verschieben.

## 12.6 Kategorie fehlt ohne Delete

Wenn eine Kategorie remote fehlt, aber keine gültige Delete-Operation existiert:

- Kategorie erhält `quarantinedMissingWithoutDelete`.
- lokale Snapshot-Kopie bleibt verfügbar.
- Items werden `containerQuarantined`, falls sie diese Kategorie referenzieren.
- Restore-Kategorie wird angeboten.

## 12.7 Legitimes Kategorie-Löschen

Wenn eine Kategorie durch gültige Delete-Operation gelöscht wurde:

- Kategorie wird `deletedByTrustedDevice`.
- Items, die diese Kategorie noch referenzieren, müssen behandelt werden.

Empfohlene Regel:

- Delete Category darf nicht still Items löschen.
- Delete Category erzeugt entweder:
  - Kategorie-Tombstone und separate Item-Updates auf `categoryId = null`, oder
  - Kategorie-Tombstone und UI zeigt Items unter „Ohne Kategorie“.

Verbindliche Entscheidung für Singra Vault:

> Das Löschen einer Kategorie löscht niemals automatisch Items. Items wechseln nach gültiger Kategorie-Löschung in „Ohne Kategorie“, sofern die Item-Records selbst gültig bleiben.

---

# 13. Sync-Protokoll

## 13.1 Grundablauf beim Start/Unlock

```text
1. Nutzer entsperrt Vault-Key.
2. Lokaler Trust-State wird geladen.
3. Lokaler letzter verifizierter Zustand wird geladen.
4. Pending lokale Operationen werden geprüft.
5. Server wird nach Operationen seit lastVerifiedVaultHead / lastServerRevision gefragt.
6. Operationen werden geladen.
7. Jede Operation wird verifiziert.
8. Zugehörige Records werden verifiziert.
9. Lokaler Zustand wird aktualisiert.
10. UI erhält nur verified/conflict/quarantine States, niemals rohe Remote-Daten.
```

## 13.2 Push lokaler Änderungen

Wenn der Nutzer lokal ein Item ändert:

```text
1. aktuellen verified Record laden.
2. neuen Plaintext bauen.
3. Plaintext validieren.
4. Record-AAD bauen.
5. Record verschlüsseln.
6. ciphertextHash berechnen.
7. Operation mit baseRecordVersion und previousRecordHash bauen.
8. Operation signieren.
9. lokal in pendingOperations speichern.
10. lokalen Zustand optimistisch als verified aktualisieren, aber mit pendingSync-Flag.
11. Operation an Server senden.
12. Server speichert Operation und Record atomar.
13. Client markiert Operation als synced.
```

## 13.3 Pull remote Änderungen

Wenn ein Client Änderungen lädt:

```text
1. Operationen seit letztem bekannten Punkt laden.
2. nach Serverreihenfolge sortieren, aber nicht blind vertrauen.
3. jede Operation kryptografisch prüfen.
4. Record-Payload laden.
5. Record prüfen.
6. lokale Zustandsmaschine anwenden.
7. Konflikte oder Quarantänen erzeugen.
8. Snapshot optional aktualisieren, wenn Zustand stabil verified ist.
```

## 13.4 Idempotenz

Jede Operation ist idempotent.

Das bedeutet:

- Wiederholtes Senden derselben Operation erzeugt keinen zweiten Effekt.
- Retry ist sicher.
- Offline Queue kann nach App-Absturz erneut abgespielt werden.
- Server darf eine Operation mit gleicher `opId` nur akzeptieren, wenn Inhalt und Hash identisch sind.

## 13.5 Server-RPC

Alle Vault-Schreiboperationen gehen über eine einzige sichere Schnittstelle.

Beispiel:

```text
submit_vault_operation(operation, recordPayload)
```

Direkte Writes auf `vault_items`, `categories` oder ähnliche Tabellen sind verboten.

Serverseitige Checks:

- Nutzer hat Zugriff auf Vault.
- Operation gehört zu Vault.
- Record gehört zu Vault.
- `opId` ist neu oder exakt idempotent identisch.
- Größenlimits werden eingehalten.
- `baseRecordVersion` passt zum aktuellen Serverstand oder erzeugt serverseitig einen Konfliktstatus.
- `recordVersion` ist plausibel.
- `lastOpId` passt zu Operation.

Der Server prüft nicht den Plaintext. Er kann ihn nicht lesen.

---

# 14. Offline-First-Modell

## 14.1 Lokale Mutation Queue

Die lokale Queue speichert keine nackten Payloads mehr, sondern vollständige signierte Operationen mit Record-Payload.

```ts
type PendingLocalOperation = {
  op: VaultOperationRow;
  record: VaultRecordRow | null;
  createdAtLocal: string;
  retryCount: number;
  lastError: string | null;
  state: 'pending' | 'syncing' | 'synced' | 'failed';
};
```

## 14.2 Kein TTL-Fenster mehr

Das bisherige `LOCAL_WRITE_CACHE_TTL_MS`-Prinzip wird abgeschafft.

Warum:

- Zeitfenster sind Race-Condition-Heuristiken.
- Multi-Client-Sync braucht kausale Versionen und Operationen.
- Ein legitimer lokaler Write bleibt auch nach 10 Minuten legitim.
- Ein illegitimer Remote-Write wird nicht nach 60 Sekunden legitim.

Stattdessen:

- `opId`,
- `baseRecordVersion`,
- `previousRecordHash`,
- Signatur,
- idempotenter Server-Commit.

## 14.3 Offline Update

Wenn offline:

```text
1. Operation lokal erzeugen und signieren.
2. lokalen State aktualisieren.
3. Operation in Queue speichern.
4. UI zeigt Änderung als lokal pending.
5. Bei Online-Verfügbarkeit wird Operation gesendet.
```

## 14.4 Remote-Konflikt nach Offline-Zeit

Wenn ein anderer Client denselben Record geändert hat:

```text
1. lokale Operation basiert auf Version N.
2. Server hat inzwischen Version N+1 von anderem trusted Device.
3. lokale Operation wird nicht still überschrieben.
4. Client erzeugt Conflict.
5. Nutzer löst Conflict.
6. Auflösung erzeugt neue Operation N+2.
```

---

# 15. Konfliktmodell

## 15.1 Konfliktdefinition

Ein Konflikt liegt vor, wenn zwei oder mehr gültige Operationen vertrauenswürdiger Geräte denselben Record verändern, aber auf derselben oder inkompatibler Basisversion beruhen.

Konflikt ist kein Sicherheitsvorfall.

## 15.2 Konfliktzustand

```ts
type LocalRecordConflict = {
  recordId: string;
  recordType: string;
  baseRecordHash: string | null;
  variants: Array<{
    opId: string;
    authorDeviceId: string;
    createdAtClient: string;
    recordVersion: number;
    ciphertextHash: string;
    decryptState: 'verified' | 'unreadable';
    plaintextPreviewAllowed: boolean;
  }>;
};
```

## 15.3 Konfliktlösung

Der Nutzer kann:

- Version A behalten,
- Version B behalten,
- duplizieren,
- manuell zusammenführen,
- lokale Version wiederherstellen,
- Remote-Version akzeptieren.

Jede Lösung erzeugt eine neue signierte Operation.

## 15.4 Keine automatische Last-Write-Wins-Regel für Passwörter

Für Passwort-Items ist Last-Write-Wins gefährlich.

Begründung:

- Ein älteres Passwort kann ein neueres überschreiben.
- Ein gelöschtes Login kann zurückkehren.
- Benutzer verliert Kontrolle über kritische Zugangsdaten.

Verbindliche Regel:

> Bei konkurrierenden Änderungen desselben Passwort-Items gibt es keine stille Last-Write-Wins-Auflösung.

Ausnahme:

- rein kosmetische, nicht sicherheitsrelevante Felder könnten später automatisiert gemerged werden.
- Für die erste Version wird kein automatischer semantischer Merge implementiert.

---

# 16. Quarantänemodell

## 16.1 Quarantäne-Gründe

```ts
type QuarantineReason =
  | 'missing_valid_operation'
  | 'unknown_author_device'
  | 'revoked_author_device'
  | 'invalid_signature'
  | 'record_hash_mismatch'
  | 'aad_hash_mismatch'
  | 'ciphertext_hash_mismatch'
  | 'unexpected_record_version'
  | 'missing_without_delete'
  | 'aead_decryption_failed'
  | 'plaintext_schema_invalid'
  | 'container_category_invalid'
  | 'rollback_suspected'
  | 'operation_log_gap'
  | 'unsupported_schema_version';
```

## 16.2 Quarantäne-Aktionen

Nicht jede Quarantäne erlaubt dieselben Aktionen.

| Grund | Wiederherstellen | Löschen | Akzeptieren | Gerät vertrauen | Safe Mode |
|---|---:|---:|---:|---:|---:|
| `missing_valid_operation` | Ja | Ja | Nein | Nein | Optional |
| `unknown_author_device` | Nein | Ja | Nein | Optional nach Prüfung | Optional |
| `invalid_signature` | Ja | Ja | Nein | Nein | Optional |
| `ciphertext_hash_mismatch` | Ja | Ja | Nein | Nein | Optional |
| `missing_without_delete` | Ja | Nein | Nur nach expliziter Nutzerentscheidung | Nein | Optional |
| `aead_decryption_failed` | Ja | Ja | Nein | Nein | Optional |
| `plaintext_schema_invalid` | Ja | Ja | Nein | Nein | Optional |
| `container_category_invalid` | Kategorie wiederherstellen oder Item verschieben | Optional | Nein | Nein | Optional |
| `rollback_suspected` | Ja | Nein | Nein | Nein | Ja |

## 16.3 Akzeptieren ist streng begrenzt

„Akzeptieren“ darf nicht bedeuten:

> „Setze einfach die Baseline neu.“

Akzeptieren darf nur in genau definierten Fällen verwendet werden.

Beispiel:

- Der Nutzer bestätigt eine Löschung, obwohl die Delete-Operation fehlt.
- Dann muss eine neue signierte lokale Operation erzeugt werden, die diesen Zustand erklärt.

Also:

```text
Akzeptieren -> neue signierte Operation
nicht: lokale Baseline still ändern
```

## 16.4 Löschen quarantänisierter Remote-Records

Wenn ein unbekannter oder manipulierter Remote-Record existiert, kann der Nutzer ihn löschen.

Das Löschen erfolgt als signierte Delete-Operation des aktuellen Geräts.

Dadurch wissen andere Clients:

- dieser unbekannte Record wurde bewusst entfernt,
- die Entfernung stammt von einem trusted Device.

## 16.5 Wiederherstellen aus Snapshot

Wiederherstellen erzeugt immer eine Restore-Operation.

Ablauf:

```text
1. Snapshot-Record finden.
2. Snapshot-Signatur prüfen.
3. Snapshot-Record-Hash prüfen.
4. Optional entschlüsseln und Schema validieren.
5. neuen Record mit aktueller Version erzeugen.
6. Restore-Operation bauen.
7. Restore-Operation signieren.
8. lokal anwenden.
9. an Server senden.
```

---

# 17. Safe Mode

## 17.1 Zweck

Safe Mode schützt den Nutzer, wenn der aktuelle Remote-Zustand großflächig verdächtig oder inkonsistent ist.

Safe Mode bedeutet:

- arbeite aus lokalem Trusted Snapshot,
- blockiere ungeprüfte Remote-Daten,
- ermögliche Recovery,
- vermeide automatische Reparaturen.

## 17.2 Auslöser

Safe Mode kann vorgeschlagen oder automatisch aktiviert werden bei:

- ungewöhnlich vielen Records mit `missing_without_delete`,
- vielen Hash-Mismatches,
- Operation-Log-Lücken,
- Rollback-Verdacht auf Vault-Head,
- Server liefert älteren Zustand als lokal bekannt,
- mehrere Kategorien/Container gleichzeitig beschädigt,
- Remote-Daten widersprechen lokal signiertem Snapshot stark.

## 17.3 Safe Mode UI

Der Nutzer sieht:

```text
Sicherheitsmodus aktiv
Der aktuelle Serverzustand ist nicht vollständig vertrauenswürdig.
Singra Vault verwendet den letzten lokal geprüften Snapshot.

Optionen:
- Lokale Daten ansehen
- Einzelne Einträge wiederherstellen
- Diagnose anzeigen
- Remote-Zustand erneut prüfen
- Support-/Exportpaket ohne Klartext erstellen
```

## 17.4 Safe Mode darf nicht

Safe Mode darf nicht:

- automatisch Remote überschreiben,
- automatisch Baselines neu setzen,
- ungeprüfte Remote-Items entschlüsseln,
- Quarantäne umgehen,
- Konflikte still lösen.

---

# 18. Trusted Snapshots

## 18.1 Zweck

Trusted Snapshots sind lokale, verschlüsselte und signierte Wiederherstellungspunkte.

Sie ermöglichen Recovery, wenn:

- Serverdaten manipuliert wurden,
- Records fehlen,
- Remote-Ciphertexte kaputt sind,
- Kategorien beschädigt sind,
- der Nutzer zu einem früher geprüften Zustand zurückkehren möchte.

## 18.2 Snapshot-Struktur

```ts
type TrustedSnapshot = {
  snapshotId: string;
  vaultId: string;
  createdAt: string;
  createdByDeviceId: string;
  verifiedVaultHead: string | null;
  trustEpoch: number;
  records: Array<{
    recordId: string;
    recordType: string;
    recordVersion: number;
    ciphertext: string;
    nonce: string;
    aadHash: string;
    ciphertextHash: string;
    lastVerifiedOpId: string;
    deleted: boolean;
  }>;
  trustedDevicesHash: string;
  manifestHash: string;
  snapshotHash: string;
  signature: string;
};
```

## 18.3 Snapshot-Erstellung

Ein Snapshot darf nur erstellt werden, wenn:

- Vault-Key verfügbar ist,
- Manifest verifiziert ist,
- Device-Trust verifiziert ist,
- Records entweder `verified`, `deletedByTrustedDevice` oder bewusst ausgeschlossen sind,
- keine ungeklärte Root-Inkonsistenz besteht.

## 18.4 Snapshot-Frequenz

Empfehlung:

- Snapshot nach erfolgreichem Unlock und Sync, wenn Zustand normal ist.
- Snapshot nach größeren verifizierten Änderungen.
- Snapshot vor Rekey/Migration.
- Snapshot nach erfolgreicher Konfliktlösung.

Nicht bei jedem kleinen UI-Refresh.

## 18.5 Snapshot-Retention

Mindestens:

- letzter geprüfter Snapshot,
- letzter Snapshot vor Migration,
- letzter Snapshot vor Rekey,
- einige zeitliche Versionen.

Beispiel:

```text
- latest
- daily: 7 Tage
- weekly: 4 Wochen
- pre-migration
- pre-rekey
```

## 18.6 Snapshot-Sicherheit

Snapshots werden:

- lokal verschlüsselt,
- signiert,
- an VaultId und DeviceId gebunden,
- nie unverschlüsselt gespeichert,
- nicht automatisch an Server übertragen, außer es gibt später ein explizites verschlüsseltes Backup-Feature.

---

# 19. Gerätevertrauen

## 19.1 Login ist nicht gleich Gerätevertrauen

Ein Nutzer kann sich bei Supabase/Auth anmelden. Das bedeutet nur:

- der Server darf diesem Account Daten liefern.

Es bedeutet nicht:

- dieses Gerät darf Vault-Operationen erzeugen,
- dieses Gerät ist kryptografisch trusted.

## 19.2 Erstes Gerät

Beim Erstellen eines Vaults:

```text
1. Master-Passwort/KDF einrichten.
2. Vault Encryption Key erzeugen.
3. Device Signing Key erzeugen.
4. Vault Manifest erzeugen.
5. erstes Trusted Device eintragen.
6. Manifest und Device-Trust initial signieren.
```

## 19.3 Neues Gerät hinzufügen

Empfohlenes Standardmodell:

```text
1. Neues Gerät loggt sich ein.
2. Neues Gerät erzeugt Device Signing Key.
3. Neues Gerät zeigt Pairing-Code oder QR-Code.
4. Bereits vertrauenswürdiges Gerät scannt/bestätigt.
5. Bereits vertrauenswürdiges Gerät signiert Add-Device-Operation.
6. Neues Gerät wird trusted.
```

## 19.4 Fallback: Master-Passwort-basierte Geräteaufnahme

Falls kein altes Gerät verfügbar ist:

- Nutzer entsperrt mit Master-Passwort.
- Zusätzlich kann 2FA/Account-Schutz erforderlich sein.
- Das neue Gerät wird als „unbestätigt neu“ markiert.
- Andere Geräte zeigen beim nächsten Sync eine Warnung.

Diese Variante ist nutzbarer, aber schwächer.

Verbindliche UX:

> Neues Gerät ohne Bestätigung durch bestehendes Gerät muss deutlich sichtbar sein.

## 19.5 Gerät widerrufen

Widerruf erzeugt eine Revoke-Device-Operation.

Nach Widerruf:

- neue Operationen dieses Geräts werden abgelehnt,
- alte gültige Operationen bleiben historisch gültig,
- Trust-Epoch steigt,
- optional wird Rekey empfohlen.

## 19.6 Kompromittiertes Gerät

Wenn ein vertrauenswürdiges Gerät kompromittiert wurde:

- Gerät widerrufen,
- alle letzten Operationen dieses Geräts auditieren,
- verdächtige Änderungen aus Snapshot wiederherstellen,
- optional Vault-Key rotieren.

---

# 20. Servermodell

## 20.1 Serveraufgaben

Der Server darf:

- Operationen speichern,
- Records speichern,
- Zugriff auf Vault nach Account-Rechten begrenzen,
- Operationen atomar anwenden,
- serverseitige Revisionen für effizientes Sync führen,
- Größenlimits und Rate Limits erzwingen,
- idempotente Retries unterstützen.

## 20.2 Server darf nicht

Der Server darf nicht:

- Klartext sehen,
- Vault-Key kennen,
- Operationen ohne Signatur erzeugen,
- direkte Vault-Record-Änderungen außerhalb der Operation-Schicht zulassen,
- Löschungen ohne Tombstone als legitim darstellen,
- Clients dazu bringen, Daten ohne lokale Prüfung zu akzeptieren.

## 20.3 Tabellen

Empfohlene Tabellen:

```text
vaults
vault_records
vault_operations
vault_device_trust_records
vault_server_revisions
```

Optional:

```text
vault_conflict_heads
vault_audit_events
```

## 20.4 Direkte Tabellenzugriffe verbieten

Client-Code darf nicht mehr direkt schreiben in:

- `vault_items`,
- `categories`,
- vergleichbare alte Tabellen.

Stattdessen ausschließlich:

```text
submit_vault_operation
```

Lesen darf ebenfalls bevorzugt über definierte Sync-Endpunkte erfolgen:

```text
get_vault_changes_since
get_vault_records_by_ids
get_vault_head
```

---

# 21. Client-Architektur

## 21.1 Services

Empfohlene neue Services:

```text
cryptoRecordService
operationSigningService
deviceTrustService
vaultSyncService
vaultStateMachine
quarantineService
trustedSnapshotService
conflictResolutionService
safeModeService
migrationService
```

## 21.2 cryptoRecordService

Verantwortung:

- Record-AAD bauen,
- Record verschlüsseln,
- Record vor Entschlüsselung prüfen,
- Record entschlüsseln,
- Plaintext-Schema validieren,
- Hashes berechnen.

## 21.3 operationSigningService

Verantwortung:

- Operation kanonisieren,
- Operation signieren,
- Signatur prüfen,
- opHash berechnen.

## 21.4 deviceTrustService

Verantwortung:

- Trusted Devices verwalten,
- Add/Revoke Device prüfen,
- Trust-Epoch prüfen,
- Autor-Geräte klassifizieren.

## 21.5 vaultSyncService

Verantwortung:

- Remote-Operationen laden,
- lokale Operationen pushen,
- idempotente Retries,
- Serverantworten einordnen,
- keine Sicherheitsentscheidung ohne State Machine treffen.

## 21.6 vaultStateMachine

Verantwortung:

- Operationen anwenden,
- Record-Zustände setzen,
- Konflikte erkennen,
- Quarantäne auslösen,
- VaultSecurityMode bestimmen.

## 21.7 quarantineService

Verantwortung:

- Quarantänegründe verwalten,
- erlaubte Aktionen berechnen,
- Wiederherstellung/Löschung/Akzeptieren in signierte Operationen übersetzen.

## 21.8 trustedSnapshotService

Verantwortung:

- Snapshots erstellen,
- Snapshots prüfen,
- Snapshot-Records indexieren,
- Restore-Payloads erzeugen.

---

# 22. UI-Regeln

## 22.1 Normale Vault-Liste

Die normale Vault-Liste zeigt nur:

- `verified`,
- optional `containerQuarantined` mit Warnung,
- keine `quarantined*` Records,
- keine `pendingVerification` Records.

## 22.2 Quarantäne-Bereich

Der Quarantäne-Bereich zeigt Metadaten, soweit sicher.

Falls Metadaten selbst nicht vertrauenswürdig sind, zeigt er technische Platzhalter:

```text
Unbekannter Eintrag
Record-ID: abc...
Grund: ungültige Signatur
Aktion: Löschen / Wiederherstellen / Diagnose
```

Keine Plaintext-Vorschau bei nicht verifiziertem Record.

## 22.3 Autofill

Autofill darf nur Records verwenden mit:

```text
RecordSecurityState = verified
VaultSecurityMode != lockedCritical
Item-URI-Prüfung erfolgreich
kein aktiver Item-Konflikt
kein Item-Quarantänegrund
```

Bei `containerQuarantined` ist Autofill nur erlaubt, wenn:

- das Item selbst verified ist,
- die Kategorie nicht sicherheitsrelevant für Berechtigungen ist,
- URI-Prüfung erfolgreich ist.

Für die erste Version wird empfohlen:

> Autofill nur für vollständig `verified` Items ohne Containerwarnung.

Das ist konservativer.

## 22.4 Export

Export darf nur enthalten:

- verified Records,
- optional explizit vom Nutzer ausgewählte Konfliktversionen.

Export darf nicht enthalten:

- quarantänisierte Records,
- unreadable Records,
- unknown-author Records,
- pendingVerification Records.

## 22.5 Suche

Suchindex darf nur aus entschlüsselten, verifizierten Plaintexts aufgebaut werden.

Wenn ein Record Quarantäne erreicht:

- Suchindex-Eintrag entfernen.

## 22.6 Clipboard

Clipboard-Aktionen nur für verified Items.

Wenn ein Item während einer UI-Sitzung in Quarantäne fällt:

- bestehende Klartext-State-Objekte sofort invalidieren,
- Clipboard-Buttons deaktivieren,
- Detailansicht schließen oder Sicherheitswarnung anzeigen.

---

# 23. Migration vom alten System

## 23.1 Ziele der Migration

Die Migration muss:

- bestehende Items erhalten,
- bestehende Kategorien erhalten,
- lokale Snapshots sichern,
- neue Record-Struktur erzeugen,
- initiale Operationen erzeugen,
- erstes Gerät als Trusted Device anlegen,
- alte Baseline nicht mehr als Hauptvertrauensanker verwenden.

## 23.2 Migrationsphasen

### Phase 0: Sicherheitsfreeze

Vor Migration:

- keine parallelen Vault-Writes erlauben,
- Nutzer informiert sehen,
- lokaler Pre-Migration-Snapshot erstellen,
- Snapshot signieren und verschlüsseln.

### Phase 1: Daten lesen

Alte Daten werden mit altem Schlüsselmodell entschlüsselt.

Jeder entschlüsselte Eintrag wird schema-validiert.

Nicht entschlüsselbare alte Einträge werden nicht migriert, sondern als Legacy-Quarantäne markiert.

### Phase 2: Neue Records erzeugen

Für jedes alte Item:

- neue `recordId` übernehmen oder sauber mappen,
- neuen Item-Plaintext bauen,
- Kategorie-ID einbetten,
- mit neuem Record-AAD verschlüsseln,
- initiale Create-Operation signieren.

Für jede alte Kategorie:

- neuen Category-Record erzeugen,
- initiale Create-Operation signieren.

### Phase 3: Device Trust initialisieren

- aktuelles Gerät erzeugt Device Signing Key,
- Vault Manifest wird erstellt,
- aktuelles Gerät wird erstes Trusted Device,
- Manifest-Operation wird signiert.

### Phase 4: Server Commit

Alle initialen Operationen werden über neue RPC-Schicht geschrieben.

Keine direkten Tabellen-Upserts.

### Phase 5: Verifikation

Nach Commit:

- Client lädt neuen Zustand erneut,
- prüft Operationen,
- prüft Records,
- erstellt ersten neuen Trusted Snapshot.

## 23.3 Legacy-Fallback

Wenn Migration scheitert:

- alter lokaler Snapshot bleibt erhalten,
- keine teilweise Migration als normal anzeigen,
- Nutzer sieht Migrationsfehler,
- Retry möglich.

---

# 24. Verbindliche Entscheidungsregeln

## 24.1 Remote Record ohne Operation

```text
Fall:
Server liefert Record, aber keine gültige Operation.

Entscheidung:
Quarantäne: missing_valid_operation.
Nicht entschlüsseln.
Nicht integrieren.
```

## 24.2 Operation von unbekanntem Gerät

```text
Fall:
Operation signiert, aber authorDeviceId ist unbekannt.

Entscheidung:
Quarantäne: unknown_author_device.
Nicht entschlüsseln.
Geräteprüfung anbieten.
```

## 24.3 Operation von widerrufenem Gerät

```text
Fall:
Operation nach Revoke-Zeitpunkt eines Geräts.

Entscheidung:
Quarantäne: revoked_author_device.
Nicht entschlüsseln.
```

## 24.4 Gültige Operation, aber Decrypt schlägt fehl

```text
Fall:
Signatur und Operation gültig, aber AEAD-Decrypt schlägt fehl.

Entscheidung:
Quarantäne: aead_decryption_failed.
Nicht anzeigen.
Recovery anbieten.
```

## 24.5 Gültige Operation, aber Schema falsch

```text
Fall:
Decrypt erfolgreich, Plaintext-Schema ungültig.

Entscheidung:
Quarantäne: plaintext_schema_invalid.
Nicht normal anzeigen.
```

## 24.6 Kategorie kaputt

```text
Fall:
Kategorie-Record manipuliert oder unreadable.

Entscheidung:
Nur Kategorie quarantänisieren.
Items separat prüfen.
Items mit dieser categoryId als containerQuarantined anzeigen.
Vault nicht blockieren.
```

## 24.7 Item kaputt

```text
Fall:
Item-Record manipuliert oder unreadable.

Entscheidung:
Nur Item quarantänisieren.
Vault nicht blockieren.
Kategorie nicht automatisch blockieren.
```

## 24.8 Record fehlt remote

```text
Fall:
Lokal bekannter Record fehlt remote ohne Delete-Operation.

Entscheidung:
missing_without_delete.
Lokale Kopie behalten.
Restore anbieten.
Nicht automatisch akzeptieren.
```

## 24.9 Legitimer Delete

```text
Fall:
Gültige Delete-Operation vorhanden.

Entscheidung:
Als deletedByTrustedDevice behandeln.
Kein Quarantänefall.
```

## 24.10 Zwei gültige Updates

```text
Fall:
Zwei trusted Geräte ändern denselben Record konkurrierend.

Entscheidung:
Conflict.
Nicht Quarantäne.
Nutzer löst Konflikt.
```

## 24.11 Server-Rollback-Verdacht

```text
Fall:
Server liefert Zustand älter als lokal verifizierter Head oder unterschlägt bekannte Operationen.

Entscheidung:
Safe Mode vorschlagen oder aktivieren.
Keine automatische Rebaseline.
```

## 24.12 Manifest kaputt

```text
Fall:
Vault Manifest nicht verifizierbar.

Entscheidung:
lockedCritical.
Kein normaler Vault-Zugriff.
Nur Recovery/Diagnose.
```

---

# 25. Pseudocode: Apply Remote Operation

```ts
async function applyRemoteOperation(op: VaultOperationRow, record: VaultRecordRow | null): Promise<ApplyResult> {
  const canonical = canonicalizeOperationWithoutSignature(op);
  const computedOpHash = hash(canonical + op.signature);

  if (computedOpHash !== op.op_hash) {
    return quarantineOperation(op, 'operation_hash_mismatch');
  }

  const author = deviceTrustService.getTrustedDevice(op.author_device_id);

  if (!author) {
    return quarantineOperation(op, 'unknown_author_device');
  }

  if (deviceTrustService.isRevokedForOperation(author, op)) {
    return quarantineOperation(op, 'revoked_author_device');
  }

  const signatureOk = await operationSigningService.verify(op, author.publicSigningKey);

  if (!signatureOk) {
    return quarantineOperation(op, 'invalid_signature');
  }

  const localRecord = localState.getRecord(op.record_id);

  const chainResult = verifyRecordChain(op, localRecord);

  if (chainResult.type === 'conflict') {
    return createConflict(op, record, chainResult);
  }

  if (chainResult.type === 'invalid') {
    return quarantineOperation(op, chainResult.reason);
  }

  if (op.op_type === 'delete') {
    return applyTrustedDelete(op);
  }

  if (!record) {
    return quarantineOperation(op, 'missing_record_payload');
  }

  const recordContextOk = verifyRecordContext(op, record);

  if (!recordContextOk.ok) {
    return quarantineRecord(record, recordContextOk.reason);
  }

  const plaintextResult = await cryptoRecordService.openVerifiedRecord(record);

  if (!plaintextResult.ok) {
    return quarantineRecord(record, plaintextResult.reason);
  }

  return applyVerifiedRecord(op, record, plaintextResult.plaintext);
}
```

---

# 26. Pseudocode: Open Verified Record

```ts
async function openVerifiedRecord(record: VaultRecordRow): Promise<OpenRecordResult> {
  const aad = buildRecordAAD({
    vaultId: record.vault_id,
    recordId: record.record_id,
    recordType: record.record_type,
    recordVersion: record.record_version,
    keyVersion: record.key_version,
    encryptionSchema: record.encryption_schema,
  });

  if (hashCanonical(aad) !== record.aad_hash) {
    return { ok: false, reason: 'aad_hash_mismatch' };
  }

  const computedCiphertextHash = computeCiphertextHash(record, aad);

  if (computedCiphertextHash !== record.ciphertext_hash) {
    return { ok: false, reason: 'ciphertext_hash_mismatch' };
  }

  const key = deriveRecordKey(vaultEncryptionKey, record);

  const plaintext = await aeadDecrypt({
    key,
    nonce: record.nonce,
    ciphertext: record.ciphertext,
    aad,
  }).catch(() => null);

  if (!plaintext) {
    return { ok: false, reason: 'aead_decryption_failed' };
  }

  const schemaOk = validatePlaintextSchema(record.record_type, plaintext);

  if (!schemaOk) {
    return { ok: false, reason: 'plaintext_schema_invalid' };
  }

  return { ok: true, plaintext };
}
```

---

# 27. Pseudocode: Local Update

```ts
async function updateVaultItem(recordId: string, patch: ItemPatch): Promise<void> {
  const current = localState.requireVerifiedRecord(recordId);

  const currentPlaintext = await cryptoRecordService.openVerifiedRecord(current.record);

  if (!currentPlaintext.ok) {
    throw new Error('Cannot update unverified record');
  }

  const nextPlaintext = applyItemPatch(currentPlaintext.plaintext, patch);

  validateItemPlaintextOrThrow(nextPlaintext);

  const nextVersion = current.record.record_version + 1;

  const encrypted = await cryptoRecordService.encryptRecord({
    vaultId,
    recordId,
    recordType: 'item',
    recordVersion: nextVersion,
    keyVersion: current.record.key_version,
    plaintext: nextPlaintext,
  });

  const op = await operationSigningService.signOperation({
    opId: generateOpId(),
    vaultId,
    authorDeviceId: currentDeviceId,
    opType: 'update',
    recordId,
    recordType: 'item',
    baseRecordVersion: current.record.record_version,
    previousRecordHash: current.record.ciphertext_hash,
    newRecordHash: encrypted.ciphertextHash,
    baseVaultHead: localState.lastVerifiedVaultHead,
    payloadCiphertextHash: encrypted.ciphertextHash,
    payloadAadHash: encrypted.aadHash,
    createdAtClient: nowIso(),
    trustEpoch: deviceTrustService.currentTrustEpoch(),
  });

  await pendingQueue.add({ op, record: encrypted.record });

  localState.applyPendingVerifiedUpdate(op, encrypted.record, nextPlaintext);

  vaultSyncService.tryPushPendingOperations();
}
```

---

# 28. Recovery-Abläufe

## 28.1 Item aus Snapshot wiederherstellen

```text
1. Nutzer wählt quarantänisiertes Item.
2. Client sucht passenden Snapshot-Record.
3. Snapshot-Signatur wird geprüft.
4. Snapshot-Record wird kryptografisch geprüft.
5. Snapshot-Item wird entschlüsselt und schema-validiert.
6. Client erzeugt neue Record-Version.
7. Client verschlüsselt Snapshot-Plaintext neu oder übernimmt Ciphertext nur, wenn Kontext passt.
8. Client erzeugt Restore-Operation.
9. Restore-Operation wird signiert.
10. Lokaler Zustand wird aktualisiert.
11. Operation wird synchronisiert.
```

Empfehlung:

> Beim Restore sollte bevorzugt neu verschlüsselt werden, damit RecordVersion, AAD und aktueller Kontext sauber sind.

## 28.2 Kategorie aus Snapshot wiederherstellen

Ablauf wie Item-Restore.

Nach Restore:

- Kategorie wird wieder `verified`.
- Items, die nur wegen dieser Kategorie `containerQuarantined` waren, werden neu bewertet.
- Wenn Items selbst verified sind, werden sie wieder normal einsortiert.

## 28.3 Missing Record wiederherstellen

Wenn Record remote fehlt:

- lokale verified Kopie oder Snapshot-Kopie verwenden,
- Restore-Operation erzeugen,
- Server speichert Record erneut,
- andere Clients akzeptieren Restore.

## 28.4 Unbekannten Remote-Record löschen

Ablauf:

```text
1. Nutzer wählt Löschen.
2. Client erzeugt Delete-Operation für unbekannten Record.
3. Wenn previousRecordHash unbekannt ist, wird spezieller Delete-Untrusted-Record-Typ verwendet.
4. Operation signieren.
5. Server entfernt/markiert unbekannten Record.
```

Wichtig:

Ein unbekannter Record darf nicht entschlüsselt werden, nur um seinen Inhalt zu prüfen.

---

# 29. Audit und Diagnose

## 29.1 Lokale Diagnoseinformationen

Für jede Quarantäne sollte gespeichert werden:

```ts
type QuarantineDiagnostic = {
  recordId: string;
  recordType: string;
  reason: QuarantineReason;
  detectedAt: string;
  relatedOpId: string | null;
  authorDeviceId: string | null;
  localKnownHash: string | null;
  remoteHash: string | null;
  snapshotAvailable: boolean;
  recommendedAction: string;
};
```

Keine Klartexte in Diagnose.

## 29.2 Nutzerfreundliche Meldungen

Technische Gründe müssen verständlich übersetzt werden.

Beispiele:

`unknown_author_device`:

> Dieser Eintrag wurde von einem Gerät geändert, dem dieser Tresor nicht vertraut. Der Eintrag bleibt gesperrt, bis du das Gerät überprüfst oder den Eintrag entfernst.

`missing_without_delete`:

> Dieser Eintrag fehlt auf dem Server, aber es gibt keinen gültigen Lösch-Nachweis. Singra Vault behält deine lokale geprüfte Kopie und bietet Wiederherstellung an.

`container_category_invalid`:

> Die Kategorie dieses Eintrags ist beschädigt oder nicht verifizierbar. Der Eintrag selbst wurde geprüft, wird aber vorübergehend in einem Sicherheitsbereich angezeigt.

---

# 30. Sicherheitsinvarianten

Diese Invarianten dürfen im Code niemals verletzt werden.

## I1

Ein Record mit ungültiger oder fehlender Operation wird nicht entschlüsselt.

## I2

Ein Record von unbekanntem Autorgerät wird nicht entschlüsselt.

## I3

Ein Record mit falschem AAD-Hash wird nicht entschlüsselt.

## I4

Ein Record mit falschem Ciphertext-Hash wird nicht entschlüsselt.

## I5

Ein Record mit fehlgeschlagener AEAD-Entschlüsselung wird nicht angezeigt.

## I6

Ein Record mit ungültigem Plaintext-Schema wird nicht normal angezeigt.

## I7

Ein Delete ist nur legitim, wenn eine gültige Delete-Operation existiert.

## I8

Ein Konflikt zwischen gültigen Operationen ist kein Quarantänefall.

## I9

Kategoriefehler blockieren nicht den gesamten Vault.

## I10

Recovery aus Snapshot erzeugt immer eine neue signierte Operation.

## I11

Direkte Vault-Schreibzugriffe außerhalb der Operation-Schicht sind verboten.

## I12

Autofill verwendet nur verified Items.

## I13

Export enthält keine quarantänisierten Records.

## I14

Safe Mode setzt keine Baseline automatisch neu.

## I15

Locked Critical darf nur durch Root-Vertrauensprobleme ausgelöst werden.

---

# 31. Testplan

## 31.1 Unit Tests

Testbereiche:

- AAD-Kanonisierung,
- ciphertextHash-Berechnung,
- opHash-Berechnung,
- Signaturprüfung,
- Record-Key-Ableitung,
- Schema-Validierung,
- Quarantäneklassifikation,
- Konflikterkennung,
- Snapshot-Signaturprüfung,
- Tombstone-Logik.

## 31.2 Integration Tests

Szenarien:

1. Tauri ändert Item, Web integriert ohne Quarantäne.
2. Web ändert Kategorie, Tauri integriert ohne Vault-Blockade.
3. Server verändert Ciphertext ohne Operation, Item wird quarantänisiert.
4. Server löscht Item ohne Delete, Item wird als missing_without_delete markiert.
5. Trusted Device löscht Item, anderer Client akzeptiert Tombstone.
6. Zwei Clients ändern dasselbe Item offline, Conflict entsteht.
7. Kategorie manipuliert, nur Kategorie und betroffene Container werden isoliert.
8. Snapshot-Restore erzeugt Restore-Operation.
9. Unbekanntes Gerät erzeugt Operation, Record bleibt gesperrt.
10. Widerrufenes Gerät erzeugt Operation, Operation wird abgelehnt.
11. Operation-Log-Lücke aktiviert Safe Mode.
12. Manifest-Manipulation führt zu lockedCritical.

## 31.3 Property Tests

Eigenschaften:

- gleiche Operation ergibt gleichen opHash,
- geändertes signiertes Feld macht Signatur ungültig,
- geändertes AAD macht Decrypt unmöglich,
- Record kann nicht in anderen Vault verschoben werden,
- Record kann nicht als anderer Typ entschlüsselt werden,
- Retry derselben Operation ist idempotent.

## 31.4 Regression Tests gegen alte Fehler

Explizit testen:

- legitime Browser-Änderung triggert nicht „Tresorzugriff blockiert“,
- legitime Tauri-Änderung landet nicht in Web-Quarantäne,
- Kategorie-Farbänderung blockiert nicht Vault,
- Kategorie-Löschung löscht keine Items,
- Unlock/Lock/Unlock ist nicht nötig, um legitimen Sync zu reparieren,
- keine automatische Rebaseline bei unbekannter Remote-Änderung.

---

# 32. Implementierungsreihenfolge

## Schritt 1: Altes Block-Verhalten entschärfen

- Kategorie-Mismatch nicht mehr `blocked`.
- Neue Zustände für Kategoriequarantäne einführen.
- Quarantäne granularer machen.

## Schritt 2: Einheitliche Mutationsschnittstelle

- Direkte Writes entfernen.
- Alle Änderungen über `submit_vault_operation` führen.
- `opId`, `baseRecordVersion`, `previousRecordHash` einführen.

## Schritt 3: Record-Modell einführen

- Items und Kategorien als Records modellieren.
- AAD und CiphertextHash verbindlich machen.
- Tombstones einführen.

## Schritt 4: Geräte-Signaturen einführen

- Device Signing Key erzeugen.
- Operationen signieren.
- Operationen anderer Clients verifizieren.

## Schritt 5: Operation-Log als Integrationsquelle

- Pull/Push über Operationen.
- Snapshot nur noch als Cache/Recovery verwenden.

## Schritt 6: Snapshot-Recovery umbauen

- Restore erzeugt signierte Restore-Operation.
- Kein direkter Upsert aus Snapshot mehr.

## Schritt 7: Konflikt-UI

- Konflikte klar getrennt von Quarantäne anzeigen.
- Nutzerlösung erzeugt neue Operation.

## Schritt 8: Safe Mode sauber implementieren

- Safe Mode nur bei großflächigem Misstrauen.
- Keine automatische Reparatur.

## Schritt 9: Migration finalisieren

- alte Daten in neue Records und Operationen migrieren.
- Pre-Migration-Snapshot sichern.
- Tests gegen alte Fehler durchführen.

---

# 33. Strikte Verbote im neuen System

Folgende Muster sind verboten:

1. Remote-Daten akzeptieren, nur weil sie entschlüsselbar sind.
2. Lokale Baseline automatisch neu setzen, um Drift verschwinden zu lassen.
3. Kategorien als Grund für globale Vault-Sperre behandeln.
4. Direkte Supabase-Upserts für Vault-Inhalte verwenden.
5. Direkte Deletes ohne Tombstone verwenden.
6. Zeitfenster wie 60-Sekunden-TTL als Vertrauenslogik verwenden.
7. Quarantäne-Records im UI-Renderpfad entschlüsseln.
8. Quarantäne-Records in Autofill oder Export verwenden.
9. Konflikte als Manipulation behandeln.
10. Snapshot als globale Wahrheit behandeln.
11. Safe Mode als automatische Reparatur verwenden.
12. Unknown-author Records nachträglich still akzeptieren.
13. LockedCritical für normale Record-Probleme auslösen.

---

# 34. Zielzustand in einem Satz

Singra Vault integriert Änderungen nur, wenn sie als signierte, versionierte und entschlüsselbare Operation eines vertrauenswürdigen Geräts verifizierbar sind; alles andere wird granular isoliert, aus lokalen Snapshots wiederherstellbar gemacht und niemals stillschweigend entschlüsselt oder akzeptiert.

---

# 35. Kurzform für Entwickler

Wenn eine neue Vault-Änderung implementiert wird, muss der Entwickler diese Fragen mit „Ja“ beantworten können:

1. Wird die Änderung als Operation modelliert?
2. Wird die Operation signiert?
3. Enthält sie `baseRecordVersion`?
4. Enthält sie `previousRecordHash`?
5. Wird der Record mit AEAD und korrektem AAD verschlüsselt?
6. Wird die Änderung über die zentrale Operation-RPC gesendet?
7. Ist Retry idempotent?
8. Können andere Clients die Operation ohne lokale Heuristik akzeptieren?
9. Gibt es einen klaren Konfliktfall?
10. Gibt es einen klaren Quarantänefall?
11. Wird Recovery als neue signierte Operation umgesetzt?
12. Wird der Vault nur bei Root-Problemen blockiert?

Wenn eine dieser Fragen mit „Nein“ beantwortet wird, ist die Implementierung nicht konform mit diesem Konzept.

---

# 36. Endgültige Designentscheidung

Das alte System wird nicht schrittweise durch weitere Heuristiken repariert.

Es wird ersetzt durch:

```text
Recordweise AEAD-Verschlüsselung
+ signierte Operationen pro vertrauenswürdigem Gerät
+ Operation-Log als Integrationsquelle
+ Tombstones statt stiller Deletes
+ Konflikte statt falscher Quarantäne
+ granulare Quarantäne statt Vault-Blockade
+ lokale signierte Snapshots für Recovery
+ Safe Mode bei großflächigem Remote-Misstrauen
```

Diese Architektur ist die verbindliche Grundlage für den Neuaufbau des Integrations-, Quarantäne- und Manipulationsschutzsystems von Singra Vault.

