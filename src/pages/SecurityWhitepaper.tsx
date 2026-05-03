// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE
/**
 * @fileoverview Technical Security Whitepaper
 *
 * This page is intentionally code-backed documentation. It avoids broad
 * marketing claims and marks claims without repository evidence explicitly.
 */

import { useEffect, useMemo } from 'react';
import { useTranslation } from 'react-i18next';
import { Link } from 'react-router-dom';
import { AlertTriangle, ExternalLink, Shield } from 'lucide-react';

import { Badge } from '@/components/ui/badge';
import { DesktopSubpageHeader } from '@/components/layout/DesktopSubpageHeader';
import { SEO, createArticleStructuredData, createBreadcrumbStructuredData } from '@/components/SEO';
import { Header } from '@/components/landing/Header';
import { Footer } from '@/components/landing/Footer';
import { shouldShowWebsiteChrome } from '@/platform/appShell';
import { APP_VERSION_DISPLAY, APP_VERSION_SOURCE } from '@/config/appVersion';

type Status = 'BELEGT' | 'TEILWEISE' | 'NICHT BELEGT';

interface Evidence {
  file: string;
  functionName?: string;
  dataFormat?: string;
  tests?: string;
  residualRisk: string;
  status: Status;
}

interface Section {
  id: string;
  title: string;
  summary: string;
  body: string[];
  evidence: Evidence[];
}

interface MatrixRow {
  cells: string[];
  status?: Status;
}

const WHITEPAPER_VERSION = '2026.04.28-tech-1';
const WHITEPAPER_LAST_UPDATED = '2026-04-28';

const statusVariant: Record<Status, 'default' | 'secondary' | 'destructive'> = {
  BELEGT: 'default',
  TEILWEISE: 'secondary',
  'NICHT BELEGT': 'destructive',
};

const references = [
  ['Bitwarden Security Whitepaper', 'https://bitwarden.com/pdf/help-bitwarden-security-white-paper.pdf'],
  ['RFC 9807 OPAQUE', 'https://www.ietf.org/ietf-ftp/rfc/rfc9807.html'],
  ['OWASP XSS Prevention Cheat Sheet', 'https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html'],
  ['OWASP DOM XSS Prevention Cheat Sheet', 'https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html'],
  ['OWASP CSP Cheat Sheet', 'https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html'],
  ['OWASP Password Storage Cheat Sheet', 'https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html'],
  ['NIST SP 800-63B', 'https://pages.nist.gov/800-63-4/sp800-63b.html'],
  ['WebCrypto Level 2', 'https://www.w3.org/TR/webcrypto-2/'],
  ['Tauri Security / CSP', 'https://v2.tauri.app/security/csp/'],
] as const;

function statusBadge(status: Status) {
  return <Badge variant={statusVariant[status]}>{status}</Badge>;
}

function normalizeLanguage(language: string): 'de' | 'en' {
  return language.startsWith('en') ? 'en' : 'de';
}

function getContent(language: 'de' | 'en') {
  if (language === 'en') {
    return {
      title: 'Singra Vault Security Whitepaper',
      subtitle: 'Technical, repository-backed security model for the current Singra Vault implementation.',
      auditStatus: 'No external independent security audit has been performed yet. Evidence below means repository evidence, internal review notes, automated tests, or manual runtime checks.',
      scope: 'Scope: Web, PWA, and Tauri/Desktop. The public core is source-available; optional Premium code is loaded through the private package boundary. Premium is referenced only where repository docs or public extension contracts expose the behavior.',
      sections: buildSections('en'),
      dataRows: buildDataRows('en'),
      testRows: buildTestRows('en'),
      claimRows: buildClaimRows('en'),
      glossaryRows: buildGlossaryRows('en'),
    };
  }

  return {
    title: 'Singra Vault Security Whitepaper',
    subtitle: 'Technisches, repository-basiertes Sicherheitsmodell für den aktuellen Singra-Vault-Stand.',
    auditStatus: 'Noch kein externer unabhängiger Security Audit durchgeführt. Belege unten bedeuten Repository-Belege, interne Review-Notizen, automatisierte Tests oder manuelle Laufzeitprüfungen.',
    scope: 'Scope: Web, PWA und Tauri/Desktop. Der öffentliche Core ist source-available; optionale Premium-Funktionen werden über die private Paketgrenze geladen. Premium wird nur dort beschrieben, wo Repository-Dokumente oder öffentliche Extension-Verträge das Verhalten belegen.',
    sections: buildSections('de'),
    dataRows: buildDataRows('de'),
    testRows: buildTestRows('de'),
    claimRows: buildClaimRows('de'),
    glossaryRows: buildGlossaryRows('de'),
  };
}

function buildSections(language: 'de' | 'en'): Section[] {
  const de = language === 'de';
  return [
    {
      id: 'executive-summary',
      title: de ? '1. Executive Summary' : '1. Executive Summary',
      summary: de
        ? 'Singra Vault schützt Vault-Payloads durch clientseitige Verschlüsselung; der Server ist Sync- und Storage-Schicht für Ciphertext und technische Metadaten.'
        : 'Singra Vault protects vault payloads with client-side encryption; the server is a sync and storage layer for ciphertext and technical metadata.',
      body: [
        de
          ? 'Zero-Knowledge wird hier präzise verwendet: Vault-Inhalte sollen den Client als Klartext nicht verlassen. Server, Datenbank und Storage können weiterhin IDs, Besitzbeziehungen, Zeitpunkte, technische Statusfelder, Sessiondaten und Zugriffsmuster sehen.'
          : 'Zero-knowledge is used narrowly: vault contents should not leave the client as plaintext. Server, database, and storage can still see IDs, ownership links, timestamps, technical status fields, session data, and access patterns.',
        de
          ? 'Das Whitepaper macht keine pauschalen Sicherheitsversprechen. Grenzen wie Same-Origin-XSS, Malware, entsperrter Client, Recovery-/Emergency-Pfade und fehlender externer Audit sind Teil des Modells.'
          : 'This whitepaper does not claim the product is unbreakable or fully secure. Limits such as same-origin XSS, malware, unlocked clients, recovery/emergency paths, and the missing external audit are part of the model.',
      ],
      evidence: [
        ev('src/services/cryptoService.ts', 'encryptVaultItem(), decryptVaultItem()', 'sv-vault-v1', 'src/services/vaultItemCryptoStorage.test.ts', de ? 'Entsperrter Client und lokales Gerät bleiben Vertrauensgrenzen.' : 'Unlocked clients and local devices remain trust boundaries.', 'BELEGT'),
      ],
    },
    {
      id: 'scope-status',
      title: de ? '2. Scope und Status' : '2. Scope and Status',
      summary: de ? 'Beschreibt belegte Plattformen, Core/Premium-Grenzen und Audit-Status.' : 'Describes evidenced platforms, Core/Premium boundary, and audit status.',
      body: [
        de
          ? 'Im Scope: Core-Vault-Einträge, Notizen, TOTP-Payloads, OPAQUE-Login, Vault Unlock, Offline-Cache, Integrity/Quarantine, RLS/Storage, Sessions, WebAuthn/Passkeys, Import/Export und dokumentierte Premium-Pfade für Dateien, Sharing und Emergency Access.'
          : 'In scope: core vault items, notes, TOTP payloads, OPAQUE login, vault unlock, offline cache, integrity/quarantine, RLS/storage, sessions, WebAuthn/passkeys, import/export, and documented Premium paths for files, sharing, and Emergency Access.',
        de
          ? 'Nicht belegt als externer Audit: eine unabhängige, vollständige Security-Prüfung. Belegt sind fokussierte interne Dokumente, Unit-/Integrationstests und einzelne manuelle Runtime-Prüfungen.'
          : 'Not evidenced as external audit: an independent full security review. Evidence exists for focused internal docs, unit/integration tests, and selected manual runtime checks.',
      ],
      evidence: [
        ev('docs/SECURITY.md', undefined, undefined, undefined, de ? 'Kanonisches Security-Dokument; Detailnachweise liegen im Archiv.' : 'Canonical security document; detailed evidence is archived.', 'TEILWEISE'),
        ev('docs/archive/xss-same-origin-hardening-2026-04-28.md', undefined, undefined, undefined, de ? 'Archivierter fokussierter Check, kein Gesamtaudit.' : 'Archived focused check, not a full audit.', 'TEILWEISE'),
      ],
    },
    {
      id: 'threat-model',
      title: de ? '3. Threat Model' : '3. Threat Model',
      summary: de ? 'Assets, Angreifer und explizite Grenzen.' : 'Assets, attackers, and explicit boundaries.',
      body: [
        de
          ? 'Assets: Account-/Master-/Vault-Passwort, User/Vault Key, Device Keys, encrypted_user_key, Vault Items, Notes, TOTP-Secrets, Datei-Keys, Emergency-Key-Material, Sharing-Keys, Sessions/Refresh Tokens, Recovery/Backup Codes, Offline-Cache und Integrity-Baselines.'
          : 'Assets: account/master/vault password, user/vault key, device keys, encrypted_user_key, vault items, notes, TOTP secrets, file keys, emergency key material, sharing keys, sessions/refresh tokens, recovery/backup codes, offline cache, and integrity baselines.',
        de
          ? 'Angreifer: DB- oder Storage-Leser, bösartiger Server/Insider, Netzwerkangreifer, Same-Origin-XSS, Malware auf entsperrtem Gerät, kompromittierter Trustee, gestohlene Session, manipulierte Vault-Daten und gestohlene Exporte.'
          : 'Attackers: database or storage readers, malicious server/insider, network attacker, same-origin XSS, malware on an unlocked device, compromised trustee, stolen session, tampered vault data, and stolen exports.',
        de
          ? 'Out of scope: kompromittierter entsperrter Client, RAM/Clipboard/Keyboard-Malware, freiwillige Passwortpreisgabe, App-external Phishing, Geräteverlust ohne OS-Schutz, Social Engineering und externe OAuth-Provider-Kompromisse.'
          : 'Out of scope: compromised unlocked client, RAM/clipboard/keyboard malware, voluntary password disclosure, phishing outside the app, device loss without OS protection, social engineering, and compromised external OAuth providers.',
      ],
      evidence: [
        ev('docs/SECURITY.md', undefined, undefined, undefined, de ? 'Web/PWA-Grenzen gelten nicht automatisch identisch für Tauri.' : 'Web/PWA boundaries do not automatically equal Tauri boundaries.', 'TEILWEISE'),
      ],
    },
    {
      id: 'architecture',
      title: de ? '4. Architekturübersicht' : '4. Architecture Overview',
      summary: de ? 'Client-Krypto, Supabase als Ciphertext-Schicht, Core/Premium-Boundary.' : 'Client crypto, Supabase as ciphertext layer, Core/Premium boundary.',
      body: [
        de
          ? 'Vault-Payloads werden im Client serialisiert und mit WebCrypto AES-GCM verschlüsselt. Supabase Postgres speichert Ciphertexts und technische Felder; Supabase Storage speichert bei Premium-Dateien opaque Objekte/Chunks.'
          : 'Vault payloads are serialized in the client and encrypted with WebCrypto AES-GCM. Supabase Postgres stores ciphertexts and technical fields; Supabase Storage stores opaque objects/chunks for Premium files.',
        de
          ? 'Core enthält die zentrale Vault-Krypto. Premium wird über Extension-Slots geladen und darf diese Grenze nicht durch direkte Core/Premium-Modul-Doppelidentitäten brechen.'
          : 'Core contains the central vault crypto. Premium is loaded through extension slots and must not break this boundary through duplicate Core/Premium module identities.',
      ],
      evidence: [
        ev('src/extensions/registry.ts', 'registerExtension(), getServiceHooks()', undefined, 'src/extensions/registry.test.ts', de ? 'Private Premium-Implementierung ist nicht vollständig im öffentlichen Repo belegbar.' : 'Private Premium implementation is not fully evidenced in the public repo.', 'TEILWEISE'),
        ev('vite.config.ts', 'premiumResolvePlugin()', undefined, undefined, de ? 'Laufzeitprüfung auf Settings-Routen bleibt Pflicht bei Importpfadänderungen.' : 'Runtime checks on settings routes remain required when import paths change.', 'BELEGT'),
      ],
    },
    {
      id: 'data-visibility',
      title: de ? '5. Datenklassen und Sichtbarkeit' : '5. Data Classes and Visibility',
      summary: de ? 'Die Tabelle unten trennt Klartext, Ciphertext, technische Metadaten und nicht belegte Aussagen.' : 'The table below separates plaintext, ciphertext, technical metadata, and claims without evidence.',
      body: [de ? 'Die Sichtbarkeit ist feld- und featureabhängig. "Server sieht nicht" bedeutet in diesem Whitepaper nicht "keine Metadaten".' : 'Visibility is field- and feature-dependent. In this whitepaper, "server cannot see" does not mean "no metadata".'],
      evidence: [
        ev('src/services/vaultItemCryptoStorage.test.ts', undefined, 'encrypted_data contract', 'src/services/vaultItemCryptoStorage.test.ts', de ? 'Testet Core-Items, nicht jeden Premium-Pfad.' : 'Tests core items, not every Premium path.', 'BELEGT'),
      ],
    },
    {
      id: 'cryptography',
      title: de ? '6. Kryptografie' : '6. Cryptography',
      summary: de ? 'AES-256-GCM, Argon2id, HKDF, OPAQUE, non-extractable CryptoKeys und versionierte Formate.' : 'AES-256-GCM, Argon2id, HKDF, OPAQUE, non-extractable CryptoKeys, and versioned formats.',
      body: [
        de
          ? 'Vault-Items nutzen sv-vault-v1: base64(IV || Ciphertext || Auth Tag). encryptVaultItem() serialisiert JSON und bindet die Item-ID als AAD. Unbekannte sv-vault-* Versionen schlagen fail-closed fehl; unversionierte Daten werden als Legacy gelesen.'
          : 'Vault items use sv-vault-v1: base64(IV || ciphertext || auth tag). encryptVaultItem() serializes JSON and binds the item ID as AAD. Unknown sv-vault-* versions fail closed; unversioned data is read as legacy.',
        de
          ? 'Argon2id-Parameter sind versioniert; v1 nutzt 64 MiB, v2 128 MiB. HKDF wird für Device-Key-Kombination und User-Key-Wrap-Domain-Separation genutzt. CryptoKeys werden als nicht extrahierbare AES-GCM Keys importiert.'
          : 'Argon2id parameters are versioned; v1 uses 64 MiB, v2 uses 128 MiB. HKDF is used for device-key combination and user-key wrap domain separation. CryptoKeys are imported as non-extractable AES-GCM keys.',
        de
          ? 'PQ/Hybrid ist kein genereller Vault-Datenmodus. Es betrifft Key-Wrapping-Pfade wie Sharing/Emergency; Vault-Payloads bleiben AES-GCM.'
          : 'PQ/hybrid is not a general vault-data mode. It applies to key-wrapping paths such as sharing/emergency; vault payloads remain AES-GCM.',
      ],
      evidence: [
        ev('src/services/cryptoService.ts', 'deriveRawKey(), importMasterKey(), encrypt(), encryptVaultItem()', 'sv-vault-v1', 'src/test/integration-crypto-pipeline.test.ts; src/services/vaultItemCryptoStorage.test.ts', de ? 'JS-Speicherlöschung bleibt best-effort.' : 'JS memory clearing remains best-effort.', 'BELEGT'),
        ev('src/services/pqCryptoService.ts', 'hybridEncrypt(), hybridDecrypt()', 'version bytes 0x03/0x04', 'src/services/pqCryptoService.test.ts', de ? 'PQ schützt nicht gegen kompromittierte Endpunkte.' : 'PQ does not protect against compromised endpoints.', 'BELEGT'),
      ],
    },
    {
      id: 'account-login',
      title: de ? '7. Account-Erstellung und Login' : '7. Account Creation and Login',
      summary: de ? 'App-eigener Passwortlogin über OPAQUE; OAuth/Social Login ist separat.' : 'App-owned password login uses OPAQUE; OAuth/social login is separate.',
      body: [
        de
          ? 'Das Passwort wird im OPAQUE-Pfad lokal verarbeitet; Edge Functions erhalten OPAQUE-Protokollnachrichten. Direkte Legacy-Passwort-Posts werden serverseitig blockiert. Identifier werden normalisiert, Server Static Public Key Pinning ist dokumentiert, und Sessions werden nach OPAQUE-Finish erzeugt.'
          : 'The password is processed locally in the OPAQUE path; Edge Functions receive OPAQUE protocol messages. Direct legacy password posts are blocked server-side. Identifiers are normalized, server static public key pinning is documented, and sessions are created after OPAQUE finish.',
        de
          ? 'OAuth/Social Login ist nicht OPAQUE. Passkeys/WebAuthn sind an Origin/RP-ID und Challenge-Scope gebunden und ersetzen nicht automatisch den Vault-Unlock.'
          : 'OAuth/social login is not OPAQUE. Passkeys/WebAuthn are bound to origin/RP ID and challenge scope and do not automatically replace vault unlock.',
      ],
      evidence: [
        ev('src/services/opaqueService.ts', 'startRegistration(), finishLogin()', 'OPAQUE messages', 'src/test/opaque-registration-flow.test.ts; src/test/auth-flow-hardening.test.ts', de ? 'Die Protokollsicherheit hängt zusätzlich von korrekter Serverfunktion und TLS ab.' : 'Protocol security also depends on correct server functions and TLS.', 'BELEGT'),
        ev('supabase/functions/auth-session/index.ts', undefined, undefined, 'src/test/auth-flow-hardening.test.ts', de ? 'Rate-Limits und Enumeration-Schutz sind serverseitig zu prüfen.' : 'Rate limits and enumeration protection must be checked server-side.', 'TEILWEISE'),
      ],
    },
    {
      id: 'vault-unlock-key-hierarchy',
      title: de ? '8. Vault Unlock und Key-Hierarchie' : '8. Vault Unlock and Key Hierarchy',
      summary: de ? 'Account Login und Vault Unlock sind getrennte Schritte.' : 'Account login and vault unlock are separate steps.',
      body: [
        de
          ? 'Der Account-Login erzeugt Zugriff auf die App-Session. Der Vault-Unlock leitet aus Vault-/Master-Passwort, Salt, KDF-Version und optional Device Key Key-Material ab. encrypted_user_key erlaubt eine User-Key-Schicht statt direkter KDF-Key-Nutzung.'
          : 'Account login grants app-session access. Vault unlock derives key material from vault/master password, salt, KDF version, and optional device key. encrypted_user_key enables a user-key layer instead of direct KDF-key use.',
        de
          ? 'Lock entfernt aktive Key-Referenzen aus dem React Context. Logout räumt zusätzlich Session-/Offline-Indikatoren auf. Passwortwechsel rewrappt Keys; Vault-Reset ist destruktiv und stellt alte Vault-Daten nicht wieder her.'
          : 'Lock removes active key references from React context. Logout additionally clears session/offline indicators. Password change rewraps keys; vault reset is destructive and does not recover old vault data.',
      ],
      evidence: [
        ev('src/contexts/VaultContext.tsx', 'unlock(), lock(), clearActiveVaultSession()', undefined, 'src/contexts/__tests__/VaultContext.test.tsx', de ? 'Entsperrte Daten liegen in JS-Objekten und RAM vor.' : 'Unlocked data exists in JS objects and RAM.', 'BELEGT'),
        ev('src/services/cryptoService.ts', 'createEncryptedUserKey(), unwrapUserKey(), rewrapUserKey()', 'encrypted_user_key', 'src/test/integration-crypto-pipeline.test.ts', de ? 'Recovery-Pfade können zusätzliches Key-Wrapping erzeugen.' : 'Recovery paths can create additional key wrapping.', 'BELEGT'),
      ],
    },
    {
      id: 'vault-items-notes-totp',
      title: de ? '9-11. Vault Items, Notizen und Authenticator/TOTP' : '9-11. Vault Items, Notes, and Authenticator/TOTP',
      summary: de ? 'Passwörter, Notizen und TOTP-Felder verwenden denselben encrypted_data-Pfad.' : 'Passwords, notes, and TOTP fields use the same encrypted_data path.',
      body: [
        de
          ? 'VaultItemData enthält title, username, password, websiteUrl, notes, itemType, categoryId und TOTP-Felder. Notes bei Passwort-, Notiz- und TOTP-Einträgen liegen im verschlüsselten JSON. item_type kann serverseitig sichtbar sein; sensible TOTP-Parameter liegen im Payload.'
          : 'VaultItemData contains title, username, password, websiteUrl, notes, itemType, categoryId, and TOTP fields. Notes on password, note, and TOTP entries are inside encrypted JSON. item_type can be server-visible; sensitive TOTP parameters are in the payload.',
        de
          ? 'otpauth-QR-Daten werden geparst und nicht als QR-Rohtext persistiert. TOTP-Codes werden lokal berechnet. Klartext-Export ist eine explizite lokale Nutzeraktion und enthält Secrets.'
          : 'otpauth QR data is parsed and not persisted as raw QR text. TOTP codes are computed locally. Plaintext export is an explicit local user action and contains secrets.',
      ],
      evidence: [
        ev('src/services/cryptoService.ts', 'VaultItemData, encryptVaultItem()', 'sv-vault-v1 JSON', 'src/services/vaultItemCryptoStorage.test.ts', de ? 'item_type und technische Zeilenmetadaten können sichtbar bleiben.' : 'item_type and technical row metadata can remain visible.', 'BELEGT'),
        ev('src/services/totpService.ts', 'parseOTPAuthUri(), generateTOTP()', 'otpauth URI parsed to fields', 'src/test/edge-cases.test.ts; src/components/vault/__tests__/TOTPDisplay.test.tsx', de ? 'Entsperrter Client kann TOTP-Secrets lesen.' : 'Unlocked client can read TOTP secrets.', 'BELEGT'),
      ],
    },
    {
      id: 'file-attachments',
      title: de ? '12. Datei-Anhänge / Premium File E2EE' : '12. File Attachments / Premium File E2EE',
      summary: de ? 'Premium-Dateien nutzen Core-Key-Fundament plus eigene File-E2EE-Schicht.' : 'Premium files use the Core key foundation plus a file E2EE layer.',
      body: [
        de
          ? 'Dokumentiert ist: pro Datei zufälliger File-Key, File-Key-Wrapping, Chunk-Verschlüsselung, verschlüsseltes Manifest und opaque Storage-Pfade. Dateiname, MIME, Endung und Originalgröße gehören laut Dokument in das verschlüsselte Manifest; sichtbar bleiben Ciphertext-Größe, Chunk-Zahl, Pfade, Zeitpunkte und Zugriffsmuster.'
          : 'Documented behavior: per-file random file key, file-key wrapping, chunk encryption, encrypted manifest, and opaque storage paths. File name, MIME type, extension, and original size belong in the encrypted manifest; ciphertext size, chunk count, paths, timestamps, and access patterns remain visible.',
        de
          ? 'Kein Padding ist belegt. Pending Attachments beim Erstellen sind laut vorhandener Notizen nicht als vollständig unterstützter Flow belegt. Riskante Formate sollen nicht inline als HTML/SVG/XML/PDF gerendert werden.'
          : 'Padding is not evidenced. Pending attachments during item creation are not evidenced as a fully supported flow in current notes. Risky formats should not be rendered inline as HTML/SVG/XML/PDF.',
      ],
      evidence: [
        ev('docs/archive/premium-file-upload-e2ee.md', undefined, 'encrypted manifest, chunks', undefined, de ? 'Archivierte Premium-Notiz; private Premium-Codepfade sind im öffentlichen Repo nur teilweise belegbar.' : 'Archived Premium note; private Premium code paths are only partially evidenced in the public repo.', 'TEILWEISE'),
        ev('supabase/migrations/20260426143000_file_attachment_e2ee_chunked_limits.sql', undefined, undefined, undefined, de ? 'DB/Storage-Metadaten bleiben sichtbar.' : 'DB/storage metadata remains visible.', 'TEILWEISE'),
      ],
    },
    {
      id: 'sharing-emergency',
      title: de ? '13-14. Sharing und Emergency Access' : '13-14. Sharing and Emergency Access',
      summary: de ? 'Sharing/Emergency sind Key-Wrapping-Pfade, keine generelle PQ-Vault-Verschlüsselung.' : 'Sharing/emergency are key-wrapping paths, not general PQ vault encryption.',
      body: [
        de
          ? 'Sharing nutzt Empfänger-/Trustee-Key-Material, um Zugriff auf Vault- oder Shared-Key-Material clientseitig zu wrappen. Der Server sieht Mitgliedschaften, Rollen, Status, Zeitpunkte und Ciphertexts, aber nicht den entschlüsselten Vault-Key.'
          : 'Sharing uses recipient/trustee key material to wrap vault or shared key material client-side. The server sees memberships, roles, status, timestamps, and ciphertexts, but not the decrypted vault key.',
        de
          ? 'Emergency Access ist ausdrücklich ein alternativer Vault-Key-Wrapping-Pfad: Vault-Key-Material kann clientseitig für einen Trustee gewrappt werden. Ein kompromittierter Trustee wird dadurch Teil der Sicherheitsarchitektur.'
          : 'Emergency Access is explicitly an alternative vault-key wrapping path: vault-key material can be wrapped client-side for a trustee. A compromised trustee therefore becomes part of the security architecture.',
        de
          ? 'Revocation verhindert künftigen Zugriff auf neue Key-Versionen nicht automatisch auf bereits kopierte Klartexte oder Schlüssel. PQ/Hybrid betrifft Key-Wrapping und löst keine Endpoint- oder Social-Engineering-Risiken.'
          : 'Revocation cannot undo already copied plaintexts or keys. PQ/hybrid concerns key wrapping and does not solve endpoint or social-engineering risks.',
      ],
      evidence: [
        ev('docs/archive/EMERGENCY_ACCESS.md', undefined, undefined, undefined, de ? 'Archivierte Premium-Notiz; private Premium-Implementierung nur teilweise im öffentlichen Repo belegbar.' : 'Archived Premium note; private Premium implementation is only partially evidenced in the public repo.', 'TEILWEISE'),
        ev('src/services/pqCryptoService.ts', 'hybridWrapKey(), hybridUnwrapKey()', 'hybrid ciphertext 0x04', 'src/services/pqCryptoService.test.ts', de ? 'Nur Key-Wrapping-Pfad, nicht gesamte Vault-Daten.' : 'Only key-wrapping path, not all vault data.', 'BELEGT'),
      ],
    },
    {
      id: 'reset-2fa-sessions-device',
      title: de ? '15-18. Reset, 2FA, Sessions, Device Keys und Passkeys' : '15-18. Reset, 2FA, Sessions, Device Keys, and Passkeys',
      summary: de ? 'Account-Zugang, Vault-Key-Recovery und Vault-Unlock sind getrennt.' : 'Account access, vault-key recovery, and vault unlock are separate.',
      body: [
        de
          ? 'Passwort-Reset ist OPAQUE-kompatibles Re-Enrollment mit E-Mail-Code und optionalem 2FA-Gate. Backup/Recovery Codes sind one-time-use und gehasht gespeichert. Account-Zugang ist nicht automatisch Vault-Key-Recovery.'
          : 'Password reset is OPAQUE-compatible re-enrollment with email code and optional 2FA gate. Backup/recovery codes are one-time-use and stored hashed. Account access is not automatically vault-key recovery.',
        de
          ? 'Supabase Sessions, Refresh Tokens und JWTs schützen Account-Zugriff. Logout und globale Cleanup-Pfade räumen Fallbacks/Keychain-Material auf; alte Access JWTs können bis Ablauf gültig bleiben.'
          : 'Supabase sessions, refresh tokens, and JWTs protect account access. Logout and global cleanup paths clear fallbacks/keychain material; old access JWTs can remain valid until expiry.',
        de
          ? 'Device Keys werden lokal gespeichert: Tauri über OS-Secret-Store-Kommandos, Web/PWA über browserbasierte Stores als Defense-in-Depth. WebAuthn/Passkeys sind pro Origin/RP-ID zu betrachten.'
          : 'Device keys are stored locally: Tauri through OS secret-store commands, Web/PWA through browser-based stores as defense in depth. WebAuthn/passkeys must be considered per origin/RP ID.',
      ],
      evidence: [
        ev('src/services/twoFactorService.ts', 'hashBackupCode(), verifyAndConsumeBackupCode()', 'Argon2id backup-code hash v3', 'src/services/__tests__/twoFactorService.mock.test.ts', de ? '2FA schützt nicht gegen entsperrten kompromittierten Client.' : '2FA does not protect against a compromised unlocked client.', 'BELEGT'),
        ev('src/services/authSessionManager.ts', 'persistSession(), clearPersistentSession()', 'HttpOnly/BFF and fallback cleanup paths', 'src/services/authSessionManager.test.ts; src/test/auth-session-cookie.test.ts', de ? 'Bearer Tokens bleiben bis Ablauf ein Risiko.' : 'Bearer tokens remain a risk until expiry.', 'TEILWEISE'),
        ev('src/services/deviceKeyService.ts', 'storeDeviceKey(), deriveWithDeviceKey()', 'HKDF SINGRA_DEVICE_KEY_V1', 'src/services/__tests__/deviceKeyService.test.ts', de ? 'Web/PWA ist keine OS-Keychain-Grenze.' : 'Web/PWA is not an OS-keychain boundary.', 'BELEGT'),
      ],
    },
    {
      id: 'offline-clipboard-memory',
      title: de ? '19-20. Offline Mode, Clipboard und Memory Cleaning' : '19-20. Offline Mode, Clipboard, and Memory Cleaning',
      summary: de ? 'Offline-Snapshots speichern Ciphertexts; Clipboard/Memory-Schutz ist best-effort.' : 'Offline snapshots store ciphertexts; clipboard/memory protection is best effort.',
      body: [
        de
          ? 'OfflineVaultSnapshot hält Items, Kategorien, Mutation Queue, Credentials-Metadaten und Sync-Revisions in IndexedDB. Tests belegen, dass Notiz-Klartext nicht in Offline-Snapshots gelangt, wenn Callers encrypted_data übergeben.'
          : 'OfflineVaultSnapshot keeps items, categories, mutation queue, credential metadata, and sync revisions in IndexedDB. Tests evidence that note plaintext does not enter offline snapshots when callers pass encrypted_data.',
        de
          ? 'Clipboard wird nach Timeout nur geleert, wenn der Inhalt noch dem zuletzt geschriebenen Wert entspricht. OS-Clipboard-History und Malware bleiben Grenzen.'
          : 'Clipboard is cleared after timeout only if it still equals the last written value. OS clipboard history and malware remain limits.',
        de
          ? 'Memory Cleaning ist in JavaScript best-effort: Uint8Array.fill(0), SecureBuffer.destroy() und nicht-extrahierbare CryptoKeys helfen, garantieren aber keinen sicheren RAM.'
          : 'Memory cleaning in JavaScript is best-effort: Uint8Array.fill(0), SecureBuffer.destroy(), and non-extractable CryptoKeys help but do not guarantee safe RAM.',
      ],
      evidence: [
        ev('src/services/offlineVaultService.ts', 'saveOfflineSnapshot(), syncOfflineMutations()', 'IndexedDB snapshot', 'src/services/__tests__/offlineVaultService.test.ts', de ? 'Kompromittierter lokaler Browser kann Offline-Daten abfragen.' : 'Compromised local browser can query offline data.', 'BELEGT'),
        ev('src/services/clipboardService.ts', 'writeClipboard()', '30s timer', 'src/test/edge-cases.test.ts', de ? 'Clipboard-History und Malware sind außerhalb der App-Kontrolle.' : 'Clipboard history and malware are outside app control.', 'BELEGT'),
        ev('src/services/secureBuffer.ts', 'SecureBuffer.destroy()', undefined, 'src/services/secureBuffer.test.ts', de ? 'JS-Strings und GC sind nicht zuverlässig löschbar.' : 'JS strings and GC cannot be reliably wiped.', 'BELEGT'),
      ],
    },
    {
      id: 'integrity-categories',
      title: de ? '21-22. Manipulationserkennung, Quarantäne und Kategorien' : '21-22. Tamper Detection, Quarantine, and Categories',
      summary: de ? 'AES-GCM Auth Tags und lokale Baselines erkennen Manipulationen; Freshness bleibt begrenzt.' : 'AES-GCM auth tags and local baselines detect tampering; freshness remains limited.',
      body: [
        de
          ? 'AES-GCM bindet Ciphertext und AAD. Zusätzlich berechnet vaultIntegrityService Digests über Items und Kategorien, speichert verschlüsselte lokale Baselines und kann verdächtige Items in Quarantäne isolieren.'
          : 'AES-GCM binds ciphertext and AAD. Additionally, vaultIntegrityService computes digests over items and categories, stores encrypted local baselines, and can isolate suspicious items in quarantine.',
        de
          ? 'Kategorie-Felder name/icon/color werden verschlüsselt gespeichert und in die Baseline einbezogen. Legitimer Rebaseline-Flow aktualisiert nur vertrauenswürdige lokale Mutationen.'
          : 'Category fields name/icon/color are stored encrypted and included in the baseline. Legitimate rebaseline flow updates only trusted local mutations.',
        de
          ? 'Grenze: Ohne vertrauenswürdigen letzten Checkpoint oder externe Freshness-Quelle kann ein bösartiger Server alte gültige Ciphertexts replayen.'
          : 'Limit: without a trusted last checkpoint or external freshness source, a malicious server can replay old valid ciphertexts.',
      ],
      evidence: [
        ev('src/services/vaultIntegrityService.ts', 'inspectVaultSnapshotIntegrity(), persistIntegrityBaseline()', 'encrypted local baseline', 'src/services/vaultIntegrityService.test.ts', de ? 'Rollback-Erkennung braucht einen vorhandenen vertrauenswürdigen Zustand.' : 'Rollback detection needs an existing trusted state.', 'BELEGT'),
        ev('src/components/vault/categoryIconPolicy.ts', 'normalizeCategoryIcon()', 'emoji allowlist', 'src/components/vault/__tests__/categoryIconPolicy.test.ts', de ? 'Kategorie-IDs und Zeilenmetadaten bleiben sichtbar.' : 'Category IDs and row metadata remain visible.', 'BELEGT'),
      ],
    },
    {
      id: 'db-storage-xss-cors-logging',
      title: de ? '23-26. Datenbank, Storage, XSS/CSP, CORS und Logging' : '23-26. Database, Storage, XSS/CSP, CORS, and Logging',
      summary: de ? 'RLS, CSP und Logging sind Defense-in-Depth, keine Ersatzgrenzen für Client-Kompromiss.' : 'RLS, CSP, and logging are defense in depth, not replacement boundaries for client compromise.',
      body: [
        de
          ? 'Supabase RLS beschränkt Zeilenzugriff auf Besitzer oder explizite Mitgliedschaften. Service Role darf nur serverseitig genutzt werden. Private Buckets und opaque Pfade reduzieren Dateimetadaten, entfernen sie aber nicht.'
          : 'Supabase RLS restricts row access to owners or explicit memberships. Service role must only be used server-side. Private buckets and opaque paths reduce file metadata but do not remove it.',
        de
          ? 'React escaped Textausgabe, Safe-Sink-Regeln, URL-/Filename-Sanitization und Production-CSP reduzieren XSS-Risiken. Browser/PWA ist aber keine echte Secret Boundary, wenn Same-Origin-App-JS kompromittiert ist.'
          : 'React escaped text output, safe-sink rules, URL/filename sanitization, and production CSP reduce XSS risks. Browser/PWA is not a hard secret boundary if same-origin app JavaScript is compromised.',
        de
          ? 'CORS begrenzt Browser-Origin-Missbrauch, ist aber keine Authentifizierung. Logging darf keine Passwörter, Notes, TOTP-Secrets, File-Metadaten oder Keys enthalten; Logger-Sanitization ist Defense-in-Depth.'
          : 'CORS limits browser-origin abuse but is not authentication. Logging must not contain passwords, notes, TOTP secrets, file metadata, or keys; logger sanitization is defense in depth.',
      ],
      evidence: [
        ev('supabase/migrations', 'RLS policies', undefined, 'src/test/security-rls-emergency-access.test.ts; src/test/vault-reset-rpc-contract.test.ts', de ? 'RLS-Tests decken nicht jede Policy-Kombination ab.' : 'RLS tests do not cover every policy combination.', 'TEILWEISE'),
        ev('vite.config.ts; vercel.json; src-tauri/tauri.conf.json', 'buildContentSecurityPolicy()', 'CSP header/meta', undefined, de ? 'Trusted Types ist nicht enforced.' : 'Trusted Types is not enforced.', 'TEILWEISE'),
        ev('src/lib/logger.ts', 'sanitize()', undefined, 'src/test/security-regression-suite.test.ts', de ? 'Neue Log-Sites müssen weiter reviewt werden.' : 'New log sites still need review.', 'TEILWEISE'),
      ],
    },
    {
      id: 'import-export-delete-premium',
      title: de ? '27-29. Import/Export, Account Delete und Premium/Core Boundary' : '27-29. Import/Export, Account Delete, and Premium/Core Boundary',
      summary: de ? 'Export ist ein lokales Klartext-Risiko; Delete und Premium sind realistisch begrenzt dokumentiert.' : 'Export is a local plaintext risk; delete and Premium are documented with realistic limits.',
      body: [
        de
          ? 'Import liest lokale Daten und schreibt verschlüsselte Vault-Payloads. Klartext-Export enthält Secrets und ist eine bewusste Nutzeraktion; er sollte nicht an den Server übertragen werden. Dateinamen werden bei Export/Download normalisiert.'
          : 'Import reads local data and writes encrypted vault payloads. Plaintext export contains secrets and is an explicit user action; it should not be uploaded to the server. Filenames are normalized for export/download.',
        de
          ? 'Account Delete entfernt user-owned Daten über DB/RPC-Pfade. Physische Entfernung aus Provider-Backups oder Logs kann nicht als sofort belegt werden und wird nicht behauptet.'
          : 'Account delete removes user-owned data through DB/RPC paths. Immediate physical removal from provider backups or logs is not evidenced and is not claimed.',
        de
          ? 'Premium ist closed source und wird über Slots injiziert. Premium nutzt die Core-Krypto-Schicht; eigenständige Premium-Gesamttests sind nur teilweise belegt.'
          : 'Premium is closed source and injected through slots. Premium uses the Core crypto layer; standalone Premium full-system tests are only partially evidenced.',
      ],
      evidence: [
        ev('src/services/vaultExportService.ts; src/services/exportFileService.ts', 'exportVaultItems(), sanitizeExportFilename()', 'plaintext export', 'src/services/exportFileService.test.ts', de ? 'Nach lokalem Export liegt Verantwortung beim Nutzer/OS.' : 'After local export, responsibility moves to user/OS.', 'BELEGT'),
        ev('src/services/vaultRecoveryService.ts', 'resetLocalVaultStateAfterRemoteReset()', undefined, 'src/services/vaultRecoveryService.test.ts', de ? 'Provider-Backups/Logs sind nicht als sofort gelöscht belegt.' : 'Provider backups/logs are not evidenced as immediately deleted.', 'TEILWEISE'),
        ev('docs/archive/premium-service-boundary-2026-03.md; src/extensions/registry.ts', undefined, undefined, 'src/extensions/registry.test.ts', de ? 'Private Premium-Codeabdeckung bleibt NICHT BELEGT im öffentlichen Repo.' : 'Private Premium code coverage remains NOT EVIDENCED in the public repo.', 'TEILWEISE'),
      ],
    },
    {
      id: 'testing-limitations-claims-glossary',
      title: de ? '30-33. Verification, offene Risiken, Claims Matrix und Glossar' : '30-33. Verification, Open Risks, Claims Matrix, and Glossary',
      summary: de ? 'Die folgenden Tabellen markieren Status und Grenzen explizit.' : 'The following tables explicitly mark status and limits.',
      body: [
        de
          ? 'Known limitations: kein externer Audit, Same-Origin-XSS im entsperrten Web/PWA-Client, Malware/RAM/Clipboard, Trusted Types nicht enforced, kein Datei-Padding belegt, Rollback-Freshness-Grenzen, Premium-Gesamttests teilweise offen, Provider-Metadaten, Recovery-/Trustee-Risiken.'
          : 'Known limitations: no external audit, same-origin XSS in unlocked Web/PWA client, malware/RAM/clipboard, Trusted Types not enforced, no evidenced file padding, rollback freshness limits, Premium full tests partially open, provider metadata, recovery/trustee risks.',
      ],
      evidence: [
        ev('docs/SECURITY.md', undefined, undefined, undefined, de ? 'Kanonisches Modell, kein externes Audit-Siegel.' : 'Canonical model, not an external audit seal.', 'TEILWEISE'),
      ],
    },
  ];
}

function ev(file: string, functionName: string | undefined, dataFormat: string | undefined, tests: string | undefined, residualRisk: string, status: Status): Evidence {
  return { file, functionName, dataFormat, tests: tests ?? 'NICHT BELEGT', residualRisk, status };
}

function buildDataRows(language: 'de' | 'en'): MatrixRow[] {
  const de = language === 'de';
  return [
    row(['Vault Item Title', de ? 'Eintragstitel' : 'Item title', 'vault_items.encrypted_data', de ? 'Nein, neue Rows nutzen Platzhalter' : 'No, new rows use placeholder', 'Ja', 'AES-GCM sv-vault-v1 + AAD itemId', 'cryptoService.encryptVaultItem()', 'vaultItemCryptoStorage.test.ts', de ? 'Legacy-/Migrationsfelder möglich' : 'Legacy/migration fields possible'], 'BELEGT'),
    row(['Username', 'person@example.test', 'encrypted_data', 'Nein', 'Ja', 'AES-GCM', 'VaultItemData.username', 'vaultItemCryptoStorage.test.ts', de ? 'Im entsperrten Client sichtbar' : 'Visible in unlocked client'], 'BELEGT'),
    row(['Password', 'secret', 'encrypted_data', 'Nein', 'Ja', 'AES-GCM', 'VaultItemData.password', 'integration-crypto-pipeline.test.ts', de ? 'Clipboard/Export-Risiko' : 'Clipboard/export risk'], 'BELEGT'),
    row(['URL', 'https://example.test', 'encrypted_data / legacy website_url fallback', de ? 'Neue Rows: nein; Legacy-Fallback möglich' : 'New rows: no; legacy fallback possible', 'Ja', 'AES-GCM', 'VaultItemDialog.normalizeUrl()', 'VaultItemDialog.test.tsx', de ? 'URL kann beim Öffnen an Zielseite gehen' : 'URL can be sent to target when opened'], 'TEILWEISE'),
    row(['Notes', de ? 'Notiztext' : 'Note text', 'encrypted_data', 'Nein', 'Ja', 'AES-GCM', 'VaultItemData.notes', 'vaultItemCryptoStorage.test.ts', de ? 'Klartext-Export enthält Notes' : 'Plaintext export contains notes'], 'BELEGT'),
    row(['TOTP Secret', 'JBSWY3...', 'encrypted_data', 'Nein', 'Ja', 'AES-GCM', 'VaultItemData.totpSecret', 'vaultItemCryptoStorage.test.ts', de ? 'Entsperrter Client kann Codes erzeugen' : 'Unlocked client can generate codes'], 'BELEGT'),
    row(['TOTP issuer/label/algorithm/digits/period', 'GitHub / SHA1 / 6 / 30', 'encrypted_data', 'Nein', 'Ja', 'AES-GCM', 'VaultItemData.totp*', 'vaultItemCryptoStorage.test.ts', de ? 'item_type kann sichtbar sein' : 'item_type can be visible'], 'BELEGT'),
    row(['Categories', de ? 'Name, Icon, Farbe' : 'Name, icon, color', 'categories.name/icon/color', de ? 'Nein für verschlüsselte Felder' : 'No for encrypted fields', 'Ja', 'Encrypted category prefix + AES-GCM', 'cryptoService reEncryptVault()', 'vaultIntegrityService.test.ts', de ? 'Kategorie-ID/Zeilenstruktur sichtbar' : 'Category ID/row structure visible'], 'BELEGT'),
    row(['File Attachments', de ? 'Dateiinhalt' : 'File content', 'Supabase Storage chunks', 'Nein', 'Ja', 'Per-file key + chunk AES-GCM', 'docs/archive/premium-file-upload-e2ee.md', 'NICHT BELEGT im öffentlichen Repo', de ? 'Premium-Code privat; Größe/Zugriff sichtbar' : 'Premium code private; size/access visible'], 'TEILWEISE'),
    row(['File Attachment Metadata', de ? 'Name/MIME/Größe' : 'Name/MIME/size', 'encrypted manifest', de ? 'Laut archivierter Doku nein; technische Metadaten ja' : 'According to archived docs no; technical metadata yes', 'Ja', 'Encrypted manifest', 'docs/archive/premium-file-upload-e2ee.md', 'NICHT BELEGT im öffentlichen Repo', de ? 'Kein Padding belegt' : 'No padding evidenced'], 'TEILWEISE'),
    row(['Emergency Access Key Material', de ? 'Grantor Vault-Key Wrap' : 'Grantor vault-key wrap', 'emergency access tables', de ? 'Klartext nein; Status ja' : 'Plaintext no; status yes', 'Ja', 'Hybrid/PQ key wrapping', 'EMERGENCY_ACCESS.md; pqCryptoService.ts', 'security-rls-emergency-access.test.ts', de ? 'Trustee-Kompromiss' : 'Trustee compromise'], 'TEILWEISE'),
    row(['Sharing Data', de ? 'Collection membership' : 'Collection membership', 'shared collection tables', de ? 'Mitgliedschaft/Rollen ja' : 'Membership/roles yes', de ? 'Keys gewrappt' : 'Keys wrapped', 'RSA/PQ wrapping where implemented', 'SHARED_COLLECTIONS_ENCRYPTION.md', 'NICHT BELEGT vollständig', de ? 'Revocation-Grenzen' : 'Revocation limits'], 'TEILWEISE'),
    row(['Device Keys', de ? 'lokaler Device Key' : 'local device key', 'OS store / IndexedDB', de ? 'Server nein' : 'Server no', de ? 'lokal geschützt' : 'locally protected', 'HKDF device-key path', 'deviceKeyService.ts', 'deviceKeyService.test.ts', de ? 'Gerätekompromiss' : 'Device compromise'], 'BELEGT'),
    row(['Recovery/Backup Codes', de ? 'Einmalcodes' : 'One-time codes', '2FA tables', 'Nein', de ? 'Gehasht' : 'Hashed', 'Argon2id hash v3', 'twoFactorService.ts', 'twoFactorService.mock.test.ts', de ? 'Codeverlust/Diebstahl' : 'Code loss/theft'], 'BELEGT'),
    row(['Sessions', 'JWT / refresh token', 'Supabase/BFF/client storage', de ? 'Server ja' : 'Server yes', de ? 'Transport/Storage geschützt, nicht Vault-E2EE' : 'Transport/storage protected, not vault E2EE', 'Supabase session + cleanup', 'authSessionManager.ts', 'authSessionManager.test.ts', de ? 'Bearer-Token bis Ablauf' : 'Bearer token until expiry'], 'TEILWEISE'),
    row(['Logs', de ? 'Fehler-/Diagnosedaten' : 'Error/diagnostic data', 'console/server logs', de ? 'Technische Daten möglich' : 'Technical data possible', de ? 'Keine Vault-Secrets beabsichtigt' : 'No vault secrets intended', 'logger sanitize()', 'logger.ts', 'security-regression-suite.test.ts', de ? 'Neue Logsites müssen geprüft werden' : 'New log sites need review'], 'TEILWEISE'),
    row(['Exportdaten', 'CSV/JSON', de ? 'lokale Datei' : 'local file', de ? 'Nach Export ja' : 'After export yes', de ? 'Klartext-Export: nein' : 'Plaintext export: no', 'User action', 'vaultExportService.ts', 'exportFileService.test.ts', de ? 'Lokale Datei enthält Secrets' : 'Local file contains secrets'], 'BELEGT'),
    row(['Offline Cache', 'Snapshot', 'IndexedDB', 'Nein für Vault-Payloads', 'Ja', 'encrypted_data rows + local snapshot', 'offlineVaultService.ts', 'offlineVaultService.test.ts', de ? 'Lokaler Browser kompromittierbar' : 'Local browser can be compromised'], 'BELEGT'),
    row(['Integrity Baselines', 'Digests', 'local secret store / IndexedDB', 'Nein', 'Ja', 'Encrypted baseline envelope', 'vaultIntegrityService.ts', 'vaultIntegrityService.test.ts', de ? 'Freshness braucht Checkpoint' : 'Freshness needs checkpoint'], 'BELEGT'),
  ];
}

function buildTestRows(language: 'de' | 'en'): MatrixRow[] {
  const de = language === 'de';
  return [
    row(['Vault item crypto', 'vaultItemCryptoStorage.test.ts; integration-crypto-pipeline.test.ts', de ? 'Route /vault/settings bei Kontextänderungen' : '/vault/settings route for context changes', 'npx tsc --noEmit; npm run build', 'BELEGT', WHITEPAPER_LAST_UPDATED], 'BELEGT'),
    row(['OPAQUE/Auth', 'opaque-registration-flow.test.ts; auth-flow-hardening.test.ts', de ? 'Login/Reset manuell prüfen' : 'Manually check login/reset', 'npx tsc --noEmit', 'TEILWEISE', WHITEPAPER_LAST_UPDATED], 'TEILWEISE'),
    row(['2FA/Backup codes', 'twoFactorService.mock.test.ts; auth-session-cookie.test.ts', de ? '2FA UI flows' : '2FA UI flows', 'npx tsc --noEmit', 'TEILWEISE', WHITEPAPER_LAST_UPDATED], 'TEILWEISE'),
    row(['Offline/Integrity', 'offlineVaultService.test.ts; vaultIntegrityService.test.ts', de ? 'Offline sync conflict checks' : 'Offline sync conflict checks', 'npm run build', 'BELEGT', WHITEPAPER_LAST_UPDATED], 'BELEGT'),
    row(['Premium files', 'NICHT BELEGT im öffentlichen Repo', de ? 'Premium Build/Runtime nötig' : 'Premium build/runtime required', de ? 'nicht vollständig öffentlich belegbar' : 'not fully evidenced publicly', 'TEILWEISE', WHITEPAPER_LAST_UPDATED], 'TEILWEISE'),
    row(['XSS/CSP', 'security-regression-suite.test.ts; exportFileService.test.ts', de ? 'Browser-Konsole und CSP prüfen' : 'Check browser console and CSP', 'npm run build', 'TEILWEISE', WHITEPAPER_LAST_UPDATED], 'TEILWEISE'),
    row(['External audit', 'NICHT BELEGT', 'NICHT BELEGT', 'NICHT BELEGT', 'NICHT BELEGT', WHITEPAPER_LAST_UPDATED], 'NICHT BELEGT'),
  ];
}

function buildClaimRows(language: 'de' | 'en'): MatrixRow[] {
  const de = language === 'de';
  return [
    row([de ? 'Passwort verlässt Client nicht beim App-eigenen Login.' : 'Password does not leave client in app-owned login.', 'OPAQUE password login', 'Ja', 'Ja', 'Ja', 'Ja', 'opaqueService.ts; auth-session function', 'opaque-registration-flow.test.ts', de ? 'OAuth ist separat; TLS/Serverfunktion bleiben TCB.' : 'OAuth is separate; TLS/server function remain TCB.', 'BELEGT'], 'BELEGT'),
    row([de ? 'Vault Items sind clientseitig verschlüsselt.' : 'Vault items are client-side encrypted.', 'Core vault', 'Ja', 'Ja', 'Ja', 'Ja', 'cryptoService.encryptVaultItem()', 'vaultItemCryptoStorage.test.ts', de ? 'Entsperrter Client sieht Klartext.' : 'Unlocked client sees plaintext.', 'BELEGT'], 'BELEGT'),
    row([de ? 'Notes sind verschlüsselt.' : 'Notes are encrypted.', 'Notes fields', 'Ja', 'Ja', 'Ja', 'Ja', 'VaultItemData.notes', 'vaultItemCryptoStorage.test.ts', de ? 'Klartext-Export enthält Notes.' : 'Plaintext export contains notes.', 'BELEGT'], 'BELEGT'),
    row([de ? 'TOTP Secrets sind verschlüsselt.' : 'TOTP secrets are encrypted.', 'TOTP item payload', 'Ja', 'Ja', 'Ja', 'Premium optional', 'VaultItemData.totpSecret', 'vaultItemCryptoStorage.test.ts', de ? 'TOTP-Code lokal im entsperrten Zustand berechenbar.' : 'TOTP code is locally computable when unlocked.', 'BELEGT'], 'BELEGT'),
    row([de ? 'Dateianhänge sind clientseitig E2EE.' : 'File attachments are client-side E2EE.', 'Premium files', 'Ja', 'Ja', 'Ja', 'Ja', 'docs/archive/premium-file-upload-e2ee.md', 'NICHT BELEGT vollständig öffentlich', de ? 'Premium-Code privat; kein Padding belegt.' : 'Premium code private; no padding evidenced.', 'TEILWEISE'], 'TEILWEISE'),
    row([de ? 'Server kann Dateien nicht lesen.' : 'Server cannot read files.', 'Premium file content', 'Ja', 'Ja', 'Ja', 'Ja', 'docs/archive/premium-file-upload-e2ee.md', 'NICHT BELEGT vollständig öffentlich', de ? 'Server sieht technische Metadaten.' : 'Server sees technical metadata.', 'TEILWEISE'], 'TEILWEISE'),
    row([de ? 'PQ nur für Sharing/Emergency Key-Wrapping.' : 'PQ only for sharing/emergency key wrapping.', 'Hybrid/PQ paths', 'Ja', 'Ja', 'Ja', 'Ja', 'pqCryptoService.ts', 'pqCryptoService.test.ts', de ? 'Nicht allgemeine Vault-Datenverschlüsselung.' : 'Not general vault data encryption.', 'BELEGT'], 'BELEGT'),
    row([de ? 'Emergency Access ist alternativer Key-Wrapping-Pfad.' : 'Emergency Access is an alternative key-wrapping path.', 'Premium emergency', 'Ja', 'Ja', 'Ja', 'Ja', 'docs/archive/EMERGENCY_ACCESS.md', 'security-rls-emergency-access.test.ts', de ? 'Trustee wird Teil der TCB.' : 'Trustee becomes part of TCB.', 'TEILWEISE'], 'TEILWEISE'),
    row([de ? 'Browser/PWA schützt nicht gegen Same-Origin-XSS im entsperrten Zustand.' : 'Browser/PWA does not protect against same-origin XSS when unlocked.', 'Web/PWA', 'Ja', 'Ja', de ? 'anders, aber entsperrter Client bleibt Risiko' : 'different, but unlocked client remains risk', 'Ja', 'docs/archive/xss-same-origin-hardening-2026-04-28.md', 'NICHT BELEGT als vollständiger Test', de ? 'Client-Kompromiss bleibt Vollrisiko.' : 'Client compromise remains full risk.', 'BELEGT'], 'BELEGT'),
    row([de ? 'Account Delete entfernt user-owned Daten.' : 'Account delete removes user-owned data.', 'Account data', 'Ja', 'Ja', 'Ja', 'Ja', 'delete RPC/migrations', 'vault-reset-rpc-contract.test.ts', de ? 'Backups/Logs nicht sofort physisch belegt.' : 'Backups/logs not evidenced as immediately physical deleted.', 'TEILWEISE'], 'TEILWEISE'),
    row([de ? 'Kein Legacy-Passwort-Fallback.' : 'No legacy password fallback.', 'App password login', 'Ja', 'Ja', 'Ja', 'Ja', 'auth-session edge function', 'auth-flow-hardening.test.ts', de ? 'OAuth ist anderer Pfad.' : 'OAuth is a different path.', 'BELEGT'], 'BELEGT'),
  ];
}

function buildGlossaryRows(language: 'de' | 'en'): MatrixRow[] {
  const de = language === 'de';
  return [
    row(['Zero-Knowledge', de ? 'Server soll Vault-Klartext nicht kennen; Metadaten bleiben möglich.' : 'Server should not know vault plaintext; metadata can remain.']),
    row(['E2EE', de ? 'Verschlüsselung und Entschlüsselung an Endpunkten; Server speichert Ciphertext.' : 'Encryption and decryption at endpoints; server stores ciphertext.']),
    row(['OPAQUE', de ? 'Asymmetrisches PAKE für Passwortlogin ohne Passwortübertragung an den Server.' : 'Asymmetric PAKE for password login without sending the password to the server.']),
    row(['AAD / AEAD', de ? 'Zusatzdaten, die authentifiziert, aber nicht verschlüsselt werden; AES-GCM ist AEAD.' : 'Additional data that is authenticated but not encrypted; AES-GCM is AEAD.']),
    row(['AES-GCM', de ? 'Authentifizierte symmetrische Verschlüsselung mit IV und Auth Tag.' : 'Authenticated symmetric encryption with IV and auth tag.']),
    row(['Argon2id', de ? 'Passwort-KDF mit Speicherhärte.' : 'Memory-hard password KDF.']),
    row(['HKDF', de ? 'Key-Derivation zur Domain-Separation und Kombination von Key-Material.' : 'Key derivation for domain separation and key-material combination.']),
    row(['Vault/User/Wrap/Device/File Key', de ? 'Getrennte Rollen für Vault-Daten, gewrapptes User-Key-Material, Wrap-Domain, Gerät und Datei.' : 'Separate roles for vault data, wrapped user-key material, wrap domain, device, and file.']),
    row(['Manifest', de ? 'Datei-Metadatenstruktur, bei Premium-Dateien laut Doku verschlüsselt.' : 'File metadata structure, encrypted for Premium files according to docs.']),
    row(['Ciphertext', de ? 'Verschlüsselte Daten inklusive Auth Tag/Envelope.' : 'Encrypted data including auth tag/envelope.']),
    row(['Quarantine', de ? 'Isolation verdächtiger Vault-Einträge nach Integrity-Drift.' : 'Isolation of suspicious vault items after integrity drift.']),
    row(['Trustee / Emergency Access', de ? 'Vertrauensperson und alternativer Vault-Key-Wrapping-Pfad.' : 'Trusted person and alternative vault-key wrapping path.']),
    row(['PQ / Hybrid', de ? 'Kombination klassischer und post-quantenorientierter Verfahren für Key-Wrapping-Pfade.' : 'Combination of classical and post-quantum-oriented methods for key-wrapping paths.']),
  ];
}

function row(cells: string[], status?: Status): MatrixRow {
  return { cells, status };
}

function Matrix({ headers, rows }: { headers: string[]; rows: MatrixRow[] }) {
  return (
    <div className="overflow-x-auto rounded-lg border">
      <table className="w-full min-w-[900px] border-collapse text-sm">
        <thead className="bg-muted/60">
          <tr>
            {headers.map((header) => (
              <th key={header} className="border-b px-3 py-2 text-left font-semibold text-foreground">
                {header}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((matrixRow, rowIndex) => (
            <tr key={`${matrixRow.cells[0]}-${rowIndex}`} className="align-top">
              {matrixRow.cells.map((cell, cellIndex) => (
                <td key={`${cellIndex}-${cell}`} className="border-b px-3 py-2 text-muted-foreground">
                  {cell}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export default function SecurityWhitepaper() {
  const { i18n } = useTranslation();
  const language = normalizeLanguage(i18n.language);
  const content = useMemo(() => getContent(language), [language]);
  const showWebsiteChrome = shouldShowWebsiteChrome();

  useEffect(() => {
    window.scrollTo({ top: 0, left: 0, behavior: 'instant' });
  }, []);

  const structuredData = {
    ...createArticleStructuredData({
      title: 'Security Whitepaper - Singra Vault',
      description: 'Code-backed security whitepaper for Singra Vault.',
      path: '/security',
    }),
    ...createBreadcrumbStructuredData([
      { name: 'Home', path: '/' },
      { name: 'Security Whitepaper', path: '/security' },
    ]),
  };

  return (
    <div className="min-h-screen bg-background flex flex-col">
      <SEO
        title="Security Whitepaper"
        description="Code-backed technical security whitepaper for Singra Vault."
        path="/security"
        keywords={['Security Whitepaper', 'OPAQUE', 'AES-GCM', 'Argon2id', 'Zero-Knowledge', 'Singra Vault']}
        structuredData={structuredData}
      />
      {showWebsiteChrome ? (
        <Header />
      ) : (
        <DesktopSubpageHeader title={content.title} description={content.subtitle} />
      )}

      <main className={`flex-grow px-4 sm:px-6 lg:px-8 ${showWebsiteChrome ? 'py-28' : 'py-6'}`}>
        <article className="mx-auto w-full max-w-6xl space-y-10">
          <header className="space-y-5 border-b pb-8">
            <div className="flex items-center gap-3 text-primary">
              <Shield className="h-6 w-6" />
              <span className="text-sm font-semibold uppercase tracking-wide">Security Whitepaper</span>
            </div>
            <div className="space-y-3">
              <h1 className="text-3xl font-bold tracking-tight sm:text-4xl">{content.title}</h1>
              <p className="max-w-3xl text-base leading-7 text-muted-foreground">{content.subtitle}</p>
            </div>
            <div className="flex flex-wrap gap-2 text-sm">
              <Badge variant="outline">Whitepaper {WHITEPAPER_VERSION}</Badge>
              <Badge variant="outline">Updated {WHITEPAPER_LAST_UPDATED}</Badge>
              <Badge variant="outline">{`App ${APP_VERSION_DISPLAY}`}</Badge>
              <Badge variant="secondary">{`Version source: ${APP_VERSION_SOURCE}`}</Badge>
            </div>
            <div className="rounded-lg border border-amber-500/40 bg-amber-500/10 p-4 text-sm leading-6">
              <div className="mb-1 flex items-center gap-2 font-semibold text-foreground">
                <AlertTriangle className="h-4 w-4" />
                Audit Status
              </div>
              <p className="text-muted-foreground">{content.auditStatus}</p>
            </div>
            <p className="text-sm leading-6 text-muted-foreground">{content.scope}</p>
          </header>

          <nav className="rounded-lg border bg-muted/20 p-4">
            <h2 className="mb-3 text-lg font-semibold">Inhaltsverzeichnis / Table of Contents</h2>
            <ol className="grid gap-2 text-sm sm:grid-cols-2">
              {content.sections.map((section) => (
                <li key={section.id}>
                  <a href={`#${section.id}`} className="text-muted-foreground underline-offset-4 hover:text-foreground hover:underline">
                    {section.title}
                  </a>
                </li>
              ))}
            </ol>
          </nav>

          {content.sections.map((section) => (
            <section key={section.id} id={section.id} className="scroll-mt-24 space-y-4 border-b pb-8">
              <div className="space-y-2">
                <h2 className="text-2xl font-semibold tracking-tight">{section.title}</h2>
                <p className="text-muted-foreground">{section.summary}</p>
              </div>
              <div className="space-y-3">
                {section.body.map((paragraph) => (
                  <p key={paragraph} className="leading-7 text-muted-foreground">
                    {paragraph}
                  </p>
                ))}
              </div>
              <div className="rounded-lg border bg-muted/20 p-4">
                <h3 className="mb-3 text-sm font-semibold uppercase tracking-wide text-muted-foreground">Codebelege / Evidence</h3>
                <div className="grid gap-3">
                  {section.evidence.map((evidence) => (
                    <div key={`${section.id}-${evidence.file}-${evidence.functionName ?? ''}`} className="space-y-1 rounded-md border bg-background p-3 text-sm">
                      <div className="flex flex-wrap items-center gap-2">
                        {statusBadge(evidence.status)}
                        <code className="text-xs">{evidence.file}</code>
                      </div>
                      {evidence.functionName ? <p><span className="font-medium">Funktion:</span> {evidence.functionName}</p> : null}
                      {evidence.dataFormat ? <p><span className="font-medium">Datenformat:</span> {evidence.dataFormat}</p> : null}
                      <p><span className="font-medium">Test:</span> {evidence.tests}</p>
                      <p><span className="font-medium">Restrisiko:</span> {evidence.residualRisk}</p>
                    </div>
                  ))}
                </div>
              </div>
            </section>
          ))}

          <section id="data-table" className="scroll-mt-24 space-y-4">
            <h2 className="text-2xl font-semibold">Datenklassen und Sichtbarkeit / Data Visibility</h2>
            <Matrix
              headers={['Datentyp', 'Beispiel', 'Wo gespeichert', 'Klartext sichtbar für Server?', 'Verschlüsselt?', 'Schlüssel/Mechanismus', 'Codebeleg', 'Tests', 'Restrisiko']}
              rows={content.dataRows}
            />
          </section>

          <section id="testing-matrix" className="scroll-mt-24 space-y-4">
            <h2 className="text-2xl font-semibold">Security Testing / Verification</h2>
            <Matrix
              headers={['Bereich', 'Testdateien', 'Manuelle Tests', 'Build/Typecheck/Lint', 'Status', 'Letzter Prüfstand']}
              rows={content.testRows}
            />
          </section>

          <section id="claims-matrix" className="scroll-mt-24 space-y-4">
            <h2 className="text-2xl font-semibold">Security Claims Matrix</h2>
            <Matrix
              headers={['Claim', 'Scope', 'Web?', 'PWA?', 'Tauri?', 'Premium?', 'Codebeleg', 'Testbeleg', 'Einschränkungen', 'Status']}
              rows={content.claimRows}
            />
          </section>

          <section id="glossary" className="scroll-mt-24 space-y-4">
            <h2 className="text-2xl font-semibold">Glossar / Glossary</h2>
            <Matrix headers={['Begriff', 'Bedeutung']} rows={content.glossaryRows} />
          </section>

          <section id="references" className="scroll-mt-24 space-y-4 border-t pt-8">
            <h2 className="text-2xl font-semibold">Referenzen / References</h2>
            <div className="grid gap-2 text-sm">
              {references.map(([label, href]) => (
                <a key={href} href={href} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-2 text-muted-foreground hover:text-foreground">
                  <ExternalLink className="h-4 w-4" />
                  {label}
                </a>
              ))}
            </div>
            <p className="text-sm text-muted-foreground">
              <Link to="/privacy" className="underline underline-offset-4 hover:text-foreground">Privacy / Datenschutz</Link>
            </p>
          </section>
        </article>
      </main>
      {showWebsiteChrome && <Footer />}
    </div>
  );
}
