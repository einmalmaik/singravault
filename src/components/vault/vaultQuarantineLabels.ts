import type { QuarantinedVaultItem } from '@/services/vaultIntegrityService';

type Translate = (key: string, options?: { defaultValue?: string }) => string;

export function getQuarantineReasonLabel(
  reason: QuarantinedVaultItem['reason'],
  t: Translate,
): string {
  switch (reason) {
    case 'ciphertext_changed':
      return t('vault.integrity.reasonCiphertextChanged', {
        defaultValue: 'Verschlüsselter Inhalt wurde verändert.',
      });
    case 'aead_auth_failed':
      return t('vault.integrity.reasonAeadAuthFailed', {
        defaultValue: 'Die kryptografische Authentifizierung des Eintrags ist fehlgeschlagen.',
      });
    case 'item_envelope_malformed':
      return t('vault.integrity.reasonItemEnvelopeMalformed', {
        defaultValue: 'Der verschlüsselte Eintrags-Umschlag ist beschädigt.',
      });
    case 'item_aad_mismatch':
      return t('vault.integrity.reasonItemAadMismatch', {
        defaultValue: 'Der Eintrag passt nicht zu seinem kryptografischen Kontext.',
      });
    case 'item_manifest_hash_mismatch':
      return t('vault.integrity.reasonItemManifestHashMismatch', {
        defaultValue: 'Der Eintrag passt nicht zum authentifizierten Manifest.',
      });
    case 'item_revision_replay':
      return t('vault.integrity.reasonItemRevisionReplay', {
        defaultValue: 'Der Eintrag hat eine unerwartet alte Revision.',
      });
    case 'item_key_id_mismatch':
      return t('vault.integrity.reasonItemKeyIdMismatch', {
        defaultValue: 'Der Eintrag wurde mit einem unerwarteten Schlüsselkontext gefunden.',
      });
    case 'duplicate_active_item_record':
      return t('vault.integrity.reasonDuplicateActiveItemRecord', {
        defaultValue: 'Für diesen Eintrag existieren mehrere aktive Server-Datensätze.',
      });
    case 'missing_on_server':
      return t('vault.integrity.reasonMissingOnServer', {
        defaultValue: 'Der Eintrag fehlt im aktuellen Tresorstand.',
      });
    case 'unknown_on_server':
      return t('vault.integrity.reasonUnknownOnServer', {
        defaultValue: 'Ein unbekannter Eintrag wurde ohne vertrauenswürdige Baseline gefunden.',
      });
    default:
      return t('vault.integrity.reasonUnknown', {
        defaultValue: 'Der Eintrag konnte nicht mehr als vertrauenswürdig bestätigt werden.',
      });
  }
}
