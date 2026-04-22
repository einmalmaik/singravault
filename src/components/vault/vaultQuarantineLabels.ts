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
