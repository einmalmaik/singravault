import { describe, expect, it } from 'vitest';

import {
  computeVaultRecoveryCodeCommitment,
  formatVaultRecoveryCodesDownload,
  isNormalizedVaultRecoveryCode,
  normalizeVaultRecoveryCode,
} from '../vaultRecoveryCodeService';

describe('vaultRecoveryCodeService', () => {
  it('normalizes formatted recovery codes without exposing alternate meanings', () => {
    const normalized = normalizeVaultRecoveryCode('svr-ABCDE-FGHJK-LMNPQ-RSTVW-XYZ234');
    const bodyStartingWithPrefix = normalizeVaultRecoveryCode('SVRABCDEFGHJKLMNPQRSTVWXYZ');

    expect(normalized).toBe('ABCDEFGHJKLMNPQRSTVWXYZ234');
    expect(isNormalizedVaultRecoveryCode(normalized)).toBe(true);
    expect(bodyStartingWithPrefix).toBe('SVRABCDEFGHJKLMNPQRSTVWXYZ');
    expect(isNormalizedVaultRecoveryCode(bodyStartingWithPrefix)).toBe(true);
  });

  it('binds commitments to vault, set and code', async () => {
    const base = {
      vaultId: 'vault-1',
      setId: 'set-1',
      recoveryCode: 'SVR-ABCDE-FGHJK-LMNPQ-RSTVW-XYZ234',
    };

    const commitment = await computeVaultRecoveryCodeCommitment(base);
    await expect(computeVaultRecoveryCodeCommitment({ ...base, setId: 'set-2' }))
      .resolves
      .not
      .toBe(commitment);
    await expect(computeVaultRecoveryCodeCommitment({ ...base, recoveryCode: 'SVR-ABCDE-FGHJK-LMNPQ-RSTVW-XYZ235' }))
      .resolves
      .not
      .toBe(commitment);
  });

  it('formats the download without hidden client-side metadata', () => {
    const content = formatVaultRecoveryCodesDownload({
      vaultId: 'vault-1',
      setId: 'set-1',
      createdAt: '2026-05-11T10:00:00.000Z',
      codes: ['SVR-ABCDE-FGHJK-LMNPQ-RSTVW-XYZ234'],
      language: 'de',
    });

    expect(content.charCodeAt(0)).toBe(0xFEFF);
    expect(content).toContain('Recovery-Codes für Gerätezugriff');
    expect(content).toContain('vertrauenswürdiges Gerät');
    expect(content).toContain('SVR-ABCDE-FGHJK-LMNPQ-RSTVW-XYZ234');
    expect(content).toContain('Support kann diese Codes nicht wiederherstellen');
    expect(content).not.toContain('private');
  });

  it('formats the download in English for non-German locales', () => {
    const content = formatVaultRecoveryCodesDownload({
      vaultId: 'vault-1',
      setId: 'set-1',
      createdAt: '2026-05-11T10:00:00.000Z',
      codes: ['SVR-ABCDE-FGHJK-LMNPQ-RSTVW-XYZ234'],
      language: 'en-US',
    });

    expect(content).toContain('recovery codes for device access');
    expect(content).toContain('Created: 2026-05-11T10:00:00.000Z');
    expect(content).toContain('Singra Support cannot restore these codes');
  });
});
