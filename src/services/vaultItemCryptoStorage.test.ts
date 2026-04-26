import { describe, expect, it } from 'vitest';

import {
  decryptVaultItem,
  encryptVaultItem,
  type VaultItemData,
} from './cryptoService';

describe('vault item encrypted_data storage contract', () => {
  it.each([
    {
      payload: {
        title: 'Mail',
        itemType: 'password' as const,
        username: 'person@example.test',
        password: 'correct horse battery staple',
        notes: 'password entry private recovery notes',
      },
      secrets: [
        'person@example.test',
        'correct horse battery staple',
        'password entry private recovery notes',
      ],
    },
    {
      payload: {
        title: 'Authenticator',
        itemType: 'totp' as const,
        notes: 'totp entry private recovery notes',
        totpSecret: 'JBSWY3DPEHPK3PXP',
        totpIssuer: 'GitHub',
        totpLabel: 'person@example.test',
        totpAlgorithm: 'SHA512' as const,
        totpDigits: 8 as const,
        totpPeriod: 60,
      },
      secrets: [
        'totp entry private recovery notes',
        'JBSWY3DPEHPK3PXP',
        'GitHub',
        'person@example.test',
        'SHA512',
      ],
    },
    {
      payload: {
        title: 'Secure note',
        itemType: 'note' as const,
        notes: 'standalone note with private recovery material',
      },
      secrets: [
        'standalone note with private recovery material',
      ],
    },
  ])('stores notes only inside encrypted_data for $payload.itemType items', async ({ payload, secrets }) => {
    const key = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt'],
    );
    const itemId = '11111111-1111-4111-8111-111111111111';
    const sensitivePayload: VaultItemData = payload;

    const encryptedData = await encryptVaultItem(sensitivePayload, key, itemId);

    for (const secret of secrets) {
      expect(encryptedData).not.toContain(secret);
    }
    await expect(decryptVaultItem(encryptedData, key, 'other-item-id')).rejects.toThrow();
    await expect(decryptVaultItem(encryptedData, key, itemId)).resolves.toMatchObject(sensitivePayload);
  });
});
