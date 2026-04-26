import { describe, expect, it } from 'vitest';

import {
  decryptVaultItem,
  encryptVaultItem,
  type VaultItemData,
} from './cryptoService';

describe('vault item encrypted_data storage contract', () => {
  it('stores notes, passwords, and TOTP secrets only inside the encrypted vault item payload', async () => {
    const key = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt'],
    );
    const itemId = '11111111-1111-4111-8111-111111111111';
    const sensitivePayload: VaultItemData = {
      title: 'Mail',
      itemType: 'totp',
      username: 'person@example.test',
      password: 'correct horse battery staple',
      notes: 'private recovery notes',
      totpSecret: 'JBSWY3DPEHPK3PXP',
    };

    const encryptedData = await encryptVaultItem(sensitivePayload, key, itemId);

    expect(encryptedData).not.toContain(sensitivePayload.password);
    expect(encryptedData).not.toContain(sensitivePayload.notes);
    expect(encryptedData).not.toContain(sensitivePayload.totpSecret);
    await expect(decryptVaultItem(encryptedData, key, 'other-item-id')).rejects.toThrow();
    await expect(decryptVaultItem(encryptedData, key, itemId)).resolves.toMatchObject(sensitivePayload);
  });
});
