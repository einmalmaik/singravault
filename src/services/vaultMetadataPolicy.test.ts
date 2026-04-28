import { describe, expect, it } from 'vitest';

import {
  ENCRYPTED_CATEGORY_PREFIX,
  ENCRYPTED_ITEM_TITLE_PLACEHOLDER,
  isEncryptedCategoryMetadataValue,
  isNeutralVaultItemServerMetadata,
  neutralizeVaultItemServerMetadata,
} from './vaultMetadataPolicy';

describe('vault metadata zero-knowledge policy', () => {
  it('neutralizes every sensitive server-visible vault item metadata field', () => {
    const row = neutralizeVaultItemServerMetadata({
      id: 'item-1',
      user_id: 'user-1',
      vault_id: 'vault-1',
      title: 'Payroll admin login',
      website_url: 'https://bank.example.test',
      icon_url: 'https://bank.example.test/favicon.ico',
      item_type: 'totp',
      is_favorite: true,
      category_id: 'finance-category',
      sort_order: 7,
      last_used_at: '2026-04-28T10:00:00.000Z',
      encrypted_data: 'sv-vault-v1:ciphertext',
    });

    expect(row).toMatchObject({
      title: ENCRYPTED_ITEM_TITLE_PLACEHOLDER,
      website_url: null,
      icon_url: null,
      item_type: 'password',
      is_favorite: false,
      category_id: null,
      sort_order: null,
      last_used_at: null,
    });
    expect(isNeutralVaultItemServerMetadata(row)).toBe(true);

    const serialized = JSON.stringify(row);
    for (const sensitive of [
      'Payroll admin login',
      'bank.example.test',
      'totp',
      'finance-category',
      '2026-04-28T10:00:00.000Z',
    ]) {
      expect(serialized).not.toContain(sensitive);
    }
  });

  it('requires category metadata to carry the encrypted category envelope prefix', () => {
    expect(isEncryptedCategoryMetadataValue(`${ENCRYPTED_CATEGORY_PREFIX}ciphertext`)).toBe(true);
    expect(isEncryptedCategoryMetadataValue('Finance')).toBe(false);
    expect(isEncryptedCategoryMetadataValue(null)).toBe(false);
  });
});
