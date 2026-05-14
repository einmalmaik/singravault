import { describe, expect, it } from "vitest";

import {
  decryptVaultItem,
  decryptVaultItemForMigration,
  decryptWithSharedKey,
  encrypt,
  encryptVaultItem,
  encryptWithSharedKey,
  generateSharedKey,
  importMasterKey,
  VAULT_ITEM_ENVELOPE_V1_PREFIX,
  type VaultItemData,
} from "@/services/cryptoService";

async function testVaultKey(): Promise<CryptoKey> {
  return importMasterKey(new Uint8Array(32).fill(42));
}

function testItem(title = "Testeintrag"): VaultItemData {
  return {
    title,
    username: "user@example.test",
    password: "synthetic-password-fixture",
    websiteUrl: "https://example.test",
    notes: "synthetic fixture only",
    itemType: "password",
  };
}

describe("cryptoService vault item envelopes", () => {
  it("encrypts current vault items as versioned AAD-bound envelopes", async () => {
    const key = await testVaultKey();
    const entryId = "entry-a";
    const encrypted = await encryptVaultItem(testItem(), key, entryId);

    expect(encrypted.startsWith(VAULT_ITEM_ENVELOPE_V1_PREFIX)).toBe(true);
    await expect(decryptVaultItem(encrypted, key, "entry-b")).rejects.toThrow();
    await expect(decryptVaultItem(encrypted, key, entryId)).resolves.toMatchObject({
      title: "Testeintrag",
      itemType: "password",
    });
  });

  it("fails closed for unsupported vault item envelope versions", async () => {
    const key = await testVaultKey();

    await expect(
      decryptVaultItem("sv-vault-v99:opaque-test-payload", key, "entry-a"),
    ).rejects.toThrow("Unsupported vault item encryption envelope version");
  });

  it("only permits legacy no-AAD vault item reads through the migration path", async () => {
    const key = await testVaultKey();
    const legacyCiphertext = await encrypt(JSON.stringify(testItem("Legacy")), key);

    await expect(decryptVaultItem(legacyCiphertext, key, "entry-a")).rejects.toThrow(
      "Legacy vault item without AAD requires migration.",
    );

    await expect(decryptVaultItemForMigration(legacyCiphertext, key, "entry-a")).resolves.toMatchObject({
      data: { title: "Legacy" },
      legacyEnvelopeUsed: true,
      legacyNoAadFallbackUsed: true,
    });
  });
});

describe("cryptoService shared item AAD", () => {
  it("binds shared item ciphertexts to their AAD context", async () => {
    const sharedKey = await generateSharedKey();
    const encrypted = await encryptWithSharedKey(testItem("Shared"), sharedKey, "shared-entry-a");

    await expect(decryptWithSharedKey(encrypted, sharedKey, "shared-entry-b")).rejects.toThrow(
      "Shared item decryption failed with the required AAD context.",
    );
    await expect(decryptWithSharedKey(encrypted, sharedKey, "shared-entry-a")).resolves.toMatchObject({
      title: "Shared",
    });
  });
});
