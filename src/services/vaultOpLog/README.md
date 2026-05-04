# `vaultOpLog/` — Operation-Log-Based Vault Integrity (Phase 1)

Pure, product-decoupled crypto and policy modules for the new vault
integration model defined in
[`docs/adr/0004-vault-operation-log-and-record-integrity.md`](../../../docs/adr/0004-vault-operation-log-and-record-integrity.md).

Phase 1 ships three services plus their shared primitives. None of
these modules is imported from any product runtime path. They are the
byte-reproducible building blocks the later phases will depend on.

## Files

| File | Responsibility |
|---|---|
| `types.ts` | Shared public types: record types, record version, AAD shape, operation shape, device trust shape, result types. |
| `canonicalJson.ts` | `canonicalizeVaultStructure` — deterministic UTF-8 byte encoding for all signed / hashed structures. Rejects `undefined`, `NaN`, infinities, symbols, functions and bigints. NFC-normalises every string. Sorts object keys by UTF-8 byte sequence. Also exposes `encodeBase64Url` / `decodeBase64Url` for key / signature / hash wire form. |
| `recordAad.ts` | `buildRecordAad` / `encodeRecordAadBytes` / `recordAadsEqual` — the canonical AAD v1 structure bound to `vaultId`, `recordId`, `recordType`, `recordVersion`, `keyVersion`, `encryptionSchema`. |
| `recordHashes.ts` | `computeAadHash`, `computeCiphertextHash`, `computeOpHash`, `computeVaultHead` — the hash contracts from ADR-0004 §6.4 and §19.1. All inputs are canonicalised before hashing. |
| `cryptoRecordService.ts` | Record key derivation (HKDF-SHA-256 from a vault encryption key), AEAD seal / open with AAD context binding, plaintext schema gate. Refuses to decrypt if any metadata (vaultId, recordId, recordType, recordVersion, keyVersion, encryptionSchema, aadHash, ciphertextHash) does not match the record-as-received. |
| `operationSigningService.ts` | Canonicalise an operation, compute `opHash`, sign with a device's WebCrypto ECDSA P-256 private key, verify a remote operation's signature against a stored SPKI public key, reject any tampered signed field. |
| `deviceTrustService.ts` | Classify an operation's author as `trusted`, `revoked` or `unknown` given a trust list and the operation's `trust_epoch` / `created_at_client`. Pure function of input. No storage. |
| `index.ts` | Barrel. |

## Testing

Every module has a matching `__tests__/<module>.test.ts` covering:

- fixed byte vectors for every shape that is signed or hashed,
- symmetric equality (same input → same bytes) and sensitivity
  (one-byte input change → different bytes, signature or hash),
- AEAD round-trip plus rejection on tampered AAD or ciphertext,
- signature verification plus rejection on tampered signed body,
- trust classification for `trusted`, `revoked`, `unknown`, and
  revoke-time ordering.

Test material is generated inline with `crypto.getRandomValues`. No
real secret, real vault, real password or real user data is read.

## Non-goals for phase 1

- No vault provider integration.
- No server RPC wrapper.
- No storage adapter.
- No migration logic.
- No UI.

Those arrive in later phases.

## Rules for future phases

Any change to the byte layout of `canonicalizeVaultStructure`,
`RecordAAD`, `VaultOperationSignedBody`, or the hash / signing
contracts is a **breaking protocol change** and MUST ship as a new
schema version (for example `record-aad-v2`,
`device-signature-v2`) together with a versioned migration, never as
a silent bump of the v1 layout. The `testVectors` file is a byte
pin. Failing vectors mean the contract shifted.
