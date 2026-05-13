# ADR-0004: Vault Operation Log, Record Integrity and Device Trust

## Status

Proposed. Accepted for implementation as a phased feature branch
(`feature/vault-operation-log-quarantine-integrity`). Supersedes ADR-0003
(Vault Integrity & Quarantine V2) once the full migration is complete.
ADR-0003 remains in force for the R3 compatibility path and the existing
Manifest V2 runtime until every phase described below has landed, passed
runtime verification on Web and Tauri, and the legacy paths have been
removed.

## Context

ADR-0003 introduced Item-Envelope V2 and Manifest V2 to reduce false
positives from the R3 integrity path. It did not eliminate the underlying
trust model problems that still exist in the product today:

- The integration source is still a server snapshot compared against a
  local baseline / authenticated manifest, not an append-only signed
  history of what each trusted device actually did.
- Direct writes to `public.vault_items` and `public.categories` still
  exist as legitimate runtime paths next to the `apply_vault_mutation_v2`
  CAS RPC.
- The runtime uses time-window heuristics to decide whether a recent
  local write should still be considered authoritative
  (`LOCAL_WRITE_CACHE_TTL_MS = 60_000` in
  `src/services/offlineVaultService.ts`).
- A single broken category can still put the vault into a degraded state
  that effectively blocks the whole list view.
- Rebaseline logic treats an unknown but decryptable remote change as a
  valid reason to advance the local trust root, even though decryptability
  alone does not prove device authorship.
- Device trust is effectively derived from being able to log in to the
  account plus holding the master password / device key / passkey PRF,
  not from an explicit per-device signature trust root.

The new model makes the server a pure transport, storage and ordering
service. Every legitimate change becomes a signed, versioned operation
authored by a trusted device and verified locally before the affected
record is ever decrypted, rendered, autofilled or exported.

This ADR defines the target architecture, the cryptographic contracts,
the data model and the migration strategy. It does not yet land any
destructive change. The runtime continues to use the existing R3/V2 path
until each phase in the migration plan has been integrated, tested and
verified in Web and Tauri.

## Decision

Introduce a new integration layer under `src/services/vaultOpLog/` that
replaces the R3 and Manifest V2 trust roots with a signed operation log
and per-record AEAD envelopes whose additional authenticated data binds
them to a specific vault, record id, record type, record version, key
version and encryption schema.

### Trust root

The trust root is a device-trust structure per vault. A device is only
trusted for a vault if it appears in that vault's `trusted_devices` list
with status `trusted`. Being authenticated against Supabase does not
grant device trust. The master password, passkey PRF and device key
protect the vault encryption key but do not sign operations. Operation
signatures come from a per-device signing key that never leaves the
device in plaintext.

### Integration source

Integration is driven exclusively by the operation log. A record is
considered legitimate only if there is a chain of signed operations
from trusted devices that produces exactly its current `ciphertext_hash`
and `aad_hash`. The server may reorder, withhold or re-serve rows; it
cannot mint a new trusted state.

### Server role

The server is a transport, ordering and quota service. It:

- stores operations and records,
- enforces vault / account access and RLS,
- enforces `op_id` uniqueness and idempotent retry equality,
- rejects operations that violate size or rate limits,
- persists server-assigned `received_at_server` and
  `server_updated_at` as data, never as a trust signal.

It does not:

- know any secret key,
- compare plaintexts,
- derive trust from session state,
- silently delete rows.

### Record shape

Every vault entity — item, category, attachment metadata, attachment
chunk, manifest, tombstone — is a `VaultRecordRow` in a single
`vault_records` table. Every mutation is a `VaultOperationRow` in
`vault_operations`. Device trust is recorded in
`vault_device_trust_records`. The shapes follow the concept document
(section 4) exactly.

### Cryptographic contracts

The following contracts are normative for this ADR and for every phase
that follows. Any deviation requires a follow-up ADR.

#### 1. Canonicalization (`canon-v1`)

All security-relevant JSON structures (AAD, signed operation bodies,
hash inputs, snapshot bodies) are serialised with a single
`canonicalizeVaultStructure` function under
`src/services/vaultOpLog/canonicalJson.ts`. The function:

- rejects values of type `undefined`, `Symbol`, `Function` or `BigInt`
  anywhere in the tree,
- rejects `NaN`, `+Infinity`, `-Infinity`,
- preserves `null` explicitly and does not drop `null` fields,
- sorts object keys by their UTF-8 byte sequence, not by locale,
- applies Unicode NFC normalisation to every string value and object
  key,
- serialises arrays in their given order,
- emits numbers as JSON integers when they are safe integers and as
  finite decimal strings in shortest-round-trip form otherwise,
- returns a `Uint8Array` of UTF-8 bytes, not a JS string.

`JSON.stringify` is never allowed for signed or hashed inputs. The
existing `src/services/vaultIntegrityV2/canonicalJson.ts` is a
convenience helper for Manifest V2 and is considered legacy for this
ADR.

#### 2. Byte encoding

Keys, hashes, signatures and nonces on the wire and in logs use
base64url without padding (RFC 4648 §5). The canonical form is the
bytes; the string form is a projection.

#### 3. Hash function (`hash-v1`)

SHA-256 is the default hash function. Every hash input is the output
of `canonicalizeVaultStructure`, not a JS string.

#### 4. Record AEAD (`record-aead-v1`)

AES-256-GCM with a 96-bit random nonce per encryption and a 128-bit
authentication tag. Nonces are generated per encryption and never
reused under the same record key. AAD is the canonical bytes of the
`RecordAAD` structure defined in concept section 5 and normatively
reproduced in `src/services/vaultOpLog/recordAad.ts`.

```ts
type RecordAAD = {
  app: 'singra-vault';
  aadSchema: 'record-aad-v1';
  vaultId: string;
  recordId: string;
  recordType:
    | 'item'
    | 'category'
    | 'attachment_metadata'
    | 'attachment_chunk'
    | 'manifest'
    | 'tombstone';
  recordVersion: number;   // >= 0
  keyVersion: number;      // >= 0
  encryptionSchema: 'record-aead-v1';
};
```

`ciphertextHash = SHA-256(canonical({ vaultId, recordId, recordType,
recordVersion, keyVersion, encryptionSchema, nonce_b64url,
ciphertext_b64url, aadHash_b64url }))`.

`aadHash = SHA-256(canonical(RecordAAD))`.

#### 5. Record key derivation

Record keys are derived from the vault encryption key with HKDF-SHA-256.
The `info` parameter is
`canonical({ purpose: 'singra-vault/record-key-v1', vaultId, recordId,
recordType, keyVersion })`. `salt` is the empty byte string. Output
length is 32 bytes. Record keys are never persisted and are wiped after
use through the existing `SecureBuffer` helpers.

The master password is never a record key. It continues to unlock the
vault encryption key via Argon2id as today (`cryptoService.ts`).

#### 6. Operation signature (`device-signature-v1`)

Phase 1 uses WebCrypto ECDSA over P-256 with SHA-256 because it is
natively available in every supported browser and Tauri WebView. Every
device generates a non-exportable private signing key and a
base64url-encoded SPKI public key. The public key is stored in the
`vault_device_trust_records` table. The private key:

- is non-exportable on every platform where WebCrypto supports
  `extractable: false`,
- is persisted only as a wrapped, extractable-free `CryptoKey` handle
  referenced by `deviceId`,
- Tauri stores its `CryptoKey` handle in the same IndexedDB scope as
  today's Web client. Phase 5 promotes Tauri to the OS keychain via the
  already-planned Tauri secure storage work; until then the risk
  difference between Web and Tauri is documented in `docs/SECURITY.md`.

`opHash = SHA-256(canonical(operationWithoutSignature))`. The signature
input is the raw `opHash` bytes, never a hex or base64url string. The
signed body contains exactly the fields enumerated in concept section
6.5. A follow-up ADR can extend the signature scheme to ML-DSA
(`device-signature-pq-v1`) reusing the existing `@noble/post-quantum`
dependency.

#### 7. Operation log head (`head-v1`)

`resultingVaultHead = SHA-256(canonical({ previousVaultHead_b64url |
null, opHash_b64url, recordId, recordType, newRecordHash_b64url | null,
opType }))`. The client stores the last locally verified head as
`lastVerifiedVaultHead`. A head conflict does not trigger a silent
rebaseline — it triggers safe mode or a fork diagnostic depending on
severity.

#### 8. Rebase model (`rebase-v1`)

When a client receives a `stale_vault_head` conflict from the server,
it may rebase the operation to the current head:

1. Generate a fresh `op_id` (UUID v4).
2. Keep the original `intent_id` unchanged to preserve user intent identity.
3. Set `rebased_from_op_id` to the original `op_id` being rebased.
4. Update `base_vault_head` to the current server head.
5. For record operations, update `base_record_version` and
   `previous_ciphertext_hash` to the current record state.
6. Re-sign with the device's private signing key.
7. Submit the rebased operation.

The server stores `intent_id` and `rebased_from_op_id` but does not
validate their relationship. Client-side verification ensures that:

- A chain of rebased operations links back to the original intent via
  `rebased_from_op_id`.
- The same `intent_id` is never used for logically different user intents.
- Rebase depth is bounded (clients enforce a maximum rebase chain length
  to prevent abuse).

`intent_id` is optional for the first submission of an intent. It becomes
mandatory for all rebased versions of that intent. `rebased_from_op_id`
is null for the first submission and non-null for rebased versions.

### Trust classification

`deviceTrustService` classifies an operation author as one of:

- `trusted` if the device is recorded as `trusted` at the operation's
  `trust_epoch` and has not been revoked before
  `created_at_client`,
- `revoked` if the device was `revoked` at or before the operation's
  creation time,
- `unknown` if the `author_device_id` is not in the trust list.

Only `trusted` authors let the operation advance the state machine.
`revoked` and `unknown` authors always produce quarantine without any
decryption attempt.

### Scope for this ADR

This ADR binds the contracts above. It does not yet:

- change the vault provider runtime,
- change the server schema,
- remove R3 or Manifest V2,
- touch the UI, autofill, export, search or clipboard paths,
- introduce a server RPC,
- change the migration flow visible to users.

These changes land in subsequent phases (see
`docs/vault-op-log/inventory-and-phase-plan.md`).

## Device key storage per platform

| Platform | Signing key material | Storage |
|---|---|---|
| Web (browser) | WebCrypto `CryptoKey` with `extractable: false` | IndexedDB, same origin as vault store |
| Tauri | Phase 1: WebCrypto `CryptoKey` with `extractable: false` inside the WebView context | Phase 5 target: `tauri-plugin-stronghold` or platform keychain, tracked separately |

Private signing keys are never exported, never logged, and never
transmitted. A lost private signing key is a device loss event — the
device must be re-enrolled by another trusted device.

## Canonicalization and hashing rules

These rules are binding for every signed or hashed structure introduced
by this ADR:

1. Object keys are sorted by their UTF-8 byte sequence.
2. `undefined`, `NaN`, `Infinity`, `-Infinity`, `Symbol`, `Function`,
   `BigInt` are rejected anywhere in the structure.
3. `null` is preserved and is not equivalent to a missing field.
4. Missing fields on optional types are explicit `null`, never omitted
   when the field is part of a security-relevant payload.
5. Strings are NFC-normalised.
6. Numbers are safe integers in JSON integer form, otherwise shortest
   round-trip decimal form with a sign.
7. The output is always `Uint8Array` of UTF-8 bytes.
8. Test vectors under
   `src/services/vaultOpLog/__tests__/testVectors/canonical.ts`
   pin the exact byte output for every canonical shape that is ever
   signed or hashed.

## Database constraints and RLS (target)

Phase 2 will realise these as SQL. They are normative for the
implementation:

- `vault_records (vault_id, record_id)` primary key; `record_version`
  monotonic per record.
- `vault_operations (op_id)` unique; `(vault_id, op_id)` also unique;
  attempting to insert an identical `op_id` with a different canonical
  body is an error.
- `vault_operations.base_record_version` / `previous_ciphertext_hash` must
  be non-null for `update`, `delete`, `restore`, `move`, `rekey`.
  `previous_ciphertext_hash` is compared against `vault_records.ciphertext_hash`
  to ensure the operation binds to the exact ciphertext state it claims to base on.
- `vault_records.last_op_id` must reference an existing
  `vault_operations.op_id` in the same vault.
- `deleted = true` is only reachable through a `delete` operation that
  writes a tombstone record.
- `submit_vault_operation` writes the operation and the resulting
  record row in one transaction; partial commits are rejected.
- RLS: a user can only read rows where they own the `vault_id` or
  where an explicit share/trust relationship exists (phase 2 decision).
  Anon role has no read access.
- Direct writes to `vault_items` and `categories` are blocked at the
  policy level in phase 6 after the runtime has moved.

## Multi-tab and Web/Tauri concurrency (target)

- The pending operation queue uses a Web Lock (`navigator.locks`) named
  `singra-vault/op-log/<vaultId>` with a Tauri fallback via a
  `localStorage` leader-election token.
- A retry of the same user intent reuses its `op_id`. A new user
  intent always gets a new `op_id`.
- App reload during sync replays pending operations from the queue on
  next unlock; a half-committed state on the server is resolved by the
  idempotent RPC.

## Plaintext lifecycle in the client

- Plaintexts are produced only after the full verification pipeline
  classifies the record as `verified`.
- Plaintexts are not stored in any global React state. They live in
  per-view closures and are wiped when the view unmounts.
- A record transitioning to any `quarantined*` state immediately
  invalidates any derived plaintext state, disables clipboard buttons
  and removes the record from the search index.
- Errors, logs and diagnostic bundles never contain plaintexts,
  signing keys, vault keys, nonces or passwords.

## Consequences

- The public vault provider API stays the same for phase 0 and phase 1.
  Every consumer of `useVault()` keeps working because no runtime
  module has changed yet.
- Phase 1 ships three new files plus their tests under
  `src/services/vaultOpLog/`. They are not imported from any product
  path. This is intentional — the contracts need to be pinned and
  byte-reproducible before any state machine or sync work can safely
  depend on them.
- Phase 1 adds no new runtime dependency. It reuses WebCrypto,
  `hash-wasm` / `argon2id` (already present) and the existing
  `SecureBuffer` helper.
- Phase 2 (DB schema) and phase 6 (provider rewrite) are the points at
  which user-visible behaviour changes. Every phase must ship with a
  targeted test suite and a documented runtime check on Web and Tauri
  before the corresponding legacy code is removed.

## Open questions tracked for later phases

1. Whether `rekey` gets its own `vaultKeyWrapping` sub-structure or
   reuses the existing encrypted user-key envelope. Decision in
   phase 2.
2. Whether attachments continue to use the current chunked bucket model
   and only their metadata becomes a `VaultRecordRow`, or whether
   chunks are also represented as records. Decision in phase 3.
3. Whether shared / family collection rows become per-share operation
   logs or whether sharing joins via an additional trust list.
   Decision deferred to after single-user parity.
4. Whether the server enforces the `previous_op_hash` chain (cheap and
   detects gaps early) or only surfaces gap diagnostics and lets the
   client decide. Decision in phase 2.
5. Whether Post-Quantum signatures (`device-signature-pq-v1`) replace
   ECDSA in a follow-up or run as a dual-signature scheme during
   transition. Decision deferred.

## Tests

Phase 1 tests live in `src/services/vaultOpLog/__tests__/` and cover:

- canonicalisation byte vectors for fixed shapes,
- rejection of `undefined`, `NaN`, infinities, non-plain types,
- NFC normalisation byte-equality,
- key ordering by UTF-8 bytes on non-ASCII keys,
- AAD v1 construction, byte output and equality semantics,
- record key derivation output equality for identical inputs and
  non-equality when any derivation input differs by one byte,
- AEAD seal/open round-trip,
- AEAD open rejection on any AAD field mutation,
- AEAD open rejection on any ciphertext byte mutation,
- opHash byte stability,
- signature verification,
- signature rejection when any signed field is mutated,
- device trust classification for `trusted`, `revoked` and `unknown`,
- revocation time ordering (operations signed after revocation are
  always `revoked`),
- trust epoch monotonicity.

No test reads or writes real vault data, real passwords or real
secrets. All test material is generated inline with
`crypto.getRandomValues`.

## References

- `docs/vault-op-log/inventory-and-phase-plan.md` — phase plan and
  legacy-path inventory with file and line pointers.
- `singra_vault_neues_integrations_quarantaene_konzept.md` — binding
  product concept this ADR implements.
- `docs/adr/0003-vault-integrity-quarantine-v2.md` — superseded in full
  once phase 7 completes.
