# Premium File Upload E2EE

**Status:** 2026-04-26

## Format

Premium attachments use `sv-file-manifest-v1` in `@singra/premium/src/services/fileAttachmentService.ts`.

- One random AES-256-GCM file key is generated per file.
- The file key is wrapped with the locally unlocked vault/UserKey via binary vault encryption.
- Files are sliced into 4 MiB plaintext chunks.
- Every chunk is encrypted client-side before upload with AES-GCM, a random nonce, and AAD.
- The encrypted manifest contains the original filename, extension, MIME type, original size, last-modified timestamp, chunk list, ciphertext hashes, revision fields, and preview metadata.
- Supabase stores only opaque paths, ciphertext chunks, ciphertext size, owner/item binding, timestamps, and the encrypted manifest.

All file types are treated as opaque binary input. There is no server-side preview, thumbnail, OCR, MIME detection, EXIF extraction, PDF metadata parsing, or plaintext classification.

## Download Memory Behavior

Downloads prefer a streaming writer:

- Web/PWA: if `showSaveFilePicker` is available, the client writes each decrypted chunk to the selected `FileSystemWritableFileStream` and clears the chunk buffer best-effort after writing.
- Tauri/Desktop: the client writes each decrypted chunk to `<target>.singra-partial` through the Tauri FS plugin, closes the file, then renames it to the target path. On handled errors the partial file is removed.
- Fallback: browsers without a writable file API still build a plaintext Blob to trigger a normal browser download. This fallback is compatible but not RAM-optimal for 1 GB files.

No decrypted chunk is uploaded, cached, or written to Supabase. Browser and OS behavior after the user explicitly saves a decrypted file is outside the vault-storage boundary.

## Upload And Resume

The current implementation uses own encrypted chunk objects rather than Supabase TUS resumable uploads.

Reason: the cryptographic unit is the encrypted chunk plus encrypted manifest. Chunk paths are opaque, chunks are authenticated through AAD, and the database row is inserted only after all ciphertext chunks and the encrypted manifest are ready. Supabase TUS is suitable for resumable large object transport, but using it safely here would still require encrypted payloads, opaque object names, authenticated chunk/session state, and manifest commit logic.

Current behavior:

- Only encrypted chunks are uploaded.
- `file_id` acts as the upload session/prefix.
- A file is not visible as an attachment until the manifest row is committed.
- On handled upload errors, chunks uploaded in that session are removed.

Known gap: there is no durable cross-session resume or server-side cleanup job for app/browser crashes yet. Such crashes can leave orphaned ciphertext chunks. This is a storage/accounting risk, not a plaintext leak, but it should be cleaned up with an incomplete-upload registry or scheduled storage prefix cleanup.

## Rollback And Freshness

AES-GCM and chunk hashes detect corruption, replacement, reordering, and wrong keys for the currently referenced manifest. Freshness needs state.

Implemented detection:

- `file_revision` is included in the encrypted manifest.
- `manifest_root` covers the planned chunk layout.
- `previous_manifest_hash` is part of the manifest format.
- Chunk AAD binds `userId`, `vaultItemId`, `fileId`, `fileRevision`, `manifestRoot`, `chunkIndex`, and `chunkCount`.
- The client stores a local last-seen manifest revision/hash checkpoint and blocks older or conflicting revisions when that checkpoint exists.

Limit: without a trusted local checkpoint or an external transparency/audit system, a malicious server can replay an older valid manifest plus old ciphertext chunks to a fresh device. The accurate claim is rollback detection when a trusted previous state is available, not absolute rollback impossibility.

## Visible Metadata

Visible to Supabase/server/storage:

- owner/user binding
- vault item/file binding
- upload/update timestamps
- opaque object paths
- number of chunks
- ciphertext object sizes
- approximate storage usage
- access/download timing

Not currently hidden:

- approximate plaintext size, because no padding is implemented
- access patterns
- object count

Not visible in plaintext by design:

- file content
- original filename
- extension
- MIME type
- EXIF/image metadata
- PDF metadata
- text metadata
- preview/thumbnail metadata
- wrapped file key plaintext

## Release Safety

Private recovery/backup/key material and installers must not live in `public/`, `dist/`, `build/`, or shipped asset folders. `npm run release:check-artifacts` scans release-exposed paths and fails on suspicious private/recovery names, private text files in `public/`, large shipped artifacts, and installers/archives.
