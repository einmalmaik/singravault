// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 — see LICENSE
/**
 * @fileoverview File Attachment Service
 *
 * Upload, download, and manage encrypted file attachments
 * for vault items. Files are encrypted client-side before upload
 * and stored in Supabase Storage.
 *
 * File metadata (file_name, mime_type) is encrypted in the
 * `encrypted_metadata` column so that a database-level attacker
 * cannot see which filenames or types a user stores. The plaintext
 * `file_name` and `mime_type` columns are kept as opaque placeholders
 * for backward-compat (set to "encrypted" / "application/octet-stream").
 *
 * Limits: 100MB per file, 1GB total per user.
 */

import { supabase } from '@/integrations/supabase/client';

// ============ Types ============

export interface FileAttachment {
    id: string;
    vault_item_id: string;
    file_name: string;
    file_size: number;
    mime_type: string | null;
    storage_path: string;
    encrypted: boolean;
    encrypted_metadata?: string | null;
    created_at: string;
}

export interface UploadProgress {
    fileName: string;
    progress: number; // 0–100
    status: 'encrypting' | 'uploading' | 'complete' | 'error';
    error?: string;
}

/**
 * Internal shape of the cleartext metadata object that gets encrypted.
 */
interface FileMetadata {
    file_name: string;
    mime_type: string | null;
}

// ============ Constants ============

const MAX_FILE_SIZE = 100 * 1024 * 1024;   // 100 MB per file
const MAX_TOTAL_SIZE = 1024 * 1024 * 1024; // 1 GB total per user
const BUCKET_NAME = 'vault-attachments';

// ============ Helpers ============

/**
 * Format bytes to human-readable string
 */
export function formatFileSize(bytes: number): string {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
    return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

/**
 * Get file icon based on MIME type
 */
export function getFileIcon(mimeType: string | null): string {
    if (!mimeType) return '📎';
    if (mimeType.startsWith('image/')) return '🖼️';
    if (mimeType.startsWith('video/')) return '🎬';
    if (mimeType.startsWith('audio/')) return '🎵';
    if (mimeType.includes('pdf')) return '📄';
    if (mimeType.includes('zip') || mimeType.includes('rar') || mimeType.includes('tar')) return '📦';
    if (mimeType.includes('text')) return '📝';
    if (mimeType.includes('spreadsheet') || mimeType.includes('excel')) return '📊';
    if (mimeType.includes('document') || mimeType.includes('word')) return '📋';
    return '📎';
}

// ============ Metadata Encryption Helpers ============

/**
 * Encrypts file metadata (name + MIME type) into a single ciphertext string.
 *
 * @param fileName - Original file name
 * @param mimeType - MIME type (or null)
 * @param encryptFn - Vault encryption callback (from VaultContext.encryptData)
 * @returns Encrypted JSON string
 */
async function encryptFileMetadata(
    fileName: string,
    mimeType: string | null,
    encryptFn: (plaintext: string) => Promise<string>,
): Promise<string> {
    const meta: FileMetadata = { file_name: fileName, mime_type: mimeType };
    return encryptFn(JSON.stringify(meta));
}

/**
 * Decrypts encrypted_metadata back into file_name and mime_type.
 * Falls back to the plaintext columns when encrypted_metadata is absent
 * (backward-compat with rows created before this feature).
 *
 * @param row - Raw row from the database
 * @param decryptFn - Vault decryption callback
 * @returns FileAttachment with plaintext file_name and mime_type restored
 */
async function decryptFileMetadataRow(
    row: FileAttachment,
    decryptFn?: (encrypted: string) => Promise<string>,
): Promise<FileAttachment> {
    if (!row.encrypted_metadata || !decryptFn) {
        // Legacy row or no decrypt function — use plaintext columns as-is
        return row;
    }

    try {
        const json = await decryptFn(row.encrypted_metadata);
        const meta: FileMetadata = JSON.parse(json);
        return {
            ...row,
            file_name: meta.file_name,
            mime_type: meta.mime_type,
        };
    } catch {
        // If decryption fails (wrong key, corrupted), fall back to raw columns
        console.error('Failed to decrypt file metadata, using raw columns');
        return row;
    }
}

// ============ Service Functions ============

/**
 * Get all attachments for a vault item.
 * When a decryptFn is provided, encrypted metadata is transparently decrypted
 * so callers see the real file_name and mime_type.
 *
 * @param vaultItemId - The vault item to list attachments for
 * @param decryptFn - Optional vault decryption callback
 */
export async function getAttachments(
    vaultItemId: string,
    decryptFn?: (encrypted: string) => Promise<string>,
): Promise<FileAttachment[]> {
    const { data, error } = await supabase
        .from('file_attachments')
        .select('*')
        .eq('vault_item_id', vaultItemId)
        .order('created_at', { ascending: false });

    if (error) throw error;
    const rows = (data || []) as FileAttachment[];

    // Decrypt metadata in parallel when a decrypt function is available
    if (decryptFn) {
        return Promise.all(rows.map(row => decryptFileMetadataRow(row, decryptFn)));
    }
    return rows;
}

/**
 * Get total storage used by user
 */
export async function getStorageUsage(userId: string): Promise<{ used: number; limit: number }> {
    const { data, error } = await supabase
        .from('file_attachments')
        .select('file_size')
        .eq('user_id', userId);

    if (error) throw error;

    const used = (data || []).reduce((sum, f) => sum + Number(f.file_size), 0);
    return { used, limit: MAX_TOTAL_SIZE };
}

/**
 * Upload an encrypted file attachment.
 * Both the file content and the file metadata (name, MIME type) are encrypted
 * client-side before being stored.
 *
 * @param userId - Owner user ID
 * @param vaultItemId - Vault item to attach to
 * @param file - Browser File object
 * @param encryptFn - Vault encryption callback (encrypts plaintext string -> ciphertext string)
 */
export async function uploadAttachment(
    userId: string,
    vaultItemId: string,
    file: File,
    encryptFn: (data: string) => Promise<string>,
): Promise<FileAttachment> {
    // Validate file size
    if (file.size > MAX_FILE_SIZE) {
        throw new Error(`FILE_TOO_LARGE:${formatFileSize(MAX_FILE_SIZE)}`);
    }

    // Check total usage
    const { used } = await getStorageUsage(userId);
    if (used + file.size > MAX_TOTAL_SIZE) {
        throw new Error(`STORAGE_LIMIT_REACHED:${formatFileSize(used)}:${formatFileSize(MAX_TOTAL_SIZE)}`);
    }

    // Read file as base64
    const arrayBuffer = await file.arrayBuffer();
    const base64 = btoa(
        new Uint8Array(arrayBuffer).reduce((data, byte) => data + String.fromCharCode(byte), '')
    );

    // Encrypt the base64 content
    const encryptedContent = await encryptFn(base64);

    // Generate unique storage path
    const fileId = crypto.randomUUID();
    const storagePath = `${userId}/${vaultItemId}/${fileId}`;

    // Upload encrypted content to Supabase Storage
    const blob = new Blob([encryptedContent], { type: 'application/octet-stream' });
    const { error: uploadError } = await supabase.storage
        .from(BUCKET_NAME)
        .upload(storagePath, blob, {
            contentType: 'application/octet-stream',
            upsert: false,
        });

    if (uploadError) throw uploadError;

    // Encrypt file metadata (name + MIME type)
    const encryptedMeta = await encryptFileMetadata(file.name, file.type || null, encryptFn);

    // Save metadata in database.
    // file_name and mime_type are set to opaque placeholders so that a
    // database-level attacker learns nothing. The real values are in
    // encrypted_metadata and can only be read with the vault key.
    const { data: attachment, error: dbError } = await supabase
        .from('file_attachments')
        .insert({
            user_id: userId,
            vault_item_id: vaultItemId,
            file_name: 'encrypted',
            file_size: file.size,
            mime_type: 'application/octet-stream',
            storage_path: storagePath,
            encrypted: true,
            encrypted_metadata: encryptedMeta,
        })
        .select('*')
        .single();

    if (dbError) {
        // Cleanup: remove uploaded file if DB insert fails
        await supabase.storage.from(BUCKET_NAME).remove([storagePath]);
        throw dbError;
    }

    // Return the attachment with plaintext metadata restored for immediate use
    return {
        ...(attachment as FileAttachment),
        file_name: file.name,
        mime_type: file.type || null,
    };
}

/**
 * Download and decrypt a file attachment.
 * If the attachment has encrypted_metadata, it is decrypted to obtain
 * the real file_name and mime_type for the browser download.
 *
 * @param attachment - The FileAttachment record (may already have decrypted metadata)
 * @param decryptFn - Vault decryption callback
 */
export async function downloadAttachment(
    attachment: FileAttachment,
    decryptFn: (data: string) => Promise<string>,
): Promise<void> {
    // Download from storage
    const { data, error } = await supabase.storage
        .from(BUCKET_NAME)
        .download(attachment.storage_path);

    if (error) throw error;
    if (!data) throw new Error('Download failed');

    // Read encrypted content
    const encryptedContent = await data.text();

    // Decrypt
    const base64 = await decryptFn(encryptedContent);

    // Convert base64 back to bytes
    const binaryString = atob(base64);
    const bytes = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) {
        bytes[i] = binaryString.charCodeAt(i);
    }

    // Decrypt metadata if not already done (safety net)
    const resolved = await decryptFileMetadataRow(attachment, decryptFn);

    // Trigger browser download
    const blob = new Blob([bytes], { type: resolved.mime_type || 'application/octet-stream' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = resolved.file_name;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

/**
 * Delete a file attachment
 */
export async function deleteAttachment(attachment: FileAttachment): Promise<void> {
    // Delete from storage
    const { error: storageError } = await supabase.storage
        .from(BUCKET_NAME)
        .remove([attachment.storage_path]);

    if (storageError) {
        console.error('Storage delete error (continuing with DB delete):', storageError);
    }

    // Delete from database
    const { error: dbError } = await supabase
        .from('file_attachments')
        .delete()
        .eq('id', attachment.id);

    if (dbError) throw dbError;
}
