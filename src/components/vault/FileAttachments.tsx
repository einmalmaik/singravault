// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 — see LICENSE
/**
 * @fileoverview File Attachments Component
 *
 * Drag & drop file upload with encrypted storage.
 * Shows list of attached files with download/delete actions.
 * Premium feature — wrapped in FeatureGate by parent.
 */

import { useState, useEffect, useRef, useCallback } from 'react';
import { useTranslation } from 'react-i18next';
import {
    Upload,
    Download,
    Trash2,
    Loader2,
    FolderOpen,
    HardDrive,
} from 'lucide-react';

import { Button } from '@/components/ui/button';
import { Progress } from '@/components/ui/progress';
import { useToast } from '@/hooks/use-toast';
import { useAuth } from '@/contexts/AuthContext';
import { useVault } from '@/contexts/VaultContext';
import { FeatureGate } from '@/components/Subscription/FeatureGate';
import {
    getAttachments,
    uploadAttachment,
    downloadAttachment,
    deleteAttachment,
    getStorageUsage,
    formatFileSize,
    getFileIcon,
    type FileAttachment,
} from '@/services/fileAttachmentService';
import { cn } from '@/lib/utils';

interface FileAttachmentsProps {
    vaultItemId: string | null;
}

export function FileAttachments({ vaultItemId }: FileAttachmentsProps) {
    const { t } = useTranslation();
    const { toast } = useToast();
    const { user } = useAuth();
    const { encryptItem, decryptItem, encryptData, decryptData } = useVault();

    const [files, setFiles] = useState<FileAttachment[]>([]);
    const [loading, setLoading] = useState(false);
    const [uploading, setUploading] = useState(false);
    const [downloadingId, setDownloadingId] = useState<string | null>(null);
    const [deletingId, setDeletingId] = useState<string | null>(null);
    const [isDragOver, setIsDragOver] = useState(false);
    const [usage, setUsage] = useState({ used: 0, limit: 1073741824 });
    const fileInputRef = useRef<HTMLInputElement>(null);

    // Load attachments
    const loadFiles = useCallback(async () => {
        if (!vaultItemId || !user) return;
        setLoading(true);
        try {
            const [attachments, storageUsage] = await Promise.all([
                getAttachments(vaultItemId, decryptData),
                getStorageUsage(user.id),
            ]);
            setFiles(attachments);
            setUsage(storageUsage);
        } catch (err) {
            console.error('Failed to load attachments:', err);
        } finally {
            setLoading(false);
        }
    }, [vaultItemId, user, decryptData]);

    useEffect(() => {
        loadFiles();
    }, [loadFiles]);

    const handleUpload = async (filesToUpload: File[]) => {
        if (!user || !vaultItemId) return;

        setUploading(true);
        let successCount = 0;

        for (const file of filesToUpload) {
            try {
                await uploadAttachment(
                    user.id,
                    vaultItemId,
                    file,
                    encryptData,
                );
                successCount++;
            } catch (err) {
                const msg = err instanceof Error ? err.message : String(err);
                let description = msg;
                if (msg.startsWith('FILE_TOO_LARGE:')) {
                    description = t('fileAttachments.fileTooLarge', { size: msg.split(':')[1] });
                } else if (msg.startsWith('STORAGE_LIMIT_REACHED:')) {
                    const parts = msg.split(':');
                    description = t('fileAttachments.storageLimitReached', { used: parts[1], limit: parts[2] });
                }
                toast({
                    title: t('fileAttachments.uploadError'),
                    description,
                    variant: 'destructive',
                });
            }
        }

        if (successCount > 0) {
            toast({ title: t('fileAttachments.uploaded', { count: successCount }) });
            await loadFiles();
        }
        setUploading(false);
    };

    const handleDownload = async (attachment: FileAttachment) => {
        setDownloadingId(attachment.id);
        try {
            await downloadAttachment(
                attachment,
                decryptData,
            );
        } catch (err) {
            toast({
                title: t('fileAttachments.downloadError'),
                description: err instanceof Error ? err.message : String(err),
                variant: 'destructive',
            });
        } finally {
            setDownloadingId(null);
        }
    };

    const handleDelete = async (attachment: FileAttachment) => {
        setDeletingId(attachment.id);
        try {
            await deleteAttachment(attachment);
            toast({ title: t('fileAttachments.deleted') });
            await loadFiles();
        } catch (err) {
            toast({
                title: t('fileAttachments.deleteError'),
                description: err instanceof Error ? err.message : String(err),
                variant: 'destructive',
            });
        } finally {
            setDeletingId(null);
        }
    };

    // Drag and drop handlers
    const onDragOver = (e: React.DragEvent) => {
        e.preventDefault();
        setIsDragOver(true);
    };
    const onDragLeave = () => setIsDragOver(false);
    const onDrop = (e: React.DragEvent) => {
        e.preventDefault();
        setIsDragOver(false);
        const droppedFiles = Array.from(e.dataTransfer.files);
        if (droppedFiles.length > 0) handleUpload(droppedFiles);
    };
    const onFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
        const selectedFiles = Array.from(e.target.files || []);
        if (selectedFiles.length > 0) handleUpload(selectedFiles);
        e.target.value = '';
    };

    if (!vaultItemId) return null;

    const usagePercent = Math.round((usage.used / usage.limit) * 100);

    return (
        <FeatureGate feature="file_attachments" featureLabel={t('fileAttachments.title')}>
            <div className="space-y-4 pt-4 border-t">
                <div className="flex items-center justify-between">
                    <h3 className="text-sm font-semibold flex items-center gap-2">
                        <FolderOpen className="w-4 h-4" />
                        {t('fileAttachments.title')}
                    </h3>
                    <div className="flex items-center gap-2 text-xs text-muted-foreground">
                        <HardDrive className="w-3 h-3" />
                        {formatFileSize(usage.used)} / {formatFileSize(usage.limit)}
                    </div>
                </div>

                {/* Storage usage bar */}
                <Progress value={usagePercent} className="h-1.5" />

                {/* Drop zone */}
                <div
                    onDragOver={onDragOver}
                    onDragLeave={onDragLeave}
                    onDrop={onDrop}
                    onClick={() => fileInputRef.current?.click()}
                    className={cn(
                        'border-2 border-dashed rounded-lg p-6 text-center cursor-pointer transition-all',
                        'hover:border-primary/50 hover:bg-primary/5',
                        isDragOver && 'border-primary bg-primary/10 scale-[1.02]',
                        uploading && 'pointer-events-none opacity-50',
                    )}
                >
                    <input
                        ref={fileInputRef}
                        type="file"
                        multiple
                        className="hidden"
                        onChange={onFileSelect}
                    />
                    {uploading ? (
                        <Loader2 className="w-8 h-8 mx-auto animate-spin text-primary" />
                    ) : (
                        <>
                            <Upload className="w-8 h-8 mx-auto text-muted-foreground mb-2" />
                            <p className="text-sm text-muted-foreground">
                                {t('fileAttachments.dropzone')}
                            </p>
                            <p className="text-xs text-muted-foreground/70 mt-1">
                                {t('fileAttachments.maxSize', { size: '100 MB' })}
                            </p>
                        </>
                    )}
                </div>

                {/* File list */}
                {loading ? (
                    <div className="flex justify-center py-4">
                        <Loader2 className="w-5 h-5 animate-spin text-muted-foreground" />
                    </div>
                ) : files.length > 0 ? (
                    <div className="space-y-2">
                        {files.map((file) => (
                            <div
                                key={file.id}
                                className="flex items-center gap-3 p-3 rounded-lg bg-muted/30 hover:bg-muted/50 transition-colors"
                            >
                                <span className="text-lg">{getFileIcon(file.mime_type)}</span>
                                <div className="flex-1 min-w-0">
                                    <p className="text-sm font-medium truncate">{file.file_name}</p>
                                    <p className="text-xs text-muted-foreground">
                                        {formatFileSize(file.file_size)}
                                    </p>
                                </div>
                                <div className="flex items-center gap-1">
                                    <Button
                                        variant="ghost"
                                        size="icon"
                                        className="h-8 w-8"
                                        onClick={() => handleDownload(file)}
                                        disabled={downloadingId === file.id}
                                    >
                                        {downloadingId === file.id ? (
                                            <Loader2 className="w-4 h-4 animate-spin" />
                                        ) : (
                                            <Download className="w-4 h-4" />
                                        )}
                                    </Button>
                                    <Button
                                        variant="ghost"
                                        size="icon"
                                        className="h-8 w-8 text-destructive hover:text-destructive"
                                        onClick={() => handleDelete(file)}
                                        disabled={deletingId === file.id}
                                    >
                                        {deletingId === file.id ? (
                                            <Loader2 className="w-4 h-4 animate-spin" />
                                        ) : (
                                            <Trash2 className="w-4 h-4" />
                                        )}
                                    </Button>
                                </div>
                            </div>
                        ))}
                    </div>
                ) : null}
            </div>
        </FeatureGate>
    );
}
