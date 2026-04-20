// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE
/**
 * @fileoverview Shared export save abstraction for browser and desktop.
 *
 * Web/PWA continue to use Blob downloads. Tauri uses the native save dialog
 * and writes the chosen file path directly.
 */

import { isTauriRuntime } from "@/platform/runtime";

export interface ExportFilePayload {
  name: string;
  mime: string;
  content: Blob | string | Uint8Array | ArrayBuffer;
}

export async function saveExportFile(payload: ExportFilePayload): Promise<boolean> {
  if (isTauriRuntime()) {
    return saveExportFileInDesktopShell(payload);
  }

  return saveExportFileInBrowser(payload);
}

async function saveExportFileInDesktopShell(payload: ExportFilePayload): Promise<boolean> {
  const [{ save }, { writeFile }] = await Promise.all([
    import("@tauri-apps/plugin-dialog"),
    import("@tauri-apps/plugin-fs"),
  ]);

  const path = await save({
    defaultPath: payload.name,
    filters: buildDialogFilters(payload.name, payload.mime),
  });

  if (!path) {
    return false;
  }

  await writeFile(path, await toUint8Array(payload.content));
  return true;
}

function saveExportFileInBrowser(payload: ExportFilePayload): boolean {
  const blob = payload.content instanceof Blob
    ? payload.content
    : new Blob([payload.content], { type: payload.mime });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = payload.name;
  document.body.appendChild(anchor);
  anchor.click();
  document.body.removeChild(anchor);
  URL.revokeObjectURL(url);
  return true;
}

function buildDialogFilters(name: string, mime: string): Array<{ name: string; extensions: string[] }> | undefined {
  const extension = getFileExtension(name);
  if (!extension) {
    return undefined;
  }

  return [{
    name: mime || "Export",
    extensions: [extension],
  }];
}

function getFileExtension(name: string): string | null {
  const trimmedName = name.trim();
  const lastDot = trimmedName.lastIndexOf(".");
  if (lastDot <= 0 || lastDot === trimmedName.length - 1) {
    return null;
  }

  return trimmedName.slice(lastDot + 1).toLowerCase();
}

async function toUint8Array(content: ExportFilePayload["content"]): Promise<Uint8Array> {
  if (typeof content === "string") {
    return new TextEncoder().encode(content);
  }

  if (content instanceof Uint8Array) {
    return content;
  }

  if (content instanceof ArrayBuffer) {
    return new Uint8Array(content);
  }

  return new Uint8Array(await content.arrayBuffer());
}
