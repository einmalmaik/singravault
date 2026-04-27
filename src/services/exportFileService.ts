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

const WINDOWS_RESERVED_FILE_BASENAME = /^(con|prn|aux|nul|com[1-9]|lpt[1-9])(\..*)?$/i;

function removeControlCharacters(value: string): string {
  return [...value].filter((char) => {
    const codePoint = char.codePointAt(0) ?? 0;
    return codePoint > 0x1f && codePoint !== 0x7f;
  }).join("");
}

export async function saveExportFile(payload: ExportFilePayload): Promise<boolean> {
  const safePayload = {
    ...payload,
    name: sanitizeExportFileName(payload.name),
  };

  if (isTauriRuntime()) {
    return saveExportFileInDesktopShell(safePayload);
  }

  return saveExportFileInBrowser(safePayload);
}

export function sanitizeExportFileName(name: string): string {
  const normalized = removeControlCharacters(name.normalize("NFKC"))
    .replace(/[<>:"/\\|?*\u2028\u2029\u202a-\u202e\u2066-\u2069]/g, "-")
    .replace(/\s+/g, " ")
    .trim();

  const withoutTrailingDots = normalized.replace(/[. ]+$/g, "");
  const safeName = withoutTrailingDots && withoutTrailingDots !== "." && withoutTrailingDots !== ".."
    ? withoutTrailingDots
    : "singra-vault-export";

  const nonReservedName = WINDOWS_RESERVED_FILE_BASENAME.test(safeName)
    ? `_${safeName}`
    : safeName;

  return nonReservedName.slice(0, 180);
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
